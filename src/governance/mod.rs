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
    /// SHA-256 hex digest of the configured /admin bearer token, computed once at construction. The
    /// plaintext token is NOT retained — only its digest, which is all the constant-time compare on
    /// the /admin path needs (less plaintext secret held in memory). `None` = admin API disabled.
    admin_token_hash: Option<String>,
    /// Fail-mode for the atomic budget check-and-charge on a STORE ERROR. `Allow` (default) fails
    /// open (proceed → availability); `Deny` fails closed (reject → hard guarantee). Only the
    /// store-error path consults this; a definitive over-budget result always rejects. Set from
    /// `GovernanceCfg::budget_on_store_error` via `with_budget_on_store_error` at construction.
    budget_on_store_error: crate::config::BudgetOnStoreError,
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

impl GovState {
    pub(crate) fn new(
        store: Arc<dyn Store>,
        price_per_request_cents: i64,
        price_per_1k_tokens_cents: i64,
        admin_token: Option<String>,
    ) -> StoreResult<Self> {
        let by_hash = Self::load(store.as_ref())?;
        let by_access_key_id = Self::load_by_access_key_id(store.as_ref(), &by_hash)?;
        Ok(Self {
            store,
            caches: RwLock::new(GovCaches {
                by_hash,
                by_access_key_id,
            }),
            price_per_request_cents,
            price_per_1k_tokens_cents,
            rate: RwLock::new(HashMap::new()),
            token_spend_carry: std::sync::Mutex::new(HashMap::new()),
            rate_sweep_ticker: AtomicU32::new(0),
            admin_token_hash: admin_token
                .as_ref()
                .map(|t| crate::sigv4::sha256_hex(t.as_bytes())),
            // Default fail-open; main.rs overrides from config via the setter.
            budget_on_store_error: crate::config::BudgetOnStoreError::Allow,
        })
    }

    /// Set the budget store-error fail-mode. Builder-style so `GovState::new`'s signature is
    /// unchanged (its many call sites stay intact); main.rs chains this from `GovernanceCfg`.
    pub(crate) fn with_budget_on_store_error(
        mut self,
        mode: crate::config::BudgetOnStoreError,
    ) -> Self {
        self.budget_on_store_error = mode;
        self
    }

    /// The configured budget store-error fail-mode. Consulted by the route.rs admission site.
    pub(crate) fn budget_on_store_error(&self) -> crate::config::BudgetOnStoreError {
        self.budget_on_store_error
    }

    /// Run a best-effort, FIRE-AND-FORGET store write WITHOUT blocking the async executor thread.
    ///
    /// SINGLE OFFLOAD. The op is a SYNCHRONOUS store closure (it calls the sync `Store` trait methods,
    /// which run the SQL inline via `*_inner` — NO nested `spawn_blocking`). When a runtime is present
    /// we move it into ONE `tokio::task::spawn_blocking`: the blocking SQL runs on the blocking pool,
    /// any error is logged (never propagated), and we return immediately (fire-and-forget). This is
    /// deliberately NOT the `*_async` path: those methods are for the hot blocking-AWAIT gate and would
    /// here cost a second task — a `tokio::spawn`ed future whose only job is to await a `spawn_blocking`
    /// (two tasks + extra key-id allocs) — for no benefit, since a fire-and-forget caller never awaits
    /// the result. Outside a runtime (unit tests that call the accounting methods directly) we run the
    /// sync op INLINE on the calling thread, so behaviour stays observable synchronously.
    fn offload_store_write<F>(&self, what: &'static str, key_id: &str, op: F)
    where
        F: FnOnce(&dyn Store) -> StoreResult<()> + Send + 'static,
    {
        let store = self.store.clone();
        let key_id = key_id.to_string();
        if tokio::runtime::Handle::try_current().is_ok() {
            tokio::task::spawn_blocking(move || {
                if let Err(e) = op(&*store) {
                    tracing::warn!(key = %key_id, error = %e, "{what}");
                }
            });
        } else if let Err(e) = op(&*store) {
            tracing::warn!(key = %key_id, error = %e, "{what}");
        }
    }

    /// Accrue token-based usage from a completed response to a key's current budget window: adds
    /// `tokens/1000 * price_per_1k_tokens_cents` to spend, plus the raw tokens (for TPM). Called
    /// once per request at stream end from the response usage tap. Best-effort (store errors logged).
    /// The SQLite write is offloaded to the blocking pool so it never stalls the async executor;
    /// the in-memory TPM counter is updated inline (it is cheap and must reflect the write order).
    pub(crate) fn record_tokens(&self, key_id: &str, budget_period: &str, now: u64, tokens: u64) {
        if tokens == 0 {
            return; // nothing to spend or count
        }
        let window = budget_window(budget_period, now);
        // Sub-cent precision (no zero-billing of small requests): accrue spend in MILLICENTS. Price is
        // cents-per-1000-tokens, so `tokens * price_per_1k_cents` is already millicents (= cents*1000).
        // Add the carried remainder, flush the WHOLE cents, keep the 0..999 millicent remainder.
        let millicents = tokens.saturating_mul(self.price_per_1k_tokens_cents.max(0) as u64);
        let whole_cents = {
            let mut carry = self
                .token_spend_carry
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            let entry = carry.entry(key_id.to_string()).or_insert((window, 0));
            // Reset the remainder when the budget window rolls over, so a sub-cent remainder is
            // attributed to the window it was generated in rather than leaking into the next window's
            // spend. The <1¢ dropped at the rollover is the documented "sub-1¢ per key is acceptable
            // to drop" trade-off (same as the on-restart drop).
            if entry.0 != window {
                *entry = (window, 0);
            }
            let total = entry.1.saturating_add(millicents);
            entry.1 = total % MILLICENTS_PER_CENT;
            total / MILLICENTS_PER_CENT
        };
        // Clamp the whole-cent flush into i64. Defense-in-depth (data-integrity LOW): a bare `as i64`
        // on a value > i64::MAX wraps NEGATIVE and would DECREMENT the stored counter (defeating the
        // budget cap). Unreachable from real token counts, but the clamp makes it impossible.
        let spend = whole_cents.min(i64::MAX as u64) as i64;
        let key_owned = key_id.to_string();
        // count_request = false: this accrues token spend for a request already counted at admission
        // (production: the atomic `charge_within_budget`; tests: `record_request`), so it must not
        // increment the request counter again.
        self.offload_store_write("token usage record failed", key_id, move |s| {
            s.add_usage(&key_owned, window, spend, tokens, false)
        });
        // Feed the TPM counter. `add_rate_tokens` is UPDATE-only: it credits an existing entry
        // (created by `check_rate` for a capped key) but never materialises one — an uncapped key has
        // no entry and must not gain one here, otherwise the rate map grows unboundedly for caps-free
        // deployments.
        self.add_rate_tokens(key_id, now, tokens);
    }

    /// Record one completed response's RAW consumption into the per-(key, day-bucket, model,
    /// provider) metering series — observability/FinOps data, NEVER enforcement (budgets stay on
    /// `record_tokens`/`charge_within_budget`). Carries the token SPLIT (input / output /
    /// cache-read / cache-creation — each prices differently) so a consumer with its own price
    /// catalog can reconstruct cost from the raw counts; busbar's derived spend is computed at read
    /// time. Zero-token responses still count the request (a flat-fee op is a request against a
    /// model). Best-effort: the write is offloaded to the blocking pool and errors are logged.
    pub(crate) fn record_metering(
        &self,
        key_id: &str,
        model: &str,
        provider: &str,
        usage: Option<&crate::ir::IrUsage>,
        now: u64,
    ) {
        let delta = MeteringDelta {
            key_id: key_id.to_string(),
            bucket: metering_bucket(now),
            model: model.to_string(),
            provider: provider.to_string(),
            tokens_input: usage.map(|u| u.input_tokens).unwrap_or(0),
            tokens_output: usage.map(|u| u.output_tokens).unwrap_or(0),
            tokens_cache_read: usage.and_then(|u| u.cache_read_input_tokens).unwrap_or(0),
            tokens_cache_creation: usage
                .and_then(|u| u.cache_creation_input_tokens)
                .unwrap_or(0),
        };
        self.offload_store_write("metering record failed", key_id, move |s| {
            s.add_metering(&delta)
        });
    }

    /// Every metering row for `bucket` (a [`metering_bucket`] day start) — the raw material of the
    /// usage read's by-model / by-key aggregations. Synchronous store read; admin-plane callers run
    /// it via `spawn_blocking`.
    pub(crate) fn metering_for(&self, bucket: u64) -> StoreResult<Vec<MeteringRow>> {
        self.store.list_metering(bucket)
    }

    /// The operator-configured prices `(per_request_cents, per_1k_tokens_cents)` — the inputs of the
    /// usage read's DERIVED `spend_micros` (raw counts are stored; spend is computed at read time).
    pub(crate) fn prices(&self) -> (i64, i64) {
        (self.price_per_request_cents, self.price_per_1k_tokens_cents)
    }

    /// Acquire the `rate` map for writing, recovering from a poisoned lock rather than panicking.
    ///
    /// A panic while any holder owns this lock marks it poisoned; a plain `.write().unwrap()` would
    /// then panic on EVERY subsequent `check_rate`/`add_rate_tokens`, cascading a single transient
    /// fault into a full governance outage (the project rule is no panic on the request path). The
    /// `rate` map is best-effort, single-node TPM/RPM accounting — its invariants are re-established
    /// per call (stale windows are reset in place), so continuing with the recovered guard is safe.
    fn rate_write(&self) -> std::sync::RwLockWriteGuard<'_, HashMap<String, RateState>> {
        self.rate.write().unwrap_or_else(|p| p.into_inner())
    }

    /// Acquire the `rate` map for reading (poison-recovering, same rationale as `rate_write`).
    /// Read by `rate_headroom`, which is wired into production routing: `decide_policy_order` in
    /// `forward.rs` calls `lookup` + `rate_headroom` (one key lookup shared with the `send_user`
    /// identity projection) to compute the per-lane `usage` routing signal.
    fn rate_read(&self) -> std::sync::RwLockReadGuard<'_, HashMap<String, RateState>> {
        self.rate.read().unwrap_or_else(|p| p.into_inner())
    }

    /// READ-ONLY rate-limit headroom for a key: the fraction `[0.0, 1.0]` of the most-constrained
    /// configured rate limit (RPM and/or TPM) still available in the current 60s window, where `1.0`
    /// is "fully unused" and `0.0` is "at the cap". `None` when the key has neither an RPM nor a TPM
    /// limit (nothing to be near). The routing `usage` policy ranks by this (more headroom = preferred).
    ///
    /// This is a pure observation: it NEVER mutates the window (no increment, no stale-reset, no
    /// sweep) — `check_rate` owns all of that on the admission path. A stale entry (from an older
    /// window) reads as fully-available for the current window, which is correct: its counters do not
    /// carry forward. When both RPM and TPM are set, the headroom is the MINIMUM of the two (the
    /// tighter constraint governs how close the key is to a 429).
    // Wired into production routing: `forward.rs::decide_policy_order` calls this on the key it
    // looked up (one lookup shared with the `send_user` identity projection) to produce the
    // per-lane `usage` signal; the in-crate tests also exercise it directly.
    pub(crate) fn rate_headroom(&self, key: &VirtualKey, now: u64) -> Option<f64> {
        if key.rpm_limit.is_none() && key.tpm_limit.is_none() {
            return None;
        }
        let window = now / RATE_WINDOW_SECS * RATE_WINDOW_SECS;
        // Counters for THIS window only; a stale (older-window) entry contributes zero usage.
        let (requests, tokens) = match self.rate_read().get(&key.id) {
            Some(st) if st.window_start == window => (st.requests, st.tokens),
            _ => (0, 0),
        };
        let mut headroom = 1.0_f64;
        if let Some(rpm) = key.rpm_limit {
            // `rpm == 0` is a fully-closed limit: no headroom. Avoid a divide-by-zero.
            let frac = if rpm == 0 {
                0.0
            } else {
                1.0 - (requests as f64 / rpm as f64)
            };
            headroom = headroom.min(frac);
        }
        if let Some(tpm) = key.tpm_limit {
            let frac = if tpm == 0 {
                0.0
            } else {
                1.0 - (tokens as f64 / tpm as f64)
            };
            headroom = headroom.min(frac);
        }
        // Clamp to [0,1]: a window that already exceeded its cap (in-flight concurrency can push usage
        // past the limit, per `check_rate`'s best-effort note) would otherwise yield a negative value.
        Some(headroom.clamp(0.0, 1.0))
    }

    /// Acquire the combined key caches (`by_hash` + `by_access_key_id`) for reading, recovering from a
    /// poisoned lock instead of panicking. Mirrors `rate_write`'s rationale for the auth hot path:
    /// `lookup`/`lookup_by_access_key_id` run per request and must never panic, so a poisoned cache
    /// (from a panic in some prior `refresh`) is recovered rather than propagated. The cache content is
    /// a snapshot of the durable store, so the recovered guard yields a consistent (if possibly
    /// slightly stale) view.
    fn caches_read(&self) -> std::sync::RwLockReadGuard<'_, GovCaches> {
        self.caches.read().unwrap_or_else(|p| p.into_inner())
    }

    /// Acquire the combined key caches for writing, recovering from a poisoned lock instead of
    /// panicking (see `caches_read`). Used by `refresh` after a management-API mutation.
    fn caches_write(&self) -> std::sync::RwLockWriteGuard<'_, GovCaches> {
        self.caches.write().unwrap_or_else(|p| p.into_inner())
    }

    /// SHA-256 hex digest of the configured admin token, pre-computed at construction.
    /// `Some` exactly when an admin token was supplied to `GovState::new` (the plaintext is hashed and discarded).
    pub(crate) fn admin_token_hash(&self) -> Option<&str> {
        self.admin_token_hash.as_deref()
    }

    /// Mint a new virtual key, persist it, refresh the cache, and return `(key, plaintext
    /// secret)`. The secret is shown to the caller ONCE here and never stored (only its hash is).
    pub(crate) fn create_key(
        &self,
        spec: NewKeySpec,
        now: u64,
    ) -> StoreResult<(VirtualKey, String)> {
        // `?` converts a getrandom failure into a StoreError (see `From<getrandom::Error>`), so the
        // admin handler returns a 500 via its existing error_response path instead of panicking.
        let secret = generate_secret()?;
        let hash = crate::sigv4::sha256_hex(secret.as_bytes());
        // `id` is a 64-bit prefix of the 256-bit secret hash, while `key_hash` is the full hash with
        // a UNIQUE constraint. Two distinct secrets sharing the same 64-bit prefix would produce the
        // same `id` but different `key_hash`; since `put_key` UPSERTs on the PRIMARY KEY `id`, the
        // second mint would silently OVERWRITE the first key's row (replacing its `key_hash`),
        // invalidating the previously-issued secret with no error. Birthday-bound at ~2^32 keys, but
        // the failure is silent, so guard it explicitly: if the derived id already exists for a
        // DIFFERENT key_hash, refuse rather than clobber an unrelated key. (A genuine retry that
        // somehow reproduces the same secret — and thus the same key_hash — is idempotent and allowed
        // through, since it overwrites the row with identical data.)
        let id = format!("{VK_ID_PREFIX}{}", &hash[..VK_ID_HASH_PREFIX_LEN]);
        self.ensure_id_free_for_hash(&id, &hash)?;
        let key = VirtualKey {
            id,
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

    /// Mint a virtual key that ALSO carries an AWS-style access-key-id + secret access key for inbound
    /// SigV4 verification (the MinIO/S3-compatible model). Returns `(key, bearer_secret,
    /// aws_access_key_id, aws_secret_access_key)`. BOTH secrets — the bearer secret and the AWS secret
    /// access key — are shown to the caller exactly ONCE here and never again (only the bearer secret's
    /// HASH is recoverable later; the AWS secret is stored in plaintext for HMAC verification but is
    /// never echoed by any read API). The AccessKeyId is not secret and IS returned by reads.
    ///
    /// The AWS secret is the SYMMETRIC SigV4 signing key: the client signs with it and busbar
    /// recomputes the signature with the same value. It is therefore stored in plaintext (a one-way
    /// hash would make verification impossible) and guarded by redaction discipline everywhere it could
    /// surface (`AwsCredential`'s Debug, and the admin read responses, which never include it).
    ///
    /// The credential lives in the separate `aws_credentials` table keyed by the key's id, NOT as
    /// columns on `VirtualKey` — this ties the credential to the key without changing the `VirtualKey`
    /// row shape. The bearer key row is persisted first, then the AWS credential; both then refresh
    /// the in-memory caches so the AccessKeyId resolves on the next request.
    pub(crate) fn create_key_with_aws(
        &self,
        spec: NewKeySpec,
        now: u64,
    ) -> StoreResult<(VirtualKey, String, String, String)> {
        // `?` converts any getrandom failure into a StoreError (see `From<getrandom::Error>`), so the
        // admin handler returns a 500 via its existing error_response path instead of panicking.
        let secret = generate_secret()?;
        let hash = crate::sigv4::sha256_hex(secret.as_bytes());
        let id = format!("{VK_ID_PREFIX}{}", &hash[..VK_ID_HASH_PREFIX_LEN]);
        self.ensure_id_free_for_hash(&id, &hash)?;
        let access_key_id = generate_aws_access_key_id()?;
        let secret_access_key = generate_aws_secret_access_key()?;
        let key = VirtualKey {
            id: id.clone(),
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
        // ATOMIC: persist the bearer key row and its paired AWS credential in ONE transaction (see
        // `put_key_with_aws_credential`). The previous two-call autocommit sequence could orphan an
        // inert key row if the credential write failed after the key write committed.
        self.store.put_key_with_aws_credential(
            &key,
            &AwsCredential {
                access_key_id: access_key_id.clone(),
                key_id: id,
                secret_access_key: secret_access_key.clone(),
            },
        )?;
        self.refresh()?;
        Ok((key, secret, access_key_id, secret_access_key))
    }

    /// Guard against the silent UPSERT-overwrite described in `create_key`: the PRIMARY KEY `id` is
    /// only a 64-bit prefix of the full `key_hash`, so two distinct secrets can collide on `id`
    /// while differing on `key_hash`. If `id` already exists under a DIFFERENT `key_hash`, refuse
    /// (rather than let `put_key` overwrite an unrelated key's row). An `id` that is free, or that
    /// already holds the SAME `key_hash` (an idempotent re-mint of the identical secret), is allowed.
    fn ensure_id_free_for_hash(&self, id: &str, hash: &str) -> StoreResult<()> {
        if let Some(existing) = self.store.get_key(id)? {
            if existing.key_hash != hash {
                return Err(StoreError(format!(
                    "virtual-key id collision: derived id '{id}' already belongs to a different key; \
                     retry to mint with fresh entropy (this is a ~2^-64 birthday event)"
                )));
            }
        }
        Ok(())
    }

    /// All virtual keys (metadata; callers must strip `key_hash` before returning).
    pub(crate) fn all_keys(&self) -> StoreResult<Vec<VirtualKey>> {
        self.store.list_keys()
    }

    /// Delete a key by id and refresh the cache.
    pub(crate) fn delete_key(&self, id: &str) -> StoreResult<()> {
        self.store.delete_key(id)?;
        self.refresh()
    }

    /// Apply a partial update to an existing key: enable/disable it, or adjust its rate/budget caps.
    /// `key_hash`/`name`/`allowed_pools`/`budget_period`/`created_at` are preserved (the secret is
    /// never re-minted). Returns `Ok(None)` when the key does not exist (so the caller can 404),
    /// `Ok(Some(updated_metadata))` otherwise. Validation (non-negative budget, non-zero rate caps on
    /// a *present* value) is the caller's responsibility, mirroring `create_key`'s ingress.
    ///
    /// THREE-STATE caps. The three cap fields (`rpm_limit`/`tpm_limit`/`max_budget_cents`) are
    /// `Option<Option<T>>` so the API can distinguish all three intents the JSON allows:
    ///   - `None`: field absent from the request body -> leave the stored value unchanged.
    ///   - `Some(None)`: field present as JSON `null` -> CLEAR the cap to unlimited (None).
    ///   - `Some(Some)`: field present with a value -> SET the cap to that value.
    ///
    /// The old single-`Option` shape conflated absent and present-null, so a cap could never be
    /// cleared back to unlimited once set — only widened/narrowed. `enabled` stays a plain `Option`
    /// (a bool has no "unlimited"/clear state; absent vs present is its only distinction).
    /// ROTATE a key's bearer secret in place: a fresh secret is minted, its hash replaces the
    /// stored `key_hash`, and the OLD secret stops resolving immediately (cache refresh). The key
    /// `id` stays STABLE — budgets, rate windows, usage history, and audit attribution carry over.
    /// The id-from-hash-prefix coupling is a MINT-time collision guard only (lookups resolve by the
    /// full `key_hash`), so a rotated row's id no longer matching its new hash prefix is harmless
    /// by design. An attached AWS SigV4 credential (if any) is NOT rotated here — it is a separate
    /// credential with its own lifecycle. Returns `None` for an unknown id; the new secret is shown
    /// exactly once.
    pub(crate) fn rotate_key(&self, id: &str) -> StoreResult<Option<(VirtualKey, String)>> {
        let Some(mut key) = self.store.get_key(id)? else {
            return Ok(None);
        };
        let secret = generate_secret()?;
        key.key_hash = crate::sigv4::sha256_hex(secret.as_bytes());
        self.store.put_key(&key)?;
        self.refresh()?;
        Ok(Some((key, secret)))
    }

    pub(crate) fn update_key(
        &self,
        id: &str,
        enabled: Option<bool>,
        rpm_limit: Option<Option<u32>>,
        tpm_limit: Option<Option<u32>>,
        max_budget_cents: Option<Option<i64>>,
    ) -> StoreResult<Option<VirtualKey>> {
        let Some(mut key) = self.store.get_key(id)? else {
            return Ok(None);
        };
        if let Some(e) = enabled {
            key.enabled = e;
        }
        // Outer `Some` = the field was present in the request. The inner option is then assigned
        // verbatim: inner `Some(v)` sets the cap, inner `None` (JSON null) clears it to unlimited.
        // Outer `None` (field absent) falls through and leaves the stored value untouched.
        if let Some(r) = rpm_limit {
            key.rpm_limit = r;
        }
        if let Some(t) = tpm_limit {
            key.tpm_limit = t;
        }
        if let Some(b) = max_budget_cents {
            key.max_budget_cents = b;
        }
        // `put_key` UPSERTs on the PRIMARY KEY `id` with identical `key_hash`, so this is an in-place
        // update of the existing row (no secret rotation). Refresh the in-memory cache so the change
        // takes effect on the next request.
        self.store.put_key(&key)?;
        self.refresh()?;
        Ok(Some(key))
    }

    /// Current-window usage for a key (`None` if the key does not exist).
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
    /// `Ok(())` admits the request (and counts it); `Err(retry_after_secs)` rejects it (429).
    ///
    /// RPM is enforced precisely: the request counter is incremented synchronously on admission.
    ///
    /// TPM is BEST-EFFORT, not a hard cap. Token counts are fed in post-response (from the usage
    /// tap, via `record_tokens`), so this check only sees tokens from requests
    /// that have ALREADY COMPLETED in the current 60s window. Consequences operators must know:
    /// - In-flight concurrent requests are not counted, so N requests can pass the check
    ///   simultaneously while each is under the limit and collectively exceed the configured TPM.
    /// - The first request of each window is admitted regardless of TPM, because the window's token
    ///   counter starts at zero (it is intentionally not carried across the 60s boundary).
    ///
    /// A hard TPM cap would require reserving estimated tokens at admit time; that is out of scope
    /// for the single-node best-effort limiter. Use the budget cap (cents) for a real spend ceiling.
    pub(crate) fn check_rate(&self, key: &VirtualKey, now: u64) -> Result<(), u64> {
        if key.rpm_limit.is_none() && key.tpm_limit.is_none() {
            return Ok(());
        }
        let window = now / RATE_WINDOW_SECS * RATE_WINDOW_SECS;
        let retry = (window + RATE_WINDOW_SECS).saturating_sub(now).max(1);
        // Bounded eviction of stale entries (keys that have gone silent in older windows) keeps the
        // map from leaking entries forever. This is an O(active-key-count) scan, so we DO NOT run it
        // on every admission — it is purely a memory bound and is not required for correctness (the
        // per-key staleness reset below already resets the looked-up key's own entry). Instead we
        // amortize it: only every `RATE_SWEEP_INTERVAL`th call pays the sweep.
        //
        // SINGLE write-lock: the amortized sweep and the per-key check/increment share ONE
        // `rate_write()` guard. The sweep-needed flag is the cheap lock-free ticker below (an atomic
        // `fetch_add` + `is_multiple_of`), computed BEFORE the guard; then under one guard we do the
        // conditional sweep first and the per-key resolution second. Acquiring the write lock twice
        // (sweep, then a fresh guard for the per-key work) cost a second lock round-trip on every
        // admission for no benefit: the per-key critical section is O(1) and the sweep, when it fires,
        // is O(active-key-count) but rare (every `RATE_SWEEP_INTERVAL`th call) — coalescing them under
        // one guard cannot lengthen the common-case hold (no sweep runs) and saves an acquire/release.
        // Correctness is unchanged: the sweep only evicts entries whose `window_start != window`, and
        // the per-key resolution below re-checks/refreshes this key's own entry for `window` regardless
        // of whether the sweep ran, so nothing the sweep does (or skips) can admit a request that
        // should be rejected or vice versa.
        // MSRV NOTE: `u32::is_multiple_of` was stabilized in Rust 1.87. It is used here (and clippy's
        // `manual_is_multiple_of` actively REWRITES the equivalent `% N == 0` form back to it, so the
        // two cannot both be satisfied without a declared MSRV), which makes 1.87 the effective
        // minimum supported toolchain. Cargo.toml declares `rust-version = "1.87"` so the constraint
        // is visible to toolchain installers, CI matrices, and clippy's `incompatible_msrv` lint,
        // rather than surfacing as a silent compile failure on an older pinned stable.
        // POST-increment semantics: test the value AFTER this call's increment, not the
        // pre-increment value `fetch_add` returns. This fixes two off-by-one defects of the naive
        // `fetch_add(..).is_multiple_of(N)`:
        //  1. The ticker starts at 0, so the pre-increment value on the very first call is 0, which
        //     IS a multiple of N — the sweep would fire immediately on startup against an empty map.
        //  2. When the u32 wraps, the pre-increment value 0xFFFFFFFF is NOT a multiple of N, so one
        //     sweep cycle would be silently skipped every ~4B calls.
        // Using `wrapping_add(1)` on the returned pre-increment value reproduces the value now stored
        // in the atomic: the sweep fires on calls N, 2N, 3N, ... and the wrap boundary (pre = 0xFFFF…F
        // -> post = 0, a multiple of N) is handled correctly with no skipped cycle.
        let sweep_needed = self
            .rate_sweep_ticker
            .fetch_add(1, Ordering::Relaxed)
            .wrapping_add(1)
            .is_multiple_of(crate::limits::rate_sweep_interval());
        let mut map = self.rate_write();
        if sweep_needed {
            map.retain(|_, st| st.window_start == window);
        }
        // Resolve this key's entry for the CURRENT window. Three cases:
        //  - present & current-window  -> mutate in place (fast path; no key clone).
        //  - present but STALE         -> reset it in place to the current window (counters back to
        //                                 zero). This per-key reset is what makes correctness
        //                                 independent of the global sweep above: even if the stale
        //                                 entry was not evicted, we never carry an old window's
        //                                 counts forward. (The previous code relied on the eager
        //                                 retain having already removed it, so `or_insert_with`
        //                                 minted a fresh one; with the sweep amortized we must reset
        //                                 explicitly here.)
        //  - absent                    -> insert a fresh entry (cold path; pays the key clone).
        let st = match map.get_mut(&key.id) {
            Some(st) if st.window_start == window => st,
            Some(st) => {
                *st = RateState {
                    window_start: window,
                    requests: 0,
                    tokens: 0,
                };
                st
            }
            None => map.entry(key.id.clone()).or_insert_with(|| RateState {
                window_start: window,
                requests: 0,
                tokens: 0,
            }),
        };
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

    /// Add tokens to the key's rate window for TPM accounting. Called post-response from
    /// `record_tokens` (the production token-fee path; `record_request` is test-only). `now` is the
    /// request's pinned `charged_at` (the header-arrival epoch), i.e. the window the request STARTED
    /// in — NOT a fresh completion clock. This matters for a request that straddles a 60s boundary: it is admitted by
    /// `check_rate` in its start window W0, but by the time its (streamed) response completes, a LATER
    /// admission for the same key may have rolled the live entry forward to W1. The credit then
    /// arrives carrying `charged_at` in W0 while the entry lives in W1.
    ///
    /// CREDIT THE ENTRY'S LIVE WINDOW. A start-window OLDER-or-equal to the
    /// entry's window is the straddle case above: the request's tokens belong to the same TPM budget
    /// the key is currently spending, so we credit the entry's existing (live) window IN PLACE rather
    /// than dropping the credit or rewinding the entry to the older start window. Previously a `<`
    /// (older start window than entry) was either dropped or — worse — used to REINITIALISE the entry
    /// back to W0, destroying the live W1 counter; either way a boundary-straddling request never
    /// counted against TPM, letting a key sustain above its configured limit. Only a start-window
    /// strictly NEWER than the entry (the entry is genuinely stale — an old window the sweep has not
    /// yet evicted) reinitialises the entry to the new window before crediting.
    ///
    /// UPDATE-ONLY (the rate map must not grow for uncapped keys). This method credits an entry that
    /// ALREADY EXISTS but never materialises a missing one. `check_rate` only ever creates entries for
    /// keys that carry an RPM/TPM cap (it early-returns for uncapped keys before touching the map), so
    /// the only entries that exist belong to capped keys — and crediting one is always safe. An
    /// uncapped key has no entry, and because we do not create one here, it cannot grow the map
    /// through this path. (Materialising unconditionally — as very old code did on EVERY response, for
    /// EVERY key — leaked one entry per uncapped key forever, since the sweep only evicts entries
    /// whose window is stale and a busy uncapped key keeps refreshing its own.)
    fn add_rate_tokens(&self, key_id: &str, now: u64, tokens: u64) {
        if tokens == 0 {
            return;
        }
        let window = now / RATE_WINDOW_SECS * RATE_WINDOW_SECS;
        let mut map = self.rate_write();
        let Some(st) = map.get_mut(key_id) else {
            // No entry -> do NOT materialise one. An uncapped key has no entry (check_rate never made
            // one), so skipping creation here bounds the rate map for caps-free deployments. A capped
            // key's entry is created by `check_rate` on admission, so the credit lands there.
            return;
        };
        if window <= st.window_start {
            // Start-window older-or-equal to the entry's window. Either the same window (the normal
            // case) or a boundary-straddling request whose live entry has rolled forward since
            // admission. The tokens belong to the key's currently-live TPM budget, so credit the
            // entry's existing window IN PLACE — do not rewind it to the older start window (which
            // would wipe the live counter) and do not drop the credit (which would let a straddling
            // request escape TPM accounting).
            st.tokens = st.tokens.saturating_add(tokens);
        } else {
            // Start-window strictly NEWER than the entry -> the entry is genuinely stale (an old
            // window the amortized sweep has not yet evicted). Reinitialise it for this window and
            // credit there, so a stale entry never carries old counts forward.
            *st = RateState {
                window_start: window,
                requests: 0,
                tokens,
            };
        }
    }

    /// Is this key already at/over its budget for the current window? (No cap → never.) Synchronous
    /// core. The production request-path gate is [`GovState::try_charge_request_within_budget`] (an
    /// atomic check-and-charge); this read and [`GovState::is_over_budget_async`] are the superseded,
    /// now test-only budget probes.
    ///
    /// NOTE: the budget cap is BEST-EFFORT (soft) under concurrency. This read and the later
    /// `record_request` charge are separate, non-atomic store round-trips, so N concurrent in-flight
    /// requests for the same key can each observe spend < limit, all be admitted, then all charge —
    /// overshooting `max_budget_cents` by up to (concurrent in-flight) * (per-request + token cost).
    /// The overshoot is bounded by the caller's parallelism. A hard cap would require an atomic
    /// check-and-charge (a single UPSERT returning post-charge spend) in the `Store`.
    // Read-only budget probe. The admission path now uses the ATOMIC `try_charge_request_within_budget`
    // rather than this read-then-charge pair, so production no longer calls it; it is retained
    // ONLY as a governance-unit-test helper. Hence `#[cfg(test)]` (compiled out of the release binary)
    // rather than a dead-code allow.
    #[cfg(test)]
    fn is_over_budget(&self, key: &VirtualKey, now: u64) -> bool {
        let Some(limit) = key.max_budget_cents else {
            return false;
        };
        let window = budget_window(&key.budget_period, now);
        self.store
            .get_usage(&key.id, window)
            .map(|u| u.spend_cents >= limit)
            .unwrap_or(false)
    }

    /// Async budget gate for the request path: the per-request offload now lives in the backend's
    /// `get_usage_async` (the SQLite impl runs the blocking read on the blocking pool), so this no
    /// longer hand-rolls a `spawn_blocking`. Falls back to a synchronous read when called outside a
    /// runtime (defensive — the request path always has one; the default async impl would inline
    /// anyway, but the explicit sync path keeps behaviour observable in no-runtime tests). On a
    /// store/join error it fails OPEN (returns `false`, i.e. "not over budget") to match the
    /// synchronous variant, preserving availability rather than rejecting traffic on a telemetry-store
    /// hiccup.
    // Superseded on the request path by the atomic charge; retained ONLY for tests, so `#[cfg(test)]`
    // (compiled out of the release binary) rather than a dead-code allow.
    #[cfg(test)]
    pub(crate) async fn is_over_budget_async(&self, key: &VirtualKey, now: u64) -> bool {
        if key.max_budget_cents.is_none() {
            return false;
        }
        if tokio::runtime::Handle::try_current().is_err() {
            return self.is_over_budget(key, now);
        }
        let limit = key.max_budget_cents.expect("guarded is_some above");
        let window = budget_window(&key.budget_period, now);
        match self.store.get_usage_async(&key.id, window).await {
            Ok(u) => u.spend_cents >= limit,
            Err(e) => {
                tracing::warn!(key = %key.id, error = %e, "budget read failed; failing open");
                false
            }
        }
    }

    /// ATOMIC budget check-and-charge for the admission path — the HARD-cap primitive.
    ///
    /// In ONE indivisible store round-trip, charge the flat per-request fee + one request to the key's
    /// current budget window IFF it stays within `max_budget_cents`. Replaces the old non-atomic
    /// `is_over_budget_async` (read) → later `record_request` (write) pair, which let N concurrent
    /// requests for one key each read "under budget" and all charge → overshoot by up to
    /// concurrency × per-req cost. With a single conditional UPSERT, the flat fee is a HARD cap: a
    /// request is admitted only if its charge fits.
    ///
    /// Residual (documented honestly): token cost is reconciled post-response (`record_tokens`), so a
    /// single ADMITTED request's own tokens can push spend marginally past the cap — bounded to ONE
    /// in-flight request, NOT N. The flat-fee overshoot (the N-way race) is gone.
    ///
    /// Runs the (blocking) SQLite write on the blocking pool so it never stalls a Tokio worker.
    /// Returns:
    ///   * `Ok(true)`  — charged and admitted (or uncapped key: always charged),
    ///   * `Ok(false)` — would exceed the cap → reject,
    ///   * `Err(_)`    — store/join error → the caller applies the configured fail-open/closed knob.
    ///
    /// The flat fee is charged HERE (atomically), so the caller must NOT also charge it in `finish`;
    /// `finish` emits metrics, fires the request-log webhook, and (on a non-2xx outcome) refunds the
    /// flat fee for an admitted request.
    pub(crate) async fn try_charge_request_within_budget(
        &self,
        key: &VirtualKey,
        now: u64,
    ) -> StoreResult<bool> {
        let window = budget_window(&key.budget_period, now);
        // Clamp the per-request fee >= 0 (symmetric with record_tokens / the old record_request): a
        // negative misconfigured fee must never DECREMENT accrued spend and defeat the cap.
        let fee = self.price_per_request_cents.max(0);
        let max = key.max_budget_cents;
        // The per-request offload now lives in the backend's `charge_within_budget_async` (the SQLite
        // impl runs the atomic UPSERT on the blocking pool); no hand-rolled `spawn_blocking` here.
        // Outside a runtime (unit tests calling directly) the default async impl runs the charge
        // inline, so behaviour stays synchronous and observable.
        self.store
            .charge_within_budget_async(&key.id, window, fee, max)
            .await
    }

    /// Refund the flat per-request fee + request count charged at admission, for a request that
    /// produced no usable upstream result (non-2xx). Keeps the flat-fee policy "bill 2xx only" intact
    /// even though the hard-cap charge bills every admitted request up front. Best-effort, offloaded.
    /// `now` MUST be the same `charged_at` epoch the admission charge used, so the refund lands in the
    /// SAME budget window the charge did (the request could straddle a window boundary).
    pub(crate) fn refund_request(&self, key: &VirtualKey, now: u64) {
        let window = budget_window(&key.budget_period, now);
        let fee = self.price_per_request_cents.max(0);
        let key_id = key.id.clone();
        self.offload_store_write("budget refund failed", &key.id, move |s| {
            s.refund_request(&key_id, window, fee)
        });
    }

    /// Charge one request (flat per-request cost + token count) to the key's current window.
    /// Best-effort: a store error is logged-and-dropped (telemetry must not break serving). The
    /// SQLite write is offloaded to the blocking pool so it never stalls the async executor; the
    /// in-memory TPM counter is updated inline.
    // Retained ONLY for direct-call governance tests (production charges via the atomic UPSERT), so
    // `#[cfg(test)]` — compiled out of the release binary — rather than a dead-code allow.
    #[cfg(test)]
    pub(crate) fn record_request(&self, key: &VirtualKey, now: u64, tokens: u64) {
        let window = budget_window(&key.budget_period, now);
        let key_id = key.id.clone();
        // Clamp the per-request fee at >= 0, symmetric with `record_tokens` (which already clamps the
        // per-1k-token price). A negative `price_per_request_cents` (operator/hostile-admin
        // misconfiguration; the field is a plain signed i64 with no range check at config load) would
        // otherwise DECREMENT a key's accrued spend on every successful request, driving spend below
        // zero and defeating the budget cap (`is_over_budget` compares `spend_cents >= limit`).
        let fee = self.price_per_request_cents.max(0);
        // count_request = true: this is the once-per-request accounting call.
        self.offload_store_write("usage record failed", &key.id, move |s| {
            s.add_usage(&key_id, window, fee, tokens, true)
        });
        // Feed the rate window's TPM counter. `add_rate_tokens` is UPDATE-only, so this is a no-op for
        // an uncapped key (which has no entry — `check_rate` early-returns and never creates one for
        // it) and credits a capped key's existing entry otherwise. No cap check is needed here because
        // the update-only behaviour already bounds the map: only capped keys can have an entry to
        // credit. (Production always passes `tokens = 0` — the per-request fee carries no tokens — so
        // this returns at the `tokens == 0` guard; the token fee feeds TPM via `record_tokens`.)
        self.add_rate_tokens(&key.id, now, tokens);
    }

    fn load(store: &dyn Store) -> StoreResult<HashMap<String, VirtualKey>> {
        Ok(store
            .list_keys()?
            .into_iter()
            .map(|k| (k.key_hash.clone(), k))
            .collect())
    }

    /// Build the AccessKeyId → resolved-credential index from the durable `aws_credentials` table,
    /// joined against the already-loaded `by_hash` snapshot (which holds the live `VirtualKey` rows).
    /// A credential whose owning key is missing from `by_hash` (e.g. the key row was deleted but a
    /// credential row lingered) is SKIPPED — it can never authenticate, since there is no key to attach
    /// a `GovCtx` for. `access_key_id` is the PRIMARY KEY of `aws_credentials`, so entries are unique.
    fn load_by_access_key_id(
        store: &dyn Store,
        by_hash: &HashMap<String, VirtualKey>,
    ) -> StoreResult<HashMap<String, AwsKeyEntry>> {
        // Index the live keys by id for the join (by_hash is keyed by key_hash, not id).
        let by_id: HashMap<&str, &VirtualKey> =
            by_hash.values().map(|k| (k.id.as_str(), k)).collect();
        let mut map = HashMap::new();
        for cred in store.list_aws_credentials()? {
            if let Some(key) = by_id.get(cred.key_id.as_str()) {
                map.insert(
                    cred.access_key_id.clone(),
                    AwsKeyEntry {
                        key: (*key).clone(),
                        secret_access_key: cred.secret_access_key,
                    },
                );
            }
        }
        Ok(map)
    }

    /// Resolve a presented secret to its virtual key (cache lookup; secret hashed, never compared raw).
    pub(crate) fn lookup(&self, secret: &str) -> Option<VirtualKey> {
        let hash = crate::sigv4::sha256_hex(secret.as_bytes());
        self.caches_read().by_hash.get(&hash).cloned()
    }

    /// Resolve an inbound SigV4 AccessKeyId (parsed in plaintext from the `Credential=` field of the
    /// `Authorization` header) to the owning virtual key plus its secret access key. Used ONLY by the
    /// Bedrock-ingress SigV4 verify path. Returns `None` for an unknown AccessKeyId — the verify path
    /// is written so an unknown AccessKeyId and a bad signature reject indistinguishably (no
    /// enumeration oracle): on the `None` branch the caller still runs a constant-time signature
    /// comparison against a dummy secret before rejecting.
    pub(crate) fn lookup_by_access_key_id(&self, access_key_id: &str) -> Option<AwsKeyEntry> {
        self.caches_read()
            .by_access_key_id
            .get(access_key_id)
            .cloned()
    }

    /// Direct handle to the backing store, for tests that seed/inspect persistence.
    #[cfg(test)]
    pub(crate) fn store(&self) -> Arc<dyn Store> {
        self.store.clone()
    }

    /// Reload BOTH caches (the hashed-secret index and the AWS AccessKeyId index) from the store
    /// after a management-API mutation. Rebuild `by_access_key_id` from the SAME fresh snapshot so the
    /// two indices can never drift (a key disabled/deleted/re-minted is reflected in both).
    pub(crate) fn refresh(&self) -> StoreResult<()> {
        let fresh = Self::load(self.store.as_ref())?;
        let fresh_akid = Self::load_by_access_key_id(self.store.as_ref(), &fresh)?;
        // Both indices live under the single `caches` lock, so the swap below is ONE atomic critical
        // section — a concurrent reader holding `caches_read` sees either the entire old pair or the
        // entire new pair, never a new `by_hash` against a stale `by_access_key_id` (or vice versa).
        // There is no longer a transient cross-index inconsistency window.
        let mut c = self.caches_write();
        c.by_hash = fresh;
        c.by_access_key_id = fresh_akid;
        Ok(())
    }
}

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

/// Generate a virtual-key secret from 16 bytes of the OS CSPRNG (portable across Unix/Windows via
/// getrandom). Fails closed: if the OS exposes no entropy source we refuse to mint a key rather
/// than fall back to a guessable (time-derived) secret. getrandom failure is near-impossible on
/// supported platforms; on failure we return the error so the caller (`create_key`) surfaces a 500
/// instead of panicking the process — the server stays up.
fn generate_secret() -> Result<String, getrandom::Error> {
    // Portable OS CSPRNG via getrandom: /dev/urandom on Unix, BCryptGenRandom on Windows, etc.
    let mut buf = [0u8; 16];
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

/// A virtual key issued by busbar (distinct from upstream provider keys). Maps a caller to the
/// pools they may use plus their budget/rate-limit policy.
#[derive(Clone, PartialEq)]
pub(crate) struct VirtualKey {
    pub(crate) id: String,
    /// SHA-256 hex of the presented secret (the secret itself is never stored).
    pub(crate) key_hash: String,
    pub(crate) name: String,
    /// Pools this key may target; empty = all pools allowed.
    pub(crate) allowed_pools: Vec<String>,
    /// Spend cap in cents for the budget period; None = unlimited.
    pub(crate) max_budget_cents: Option<i64>,
    /// "total" | "daily" | "monthly".
    pub(crate) budget_period: String,
    /// Requests-per-minute cap; None = unlimited.
    pub(crate) rpm_limit: Option<u32>,
    /// Tokens-per-minute cap; None = unlimited.
    pub(crate) tpm_limit: Option<u32>,
    pub(crate) enabled: bool,
    pub(crate) created_at: u64,
}

// MANUAL Debug that REDACTS `key_hash`. A derived `Debug` would print the SHA-256 of the key's
// secret in PLAINTEXT — a latent credential leak any time a `VirtualKey` (or `GovCtx`, which embeds
// one and whose derived Debug delegates here transitively) is debug-logged. The hash is the stored
// authenticator (a presented secret is matched by hashing it and looking up this value), so it is
// secret-equivalent and must never reach a log. Print presence only, never the value — mirroring
// `config::GovernanceCfg`/`auth::AuthMiddleware`. All non-secret fields are shown verbatim so the
// struct stays diagnosable.
impl std::fmt::Debug for VirtualKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VirtualKey")
            .field("id", &self.id)
            .field(
                "key_hash",
                &if self.key_hash.is_empty() {
                    "<absent>"
                } else {
                    "<redacted; present>"
                },
            )
            .field("name", &self.name)
            .field("allowed_pools", &self.allowed_pools)
            .field("max_budget_cents", &self.max_budget_cents)
            .field("budget_period", &self.budget_period)
            .field("rpm_limit", &self.rpm_limit)
            .field("tpm_limit", &self.tpm_limit)
            .field("enabled", &self.enabled)
            .field("created_at", &self.created_at)
            .finish()
    }
}

/// A durable AWS-style credential row (the `aws_credentials` table), tying an AccessKeyId + secret
/// access key to a virtual key's id (the MinIO/S3-compatible model). Stored separately from the
/// `VirtualKey` row so the key's shape is unchanged. The `secret_access_key` is the SYMMETRIC SigV4
/// signing secret (stored plaintext because HMAC verification needs the same value the client signs
/// with), so this type carries a manual redacting `Debug`.
#[derive(Clone, PartialEq)]
pub(crate) struct AwsCredential {
    /// The plaintext AccessKeyId carried in the inbound SigV4 `Authorization` header (not secret).
    pub(crate) access_key_id: String,
    /// The owning `VirtualKey.id`.
    pub(crate) key_id: String,
    /// The symmetric SigV4 secret access key — SECRET-EQUIVALENT (never log it).
    pub(crate) secret_access_key: String,
}

// MANUAL Debug that REDACTS `secret_access_key` (the symmetric SigV4 signing secret). A derived Debug
// would print it verbatim — a credential leak the moment an `AwsCredential` is debug-logged. The
// AccessKeyId and key_id are NOT secret and are shown for diagnosability; the secret prints presence
// only, never the value/length (a length is a small oracle).
impl std::fmt::Debug for AwsCredential {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AwsCredential")
            .field("access_key_id", &self.access_key_id)
            .field("key_id", &self.key_id)
            .field(
                "secret_access_key",
                &if self.secret_access_key.is_empty() {
                    "<absent>"
                } else {
                    "<redacted; present>"
                },
            )
            .finish()
    }
}

/// A resolved AWS-credential cache entry: the owning `VirtualKey` plus the secret access key needed to
/// verify the inbound SigV4 signature. Returned by `GovState::lookup_by_access_key_id`. Carries a
/// manual redacting `Debug` for the same reason as `AwsCredential` — the secret must never reach a log.
#[derive(Clone, PartialEq)]
pub(crate) struct AwsKeyEntry {
    pub(crate) key: VirtualKey,
    /// The symmetric SigV4 secret access key — SECRET-EQUIVALENT (never log it).
    pub(crate) secret_access_key: String,
}

impl std::fmt::Debug for AwsKeyEntry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AwsKeyEntry")
            .field("key", &self.key)
            .field(
                "secret_access_key",
                &if self.secret_access_key.is_empty() {
                    "<absent>"
                } else {
                    "<redacted; present>"
                },
            )
            .finish()
    }
}

/// Accumulated usage for a key within a budget window.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub(crate) struct Usage {
    pub(crate) spend_cents: i64,
    pub(crate) tokens: u64,
    pub(crate) requests: u64,
}

/// Seconds in a metering day bucket. Metering is a TIME SERIES in fixed UTC-day buckets —
/// deliberately decoupled from the per-key budget windows the enforcement counters use, so
/// per-model aggregation ACROSS keys has one well-defined time base.
pub(crate) const METERING_BUCKET_SECS: u64 = 86_400;

/// Floor an epoch to its UTC-day metering bucket start.
pub(crate) fn metering_bucket(now: u64) -> u64 {
    now - (now % METERING_BUCKET_SECS)
}

/// One per-(key, model, provider) metering accumulation from a completed response — RAW consumption
/// counts, never money. Spend is DERIVED at read time from the operator's configured prices, and a
/// third party with its own (special/negotiated) price catalog reconstructs cost from these counts:
/// input, output, cache-read, and cache-creation tokens all price differently, so each is carried
/// separately (design: expose the inputs of the cost computation, not just busbar's own result).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct MeteringDelta {
    pub(crate) key_id: String,
    /// The UTC-day bucket this response is attributed to (see [`metering_bucket`]); derived from the
    /// request's pinned header-arrival epoch, same as the budget charges (#29).
    pub(crate) bucket: u64,
    /// The SERVING lane's configured model name (post-failover — the lane that actually answered).
    pub(crate) model: String,
    /// The serving lane's provider name.
    pub(crate) provider: String,
    /// Uncached input tokens (the normalized additive-cache convention, per `billing::TokenUsage`).
    pub(crate) tokens_input: u64,
    pub(crate) tokens_output: u64,
    pub(crate) tokens_cache_read: u64,
    pub(crate) tokens_cache_creation: u64,
}

/// One accumulated metering row read back for a bucket (the raw material of `GET usage` by_model /
/// by_key aggregations — the service aggregates in memory; buckets are bounded by (keys × models)).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct MeteringRow {
    pub(crate) key_id: String,
    pub(crate) model: String,
    pub(crate) provider: String,
    pub(crate) tokens_input: u64,
    pub(crate) tokens_output: u64,
    pub(crate) tokens_cache_read: u64,
    pub(crate) tokens_cache_creation: u64,
    pub(crate) requests: u64,
}

pub(crate) type StoreResult<T> = Result<T, StoreError>;

#[derive(Debug)]
pub(crate) struct StoreError(pub(crate) String);

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
impl From<getrandom::Error> for StoreError {
    fn from(e: getrandom::Error) -> Self {
        StoreError(format!("OS CSPRNG (getrandom) unavailable: {e}"))
    }
}

/// The durable governance store seam. Swappable: `SqliteStore` today, `PostgresStore`
/// later behind the same trait.
///
/// DUAL FLAVOR (sync + async). The per-request accounting methods come in two flavors: the original
/// SYNCHRONOUS form (called directly under the governance/admin locks and in tests — e.g. the gated
/// `EXISTENCE_GATE` compound ops, the batched metrics scrape) and an ASYNC form (`*_async`) used on
/// the per-request hot path. The per-request offload is now OWNED BY THE BACKEND: each backend
/// decides how to satisfy the async flavor. The `SqliteStore` impl fulfills it by offloading the
/// synchronous SQL onto the blocking pool (`spawn_blocking`); a future `PostgresStore` would await a
/// real async driver natively. The DEFAULT trait impls simply call the matching sync method inline
/// — correct for lightweight test doubles, where no real offload is needed.
#[async_trait::async_trait]
pub(crate) trait Store: Send + Sync + 'static {
    fn put_key(&self, key: &VirtualKey) -> StoreResult<()>;
    fn get_key(&self, id: &str) -> StoreResult<Option<VirtualKey>>;
    // Lookup by key hash — exercised only by unit tests that probe the DB directly; the hot-path
    // key resolution uses the in-memory `by_hash` cache and never calls through the trait. Gated to
    // test builds so it (and its `SqliteStore` impl) leaves no dead surface in the release binary.
    #[cfg(test)]
    fn get_key_by_hash(&self, key_hash: &str) -> StoreResult<Option<VirtualKey>>;
    fn list_keys(&self) -> StoreResult<Vec<VirtualKey>>;
    fn delete_key(&self, id: &str) -> StoreResult<()>;
    /// Add usage to a key's counter for the given budget-window start (UPSERT/accumulate).
    /// `count_request` increments the request counter by one — true for the per-request fee, false
    /// when only accruing token spend for an already-counted request (so requests aren't double
    /// counted when both the flat fee and token usage are recorded for one request).
    fn add_usage(
        &self,
        key_id: &str,
        window_start: u64,
        spend_cents: i64,
        tokens: u64,
        count_request: bool,
    ) -> StoreResult<()>;
    fn get_usage(&self, key_id: &str, window_start: u64) -> StoreResult<Usage>;

    /// Accumulate one completed response's RAW consumption into the per-(key, bucket, model,
    /// provider) metering row (UPSERT/add; +1 request). Metering is observability — best-effort,
    /// never consulted for enforcement (budgets stay on `add_usage`/`charge_within_budget`).
    fn add_metering(&self, delta: &MeteringDelta) -> StoreResult<()>;

    /// Every metering row accumulated in `bucket` (a [`metering_bucket`] day start), for the usage
    /// read's by-model / by-key aggregations.
    fn list_metering(&self, bucket: u64) -> StoreResult<Vec<MeteringRow>>;

    /// ATOMIC budget check-and-charge (the HARD-cap primitive). In a SINGLE store round-trip, charge
    /// `cost_cents` (the flat per-request fee) + one request to the key's `window_start` counter IFF
    /// the post-charge spend stays within `max_cents` (`None` = uncapped → always charges). Returns
    /// `true` when the charge landed (request admitted), `false` when it would exceed the cap (reject).
    ///
    /// This replaces the non-atomic `is_over_budget` (read) + `record_request` (write) pair on the
    /// admission path: because the check and the charge are one indivisible UPSERT, N concurrent
    /// requests for the same key can NO LONGER each read "under budget" and all charge — the cap is a
    /// HARD cap for the flat fee. (Token cost is still reconciled post-response, so a single in-flight
    /// request's own tokens can push spend marginally over — bounded to ONE request, not N. See the
    /// call site in `route.rs`.)
    fn charge_within_budget(
        &self,
        key_id: &str,
        window_start: u64,
        cost_cents: i64,
        max_cents: Option<i64>,
    ) -> StoreResult<bool>;

    /// REFUND a previously-charged flat per-request fee + its request count. The
    /// atomic admission charge bills EVERY admitted request up front (hard cap); a request that then
    /// produced no usable upstream result (non-2xx) must be refunded so the flat-fee billing policy
    /// stays "charge successful requests only" — matching the pre-fix behavior where `finish` only
    /// billed 2xx. Decrements spend by `cost_cents` and requests by one, both floored at 0 so a
    /// refund can never drive a counter negative. Best-effort (called off the request path).
    fn refund_request(&self, key_id: &str, window_start: u64, cost_cents: i64) -> StoreResult<()>;

    // ── ASYNC flavor of the per-request accounting methods ───────────────────────────────────────
    // The per-request offload is owned by the backend (see the trait-level doc). These mirror the
    // four hot-path accounting methods above; the request path (`GovState`) calls THESE instead of
    // hand-rolling a `spawn_blocking` around the sync forms. The DEFAULT impl calls the sync method
    // inline (correct for test doubles); `SqliteStore` overrides each to offload onto the blocking
    // pool so a slow rusqlite call never stalls a Tokio worker.

    /// Async flavor of [`Store::charge_within_budget`]. Default: calls the sync form inline.
    async fn charge_within_budget_async(
        &self,
        key_id: &str,
        window_start: u64,
        cost_cents: i64,
        max_cents: Option<i64>,
    ) -> StoreResult<bool> {
        self.charge_within_budget(key_id, window_start, cost_cents, max_cents)
    }

    /// Async flavor of [`Store::get_usage`]. Default: calls the sync form inline.
    // Superseded on the request path by the atomic charge primitive; its only remaining caller is the
    // test-only `is_over_budget_async`, so `#[cfg(test)]` (compiled out of the release binary) rather
    // than a dead-code allow — mirrors the `is_over_budget_async` hygiene in the same module.
    #[cfg(test)]
    async fn get_usage_async(&self, key_id: &str, window_start: u64) -> StoreResult<Usage> {
        self.get_usage(key_id, window_start)
    }

    /// Persist an AWS-style credential (the MinIO/S3-compatible model) for inbound SigV4 verification.
    /// UPSERTs on the `access_key_id` PRIMARY KEY. The `secret_access_key` is the symmetric SigV4
    /// signing secret stored in plaintext (HMAC verification needs the same value the client signs
    /// with); callers must never log it.
    ///
    /// DEFAULTED so the (many) lightweight test-double `Store` impls scattered across the crate need
    /// not implement the AWS surface — only the real `SqliteStore` does. The default is a no-op-shaped
    /// error so a misconfigured store that silently dropped a credential cannot pass as success.
    fn put_aws_credential(&self, _cred: &AwsCredential) -> StoreResult<()> {
        Err(StoreError(
            "this Store does not support AWS credentials".to_string(),
        ))
    }

    /// ATOMIC key+credential mint. Persist the bearer `VirtualKey` row AND its paired `AwsCredential`
    /// row together or not at all. Under SQLite autocommit, `put_key` then `put_aws_credential` are two
    /// independent commits: a storage error (I/O, disk full, constraint) after the first leaves an
    /// inert key row with no resolvable AccessKeyId — an orphan that `create_key_with_aws` would then
    /// surface as a failure while the half-written row lingers. A real transactional store overrides
    /// this to wrap both writes in one `conn.transaction()` (mirroring `delete_key`).
    ///
    /// DEFAULT fallback: test-double stores that don't expose a transaction simply do the two writes in
    /// sequence — they have no durability boundary to violate, and this keeps the (many) lightweight
    /// `Store` impls from needing to implement the transactional path.
    fn put_key_with_aws_credential(
        &self,
        key: &VirtualKey,
        cred: &AwsCredential,
    ) -> StoreResult<()> {
        self.put_key(key)?;
        self.put_aws_credential(cred)?;
        Ok(())
    }

    /// All AWS credentials (used to rebuild the in-memory AccessKeyId index at boot / on refresh).
    /// DEFAULTED to an empty list (see `put_aws_credential`): a store with no AWS-credential support
    /// simply has none to index, so SigV4 ingress is unavailable — never an auth bypass.
    fn list_aws_credentials(&self) -> StoreResult<Vec<AwsCredential>> {
        Ok(Vec::new())
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
        let conn = Connection::open(path)?;
        // Harden the on-disk DB against `SQLITE_BUSY` from a second connection or an external tool
        // (backup/inspection): WAL lets readers and a writer proceed concurrently, and a 5s busy
        // timeout makes a transient lock contention retry-then-succeed rather than fail instantly.
        // Skip both for an in-memory path: `:memory:` ignores WAL (no rollback journal file exists)
        // and has no second connection to contend with, so the pragmas are inapplicable there.
        if !path.starts_with(":memory:") && !path.contains("mode=memory") {
            // `journal_mode` returns the resulting mode as a row, so use `pragma_update`/query rather
            // than `execute` (which rejects a statement that yields rows). `busy_timeout` is a plain
            // setter and is safe via `execute_batch`.
            conn.pragma_update(None, "journal_mode", "WAL")?;
            conn.pragma_update(
                None,
                "busy_timeout",
                crate::limits::sqlite_busy_timeout_ms(),
            )?;
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
            conn: Arc::new(Mutex::new(Connection::open_in_memory()?)),
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
        self.lock_conn().execute_batch(SCHEMA)?;
        Ok(())
    }

    // ── Shared SQL bodies for the dual-flavor accounting methods ─────────────────────────────────
    // Each `*_inner` holds the EXACT SQL of its accounting method, locking the passed connection
    // mutex (poison-recovering) so it can run from EITHER the synchronous trait method (`&self.conn`)
    // OR an async offload (a cloned `Arc<Mutex<Connection>>` moved into a `spawn_blocking` closure).
    // No `&self`, so the offload closure need not borrow the store. The SQL is byte-for-byte the
    // original — sync and async share one body, so they can never drift.

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
        )?;
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
        )?;
        Ok(())
    }

    fn list_metering_inner(conn: &Mutex<Connection>, bucket: u64) -> StoreResult<Vec<MeteringRow>> {
        let conn = Self::lock_conn_raw(conn);
        let mut stmt = conn.prepare(
            "SELECT key_id, model, provider,
                    tokens_input, tokens_output, tokens_cache_read, tokens_cache_creation, requests
             FROM usage_metering WHERE bucket = ?1",
        )?;
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
            })?
            .collect::<Result<Vec<_>, _>>()?;
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
            .optional()?;
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
        )?;
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
            .optional()?;
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
    )?;
    Ok(())
}

fn put_aws_credential_inner(conn: &rusqlite::Connection, cred: &AwsCredential) -> StoreResult<()> {
    conn.execute(
        "INSERT INTO aws_credentials (access_key_id, key_id, secret_access_key)
             VALUES (?1, ?2, ?3)
             ON CONFLICT(access_key_id) DO UPDATE SET
                key_id=excluded.key_id, secret_access_key=excluded.secret_access_key",
        params![cred.access_key_id, cred.key_id, cred.secret_access_key],
    )?;
    Ok(())
}

#[async_trait::async_trait]
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
            .optional()?;
        Ok(row)
    }

    #[cfg(test)]
    fn get_key_by_hash(&self, key_hash: &str) -> StoreResult<Option<VirtualKey>> {
        let conn = self.lock_conn();
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
        let conn = self.lock_conn();
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
        // Both DELETEs must be atomic. Under SQLite autocommit each `execute` commits on its own, so
        // a failure of the second statement (I/O error, disk full, constraint) would leave the key
        // row gone but its usage_counters rows orphaned — accumulating forever and, worse, poisoning
        // any future key re-created with the same id with stale usage. Wrap both in one transaction
        // so they commit together or not at all. The Mutex already serializes us against other
        // writers, so the transaction cannot deadlock against a concurrent busbar caller.
        let mut conn = self.lock_conn();
        let tx = conn.transaction()?;
        tx.execute("DELETE FROM virtual_keys WHERE id=?1", params![id])?;
        tx.execute("DELETE FROM usage_counters WHERE key_id=?1", params![id])?;
        // Remove any AWS credential rows tied to this key in the SAME transaction: a revoked key's
        // SigV4 credential must NOT outlive the key, or a Bedrock-SDK client signing with that
        // AccessKeyId could keep authenticating after revocation (an auth-bypass). The in-memory
        // AccessKeyId index is rebuilt on the post-delete `refresh`, and even before that rebuild the
        // index already skips a credential whose key row is gone (see `load_by_access_key_id`), so the
        // revocation is effective immediately and durably.
        tx.execute("DELETE FROM aws_credentials WHERE key_id=?1", params![id])?;
        tx.commit()?;
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
        let tx = conn.transaction()?;
        // `&tx` coerces to `&Connection` via `Transaction`'s Deref, so both writes share the exact same
        // SQL bodies as the autocommit `put_key`/`put_aws_credential` — they can never drift.
        put_key_inner(&tx, key)?;
        put_aws_credential_inner(&tx, cred)?;
        tx.commit()?;
        Ok(())
    }

    fn list_aws_credentials(&self) -> StoreResult<Vec<AwsCredential>> {
        let conn = self.lock_conn();
        let mut stmt =
            conn.prepare("SELECT access_key_id, key_id, secret_access_key FROM aws_credentials")?;
        let rows = stmt.query_map([], |r| {
            Ok(AwsCredential {
                access_key_id: r.get(0)?,
                key_id: r.get(1)?,
                secret_access_key: r.get(2)?,
            })
        })?;
        let mut out = Vec::new();
        for r in rows {
            out.push(r?);
        }
        Ok(out)
    }

    fn add_usage(
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

    fn add_metering(&self, delta: &MeteringDelta) -> StoreResult<()> {
        Self::add_metering_inner(&self.conn, delta)
    }

    fn list_metering(&self, bucket: u64) -> StoreResult<Vec<MeteringRow>> {
        Self::list_metering_inner(&self.conn, bucket)
    }

    fn charge_within_budget(
        &self,
        key_id: &str,
        window_start: u64,
        cost_cents: i64,
        max_cents: Option<i64>,
    ) -> StoreResult<bool> {
        Self::charge_within_budget_inner(&self.conn, key_id, window_start, cost_cents, max_cents)
    }

    fn refund_request(&self, key_id: &str, window_start: u64, cost_cents: i64) -> StoreResult<()> {
        Self::refund_request_inner(&self.conn, key_id, window_start, cost_cents)
    }

    fn get_usage(&self, key_id: &str, window_start: u64) -> StoreResult<Usage> {
        Self::get_usage_inner(&self.conn, key_id, window_start)
    }

    // ── ASYNC flavor overrides — the per-request offload, now OWNED BY THIS BACKEND ──────────────
    // Each offloads the synchronous `*_inner` SQL onto the Tokio blocking pool (`spawn_blocking`) so
    // a slow rusqlite call — fsync / WAL checkpoint / lock contention — never stalls a Tokio worker.
    // This is where the per-request offload now LIVES (relocated out of `GovState`'s hand-rolled
    // `spawn_blocking`s). Args are owned into the `'static` closure; the connection handle is a cheap
    // `Arc` clone of the SAME mutex the sync path locks (so sync and async serialize on one DB). A
    // panic inside the blocking closure is re-raised faithfully via `resume_unwind`; a non-panic join
    // failure (the blocking pool shut down mid-flight) maps to the crate's `StoreError` convention.

    async fn charge_within_budget_async(
        &self,
        key_id: &str,
        window_start: u64,
        cost_cents: i64,
        max_cents: Option<i64>,
    ) -> StoreResult<bool> {
        // No runtime (unit tests calling the accounting methods directly): run the SQL inline so
        // behaviour is observable synchronously — `spawn_blocking` requires a Tokio reactor.
        if tokio::runtime::Handle::try_current().is_err() {
            return Self::charge_within_budget_inner(
                &self.conn,
                key_id,
                window_start,
                cost_cents,
                max_cents,
            );
        }
        let conn = self.conn.clone();
        let key_id = key_id.to_owned();
        join_offload(tokio::task::spawn_blocking(move || {
            Self::charge_within_budget_inner(&conn, &key_id, window_start, cost_cents, max_cents)
        }))
        .await
    }

    #[cfg(test)]
    async fn get_usage_async(&self, key_id: &str, window_start: u64) -> StoreResult<Usage> {
        if tokio::runtime::Handle::try_current().is_err() {
            return Self::get_usage_inner(&self.conn, key_id, window_start);
        }
        let conn = self.conn.clone();
        let key_id = key_id.to_owned();
        join_offload(tokio::task::spawn_blocking(move || {
            Self::get_usage_inner(&conn, &key_id, window_start)
        }))
        .await
    }
}

/// Await a `spawn_blocking` handle wrapping a `StoreResult`, flattening the `JoinError`.
///
/// On a PANIC inside the blocking closure, re-raise it faithfully (`resume_unwind`) so a bug in the
/// SQL body surfaces identically to a direct call rather than being silently swallowed into a generic
/// store error. A NON-panic join failure (the blocking pool was shut down mid-flight, e.g. on
/// runtime teardown) is mapped to the crate's `StoreError` convention so the caller's fail-open /
/// fail-closed knob applies, exactly as the old `GovState` offload did.
async fn join_offload<T>(handle: tokio::task::JoinHandle<StoreResult<T>>) -> StoreResult<T> {
    match handle.await {
        Ok(res) => res,
        Err(e) if e.is_panic() => std::panic::resume_unwind(e.into_panic()),
        Err(e) => Err(StoreError(format!("store offload task failed: {e}"))),
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
#[path = "tests/tests.rs"]
mod tests;
