// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Matthew Jackson

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
const RATE_SWEEP_INTERVAL: u32 = 256;
/// `price_per_1k_tokens_cents` is priced per this many tokens.
const TOKENS_PER_PRICE_UNIT: u64 = 1_000;
/// Seconds in a UTC day, for `budget_window`'s day/month arithmetic. `pub(crate)` so sibling
/// modules (which need the same constant for their own window math) reference it as
/// `crate::governance::SECS_PER_DAY` rather than re-hardcoding `86_400`.
pub(crate) const SECS_PER_DAY: u64 = 86_400;
/// SQLite `busy_timeout` for the on-disk DB: a transient lock contention retries for this many
/// milliseconds (5s) before failing, rather than erroring instantly with `SQLITE_BUSY`.
const SQLITE_BUSY_TIMEOUT_MS: i64 = 5_000;

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
    /// observe a new `by_hash` against a stale `by_access_key_id` (LOW-1). See `GovCaches`.
    caches: RwLock<GovCaches>,
    /// Flat cents charged per request (one half of the cost model; the other is per-token, below).
    /// Total budget spend = per-request fee + tokens/1000 * price_per_1k_tokens_cents.
    price_per_request_cents: i64,
    /// cents per 1000 tokens (input + output), accrued from response usage at stream end.
    price_per_1k_tokens_cents: i64,
    /// per-key RPM/TPM windows (ephemeral).
    rate: RwLock<HashMap<String, RateState>>,
    /// Admission counter that amortizes the bounded eviction sweep of `rate` (see
    /// `RATE_SWEEP_INTERVAL`): every Nth `check_rate` call performs the full stale-entry retain,
    /// so the per-request hot path does not scan all active keys on every admission.
    rate_sweep_ticker: AtomicU32,
    /// bearer token guarding the /admin management API (None = admin API disabled).
    admin_token: Option<String>,
    /// Fail-mode for the atomic budget check-and-charge on a STORE ERROR (fix 2b). `Allow` (default)
    /// fails open (proceed → availability); `Deny` fails closed (reject → hard guarantee). Only the
    /// store-error path consults this; a definitive over-budget result always rejects. Set from
    /// `GovernanceCfg::budget_on_store_error` via `with_budget_on_store_error` at construction.
    budget_on_store_error: crate::config::BudgetOnStoreError,
}

/// parameters for minting a new virtual key (from the management API).
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
            rate_sweep_ticker: AtomicU32::new(0),
            admin_token,
            // Default fail-open (today's behavior); main.rs overrides from config via the setter.
            budget_on_store_error: crate::config::BudgetOnStoreError::Allow,
        })
    }

    /// Set the budget store-error fail-mode (fix 2b). Builder-style so `GovState::new`'s signature is
    /// unchanged (its many call sites stay intact); main.rs chains this from `GovernanceCfg`.
    pub(crate) fn with_budget_on_store_error(
        mut self,
        mode: crate::config::BudgetOnStoreError,
    ) -> Self {
        self.budget_on_store_error = mode;
        self
    }

    /// The configured budget store-error fail-mode (fix 2b). Consulted by the route.rs admission site.
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
        let spend = (tokens.saturating_mul(self.price_per_1k_tokens_cents.max(0) as u64)
            / TOKENS_PER_PRICE_UNIT) as i64;
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
    /// `forward.rs` calls `rate_headroom_for_token` (→ `rate_headroom`) to compute the per-lane
    /// `usage` routing signal.
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
    // Wired into production routing: `forward.rs::decide_policy_order` calls this (via
    // `rate_headroom_for_token`) to produce the per-lane `usage` signal; the in-crate tests also
    // exercise it directly.
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
        // `id` is a 64-bit prefix of the 256-bit secret hash, while `key_hash` is the full hash with
        // a UNIQUE constraint. Two distinct secrets sharing the same 64-bit prefix would produce the
        // same `id` but different `key_hash`; since `put_key` UPSERTs on the PRIMARY KEY `id`, the
        // second mint would silently OVERWRITE the first key's row (replacing its `key_hash`),
        // invalidating the previously-issued secret with no error. Birthday-bound at ~2^32 keys, but
        // the failure is silent, so guard it explicitly: if the derived id already exists for a
        // DIFFERENT key_hash, refuse rather than clobber an unrelated key. (A genuine retry that
        // somehow reproduces the same secret — and thus the same key_hash — is idempotent and allowed
        // through, since it overwrites the row with identical data.)
        let id = format!("vk_{}", &hash[..16]);
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
        let secret = generate_secret();
        let hash = crate::sigv4::sha256_hex(secret.as_bytes());
        let id = format!("vk_{}", &hash[..16]);
        self.ensure_id_free_for_hash(&id, &hash)?;
        let access_key_id = generate_aws_access_key_id();
        let secret_access_key = generate_aws_secret_access_key();
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

    /// all virtual keys (metadata; callers must strip `key_hash` before returning).
    pub(crate) fn all_keys(&self) -> StoreResult<Vec<VirtualKey>> {
        self.store.list_keys()
    }

    /// delete a key by id + refresh the cache.
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
            .is_multiple_of(RATE_SWEEP_INTERVAL);
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
    /// request's pinned
    /// `charged_at` (the header-arrival epoch), i.e. the window the request STARTED in — NOT a fresh
    /// completion clock. This matters for a request that straddles a 60s boundary: it is admitted by
    /// `check_rate` in its start window W0, but by the time its (streamed) response completes, a LATER
    /// admission for the same key may have rolled the live entry forward to W1. The credit then
    /// arrives carrying `charged_at` in W0 while the entry lives in W1.
    ///
    /// CREDIT THE ENTRY'S LIVE WINDOW (MED #6 fix, option b). A start-window OLDER-or-equal to the
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
            // request escape TPM). This is the MED #6 fix.
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
    // (fix 2a) rather than this read-then-charge pair, so PRODUCTION no longer calls it; it is retained
    // ONLY as a governance-unit-test helper. Hence `#[cfg(test)]` (compiled out of the release binary)
    // rather than a dead-code allow.
    #[cfg(test)]
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

    /// ATOMIC budget check-and-charge for the admission path — the HARD-cap primitive (fix 2a).
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
    ///   * `Err(_)`    — store/join error → the caller applies the fail-open/closed knob (fix 2b).
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

    /// charge one request (flat per-request cost + token count) to the key's current window.
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

    /// Rate-limit headroom for the key presenting `secret` (routing `usage` signal). `None` when the
    /// secret resolves to no key OR the key has no RPM/TPM limit. A thin convenience over
    /// `lookup` + `rate_headroom` for the routing seam, which holds the caller token but not the key.
    /// Consumed by `forward.rs::decide_policy_order` to compute each lane's `usage` routing signal.
    pub(crate) fn rate_headroom_for_token(&self, secret: &str, now: u64) -> Option<f64> {
        let key = self.lookup(secret)?;
        self.rate_headroom(&key, now)
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
        // LOW-1 (fixed): both indices live under the single `caches` lock, so the swap below is ONE
        // atomic critical section — a concurrent reader holding `caches_read` sees either the entire
        // old pair or the entire new pair, never a new `by_hash` against a stale `by_access_key_id`
        // (or vice versa). There is no longer a transient cross-index inconsistency window.
        let mut c = self.caches_write();
        c.by_hash = fresh;
        c.by_access_key_id = fresh_akid;
        Ok(())
    }
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
/// supported platforms; the panic aborts only the key-mint request (the server stays up).
fn generate_secret() -> String {
    // Portable OS CSPRNG via getrandom: /dev/urandom on Unix, BCryptGenRandom on Windows, etc.
    let mut buf = [0u8; 16];
    getrandom::getrandom(&mut buf)
        .expect("OS CSPRNG (getrandom) unavailable — refusing to mint a guessable virtual key");
    format!("sk-bb-{}", hex::encode(buf))
}

/// Generate an AWS-style AccessKeyId: the literal `AKIA` prefix (matching the real long-term-key
/// shape an AWS SDK expects and validates) followed by 16 chars from the AWS access-key alphabet
/// (uppercase A-Z + 2-7, the base32 set AWS uses). The AccessKeyId is NOT secret — it travels in
/// plaintext in the SigV4 `Authorization` header and is the public lookup handle — but it is minted
/// from the OS CSPRNG so it is unguessable and collision-resistant. Fails closed (panics the mint
/// request only, never the server) if the OS exposes no entropy, mirroring `generate_secret`.
fn generate_aws_access_key_id() -> String {
    // AWS access-key alphabet: 32 symbols (A-Z, 2-7). 16 symbols → 80 bits of entropy.
    const ALPHABET: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    let mut buf = [0u8; 16];
    getrandom::getrandom(&mut buf).expect(
        "OS CSPRNG (getrandom) unavailable — refusing to mint a guessable AWS access key id",
    );
    let mut s = String::with_capacity(20);
    s.push_str("AKIA");
    for &b in &buf {
        // Map each byte into the 32-symbol alphabet. `& 0x1f` is always in 0..=31, so the index can
        // never go out of bounds (no panic on the mint path).
        s.push(ALPHABET[(b & 0x1f) as usize] as char);
    }
    s
}

/// Generate an AWS-style secret access key: 40 chars from a base64-like alphabet (matching the shape
/// real AWS secret keys take), sourced from 30 bytes of the OS CSPRNG (240 bits, encoded). This is
/// the SYMMETRIC SigV4 signing secret — stored in plaintext (HMAC verification needs the same value
/// the client signs with) and shown to the operator exactly once at mint. Fails closed on no entropy.
fn generate_aws_secret_access_key() -> String {
    // Base64-url-safe-ish alphabet without padding: A-Z a-z 0-9 + /. 64 symbols → 6 bits each.
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    // 40 chars * 6 bits = 240 bits = 30 bytes of entropy; draw the 30 bytes and emit 40 symbols.
    let mut buf = [0u8; 30];
    getrandom::getrandom(&mut buf).expect(
        "OS CSPRNG (getrandom) unavailable — refusing to mint a guessable AWS secret access key",
    );
    // Pack the 240 bits and slice them into 40 six-bit groups. A running bit accumulator avoids any
    // dependency on a base64 crate and keeps the mapping panic-free (every index is `& 0x3f`).
    let mut out = String::with_capacity(40);
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
    out
}

/// Whether `key` may target `pool` (empty allowed_pools = all pools).
pub(crate) fn pool_allowed(key: &VirtualKey, pool: &str) -> bool {
    key.allowed_pools.is_empty() || key.allowed_pools.iter().any(|p| p == pool)
}

/// The epoch start of the budget window containing `now` for a given period. "total" = a
/// single all-time window (0); "daily" = UTC midnight; "monthly" = UTC first-of-month.
pub(crate) fn budget_window(period: &str, now: u64) -> u64 {
    match period {
        "daily" => now / SECS_PER_DAY * SECS_PER_DAY,
        "monthly" => {
            let days = (now / SECS_PER_DAY) as i64;
            let (y, m, _) = civil_from_days(days);
            (days_from_civil(y, m, 1) as u64) * SECS_PER_DAY
        }
        "total" => 0, // explicit all-time window (the documented sentinel)
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

    /// REFUND a previously-charged flat per-request fee + its request count (fix 2a companion). The
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
            conn.pragma_update(None, "busy_timeout", SQLITE_BUSY_TIMEOUT_MS)?;
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
async fn join_offload<T>(
    handle: tokio::task::JoinHandle<StoreResult<T>>,
) -> StoreResult<T> {
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
    #[tokio::test(flavor = "multi_thread", worker_threads = 8)]
    async fn test_concurrent_charges_cannot_overshoot_cap() {
        let store: Arc<dyn Store> = Arc::new(SqliteStore::open_in_memory().unwrap());
        let mut handles = Vec::new();
        for _ in 0..50 {
            let s = store.clone();
            handles.push(tokio::task::spawn_blocking(move || {
                s.charge_within_budget("k", 0, 30, Some(100)).unwrap()
            }));
        }
        let mut admitted = 0u32;
        for h in handles {
            if h.await.unwrap() {
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

    /// H1: CONCURRENCY through the REAL admission wrapper. Unlike
    /// `test_concurrent_charges_cannot_overshoot_cap` (which hits `Store::charge_within_budget`
    /// directly and bypasses the `spawn_blocking` offload), this fires N concurrent tasks through
    /// `GovState::try_charge_request_within_budget` on a SHARED `Arc<GovState>` — the exact async
    /// admission entrypoint the route path calls. With a 1c flat fee and a 5c cap, exactly 5 of 20
    /// concurrent admissions may land and final spend must be EXACTLY 5 (cap-respecting, no overshoot).
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn test_concurrent_govstate_admission_respects_cap() {
        let store = Arc::new(SqliteStore::open_in_memory().unwrap());
        let gov = Arc::new(GovState::new(store.clone(), 1, 0, None).unwrap()); // 1c flat fee
        let (key, _s) = gov
            .create_key(
                NewKeySpec {
                    name: "k".to_string(),
                    allowed_pools: vec![],
                    max_budget_cents: Some(5), // 5c cap → at most 5 one-cent admissions
                    budget_period: "total".to_string(),
                    rpm_limit: None,
                    tpm_limit: None,
                },
                1_700_000_000,
            )
            .unwrap();
        let at = 1_700_000_000u64;
        let mut handles = Vec::new();
        for _ in 0..20 {
            let gov = gov.clone();
            let key = key.clone();
            handles.push(tokio::spawn(async move {
                gov.try_charge_request_within_budget(&key, at).await.unwrap()
            }));
        }
        let mut admitted = 0u32;
        for h in handles {
            if h.await.unwrap() {
                admitted += 1;
            }
        }
        assert_eq!(
            admitted, 5,
            "exactly 5 of 20 concurrent GovState admissions fit under a 5c/1c cap"
        );
        assert_eq!(
            store.get_usage(&key.id, 0).unwrap().spend_cents,
            5,
            "final spend must be EXACTLY 5 — the async admission path holds the hard cap, no overshoot"
        );
    }

    /// H2: the charge → refund → re-admit money cycle through `GovState`. Charge a key to its cap so the
    /// next request is rejected; `refund_request` (fire-and-forget `offload_store_write`) reverses one
    /// charge; after draining the blocking write a new request is admitted again. Proves a refunded fee
    /// genuinely frees budget on the live admission path.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn test_charge_refund_readmit_cycle() {
        let store = Arc::new(SqliteStore::open_in_memory().unwrap());
        let gov = Arc::new(GovState::new(store.clone(), 1, 0, None).unwrap()); // 1c flat fee
        let (key, _s) = gov
            .create_key(
                NewKeySpec {
                    name: "k".to_string(),
                    allowed_pools: vec![],
                    max_budget_cents: Some(1), // 1c cap → exactly one request fits
                    budget_period: "total".to_string(),
                    rpm_limit: None,
                    tpm_limit: None,
                },
                1_700_000_000,
            )
            .unwrap();
        let at = 1_700_000_000u64;
        // Charge to the cap.
        assert!(
            gov.try_charge_request_within_budget(&key, at)
                .await
                .unwrap(),
            "1st (1c) admitted, spends the whole 1c cap"
        );
        // At cap → next request rejected.
        assert!(
            !gov.try_charge_request_within_budget(&key, at)
                .await
                .unwrap(),
            "2nd rejected: budget is exhausted at the cap"
        );
        // Refund the charge (fire-and-forget offloaded write), then drain the blocking pool.
        gov.refund_request(&key, at);
        let mut spend = i64::MAX;
        for _ in 0..200 {
            tokio::task::yield_now().await;
            spend = store.get_usage(&key.id, 0).unwrap().spend_cents;
            if spend == 0 {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(1)).await;
        }
        assert_eq!(spend, 0, "refund must reverse the charge back to 0 spend");
        // Budget is free again → a new request is re-admitted.
        assert!(
            gov.try_charge_request_within_budget(&key, at)
                .await
                .unwrap(),
            "post-refund request re-admitted: the refunded fee freed the budget"
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

    /// fix 2a wrapper: `try_charge_request_within_budget` charges the flat fee and rejects atomically
    /// at the cap. 1c/request flat fee, 2c cap → 2 admitted, 3rd rejected.
    #[tokio::test]
    async fn test_try_charge_request_within_budget_rejects_at_cap() {
        let store = Arc::new(SqliteStore::open_in_memory().unwrap());
        let gov = GovState::new(store, 1, 0, None).unwrap(); // 1c flat fee
        let (key, _s) = gov
            .create_key(
                NewKeySpec {
                    name: "k".to_string(),
                    allowed_pools: vec![],
                    max_budget_cents: Some(2),
                    budget_period: "total".to_string(),
                    rpm_limit: None,
                    tpm_limit: None,
                },
                1_700_000_000,
            )
            .unwrap();
        let at = 1_700_000_000u64;
        assert!(
            gov.try_charge_request_within_budget(&key, at)
                .await
                .unwrap(),
            "1st (1c) admitted"
        );
        assert!(
            gov.try_charge_request_within_budget(&key, at)
                .await
                .unwrap(),
            "2nd (2c) admitted"
        );
        assert!(
            !gov.try_charge_request_within_budget(&key, at)
                .await
                .unwrap(),
            "3rd (would be 3c > 2c cap) rejected atomically"
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

    #[test]
    fn test_virtualkey_debug_redacts_key_hash() {
        // LOW #17 (SECURITY): VirtualKey's Debug must NOT print `key_hash` (the stored authenticator
        // for the key's secret). A derived Debug leaked it in plaintext; the manual impl prints
        // presence only. The hash value is deliberately distinctive so a substring check catches it.
        let mut k = sample_key("vk_dbg", "SECRET-key-hash-value-zzz");
        let dbg = format!("{k:?}");
        assert!(
            !dbg.contains("SECRET-key-hash-value-zzz"),
            "VirtualKey Debug leaked key_hash: {dbg}"
        );
        assert!(
            dbg.contains("<redacted; present>"),
            "VirtualKey Debug should mark key_hash present-but-redacted: {dbg}"
        );
        // Non-secret fields are still shown so the struct stays diagnosable.
        assert!(dbg.contains("vk_dbg"), "id must still appear: {dbg}");
        assert!(dbg.contains("test-key"), "name must still appear: {dbg}");

        // Redaction holds TRANSITIVELY through GovCtx (its derived Debug delegates to VirtualKey's).
        let ctx = GovCtx {
            key: Some(k.clone()),
        };
        let ctx_dbg = format!("{ctx:?}");
        assert!(
            !ctx_dbg.contains("SECRET-key-hash-value-zzz"),
            "GovCtx Debug leaked the embedded key_hash: {ctx_dbg}"
        );

        // An empty hash is marked absent (defensive; the request path never builds such a key).
        k.key_hash = String::new();
        let dbg_empty = format!("{k:?}");
        assert!(
            dbg_empty.contains("<absent>"),
            "empty key_hash should read as absent: {dbg_empty}"
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
        // The compound name matches; neither split fragment is authorized on its own.
        assert!(pool_allowed(&got, "prod,special"));
        assert!(!pool_allowed(&got, "prod"));
        assert!(!pool_allowed(&got, "special"));
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
    fn test_create_key_with_aws_issues_and_resolves_credential() {
        let store = Arc::new(SqliteStore::open_in_memory().unwrap());
        let gov = GovState::new(store, 0, 0, None).unwrap();
        let (key, _bearer, akid, secret) = gov
            .create_key_with_aws(
                NewKeySpec {
                    name: "bedrock-key".to_string(),
                    allowed_pools: vec!["prod".to_string()],
                    max_budget_cents: Some(1000),
                    budget_period: "total".to_string(),
                    rpm_limit: None,
                    tpm_limit: None,
                },
                1_700_000_000,
            )
            .unwrap();
        // AccessKeyId is AKIA-prefixed, 20 chars; secret is 40 chars.
        assert!(akid.starts_with("AKIA"), "akid shape: {akid}");
        assert_eq!(akid.len(), 20);
        assert_eq!(secret.len(), 40);
        // The AccessKeyId resolves to the SAME key + its secret.
        let entry = gov.lookup_by_access_key_id(&akid).expect("akid resolves");
        assert_eq!(entry.key.id, key.id);
        assert_eq!(entry.secret_access_key, secret);
        assert!(entry.key.enabled);
        // An unknown AccessKeyId resolves to None.
        assert!(gov
            .lookup_by_access_key_id("AKIAdoesnotexist0000")
            .is_none());
        // The bearer secret still resolves the key via the hash index too.
        assert_eq!(gov.lookup(&_bearer).unwrap().id, key.id);
    }

    #[test]
    fn test_aws_credential_persists_across_reload() {
        // A credential minted in one GovState must be visible to a fresh GovState over the same store
        // (durable + rebuilt into the AccessKeyId index at construction).
        let store: Arc<dyn Store> = Arc::new(SqliteStore::open_in_memory().unwrap());
        let akid = {
            let gov = GovState::new(store.clone(), 0, 0, None).unwrap();
            let (_k, _b, akid, _s) = gov
                .create_key_with_aws(
                    NewKeySpec {
                        name: "k".to_string(),
                        allowed_pools: vec![],
                        max_budget_cents: None,
                        budget_period: "total".to_string(),
                        rpm_limit: None,
                        tpm_limit: None,
                    },
                    0,
                )
                .unwrap();
            akid
        };
        let gov2 = GovState::new(store, 0, 0, None).unwrap();
        assert!(
            gov2.lookup_by_access_key_id(&akid).is_some(),
            "credential must survive a reload"
        );
    }

    #[test]
    fn test_delete_key_removes_aws_credential() {
        // Revoking a key must remove its AWS credential so it can no longer authenticate via SigV4.
        let store = Arc::new(SqliteStore::open_in_memory().unwrap());
        let gov = GovState::new(store, 0, 0, None).unwrap();
        let (key, _b, akid, _s) = gov
            .create_key_with_aws(
                NewKeySpec {
                    name: "k".to_string(),
                    allowed_pools: vec![],
                    max_budget_cents: None,
                    budget_period: "total".to_string(),
                    rpm_limit: None,
                    tpm_limit: None,
                },
                0,
            )
            .unwrap();
        assert!(gov.lookup_by_access_key_id(&akid).is_some());
        gov.delete_key(&key.id).unwrap();
        assert!(
            gov.lookup_by_access_key_id(&akid).is_none(),
            "a revoked key's AWS credential must be gone"
        );
        // And the durable credential row is gone too.
        assert!(gov.store().list_aws_credentials().unwrap().is_empty());
    }

    #[test]
    fn test_refresh_updates_both_indices_atomically() {
        // LOW-1 invariant: a key minted WITH an AWS credential is resolvable through BOTH auth
        // indices (the hashed-bearer `by_hash` index AND the AccessKeyId `by_access_key_id` index),
        // and a `delete_key` (which calls `refresh`) clears it from BOTH in the same swap. This pins
        // the single-lock atomic refresh against a future split-lock regression where one index could
        // be updated without the other.
        let store = Arc::new(SqliteStore::open_in_memory().unwrap());
        let gov = GovState::new(store, 0, 0, None).unwrap();
        let (key, bearer, akid, _secret) = gov
            .create_key_with_aws(
                NewKeySpec {
                    name: "dual-index-key".to_string(),
                    allowed_pools: vec![],
                    max_budget_cents: None,
                    budget_period: "total".to_string(),
                    rpm_limit: None,
                    tpm_limit: None,
                },
                1_700_000_000,
            )
            .unwrap();

        // Present in BOTH indices before deletion.
        assert_eq!(
            gov.lookup(&bearer).map(|k| k.id),
            Some(key.id.clone()),
            "bearer must resolve via by_hash before delete"
        );
        assert_eq!(
            gov.lookup_by_access_key_id(&akid).map(|e| e.key.id),
            Some(key.id.clone()),
            "akid must resolve via by_access_key_id before delete"
        );

        // delete_key -> refresh swaps both indices under the single caches lock.
        gov.delete_key(&key.id).unwrap();

        // Absent from BOTH indices after deletion — neither lags the other.
        assert!(
            gov.lookup(&bearer).is_none(),
            "bearer must be gone from by_hash after delete"
        );
        assert!(
            gov.lookup_by_access_key_id(&akid).is_none(),
            "akid must be gone from by_access_key_id after delete"
        );
    }

    #[test]
    fn test_aws_credential_debug_redacts_secret() {
        // The symmetric SigV4 secret must NEVER appear in Debug output (AwsCredential or AwsKeyEntry).
        let cred = AwsCredential {
            access_key_id: "AKIAPUBLIC1234567890".to_string(),
            key_id: "vk_x".to_string(),
            secret_access_key: "SUPER-SECRET-SIGNING-KEY-zzz".to_string(),
        };
        let dbg = format!("{cred:?}");
        assert!(
            !dbg.contains("SUPER-SECRET-SIGNING-KEY-zzz"),
            "AwsCredential Debug leaked the secret: {dbg}"
        );
        assert!(dbg.contains("<redacted; present>"));
        assert!(dbg.contains("AKIAPUBLIC1234567890"), "akid is not secret");

        let entry = AwsKeyEntry {
            key: sample_key("vk_x", "hash"),
            secret_access_key: "SUPER-SECRET-SIGNING-KEY-zzz".to_string(),
        };
        let edbg = format!("{entry:?}");
        assert!(
            !edbg.contains("SUPER-SECRET-SIGNING-KEY-zzz"),
            "AwsKeyEntry Debug leaked the secret: {edbg}"
        );
    }

    #[test]
    fn test_generated_aws_credentials_are_distinct() {
        // Two mints must produce distinct AccessKeyIds and secrets (CSPRNG-sourced, not constant).
        let store = Arc::new(SqliteStore::open_in_memory().unwrap());
        let gov = GovState::new(store, 0, 0, None).unwrap();
        let mk = |gov: &GovState, n: &str| {
            gov.create_key_with_aws(
                NewKeySpec {
                    name: n.to_string(),
                    allowed_pools: vec![],
                    max_budget_cents: None,
                    budget_period: "total".to_string(),
                    rpm_limit: None,
                    tpm_limit: None,
                },
                0,
            )
            .unwrap()
        };
        let (_k1, _b1, akid1, s1) = mk(&gov, "a");
        let (_k2, _b2, akid2, s2) = mk(&gov, "b");
        assert_ne!(akid1, akid2);
        assert_ne!(s1, s2);
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

    /// LEGACY / NON-PRODUCTION PATH. This exercises the deprecated, non-atomic read-then-write pair
    /// `is_over_budget` then `record_request`. That pair is NO LONGER on the admission path; the live
    /// request path charges atomically via `GovState::try_charge_request_within_budget` and
    /// `Store::charge_within_budget` — see `test_concurrent_charges_cannot_overshoot_cap` and
    /// `test_concurrent_govstate_admission_respects_cap`. This test covers only the still-present
    /// tests-plus-token-reconciliation API surface of the old pair; it does NOT imply the live hard-cap
    /// path is covered. Renamed with a `legacy_` prefix to make that explicit.
    #[test]
    fn legacy_test_is_over_budget_and_record() {
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

    /// Token-charge offload UNDER a real Tokio runtime: `test_record_tokens_cost` runs with no runtime
    /// and so exercises only the INLINE branch of `offload_store_write`. This one calls `record_tokens`
    /// from inside a multi-thread runtime, where `offload_store_write` takes the `spawn_blocking` branch
    /// — the fire-and-forget SYNC `add_usage` write lands on the blocking pool, asynchronously. We then
    /// DRAIN that write (bounded poll on `get_usage`, mirroring `test_charge_refund_readmit_cycle`'s
    /// drain) and assert the token cost is reflected. Pins the
    /// `record_tokens → offload_store_write → spawn_blocking → add_usage` path.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn test_record_tokens_offload_under_runtime() {
        let store = Arc::new(SqliteStore::open_in_memory().unwrap());
        // 50 cents per 1000 tokens, no per-request fee.
        let gov = GovState::new(store.clone(), 0, 50, None).unwrap();
        // 2000 tokens * 50c / 1000 = 100c. Fire-and-forget; the SQLite write is offloaded to the
        // blocking pool, so the charge is NOT yet visible synchronously after this returns.
        gov.record_tokens("k1", "total", 1_700_000_000, 2000);
        // Drain the offloaded write with a bounded poll (NOT a fixed sleep): yield to let the blocking
        // task be scheduled, then re-read until the charge lands or the retry budget is exhausted.
        let mut usage = None;
        for _ in 0..200 {
            tokio::task::yield_now().await;
            let u = store.get_usage("k1", 0).unwrap();
            if u.spend_cents == 100 {
                usage = Some(u);
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(1)).await;
        }
        let u = usage.expect("token charge must land after draining the offloaded spawn_blocking write");
        assert_eq!(u.spend_cents, 100, "2000 tokens at 50c/1k must spend exactly 100c");
        assert_eq!(u.tokens, 2000, "raw token count must be recorded for TPM accounting");
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

    /// `rate_headroom` (routing `usage` signal): pure observation of the per-key RPM/TPM budget
    /// remaining this window, as a `[0,1]` fraction. `None` when neither limit is set; never mutates
    /// the window; clamps an over-budget window to `0.0`; takes the MIN of RPM/TPM when both are set.
    #[test]
    fn test_rate_headroom_reports_fraction_remaining() {
        let store = Arc::new(SqliteStore::open_in_memory().unwrap());
        let gov = GovState::new(store, 0, 0, None).unwrap();
        let now = 1_700_000_040; // mid-window

        // No limits → no headroom signal.
        let mut unl = sample_key("ku", "hu");
        unl.rpm_limit = None;
        unl.tpm_limit = None;
        assert_eq!(gov.rate_headroom(&unl, now), None);

        // RPM=4: fresh window is fully available (1.0). Observation must NOT consume budget.
        let mut k = sample_key("k1", "h1");
        k.rpm_limit = Some(4);
        k.tpm_limit = None;
        assert_eq!(gov.rate_headroom(&k, now), Some(1.0));
        assert_eq!(
            gov.rate_headroom(&k, now),
            Some(1.0),
            "rate_headroom is read-only; repeated reads must not drain the window"
        );

        // Consume 1 of 4 via the admission path → 3/4 headroom = 0.75.
        assert!(gov.check_rate(&k, now).is_ok());
        let h = gov.rate_headroom(&k, now).unwrap();
        assert!((h - 0.75).abs() < 1e-9, "expected 0.75 headroom, got {h}");

        // Both RPM and TPM set: headroom is the tighter (min). Drive RPM to the cap → 0.0, clamped.
        let mut kb = sample_key("k2", "h2");
        kb.rpm_limit = Some(2);
        kb.tpm_limit = Some(100_000); // very loose; RPM governs
        let w = 1_700_000_100;
        assert!(gov.check_rate(&kb, w).is_ok());
        assert!(gov.check_rate(&kb, w).is_ok());
        // RPM now at 2/2 used → 0.0 headroom (min with the loose TPM).
        let hb = gov.rate_headroom(&kb, w).unwrap();
        assert!(
            hb.abs() < 1e-9,
            "RPM at cap must yield 0.0 headroom, got {hb}"
        );
    }

    #[test]
    fn test_tpm_enforced_against_accrued_tokens_same_window() {
        // TPM is enforced against tokens from completed requests in the current window.
        let store = Arc::new(SqliteStore::open_in_memory().unwrap());
        let gov = GovState::new(store, 0, 0, None).unwrap();
        let mut k = sample_key("k1", "h1");
        k.rpm_limit = None;
        k.tpm_limit = Some(1000);
        let now = 1_700_000_040; // mid-window

        // First request admitted (window token counter starts at 0).
        assert!(
            gov.check_rate(&k, now).is_ok(),
            "first request admits regardless of TPM"
        );
        // Its response completes in the same window and accrues 1000 tokens (>= the cap).
        gov.record_tokens("k1", "total", now, 1000);
        // Next request in the same window is now rejected on TPM.
        let retry = gov.check_rate(&k, now + 1).unwrap_err();
        assert!(
            (1..=60).contains(&retry),
            "TPM exceeded → 429, retry {retry}"
        );
    }

    #[test]
    fn test_add_rate_tokens_straddling_request_credits_live_window_not_dropped() {
        // MED #6 regression. Production feeds `add_rate_tokens` the request's pinned `charged_at` (the
        // window it STARTED in), not a fresh completion clock. A request that straddles a 60s boundary
        // is admitted in its start window W0, but a LATER admission for the same key rolls the live
        // entry forward to W1 before this request's (streamed) response completes. The credit then
        // arrives carrying `charged_at` in W0 while the live entry is in W1.
        //
        // The old code took `window (W0) < st.window_start (W1)` and either DROPPED the credit or
        // reinitialised the entry back to W0 — wiping the live W1 counter. Either way the straddling
        // request escaped TPM. The fix credits the entry's LIVE (W1) window in place, so the tokens
        // count against the key's currently-live TPM budget.
        let store = Arc::new(SqliteStore::open_in_memory().unwrap());
        let gov = GovState::new(store, 0, 0, None).unwrap();
        let mut k = sample_key("k1", "h1");
        k.rpm_limit = Some(10);
        k.tpm_limit = Some(500);
        let w0 = 1_700_000_040 / 60 * 60; // a window boundary
        let w1 = w0 + RATE_WINDOW_SECS; // the next window

        // The straddling request is admitted in W0 (creates a W0 entry).
        assert!(gov.check_rate(&k, w0).is_ok());
        // A later request for the same key lands in W1 and rolls the live entry forward to W1.
        assert!(gov.check_rate(&k, w1).is_ok());
        // The straddling request's response completes; its credit carries the pinned `charged_at` in
        // W0 (older than the live W1 entry). It must land on the LIVE W1 window, not be dropped.
        gov.record_tokens("k1", "total", w0, 400);
        gov.record_tokens("k1", "total", w0, 200); // 600 >= 500 against the live W1 budget
        let retry = gov.check_rate(&k, w1 + 1).unwrap_err();
        assert!(
            (1..=60).contains(&retry),
            "straddling request's tokens enforce TPM in the live window, not dropped"
        );
    }

    #[test]
    fn test_add_rate_tokens_reinitialises_a_genuinely_stale_entry() {
        // The complement of the straddle case: when the credit's start-window is strictly NEWER than
        // the entry's window, the entry is genuinely stale (an old window the amortized sweep has not
        // yet evicted). It must be reinitialised to the new window before crediting, so a stale entry
        // never carries its old counts forward.
        let store = Arc::new(SqliteStore::open_in_memory().unwrap());
        let gov = GovState::new(store, 0, 0, None).unwrap();
        let mut k = sample_key("k1", "h1");
        k.rpm_limit = Some(10);
        k.tpm_limit = Some(100);
        let w0 = 1_700_000_040 / 60 * 60;
        let w1 = w0 + RATE_WINDOW_SECS;

        // Seed a stale W0 entry directly (simulating an entry the sweep has not yet evicted), then
        // credit with a NEWER start window W1.
        {
            let mut map = gov.rate.write().unwrap_or_else(|p| p.into_inner());
            map.insert(
                "k1".to_string(),
                RateState {
                    window_start: w0,
                    requests: 5,
                    tokens: 999,
                },
            );
        }
        gov.record_tokens("k1", "total", w1, 40);
        let map = gov.rate.read().unwrap_or_else(|p| p.into_inner());
        let st = map.get("k1").expect("entry exists");
        assert_eq!(
            st.window_start, w1,
            "stale entry reinitialised to the new window"
        );
        assert_eq!(st.requests, 0, "stale request count cleared");
        assert_eq!(st.tokens, 40, "only the new window's tokens are credited");
    }

    #[test]
    fn test_check_rate_fast_path_reuses_entry_no_double_reset() {
        // The get_mut fast path must not reset an existing current-window entry (which would drop
        // the request count and break RPM). Two requests in the same window must both count.
        let store = Arc::new(SqliteStore::open_in_memory().unwrap());
        let gov = GovState::new(store, 0, 0, None).unwrap();
        let mut k = sample_key("k1", "h1");
        k.rpm_limit = Some(2);
        k.tpm_limit = None;
        let now = 1_700_000_040;
        assert!(gov.check_rate(&k, now).is_ok());
        assert!(gov.check_rate(&k, now).is_ok());
        assert!(
            gov.check_rate(&k, now).is_err(),
            "RPM=2 → third rejected (entry reused, not reset)"
        );
    }

    #[test]
    fn test_check_rate_resets_stale_entry_without_eager_sweep() {
        // Regression for the amortized-sweep change: a key whose entry belongs to an OLDER window
        // must have its counters reset on its next admission EVEN IF the global eviction sweep did
        // not run this call. Previously the per-call `retain` guaranteed a fresh entry; now the
        // per-key reset in `check_rate` must do it. We exhaust RPM in W0, then advance a full window
        // and confirm the key is admitted again (stale W0 counts must not carry forward).
        let store = Arc::new(SqliteStore::open_in_memory().unwrap());
        let gov = GovState::new(store, 0, 0, None).unwrap();
        let mut k = sample_key("k1", "h1");
        k.rpm_limit = Some(1);
        k.tpm_limit = None;
        let w0 = 1_700_000_040 / 60 * 60;

        // Burn the single W0 slot; a second W0 request is rejected.
        assert!(gov.check_rate(&k, w0).is_ok(), "W0 first admits");
        assert!(
            gov.check_rate(&k, w0).is_err(),
            "W0 second rejected (RPM=1)"
        );

        // Force the sweep ticker so the eager retain does NOT run on the next call — proving the
        // per-key reset (not the sweep) is what clears the stale W0 entry. The sweep test is now
        // POST-increment: a call fires the sweep when the value AFTER its increment is a multiple of
        // N. Set the ticker to 1 so the next call's post-increment value is 2, which is not a
        // multiple of N.
        gov.rate_sweep_ticker.store(1, Ordering::Relaxed);
        assert!(
            !2u32.is_multiple_of(RATE_SWEEP_INTERVAL),
            "test precondition: next call's post-increment value must skip the eager sweep"
        );

        // A request a full window later must be admitted: the stale W0 entry is reset in place.
        let w1 = w0 + RATE_WINDOW_SECS;
        assert!(
            gov.check_rate(&k, w1).is_ok(),
            "new window admits again despite no eager sweep (per-key stale reset)"
        );
        // And the reset took the count back to zero, so W1's own RPM=1 is re-enforced.
        assert!(
            gov.check_rate(&k, w1).is_err(),
            "W1 second rejected — counter reset to 0, not carried from W0"
        );
    }

    #[test]
    fn test_check_rate_sweep_evicts_silent_keys_to_bound_map() {
        // The amortized sweep must still evict entries for keys that have gone silent in older
        // windows, so the map stays bounded. We seed many distinct keys in W0, then trigger a sweep
        // on a later window and confirm the stale entries are gone.
        let store = Arc::new(SqliteStore::open_in_memory().unwrap());
        let gov = GovState::new(store, 0, 0, None).unwrap();
        let w0 = 1_700_000_040 / 60 * 60;

        for i in 0..10 {
            let mut k = sample_key(&format!("k{i}"), &format!("h{i}"));
            k.rpm_limit = Some(5);
            k.tpm_limit = None;
            assert!(gov.check_rate(&k, w0).is_ok());
        }
        assert_eq!(
            gov.rate.read().unwrap_or_else(|p| p.into_inner()).len(),
            10,
            "10 W0 entries present"
        );

        // Force the next call to run the eager sweep. POST-increment: the sweep fires when the value
        // AFTER the increment is a multiple of N, so set the ticker to N-1 (the next call's
        // post-increment value is N, a multiple of the interval).
        gov.rate_sweep_ticker
            .store(RATE_SWEEP_INTERVAL - 1, Ordering::Relaxed);
        let mut survivor = sample_key("survivor", "hs");
        survivor.rpm_limit = Some(5);
        survivor.tpm_limit = None;
        let w_later = w0 + RATE_WINDOW_SECS * 2;
        assert!(gov.check_rate(&survivor, w_later).is_ok());

        let map = gov.rate.read().unwrap_or_else(|p| p.into_inner());
        assert_eq!(
            map.len(),
            1,
            "sweep evicted all 10 stale W0 entries, leaving only the current-window survivor"
        );
        assert!(map.contains_key("survivor"));
    }

    #[test]
    fn test_check_rate_sweep_cadence_post_increment_no_off_by_one() {
        // Regression for the sweep-cadence off-by-one. The sweep must use POST-increment semantics:
        //  - It must NOT fire on the very first call (ticker starts at 0; the pre-increment value 0
        //    is a multiple of N, but the post-increment value 1 is not), so startup against an empty
        //    map does no wasted scan.
        //  - It must fire on calls N, 2N, 3N, ...
        //  - The u32 wrap boundary must NOT skip a cycle: when the pre-increment value is 0xFFFFFFFF
        //    (not a multiple of N), the post-increment value wraps to 0 (a multiple of N) and the
        //    sweep still fires.
        let store = Arc::new(SqliteStore::open_in_memory().unwrap());
        let gov = GovState::new(store, 0, 0, None).unwrap();
        let mut k = sample_key("k1", "h1");
        k.rpm_limit = Some(1_000_000);
        k.tpm_limit = None;
        let w0 = 1_700_000_040 / 60 * 60;

        // Seed a STALE entry under an older window so a sweep would evict it. Use a distinct key so
        // we can observe whether the sweep ran by whether the stale entry survives.
        {
            let mut map = gov.rate.write().unwrap_or_else(|p| p.into_inner());
            map.insert(
                "stale".to_string(),
                RateState {
                    window_start: w0 - RATE_WINDOW_SECS,
                    requests: 0,
                    tokens: 0,
                },
            );
        }

        // FIRST call: ticker is 0, post-increment value is 1 (not a multiple of N) -> NO sweep.
        // The stale entry must survive.
        assert_eq!(gov.rate_sweep_ticker.load(Ordering::Relaxed), 0);
        assert!(gov.check_rate(&k, w0).is_ok());
        assert!(
            gov.rate
                .read()
                .unwrap_or_else(|p| p.into_inner())
                .contains_key("stale"),
            "first call must NOT sweep (post-increment value 1 is not a multiple of N)"
        );

        // Drive the ticker to N-1 so the next call's post-increment value is exactly N -> sweep runs.
        gov.rate_sweep_ticker
            .store(RATE_SWEEP_INTERVAL - 1, Ordering::Relaxed);
        assert!(gov.check_rate(&k, w0).is_ok());
        assert!(
            !gov.rate
                .read()
                .unwrap_or_else(|p| p.into_inner())
                .contains_key("stale"),
            "call N must run the sweep and evict the stale entry"
        );

        // WRAP boundary: pre-increment value 0xFFFFFFFF is NOT a multiple of N, but post-increment
        // wraps to 0 (a multiple of N) so the sweep must still fire — no skipped cycle.
        {
            let mut map = gov.rate.write().unwrap_or_else(|p| p.into_inner());
            map.insert(
                "stale2".to_string(),
                RateState {
                    window_start: w0 - RATE_WINDOW_SECS,
                    requests: 0,
                    tokens: 0,
                },
            );
        }
        gov.rate_sweep_ticker.store(u32::MAX, Ordering::Relaxed);
        assert!(gov.check_rate(&k, w0).is_ok());
        assert_eq!(
            gov.rate_sweep_ticker.load(Ordering::Relaxed),
            0,
            "ticker wrapped to 0"
        );
        assert!(
            !gov.rate
                .read()
                .unwrap_or_else(|p| p.into_inner())
                .contains_key("stale2"),
            "wrap boundary must still sweep (post-increment 0 is a multiple of N) — no skipped cycle"
        );
    }

    #[tokio::test]
    async fn test_record_request_offloaded_charges_under_runtime() {
        // Inside a Tokio runtime, record_request offloads the SQLite write to the blocking pool.
        // The charge must still land (we await the blocking pool draining via a yield + poll).
        let store = Arc::new(SqliteStore::open_in_memory().unwrap());
        let mut k = sample_key("k1", "h1");
        k.max_budget_cents = Some(1000);
        k.budget_period = "total".to_string();
        let gov = GovState::new(store.clone(), 30, 0, None).unwrap();

        gov.record_request(&k, 1_700_000_000, 0);
        // Drain the spawn_blocking write: poll until the usage row appears (bounded retries).
        let mut spend = 0;
        for _ in 0..200 {
            tokio::task::yield_now().await;
            spend = store.get_usage("k1", 0).unwrap().spend_cents;
            if spend == 30 {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(1)).await;
        }
        assert_eq!(
            spend, 30,
            "offloaded record_request must charge the per-request fee"
        );

        // And the async budget gate observes it.
        assert!(!gov.is_over_budget_async(&k, 1_700_000_000).await);
    }

    #[test]
    fn test_record_request_clamps_negative_per_request_price() {
        // A negative per-request price must NOT decrement accrued spend (which would drive spend
        // below zero and defeat the budget cap). The fee is clamped at >= 0, symmetric with the
        // per-1k-token price clamp in record_tokens.
        let store = Arc::new(SqliteStore::open_in_memory().unwrap());
        let mut k = sample_key("k1", "h1");
        k.max_budget_cents = Some(100);
        k.budget_period = "total".to_string();
        let gov = GovState::new(store.clone(), -50, 0, None).unwrap(); // hostile negative price

        for _ in 0..5 {
            gov.record_request(&k, 1_700_000_000, 0);
        }
        let u = store.get_usage("k1", 0).unwrap();
        assert_eq!(
            u.spend_cents, 0,
            "negative per-request price must clamp to 0, never decrement spend"
        );
        assert_eq!(u.requests, 5, "requests are still counted");
        // Spend can never be driven below zero to evade the cap.
        assert!(!gov.is_over_budget(&k, 1_700_000_000));
    }

    #[test]
    fn test_record_tokens_clamps_negative_per_1k_price() {
        // Mirror assertion for the token-price path (already clamped pre-fix; lock it in).
        let store = Arc::new(SqliteStore::open_in_memory().unwrap());
        let gov = GovState::new(store.clone(), 0, -100, None).unwrap();
        gov.record_tokens("k1", "total", 1_700_000_000, 5000);
        let u = store.get_usage("k1", 0).unwrap();
        assert_eq!(u.spend_cents, 0, "negative token price must clamp to 0");
        assert_eq!(u.tokens, 5000, "tokens are still counted");
    }

    #[test]
    fn test_create_key_minted_id_is_free_so_mint_succeeds() {
        // A normal mint derives a fresh id and the collision guard does not fire (the id is free).
        let store = Arc::new(SqliteStore::open_in_memory().unwrap());
        let gov = GovState::new(store.clone(), 1, 0, None).unwrap();
        let spec = NewKeySpec {
            name: "first".to_string(),
            allowed_pools: vec![],
            max_budget_cents: None,
            budget_period: "total".to_string(),
            rpm_limit: None,
            tpm_limit: None,
        };
        let (key, secret) = gov.create_key(spec, 1_700_000_000).unwrap();
        assert!(key.id.starts_with("vk_"));
        // The minted key resolves by its own secret.
        assert_eq!(gov.lookup(&secret).unwrap().id, key.id);
    }

    #[test]
    fn test_update_key_toggles_enabled_and_limits_in_place() {
        // PATCH /admin/keys/:id (#28): a key can be disabled WITHOUT destroying it, and its caps
        // adjusted, with the secret/hash preserved. A missing field leaves its value unchanged.
        let store = Arc::new(SqliteStore::open_in_memory().unwrap());
        let gov = GovState::new(store.clone(), 1, 0, None).unwrap();
        let (key, secret) = gov
            .create_key(
                NewKeySpec {
                    name: "k".to_string(),
                    allowed_pools: vec![],
                    max_budget_cents: None,
                    budget_period: "total".to_string(),
                    rpm_limit: Some(10),
                    tpm_limit: None,
                },
                1_700_000_000,
            )
            .unwrap();
        assert!(key.enabled, "new key starts enabled");
        let hash = key.key_hash.clone();

        // Disable it; leave the limits untouched (outer None = field absent).
        let updated = gov
            .update_key(&key.id, Some(false), None, None, None)
            .unwrap()
            .expect("key exists");
        assert!(!updated.enabled, "key is now disabled");
        assert_eq!(updated.rpm_limit, Some(10), "untouched field preserved");
        assert_eq!(updated.key_hash, hash, "secret hash is not rotated");
        // The disabled state is enforced on the next lookup (the cache was refreshed).
        let looked = gov.lookup(&secret).unwrap();
        assert!(!looked.enabled, "lookup reflects the disabled key");

        // Re-enable and bump the rate cap in one call (Some(Some(50)) = set).
        let re = gov
            .update_key(&key.id, Some(true), Some(Some(50)), None, None)
            .unwrap()
            .expect("key exists");
        assert!(re.enabled);
        assert_eq!(re.rpm_limit, Some(50));

        // Updating a non-existent key returns Ok(None) (the handler maps this to 404).
        assert!(gov
            .update_key("vk_does_not_exist", Some(false), None, None, None)
            .unwrap()
            .is_none());
    }

    #[test]
    fn test_update_key_clears_caps_to_unlimited_with_inner_none() {
        // THREE-STATE caps (LOW #16/#19): `Some(None)` CLEARS a cap back to unlimited; `None` (outer)
        // leaves it unchanged; `Some(Some(v))` sets it. The old single-Option shape could only set or
        // leave-unchanged, never clear. Verify all three transitions on every cap field.
        let store = Arc::new(SqliteStore::open_in_memory().unwrap());
        let gov = GovState::new(store.clone(), 1, 0, None).unwrap();
        let (key, _secret) = gov
            .create_key(
                NewKeySpec {
                    name: "k".to_string(),
                    allowed_pools: vec![],
                    max_budget_cents: Some(5000),
                    budget_period: "total".to_string(),
                    rpm_limit: Some(10),
                    tpm_limit: Some(2000),
                },
                1_700_000_000,
            )
            .unwrap();
        assert_eq!(key.rpm_limit, Some(10));
        assert_eq!(key.tpm_limit, Some(2000));
        assert_eq!(key.max_budget_cents, Some(5000));

        // Clear ALL three caps to unlimited with inner None.
        let cleared = gov
            .update_key(&key.id, None, Some(None), Some(None), Some(None))
            .unwrap()
            .expect("key exists");
        assert_eq!(cleared.rpm_limit, None, "rpm cleared to unlimited");
        assert_eq!(cleared.tpm_limit, None, "tpm cleared to unlimited");
        assert_eq!(
            cleared.max_budget_cents, None,
            "budget cleared to unlimited"
        );
        // The clear persisted through the store, not just the returned struct.
        let persisted = store.get_key(&key.id).unwrap().unwrap();
        assert_eq!(persisted.rpm_limit, None);
        assert_eq!(persisted.tpm_limit, None);
        assert_eq!(persisted.max_budget_cents, None);

        // Now SET them again from the cleared state.
        let reset = gov
            .update_key(
                &key.id,
                None,
                Some(Some(7)),
                Some(Some(99)),
                Some(Some(123)),
            )
            .unwrap()
            .expect("key exists");
        assert_eq!(reset.rpm_limit, Some(7));
        assert_eq!(reset.tpm_limit, Some(99));
        assert_eq!(reset.max_budget_cents, Some(123));

        // And absence (outer None) leaves them UNCHANGED.
        let unchanged = gov
            .update_key(&key.id, Some(false), None, None, None)
            .unwrap()
            .expect("key exists");
        assert!(!unchanged.enabled, "enabled toggled");
        assert_eq!(unchanged.rpm_limit, Some(7), "absent leaves rpm unchanged");
        assert_eq!(unchanged.tpm_limit, Some(99), "absent leaves tpm unchanged");
        assert_eq!(
            unchanged.max_budget_cents,
            Some(123),
            "absent leaves budget unchanged"
        );
    }

    #[test]
    fn test_unlimited_key_does_not_grow_rate_map() {
        // LOW #17 (memory): a key with NO RPM/TPM cap must never grow the ephemeral `rate` map. Both
        // the rate-limit gate (`check_rate`) and the post-response accounting (`record_request` /
        // `record_tokens`) must skip the map for an uncapped key — otherwise every request leaks one
        // entry per uncapped key forever. Drive many requests for an uncapped key and assert the map
        // stays empty; then a capped key DOES get an entry (the feed still works where it should).
        let store = Arc::new(SqliteStore::open_in_memory().unwrap());
        let gov = GovState::new(store, 5, 7, None).unwrap();

        let mut uncapped = sample_key("uncapped", "h_unl");
        uncapped.rpm_limit = None;
        uncapped.tpm_limit = None;
        let now = 1_700_000_040;
        for _ in 0..50 {
            assert!(gov.check_rate(&uncapped, now).is_ok());
            gov.record_request(&uncapped, now, 1234); // non-zero tokens — would feed the map pre-fix
        }
        // record_tokens carries only the key id (no caps), so it must also not materialise an entry.
        gov.record_tokens("uncapped", "total", now, 9999);
        assert!(
            gov.rate
                .read()
                .unwrap_or_else(|p| p.into_inner())
                .get("uncapped")
                .is_none(),
            "an uncapped key must never gain a rate-map entry"
        );

        // A capped key still gets fed: check_rate creates its entry and record_request credits TPM.
        let mut capped = sample_key("capped", "h_cap");
        capped.rpm_limit = Some(100);
        capped.tpm_limit = Some(100_000);
        assert!(gov.check_rate(&capped, now).is_ok());
        gov.record_request(&capped, now, 500);
        let map = gov.rate.read().unwrap_or_else(|p| p.into_inner());
        let st = map
            .get("capped")
            .expect("a capped key must have a rate-map entry");
        assert_eq!(st.tokens, 500, "capped key's TPM counter was fed");
        assert!(
            map.get("uncapped").is_none(),
            "uncapped key still absent after a capped key was added"
        );
    }

    #[test]
    fn test_add_rate_tokens_is_update_only_never_materialises_entry() {
        // LOW #12 (completeness): `add_rate_tokens` is UPDATE-ONLY. It must NEVER create a missing
        // entry, even for a capped key. The former `create_if_absent = true` recovery branch (fed by
        // `record_request` for a "swept-capped-key") was DEAD: production always passes `tokens = 0`
        // through `record_request`, so the credit returns at the `tokens == 0` guard before reaching
        // any create path, and the token fee flows through `record_tokens` (update-only). Old code
        // with the recovery branch would have materialised an entry here from `record_request` with
        // non-zero tokens; the corrected update-only code must not.
        let store = Arc::new(SqliteStore::open_in_memory().unwrap());
        let gov = GovState::new(store, 5, 7, None).unwrap();

        // A CAPPED key with NO prior `check_rate` admission -> it has no rate-map entry yet.
        let mut capped = sample_key("late", "h_late");
        capped.rpm_limit = Some(10);
        capped.tpm_limit = Some(1000);
        let now = 1_700_000_040;

        // Feed non-zero tokens via record_request WITHOUT a preceding check_rate. The dead recovery
        // branch (create_if_absent) would have inserted an entry crediting 500 tokens; update-only
        // must leave the map untouched for this key.
        gov.record_request(&capped, now, 500);
        assert!(
            gov.rate
                .read()
                .unwrap_or_else(|p| p.into_inner())
                .get("late")
                .is_none(),
            "add_rate_tokens must not materialise an entry for a key with no prior check_rate"
        );

        // Likewise via record_tokens (the token-fee path): no entry exists, so nothing is created.
        gov.record_tokens("late", "total", now, 500);
        assert!(
            gov.rate
                .read()
                .unwrap_or_else(|p| p.into_inner())
                .get("late")
                .is_none(),
            "record_tokens (update-only) must not materialise an entry either"
        );

        // Once check_rate creates the entry (the real admission path), a subsequent credit lands.
        assert!(gov.check_rate(&capped, now).is_ok());
        gov.record_request(&capped, now, 300);
        let map = gov.rate.read().unwrap_or_else(|p| p.into_inner());
        assert_eq!(
            map.get("late")
                .expect("entry exists after check_rate")
                .tokens,
            300,
            "an existing entry is credited update-only",
        );
    }

    #[test]
    fn test_ensure_id_free_for_hash_guards_silent_overwrite() {
        // The PRIMARY KEY `id` is a 64-bit prefix of the full key_hash, so a collision can put a new
        // secret's id atop an unrelated key. The guard must REFUSE when the id already holds a
        // DIFFERENT key_hash (rather than let put_key UPSERT-overwrite and invalidate the incumbent),
        // while allowing a free id or an idempotent same-hash re-mint.
        let store = Arc::new(SqliteStore::open_in_memory().unwrap());
        let gov = GovState::new(store.clone(), 1, 0, None).unwrap();

        // A free id is allowed.
        gov.ensure_id_free_for_hash("vk_freshid", "HASH_A")
            .expect("a free id must be allowed");

        // Seed an incumbent key occupying that id under HASH_A.
        let incumbent = sample_key("vk_freshid", "HASH_A");
        store.put_key(&incumbent).unwrap();
        gov.refresh().unwrap();

        // Same id, SAME hash: idempotent re-mint is allowed.
        gov.ensure_id_free_for_hash("vk_freshid", "HASH_A")
            .expect("same-hash re-mint must be allowed");

        // Same id, DIFFERENT hash: must be rejected (the collision the fix guards against).
        let err = gov
            .ensure_id_free_for_hash("vk_freshid", "HASH_B_DIFFERENT")
            .expect_err("colliding id with a different hash must be rejected");
        assert!(
            err.to_string().contains("id collision"),
            "error must explain the id collision; got: {err}"
        );

        // The incumbent row is untouched (never overwritten).
        let still = store.get_key("vk_freshid").unwrap().unwrap();
        assert_eq!(still.key_hash, "HASH_A", "incumbent must not be clobbered");
    }

    #[test]
    fn test_poisoned_rate_lock_recovers_not_panics() {
        // Regression: a panic while the `rate` lock is held poisons it. The hot-path accessors must
        // RECOVER (via into_inner) rather than `.unwrap()`-panic on every subsequent call, which
        // would cascade a single transient fault into a full governance outage. We deliberately
        // poison the lock, then assert check_rate/add_rate_tokens still function.
        let store = Arc::new(SqliteStore::open_in_memory().unwrap());
        let gov = Arc::new(GovState::new(store, 0, 0, None).unwrap());
        let mut k = sample_key("k1", "h1");
        k.rpm_limit = Some(2);
        k.tpm_limit = None;
        let now = 1_700_000_040;

        // Poison the rate lock: panic inside the write guard.
        let g = gov.clone();
        let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _guard = g.rate.write().unwrap();
            panic!("intentional poison");
        }));
        assert!(gov.rate.is_poisoned(), "lock must be poisoned for the test");

        // Despite the poison, the hot path keeps working (no panic, RPM still enforced).
        assert!(gov.check_rate(&k, now).is_ok(), "1st admits after poison");
        assert!(gov.check_rate(&k, now).is_ok(), "2nd admits after poison");
        assert!(
            gov.check_rate(&k, now).is_err(),
            "RPM=2 still enforced on a recovered (poisoned) lock"
        );
    }

    #[test]
    fn test_poisoned_by_hash_lock_recovers_not_panics() {
        // The auth-path key cache lock has the same hazard: a poisoned `by_hash` must not make every
        // subsequent `lookup` panic. Poison it, then confirm lookup still resolves a cached key.
        let store = Arc::new(SqliteStore::open_in_memory().unwrap());
        let secret = "sk-vk-abc";
        let k = sample_key("k1", &crate::sigv4::sha256_hex(secret.as_bytes()));
        store.put_key(&k).unwrap();
        let gov = Arc::new(GovState::new(store, 1, 0, None).unwrap());

        let g = gov.clone();
        let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _guard = g.caches.write().unwrap();
            panic!("intentional poison");
        }));
        assert!(gov.caches.is_poisoned(), "cache lock must be poisoned");

        // lookup still works (no panic) and refresh still succeeds on the recovered guard.
        assert_eq!(gov.lookup(secret).unwrap().id, "k1");
        gov.refresh()
            .expect("refresh recovers the poisoned cache lock");
        assert_eq!(gov.lookup(secret).unwrap().id, "k1");
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
}
