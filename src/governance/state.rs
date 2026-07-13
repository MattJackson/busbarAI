use super::*;

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

    /// The configured budget store-error fail-mode. Consulted by the ingress admission site.
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
    pub(crate) fn offload_store_write<F>(&self, what: &'static str, key_id: &str, op: F)
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
    /// `proxy engine` calls `lookup` + `rate_headroom` (one key lookup shared with the `send_user`
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
    // Wired into production routing: `proxy engine::decide_policy_order` calls this on the key it
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
    pub(crate) fn ensure_id_free_for_hash(&self, id: &str, hash: &str) -> StoreResult<()> {
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
    pub(crate) fn add_rate_tokens(&self, key_id: &str, now: u64, tokens: u64) {
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

    pub(crate) fn load(store: &dyn Store) -> StoreResult<HashMap<String, VirtualKey>> {
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
    pub(crate) fn load_by_access_key_id(
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
