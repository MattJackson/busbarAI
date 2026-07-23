use super::*;

impl GovState {
    pub(crate) fn new(store: Arc<dyn Store>, admin_token: Option<String>) -> StoreResult<Self> {
        let by_hash = Self::load(store.as_ref())?;
        let by_access_key_id = Self::load_by_access_key_id(store.as_ref(), &by_hash)?;
        Ok(Self {
            store,
            caches: RwLock::new(GovCaches {
                by_hash,
                by_access_key_id,
            }),
            rate: Sharded::new(),
            admin_token_hash: admin_token
                .as_ref()
                .map(|t| crate::sigv4::sha256_hex(t.as_bytes())),
            budget: Sharded::new(),
        })
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

    /// Accrue one completed response's TIER-TOKEN split under `model` to EVERY bucket in the key's
    /// enforcement chain (the key's own bucket + each ancestor budget group, each in ITS OWN
    /// `budget_period` window), plus the raw total to the TPM window. Called once per request at
    /// stream end from the response usage tap. Tokens land in the AUTHORITATIVE in-memory ledger
    /// cells (marked dirty for the write-behind flusher) - NO store round-trip, NO spend math here:
    /// spend is derived from `ledger x rate_card` at check/read time.
    ///
    /// Accrual (unlike the admission charge) does not need cross-bucket atomicity: each bucket's
    /// cell is updated under its own shard lock, and enforcement always re-derives from whatever
    /// has landed.
    ///
    /// STRADDLE CASE (mirrors `add_rate_tokens`): `now` is the request's pinned `charged_at` (the
    /// window the request STARTED in), NOT a fresh clock. Per bucket:
    ///   - `window > cell.window_start` → the cell is genuinely stale: reset it to `window`
    ///     (zeroed), then add.
    ///   - `window <= cell.window_start` → same window OR the straddle: credit IN PLACE on the
    ///     live cell (never rewind/zero a newer window's counters). A straddling request's tokens
    ///     attribute to the live window rather than being dropped - bounded to one in-flight
    ///     request, never lost.
    ///   - no cell → insert fresh (defensive; post-admission the cell exists).
    pub(crate) fn record_usage(
        &self,
        cost: &crate::cost::CostModel,
        key: &VirtualKey,
        model: &str,
        tokens: &TierTokens,
        now: u64,
    ) {
        if tokens.is_zero() {
            return; // nothing to ledger
        }
        // A missing budget group cannot block ACCRUAL (the request was already admitted/served);
        // degrade to the key-only chain so the tokens are never lost.
        let chain = match cost.chain_for(key) {
            Ok(c) => c,
            Err(missing) => {
                tracing::warn!(key = %key.id, budget_group = missing,
                    "budget_group missing at accrual; tokens ledgered to the key bucket only");
                let solo = VirtualKey {
                    budget_group: None,
                    ..key.clone()
                };
                self.accrue_bucket(&solo.id, &solo.budget_period, model, tokens, now);
                self.add_rate_tokens(&key.id, now, tokens.total());
                return;
            }
        };
        for bucket in chain.iter() {
            self.accrue_bucket(bucket.bucket_id, bucket.budget_period, model, tokens, now);
        }
        // Feed the TPM counter (raw total across tiers). `add_rate_tokens` is UPDATE-only: it
        // credits an existing entry (created by `check_rate` for a capped key) but never
        // materialises one, so the rate map stays bounded for caps-free deployments.
        self.add_rate_tokens(&key.id, now, tokens.total());
    }

    /// Accrue `tokens` under `model` to ONE bucket's current-window ledger cell (straddle-safe;
    /// see [`GovState::record_usage`]).
    fn accrue_bucket(
        &self,
        bucket_id: &str,
        budget_period: &str,
        model: &str,
        tokens: &TierTokens,
        now: u64,
    ) {
        let window = budget_window(budget_period, now);
        let mut map = self.budget.write(bucket_id);
        let cell = match map.get_mut(bucket_id) {
            Some(c) if window > c.window_start => {
                *c = BudgetCell::fresh(window);
                c
            }
            Some(c) => c, // same window or straddle (cell newer-or-equal) → credit in place
            None => map
                .entry(bucket_id.to_string())
                .or_insert_with(|| BudgetCell::fresh(window)),
        };
        cell.accrue(model, tokens);
        cell.dirty = true;
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
        let (requests, tokens) = match self.rate.read(&key.id).get(&key.id) {
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
    // Only read by the `auth-admin-tokens` chain link; without that feature the getter is unused
    // (the field is still populated/validated, so keep the method rather than gate the field).
    #[cfg_attr(not(feature = "auth-admin-tokens"), allow(dead_code))]
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
        let secret = generate_secret().store()?;
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
            budget_group: spec.budget_group,
            labels: spec.labels,
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
        let secret = generate_secret().store()?;
        let hash = crate::sigv4::sha256_hex(secret.as_bytes());
        let id = format!("{VK_ID_PREFIX}{}", &hash[..VK_ID_HASH_PREFIX_LEN]);
        self.ensure_id_free_for_hash(&id, &hash)?;
        let access_key_id = generate_aws_access_key_id().store()?;
        let secret_access_key = generate_aws_secret_access_key().store()?;
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
            budget_group: spec.budget_group,
            labels: spec.labels,
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
        let secret = generate_secret().store()?;
        key.key_hash = crate::sigv4::sha256_hex(secret.as_bytes());
        self.store.put_key(&key)?;
        self.refresh()?;
        Ok(Some((key, secret)))
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

    /// BOOT-ONLY crash-recovery of accrued token ledgers into the authoritative in-memory cells:
    /// every KEY bucket plus every configured GROUP bucket, each for its own current window. A
    /// hydrated cell seeds NON-dirty with flush baselines equal to the durable record (the store
    /// already holds those values, possibly including other nodes' accruals - the first flush must
    /// send only the LOCAL delta accrued after boot). Runs OFF the hot path exactly once per fresh
    /// `GovState` (never on a config reload/apply - the prior `Arc<GovState>` keeps its live
    /// cells).
    ///
    /// M9 (boot fail-open): a store error here is FATAL, not best-effort. The old code warned and
    /// started with EMPTY cells on a `list_keys`/`get_usage` failure, which silently RESET every
    /// budget to zero - a transient store blip at boot would let a maxed-out key spend its whole cap
    /// again. Propagate any store error so boot fails loudly (the supervisor restarts) rather than
    /// resuming with an unenforced ledger. Returns `Ok(())` only when every bucket hydrated cleanly.
    pub(crate) fn hydrate_budgets(
        &self,
        cost: &crate::cost::CostModel,
        now: u64,
    ) -> StoreResult<()> {
        let keys = self.store.list_keys()?;
        let key_buckets = keys
            .iter()
            .map(|k| (k.id.as_str(), k.budget_period.as_str()));
        let group_buckets = cost
            .groups()
            .iter()
            .map(|g| (g.bucket_id.as_str(), g.budget_period.as_str()));
        for (bucket_id, period) in key_buckets.chain(group_buckets) {
            let window = budget_window(period, now);
            let ledger = self.store.get_usage(bucket_id, window)?;
            if ledger.requests == 0 && ledger.models.is_empty() {
                continue;
            }
            let mut cell = BudgetCell::fresh(window);
            cell.requests = ledger.requests;
            cell.flushed_requests = ledger.requests;
            cell.models = ledger
                .models
                .iter()
                .map(|m| ModelCell {
                    model: std::sync::Arc::from(m.model.as_str()),
                    cur: m.tokens,
                    flushed: m.tokens,
                })
                .collect();
            self.budget
                .write(bucket_id)
                .insert(bucket_id.to_string(), cell);
        }
        Ok(())
    }

    /// Current-window DERIVED usage for a key (`None` if the key does not exist): spend is
    /// recomputed at read time from the bucket's token ledger x the CURRENT rate card (+ the flat
    /// fee x requests) - reprice-on-read. The AUTHORITATIVE in-memory cell wins for the current
    /// window (it reflects hot-path accruals the write-behind flusher may not have persisted yet);
    /// falls back to the durable ledger for a bucket whose cell was never materialised.
    pub(crate) fn usage_for(
        &self,
        cost: &crate::cost::CostModel,
        id: &str,
        now: u64,
    ) -> StoreResult<Option<DerivedUsage>> {
        match self.store.get_key(id)? {
            Some(key) => Ok(Some(self.derived_bucket_usage(
                cost,
                id,
                &key.budget_period,
                true,
                now,
            )?)),
            None => Ok(None),
        }
    }

    /// The DERIVED current-window usage of one bucket (key or group): cell-authoritative, durable
    /// fallback, spend recomputed from tokens x current rates. `include_request_fee` is true for a
    /// KEY bucket only (the flat per-request fee counts against the innermost bucket alone).
    pub(crate) fn derived_bucket_usage(
        &self,
        cost: &crate::cost::CostModel,
        bucket_id: &str,
        budget_period: &str,
        include_request_fee: bool,
        now: u64,
    ) -> StoreResult<DerivedUsage> {
        let window = budget_window(budget_period, now);
        if let Some(cell) = self.budget.read(bucket_id).get(bucket_id) {
            if cell.window_start == window {
                return Ok(DerivedUsage {
                    spend_cents: cost.derive_spend_cents(
                        cell.model_views(),
                        cell.requests,
                        include_request_fee,
                    ),
                    tokens: cell.total_tokens(),
                    requests: cell.requests,
                });
            }
        }
        let ledger = self.store.get_usage(bucket_id, window)?;
        Ok(DerivedUsage {
            spend_cents: cost.derive_spend_cents(
                ledger.models.iter().map(|m| (m.model.as_str(), &m.tokens)),
                ledger.requests,
                include_request_fee,
            ),
            tokens: ledger.total_tokens(),
            requests: ledger.requests,
        })
    }

    /// SCRAPE-TIME view of one bucket's per-(model, tier) token counters for its CURRENT window:
    /// the authoritative cell when live, else the durable ledger. Off the hot path (the /metrics
    /// scrape); allocation here is fine.
    pub(crate) fn bucket_model_tokens(
        &self,
        bucket_id: &str,
        budget_period: &str,
        now: u64,
    ) -> Vec<(String, TierTokens)> {
        let window = budget_window(budget_period, now);
        {
            let map = self.budget.read(bucket_id);
            if let Some(cell) = map.get(bucket_id) {
                if cell.window_start == window {
                    return cell
                        .models
                        .iter()
                        .map(|m| (m.model.to_string(), m.cur))
                        .collect();
                }
            }
        }
        match self.store.get_usage(bucket_id, window) {
            Ok(ledger) => ledger
                .models
                .into_iter()
                .map(|m| (m.model, m.tokens))
                .collect(),
            Err(_) => Vec::new(),
        }
    }

    /// The HOOK-SEAM projection: per-bucket budget state for the key + every ancestor group -
    /// `{bucket_id, spend_micros_at_current_rate, remaining_micros, window}`. Read-only, built off
    /// the default hot path (only routing-policy pools request it). A missing budget group yields
    /// the key-only view.
    pub(crate) fn budget_state(
        &self,
        cost: &crate::cost::CostModel,
        key: &VirtualKey,
        now: u64,
    ) -> Vec<busbar_api::BudgetBucketState> {
        let chain = match cost.chain_for(key) {
            Ok(c) => c,
            Err(_) => return Vec::new(),
        };
        let mut out = Vec::with_capacity(chain.len());
        for bucket in chain.iter() {
            let window = budget_window(bucket.budget_period, now);
            let (spend_micros, requests) = {
                let map = self.budget.read(bucket.bucket_id);
                match map.get(bucket.bucket_id) {
                    Some(cell) if cell.window_start == window => (
                        cost.derive_spend_micros(cell.model_views(), cell.requests, bucket.is_key),
                        cell.requests,
                    ),
                    _ => (0, 0),
                }
            };
            let _ = requests;
            let remaining_micros = bucket.max_budget_cents.map(|cap| {
                cap.saturating_mul(10_000)
                    .saturating_sub(spend_micros)
                    .max(0)
            });
            out.push(busbar_api::BudgetBucketState {
                bucket_id: bucket.bucket_id.to_string(),
                budget_group: bucket.group_name.map(String::from),
                spend_micros_at_current_rate: spend_micros,
                remaining_micros,
                window_start: window,
                budget_period: bucket.budget_period.to_string(),
            });
        }
        out
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
        // Per-shard amortized sweep + per-key check/increment under THIS key's shard lock. The ticker
        // is the shard's own, so each shard sweeps only its own (~1/GOV_SHARDS) entries — the memory
        // bound holds per shard, and cross-key contention is confined to a single shard.
        let shard = self.rate.shard_for(&key.id);
        let sweep_needed = shard
            .sweep_ticker
            .fetch_add(1, Ordering::Relaxed)
            .wrapping_add(1)
            .is_multiple_of(crate::limits::rate_sweep_interval());
        let mut map = shard.map.write().unwrap_or_else(|p| p.into_inner());
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
        let mut map = self.rate.write(key_id);
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

    /// ATOMIC budget CHAIN check-and-charge for the admission path - the HARD-cap primitive.
    ///
    /// Resolves the key's enforcement chain ([key bucket] -> budget_group -> parent -> ... root),
    /// derives every bucket's CURRENT spend from its token ledger x the rate card (plus the flat
    /// per-request fee x requests on the key bucket only - pure recompute, no spend cache), and
    /// admits ONLY if EVERY bucket is under its own cap (AND / most-restrictive). On admit, every
    /// bucket in the chain is charged one request in the SAME critical section - all-or-nothing;
    /// on any bucket over cap, NOTHING is charged and the blocking bucket is NAMED in the error.
    ///
    /// ATOMICITY: every involved shard lock is acquired in ASCENDING shard-index order before any
    /// check runs (a canonical order = deadlock-free), so N concurrent requests can never each read
    /// "under budget" and all charge. The single-bucket case (no budget group - the common fleet)
    /// degenerates to exactly the old one-shard critical section. Zero heap allocation on the
    /// admit path: the chain and the guard set live in fixed arrays; the rejection variant (cold)
    /// may allocate its group-name String.
    ///
    /// Residual (documented honestly): token cost is reconciled post-response (`record_usage`), so
    /// an admitted request's tokens are invisible to admissions that race it. The FEE component is
    /// hard (charged atomically at admission), but the token overshoot past a cap is bounded by
    /// the token cost of EVERY in-flight admitted request for the bucket (i.e. by the concurrency
    /// in flight when the cap is reached), not by a single request. A hard token cap would require
    /// reserving estimated tokens at admit time - out of scope, as with TPM.
    ///
    /// SYNCHRONOUS and INFALLIBLE (in-memory cells; no store round-trip, no await). The flat fee is
    /// charged HERE (as +1 request; spend derives), so the caller must NOT re-charge in `finish`;
    /// a non-2xx outcome refunds via [`GovState::refund_request`].
    pub(crate) fn try_charge_request_within_budget(
        &self,
        cost: &crate::cost::CostModel,
        key: &VirtualKey,
        now: u64,
    ) -> Result<(), BudgetBlocked> {
        let chain = match cost.chain_for(key) {
            Ok(c) => c,
            // FAIL-CLOSED: a key bound to a group this node's config does not know cannot be
            // admitted under the chain's caps, so it is not admitted at all.
            Err(missing) => return Err(BudgetBlocked::MissingGroup(missing.to_string())),
        };
        let fee = cost.price_per_request_cents();
        // FIRST-REQUEST GUARD: a flat fee that ALONE exceeds the key's whole cap can never be
        // admitted, even into a fresh window. (Group caps have no fee component.)
        if let Some(m) = key.max_budget_cents {
            if fee > m {
                return Err(BudgetBlocked::Key);
            }
        }

        // Acquire every involved shard's write lock in ASCENDING shard order (dedup) - fixed-size
        // scratch, no heap. `guard_slot[i]` = the position in `guards` holding bucket i's shard.
        let mut shard_idx = [0usize; crate::cost::MAX_CHAIN];
        let mut n = 0usize;
        for bucket in chain.iter() {
            shard_idx[n] = self.budget.shard_index(bucket.bucket_id);
            n += 1;
        }
        let mut order: [usize; crate::cost::MAX_CHAIN] = shard_idx;
        order[..n].sort_unstable();
        let mut guards: [Option<std::sync::RwLockWriteGuard<'_, HashMap<String, BudgetCell>>>;
            crate::cost::MAX_CHAIN] = Default::default();
        let mut guard_shards = [usize::MAX; crate::cost::MAX_CHAIN];
        let mut g = 0usize;
        for &s in order[..n].iter() {
            if g > 0 && guard_shards[g - 1] == s {
                continue; // dedup: two buckets sharing a shard use one guard
            }
            let shard = self.budget.shard_at(s);
            // Amortized bounded eviction of stale cells, per acquired shard - identical rationale
            // to `check_rate` (POST-increment ticker; age-based, period-agnostic retain so no
            // still-current cell of ANY period is evicted; `window_start == 0` = the all-time
            // window, never aged out).
            let sweep_needed = shard
                .sweep_ticker
                .fetch_add(1, Ordering::Relaxed)
                .wrapping_add(1)
                .is_multiple_of(crate::limits::rate_sweep_interval());
            let mut map = shard.map.write().unwrap_or_else(|p| p.into_inner());
            if sweep_needed {
                let max_window = 31 * super::SECS_PER_DAY;
                map.retain(|_, c| {
                    c.window_start == 0 || c.window_start.saturating_add(max_window) > now
                });
            }
            guards[g] = Some(map);
            guard_shards[g] = s;
            g += 1;
        }
        let guard_for = |shards: &[usize], target: usize| -> usize {
            shards[..g]
                .iter()
                .position(|&s| s == target)
                .expect("every bucket's shard was acquired")
        };

        // PASS 1 - CHECK every bucket under the held guards: resolve its cell for ITS OWN current
        // window (stale cells reset in place; missing cells read as empty) and derive spend. The
        // key bucket includes the flat fee (its prospective post-charge spend adds one more fee);
        // group buckets derive tokens-only and block when already at/over cap.
        for (bi, bucket) in chain.iter().enumerate() {
            let gi = guard_for(&guard_shards, shard_idx[bi]);
            let Some(cap) = bucket.max_budget_cents else {
                continue; // uncapped bucket never blocks
            };
            let window = budget_window(bucket.budget_period, now);
            let map = guards[gi].as_deref().expect("guard held");
            // Derive from the LIVE cell when it holds this window OR a NEWER one (the straddle:
            // `now` is the pinned `charged_at`, so a request admitted just before a boundary can
            // arrive after a concurrent admission already rolled the cell forward - its charge
            // lands on the live cell in PASS 2, so the check must read that same cell's spend,
            // never treat it as a fresh window). Only a genuinely STALE (older-window) or absent
            // cell reads as zero spend.
            let derived = match map.get(bucket.bucket_id) {
                Some(cell) if cell.window_start >= window => {
                    cost.derive_spend_cents(cell.model_views(), cell.requests, bucket.is_key)
                }
                _ => 0, // stale or absent cell = fresh window = zero spend
            };
            let blocked = if bucket.is_key {
                derived.saturating_add(fee) > cap
            } else {
                derived >= cap
            };
            if blocked {
                return Err(match bucket.group_name {
                    None => BudgetBlocked::Key,
                    Some(name) => BudgetBlocked::Group(name.to_string()),
                });
            }
        }

        // PASS 2 - CHARGE every bucket (+1 request, dirty) under the SAME held guards: atomic
        // all-or-nothing with the checks above.
        for (bi, bucket) in chain.iter().enumerate() {
            let gi = guard_for(&guard_shards, shard_idx[bi]);
            let window = budget_window(bucket.budget_period, now);
            let map = guards[gi].as_deref_mut().expect("guard held");
            // STRADDLE-SAFE cell resolution (mirrors `accrue_bucket` / `add_rate_tokens`): reset
            // ONLY a genuinely stale cell (this window strictly newer). A cell holding the SAME or
            // a NEWER window is charged IN PLACE - rewinding a newer live cell to this request's
            // older `charged_at` window (the pre-fix `!=` arm) zeroed the live window's accrued
            // tokens/requests AND its flush baselines, wiping real spend at every window boundary
            // with a straddling admission. The µs-race residual: a straddle-charged fee whose
            // refund later arrives carrying the older window is dropped by `refund_bucket`
            // (bounded to one boundary-racing request; the safe direction - never a blind
            // decrement of another window's charge).
            let cell = match map.get_mut(bucket.bucket_id) {
                Some(c) if window > c.window_start => {
                    *c = BudgetCell::fresh(window);
                    c
                }
                Some(c) => c, // same window or straddle (cell newer) - charge the live cell
                None => map
                    .entry(bucket.bucket_id.to_string())
                    .or_insert_with(|| BudgetCell::fresh(window)),
            };
            cell.requests = cell.requests.saturating_add(1);
            cell.dirty = true;
        }
        Ok(())
    }

    /// Refund the request charged at admission across EVERY bucket of the key's chain, for a
    /// request that produced no usable upstream result (non-2xx). Keeps the flat-fee policy "bill
    /// 2xx only" intact (the fee derives from the request count, so -1 request = -1 fee on the key
    /// bucket). `now` MUST be the same `charged_at` epoch the admission charge used so the refund
    /// lands in the SAME window per bucket; a bucket whose window has rolled past is a no-op.
    /// Floored at 0 - a refund can never drive a counter negative.
    pub(crate) fn refund_request(&self, cost: &crate::cost::CostModel, key: &VirtualKey, now: u64) {
        let Ok(chain) = cost.chain_for(key) else {
            // The charge failed closed on a missing group, so nothing was charged; refund only the
            // key bucket defensively (it floors at 0 on a no-op).
            self.refund_bucket(&key.id, &key.budget_period, now);
            return;
        };
        for bucket in chain.iter() {
            self.refund_bucket(bucket.bucket_id, bucket.budget_period, now);
        }
    }

    fn refund_bucket(&self, bucket_id: &str, budget_period: &str, now: u64) {
        let window = budget_window(budget_period, now);
        let mut map = self.budget.write(bucket_id);
        if let Some(cell) = map.get_mut(bucket_id) {
            if cell.window_start == window {
                cell.requests = cell.requests.saturating_sub(1);
                cell.dirty = true;
            }
        }
    }

    /// WRITE-BEHIND flush of the dirty in-memory budget cells to the durable store — ADDITIVE, so
    /// the shared store reflects the TRUE FLEET TOTAL. Runs OFF the request hot path (the periodic
    /// flusher + the graceful-shutdown arm).
    ///
    /// Under each shard lock, snapshot every dirty cell's DELTA since its last acknowledged flush
    /// (current - flushed baseline) and clear its dirty flag; then OFF the lock, `add_usage`
    /// (atomic accumulate in the store) each delta and advance the cell's acked baseline on
    /// success. With N nodes sharing one store, each node's deltas SUM into the durable record —
    /// where the old absolute `put_usage` overwrite made the record whichever node flushed last.
    ///
    /// On a store error, log, RE-MARK the cell dirty, and do NOT advance the baseline, so the
    /// unacked delta is retried next tick (at-least-once: an ack lost after the write landed can
    /// double-count at most one flush interval — the honest trade for fleet additivity; the
    /// in-memory admission cap is unaffected). Snapshotting under the lock but writing off it keeps
    /// the hot-path lock hold O(dirty). Returns the number of cells flushed.
    pub(crate) fn flush_budgets(&self) -> usize {
        /// Clamp a u64 counter into the signed delta domain.
        fn signed(v: u64) -> i64 {
            i64::try_from(v).unwrap_or(i64::MAX)
        }
        /// One dirty cell's snapshot: the PER-MODEL TOKEN delta payload for `Store::add_usage`
        /// plus the current absolute counters that become the acked baseline on success. No dollar
        /// figure anywhere - only tokens + requests cross the wire.
        struct DirtySnap {
            bucket_id: String,
            window: u64,
            delta: UsageDelta,
            cur_requests: u64,
            cur_models: Vec<(std::sync::Arc<str>, TierTokens)>,
        }
        // Snapshot dirty cells across ALL shards and clear their flags. One shard is locked at a
        // time (the `write_all` iterator acquires each guard lazily), so a concurrent charge
        // blocks only on the single shard the snapshot currently holds, not the whole map.
        let mut dirty: Vec<DirtySnap> = Vec::new();
        for mut map in self.budget.write_all() {
            for (id, cell) in map.iter_mut() {
                if !cell.dirty {
                    continue;
                }
                let models: Vec<busbar_api::ModelTokensDelta> = cell
                    .models
                    .iter()
                    .filter_map(|m| {
                        let d = busbar_api::TierTokensDelta {
                            input: signed(m.cur.input) - signed(m.flushed.input),
                            output: signed(m.cur.output) - signed(m.flushed.output),
                            cache_read: signed(m.cur.cache_read) - signed(m.flushed.cache_read),
                            cache_write: signed(m.cur.cache_write) - signed(m.flushed.cache_write),
                        };
                        (!d.is_zero()).then(|| busbar_api::ModelTokensDelta {
                            model: m.model.to_string(),
                            tokens: d,
                        })
                    })
                    .collect();
                dirty.push(DirtySnap {
                    bucket_id: id.clone(),
                    window: cell.window_start,
                    delta: UsageDelta {
                        requests: signed(cell.requests) - signed(cell.flushed_requests),
                        models,
                    },
                    cur_requests: cell.requests,
                    cur_models: cell
                        .models
                        .iter()
                        .map(|m| (m.model.clone(), m.cur))
                        .collect(),
                });
                cell.dirty = false;
            }
        }
        let mut flushed = 0usize;
        for snap in dirty {
            let outcome = if snap.delta.is_zero() {
                // Nothing new since the last acked flush (e.g. a charge fully refunded back to the
                // baseline): the durable record is already correct; skip the store round-trip.
                Ok(())
            } else {
                self.store
                    .add_usage(&snap.bucket_id, snap.window, &snap.delta)
            };
            match outcome {
                Ok(()) => {
                    flushed += 1;
                    // Advance the acked baselines - only if the cell still holds the SAME window
                    // (a rollover since the snapshot reset the cell; its zeroed baselines are
                    // already correct for the new window).
                    let mut map = self.budget.write(&snap.bucket_id);
                    if let Some(cell) = map.get_mut(&snap.bucket_id) {
                        if cell.window_start == snap.window {
                            cell.flushed_requests = snap.cur_requests;
                            for (model, cur) in &snap.cur_models {
                                if let Some(mc) = cell.models.iter_mut().find(|m| m.model == *model)
                                {
                                    mc.flushed = *cur;
                                }
                            }
                        }
                    }
                }
                Err(e) => {
                    tracing::warn!(bucket = %snap.bucket_id, error = %e, "budget flush failed; will retry next tick");
                    // RE-MARK dirty so the delta is not lost — only if the cell still exists for
                    // the SAME window (after a rollover the old window's unacked delta is dropped
                    // with the cell, exactly as the pre-additive flusher behaved).
                    let mut map = self.budget.write(&snap.bucket_id);
                    if let Some(cell) = map.get_mut(&snap.bucket_id) {
                        if cell.window_start == snap.window {
                            cell.dirty = true;
                        }
                    }
                }
            }
        }
        flushed
    }

    pub(crate) fn load(store: &dyn Store) -> StoreResult<HashMap<String, Arc<VirtualKey>>> {
        // Wrap each key in `Arc` at load time so the per-request `lookup` on the hot path is a
        // refcount bump, not a deep clone; the values are immutable until the next `refresh` swap.
        Ok(store
            .list_keys()?
            .into_iter()
            .map(|k| (k.key_hash.clone(), Arc::new(k)))
            .collect())
    }

    /// Build the AccessKeyId → resolved-credential index from the durable `aws_credentials` table,
    /// joined against the already-loaded `by_hash` snapshot (which holds the live `VirtualKey` rows).
    /// A credential whose owning key is missing from `by_hash` (e.g. the key row was deleted but a
    /// credential row lingered) is SKIPPED — it can never authenticate, since there is no key to attach
    /// a `GovCtx` for. `access_key_id` is the PRIMARY KEY of `aws_credentials`, so entries are unique.
    pub(crate) fn load_by_access_key_id(
        store: &dyn Store,
        by_hash: &HashMap<String, Arc<VirtualKey>>,
    ) -> StoreResult<HashMap<String, AwsKeyEntry>> {
        // Index the live keys by id for the join (by_hash is keyed by key_hash, not id).
        let by_id: HashMap<&str, &VirtualKey> = by_hash
            .values()
            .map(|k| (k.id.as_str(), k.as_ref()))
            .collect();
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
    /// Returns a SHARED `Arc<VirtualKey>` — the clone is a refcount bump, not a deep copy of the key's
    /// `String` fields (the per-request bearer resolution on the chat hot path).
    pub(crate) fn lookup(&self, secret: &str) -> Option<Arc<VirtualKey>> {
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

    /// Direct handle to the backing store — for tests that seed/inspect persistence AND for the boot
    /// audit wiring (the durable audit sink + restore read the configured governance store).
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
