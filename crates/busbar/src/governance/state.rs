use super::*;

impl GovState {
    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn new(store: Arc<dyn Store>, admin_token: Option<String>) -> StoreResult<Self> {
        Self::new_with_signer(store, admin_token, None)
    }

    /// Construct a `GovState` with an optional TOKEN SIGNER (1.5.0 signed-token keys). `Some` at
    /// boot (a signing key resolved from `auth.signing_key` or generated on first boot); `None` in
    /// tests that exercise the SigV4/legacy-hash paths only. Hydrates the revocation denylist set
    /// from the store so a restart resumes with every revoked subject still denied.
    pub(crate) fn new_with_signer(
        store: Arc<dyn Store>,
        admin_token: Option<String>,
        signer: Option<crate::governance::signing::TokenSigner>,
    ) -> StoreResult<Self> {
        let by_hash = Self::load(store.as_ref())?;
        let by_access_key_id = Self::load_by_access_key_id(store.as_ref(), &by_hash)?;
        let verifier = signer
            .as_ref()
            .map(|s| crate::governance::signing::TokenVerifier::single(s.kid(), s.verifying_key()));
        // Hydrate the denylist. A store with no denylist support returns empty (nothing revoked);
        // a durable one returns every persisted revoked subject.
        let denylist: std::collections::HashSet<String> =
            store.list_denylist()?.into_iter().collect();
        Ok(Self {
            store,
            caches: RwLock::new(GovCaches {
                by_hash,
                by_access_key_id,
            }),
            concurrent: RwLock::new(HashMap::new()),
            admin_token_hash: admin_token
                .as_ref()
                .map(|t| crate::sigv4::sha256_hex(t.as_bytes())),
            budget: Sharded::new(),
            signer,
            verifier,
            denylist: RwLock::new(denylist),
        })
    }

    /// Whether signed-token minting is available (a signing key was resolved at boot).
    pub(crate) fn signing_enabled(&self) -> bool {
        self.signer.is_some()
    }

    /// VERIFY a presented signed token (1.5.0): signature + expiry (stateless) + the `sub` not on
    /// the revocation denylist, then resolve the policy binding by `sub`. Returns the bound
    /// `VirtualKey` (the binding record: id/group/allowed_pools/labels; no inline limits) on
    /// success. `None` = not a valid+authorized busbar token OR no signer configured OR the sub
    /// resolves to no binding (a token for a deleted key). The distinction is logged, never
    /// surfaced (no enumeration oracle - the auth path maps every `None` to one opaque 401).
    pub(crate) fn verify_token(&self, token: &str, now: u64) -> Option<Arc<VirtualKey>> {
        let verifier = self.verifier.as_ref()?;
        let claims = match verifier.verify(token, now) {
            Ok(c) => c,
            Err(e) => {
                tracing::debug!(reason = %e, "signed-token verify rejected");
                return None;
            }
        };
        // Revocation: the ONE state read on the otherwise-stateless path.
        if self
            .denylist
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .contains(&claims.sub)
        {
            tracing::debug!(sub = %claims.sub, "signed-token rejected: subject is revoked");
            return None;
        }
        // Resolve policy by `sub` (the key id). The binding lives in the `by_sub` index.
        match self.lookup_by_sub(&claims.sub) {
            Some(key) if key.enabled => Some(key),
            _ => {
                tracing::debug!(sub = %claims.sub, "signed-token subject has no enabled binding");
                None
            }
        }
    }

    /// Resolve a policy binding by its subject id (the key id / token `sub`). O(1) index read.
    pub(crate) fn lookup_by_sub(&self, sub: &str) -> Option<Arc<VirtualKey>> {
        self.caches_read()
            .by_hash
            .values()
            .find(|k| k.id == sub)
            .cloned()
    }

    /// REVOKE a signed-token key by subject id: persist to the store denylist AND update the
    /// in-memory set so the next verify rejects it immediately. Idempotent. A store-write failure
    /// is propagated (a revoke that did not durably persist must FAIL LOUD, never report success -
    /// a "revoked" token still valid after a restart is a security hole).
    pub(crate) fn revoke(&self, sub: &str, reason: &str) -> StoreResult<()> {
        self.store.add_denylist(sub, reason)?;
        self.denylist
            .write()
            .unwrap_or_else(|e| e.into_inner())
            .insert(sub.to_string());
        Ok(())
    }

    /// Whether `sub` is currently revoked (for the admin read / tests).
    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn is_revoked(&self, sub: &str) -> bool {
        self.denylist
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .contains(sub)
    }

    /// MINT a signed-token key (1.5.0): persist the policy BINDING row (subject id -> group,
    /// allowed_pools, labels; NO inline limits - keys are pure auth) and issue a busbar-SIGNED
    /// token `{sub, exp, kid}` for it. Returns `(binding, token)`; the token is shown ONCE. The
    /// subject id is a fresh unguessable `vk_<hex>` from the OS CSPRNG (its own bucket namespace).
    /// FAIL-CLOSED: no signer configured is an error (a key with no token is useless).
    pub(crate) fn mint_signed(
        &self,
        spec: NewKeySpec,
        exp: u64,
        now: u64,
    ) -> StoreResult<(VirtualKey, String)> {
        let Some(signer) = self.signer.as_ref() else {
            return Err(StoreError(
                "signed-token minting is unavailable: no signing key is configured".to_string(),
            ));
        };
        // A fresh random subject id (256-bit CSPRNG draw -> `vk_<16 hex>`). Unlike the legacy hash
        // path, the id is NOT derived from a secret (the token is the credential); it is a random
        // handle, so there is no id/hash prefix-collision hazard - but keep the `vk_` bucket
        // namespace so ledger/rate buckets stay consistent with the enforcement machinery.
        let mut raw = [0u8; 16];
        getrandom::fill(&mut raw).map_err(|e| StoreError(format!("CSPRNG unavailable: {e}")))?;
        let id = format!("{VK_ID_PREFIX}{}", hex::encode(raw));
        let binding = VirtualKey {
            id: id.clone(),
            // Not a credential: signed tokens are stateless. Kept non-empty + unique-per-key so a
            // durable store's UNIQUE(key_hash) constraint is satisfied; never used to authenticate.
            key_hash: format!("binding:{id}"),
            name: spec.name,
            // C6 intent carried intact from the mint body: None = all pools; Some([]) = none.
            allowed_pools: spec.allowed_pools,
            enabled: true,
            created_at: now,
            group: spec.group,
            labels: spec.labels,
        };
        self.store.put_key(&binding)?;
        self.refresh()?;
        let token = signer.mint(&id, exp);
        Ok((binding, token))
    }

    /// MINT a signed-token key that ALSO carries an AWS-style credential for inbound SigV4 (the
    /// MinIO/S3-compatible model). Persists the binding + AWS credential atomically and issues the
    /// signed token. Returns `(binding, token, aws_access_key_id, aws_secret_access_key)` - the
    /// token and the AWS secret are shown ONCE. See `mint_signed` for the binding shape.
    pub(crate) fn mint_signed_with_aws(
        &self,
        spec: NewKeySpec,
        exp: u64,
        now: u64,
    ) -> StoreResult<(VirtualKey, String, String, String)> {
        let Some(signer) = self.signer.as_ref() else {
            return Err(StoreError(
                "signed-token minting is unavailable: no signing key is configured".to_string(),
            ));
        };
        let mut raw = [0u8; 16];
        getrandom::fill(&mut raw).map_err(|e| StoreError(format!("CSPRNG unavailable: {e}")))?;
        let id = format!("{VK_ID_PREFIX}{}", hex::encode(raw));
        let access_key_id = generate_aws_access_key_id().store()?;
        let secret_access_key = generate_aws_secret_access_key().store()?;
        let binding = VirtualKey {
            id: id.clone(),
            key_hash: format!("binding:{id}"),
            name: spec.name,
            allowed_pools: spec.allowed_pools,
            enabled: true,
            created_at: now,
            group: spec.group,
            labels: spec.labels,
        };
        self.store.put_key_with_aws_credential(
            &binding,
            &AwsCredential {
                access_key_id: access_key_id.clone(),
                key_id: id.clone(),
                secret_access_key: secret_access_key.clone(),
            },
        )?;
        self.refresh()?;
        let token = signer.mint(&id, exp);
        Ok((binding, token, access_key_id, secret_access_key))
    }

    /// The signing key id (`kid`) this node stamps into minted tokens, if signing is enabled.
    pub(crate) fn signing_kid(&self) -> Option<&str> {
        self.signer.as_ref().map(|s| s.kid())
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
        // A missing group cannot block ACCRUAL (the request was already admitted/served);
        // degrade to the key-only bucket so the tokens are never lost.
        let chain = match cost.chain_for(key) {
            Ok(c) => c,
            Err(missing) => {
                tracing::warn!(key = %key.id, group = missing,
                    "group missing at accrual; tokens ledgered to the key bucket only");
                self.accrue_bucket(&key.id, super::WINDOW_TOTAL, model, tokens, now);
                return;
            }
        };
        for bucket in chain.iter() {
            self.accrue_bucket(bucket.bucket_id, bucket.window, model, tokens, now);
        }
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

    /// READ-ONLY limit headroom for a key: the fraction `[0.0, 1.0]` of the most-constrained
    /// `requests`/`tokens` limit across the key's GROUP CHAIN still available in each limit's own
    /// current window, where `1.0` is "fully unused" and `0.0` is "at the cap". `None` when the
    /// chain carries no requests/tokens limit (nothing to be near). The routing `usage` policy
    /// ranks by this (more headroom = preferred).
    ///
    /// This is a pure observation: it NEVER mutates a cell (no charge, no stale-reset, no sweep):
    /// `try_admit` owns all of that on the admission path. A stale (older-window) cell reads as
    /// fully-available for the current window, which is correct: its counters do not carry
    /// forward. The headroom is the MINIMUM across every windowed requests/tokens cap in the chain
    /// (the tightest constraint governs how close the key is to a 429).
    // Wired into production routing: `proxy engine::decide_policy_order` calls this on the key it
    // looked up (one lookup shared with the `send_user` identity projection) to produce the
    // per-lane `usage` signal; the in-crate tests also exercise it directly.
    pub(crate) fn rate_headroom(
        &self,
        cost: &crate::cost::CostModel,
        key: &VirtualKey,
        now: u64,
    ) -> Option<f64> {
        let chain = cost.chain_for(key).ok()?;
        let mut headroom: Option<f64> = None;
        for bucket in chain.iter() {
            if bucket.requests_cap.is_none() && bucket.tokens_cap.is_none() {
                continue;
            }
            let window = budget_window(bucket.window, now);
            // Counters for THIS window only; a stale (older-window) cell contributes zero usage.
            let (requests, tokens) = match self.budget.read(bucket.bucket_id).get(bucket.bucket_id)
            {
                Some(cell) if cell.window_start == window => (cell.requests, cell.total_tokens()),
                _ => (0, 0),
            };
            let frac = |used: u64, cap: u64| -> f64 {
                // `cap == 0` is a fully-closed limit: no headroom. Avoid a divide-by-zero.
                if cap == 0 {
                    0.0
                } else {
                    1.0 - (used as f64 / cap as f64)
                }
            };
            let mut h = f64::INFINITY;
            if let Some(cap) = bucket.requests_cap {
                h = h.min(frac(requests, cap));
            }
            if let Some(cap) = bucket.tokens_cap {
                h = h.min(frac(tokens, cap));
            }
            let h = h.clamp(0.0, 1.0);
            headroom = Some(headroom.map_or(h, |cur: f64| cur.min(h)));
        }
        headroom
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
    #[cfg_attr(not(test), allow(dead_code))]
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
            enabled: true,
            created_at: now,
            group: spec.group,
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
    #[cfg_attr(not(test), allow(dead_code))]
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
            enabled: true,
            created_at: now,
            group: spec.group,
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
    #[cfg_attr(not(test), allow(dead_code))]
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

    /// Apply a partial update to an existing key. Keys are PURE AUTH (S1), so the mutable surface
    /// is auth-shaped only: `enabled` (freeze/unfreeze the binding) and `group` (rebind the limit
    /// chain; three-state: absent = unchanged, `null` = unbind to unlimited, a value = rebind -
    /// the caller validates the named group exists). `key_hash`/`name`/`allowed_pools`/
    /// `created_at` are preserved (the credential is never re-minted). Returns `Ok(None)` when the
    /// key does not exist (so the caller can 404), `Ok(Some(updated_metadata))` otherwise.
    pub(crate) fn update_key(
        &self,
        id: &str,
        enabled: Option<bool>,
        group: Option<Option<String>>,
    ) -> StoreResult<Option<VirtualKey>> {
        let Some(mut key) = self.store.get_key(id)? else {
            return Ok(None);
        };
        if let Some(e) = enabled {
            key.enabled = e;
        }
        // Outer `Some` = the field was present in the request; inner `None` (JSON null) unbinds.
        if let Some(g) = group {
            key.group = g;
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
        let key_buckets = keys.iter().map(|k| (k.id.as_str(), super::WINDOW_TOTAL));
        let group_buckets = cost
            .groups()
            .iter()
            .flat_map(|g| g.buckets.iter())
            .map(|b| (b.bucket_id.as_str(), b.window));
        for (bucket_id, period) in key_buckets.chain(group_buckets) {
            let window = budget_window(period, now);
            let ledger = self.store.get_usage(bucket_id, window)?;
            if ledger.requests == 0 && ledger.models.is_empty() {
                continue;
            }
            // A pre-split persisted row has `billable_requests == 0` but a nonzero `requests`
            // (the two counters were one field); seed billable from `requests` so its fee base is
            // not silently zeroed on the first post-upgrade boot.
            let billable = if ledger.billable_requests == 0 && ledger.requests > 0 {
                ledger.requests
            } else {
                ledger.billable_requests
            };
            let mut cell = BudgetCell::fresh(window);
            cell.requests = ledger.requests;
            cell.flushed_requests = ledger.requests;
            cell.billable_requests = billable;
            cell.flushed_billable_requests = billable;
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
            Some(_) => Ok(Some(self.derived_bucket_usage(
                cost,
                id,
                super::WINDOW_TOTAL,
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
                    // Fee derives from the BILLABLE (2xx-only) count; `requests` reports the
                    // admission count (the requests-limit truth).
                    spend_cents: cost.derive_spend_cents(
                        cell.model_views(),
                        cell.billable_requests,
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
                ledger.billable_requests,
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
            let window = budget_window(bucket.window, now);
            let spend_micros = {
                let map = self.budget.read(bucket.bucket_id);
                match map.get(bucket.bucket_id) {
                    Some(cell) if cell.window_start == window => {
                        cost.derive_spend_micros(cell.model_views(), cell.billable_requests, true)
                    }
                    _ => 0,
                }
            };
            let remaining_micros = bucket.budget_cap.map(|cap| {
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
                budget_period: bucket.window.to_string(),
            });
        }
        out
    }

    /// The in-flight gauge for `group`, materialised on first sight. Read-locked resolve on the
    /// hot path (an existing gauge mutates through the shared atomic); the write lock is taken
    /// only to insert a missing gauge (once per group per process lifetime).
    fn concurrent_gauge(&self, group: &str) -> Arc<std::sync::atomic::AtomicI64> {
        if let Some(g) = self
            .concurrent
            .read()
            .unwrap_or_else(|p| p.into_inner())
            .get(group)
        {
            return g.clone();
        }
        self.concurrent
            .write()
            .unwrap_or_else(|p| p.into_inner())
            .entry(group.to_string())
            .or_default()
            .clone()
    }

    /// TEST-ONLY: the current in-flight count for a group's `concurrent` gauge.
    #[cfg(test)]
    pub(crate) fn concurrent_in_flight(&self, group: &str) -> i64 {
        self.concurrent
            .read()
            .unwrap_or_else(|p| p.into_inner())
            .get(group)
            .map(|g| g.load(Ordering::Relaxed))
            .unwrap_or(0)
    }

    /// ATOMIC chain ADMISSION for the request path - the generic limit engine's hard-cap
    /// primitive (P4). Resolves the key's enforcement chain ([key attribution bucket] -> the bound
    /// group's window buckets -> parent's -> ... root) and admits ONLY if EVERY limit of EVERY
    /// group in the chain admits (AND / most-restrictive). Keys carry NO limits of their own; a
    /// key with no group is authed + unlimited (its 1-bucket chain has no caps).
    ///
    /// Order of enforcement:
    /// 1. `enabled: false` anywhere in the chain FREEZES it - rejected before anything is charged.
    /// 2. `concurrent` gauges (instantaneous): each capped group's gauge is compare-and-incremented
    ///    innermost-first; on any full gauge the already-taken holds are released and the request
    ///    is rejected naming that group. The holds ride the returned [`AdmitGrant`] (RAII release).
    /// 3. Windowed limits (`requests` / `tokens` / `budget`): every involved shard lock is
    ///    acquired in ASCENDING shard-index order (canonical = deadlock-free), every bucket is
    ///    CHECKED against each of its caps for its OWN current window, and only if all pass is
    ///    every bucket CHARGED one request in the SAME critical section - all-or-nothing. On any
    ///    blocked bucket NOTHING is charged, the concurrent holds are released, and the exact
    ///    blocking (group, metric, window) is named with a `Retry-After` for rolling windows.
    ///
    /// Metric semantics per bucket:
    /// - `requests`: precise - the +1 charge is synchronous with the check.
    /// - `tokens`: BEST-EFFORT (the old TPM posture) - tokens land post-response, so the cap
    ///   blocks the NEXT request once the ledgered total has crossed it; in-flight requests'
    ///   tokens are invisible to admissions racing them.
    /// - `budget`: derived at check time from the cell's token ledger x the current rate card,
    ///   PLUS the flat per-request fee x its request count; the prospective post-charge spend
    ///   (one more fee) must stay within the cap, and a bucket already at/over cap blocks. The
    ///   fee component is hard; token overshoot past a cap is bounded by the tokens of every
    ///   in-flight admitted request (as with TPM, a hard token cap would need admit-time
    ///   reservation - out of scope).
    ///
    /// SYNCHRONOUS and INFALLIBLE (in-memory cells; no store round-trip, no await). The flat fee
    /// is charged HERE (as +1 request per bucket; spend derives), so the caller must NOT re-charge
    /// in `finish`; a non-2xx outcome refunds via [`GovState::refund_request`]. Zero heap
    /// allocation on the admit path (fixed scratch arrays; the grant's gauge Vec is empty for the
    /// common no-concurrent-cap chain; the rejection variant (cold) allocates its group-name
    /// String).
    pub(crate) fn try_admit(
        &self,
        cost: &crate::cost::CostModel,
        key: &VirtualKey,
        now: u64,
    ) -> Result<AdmitGrant, LimitBlocked> {
        let chain = match cost.chain_for(key) {
            Ok(c) => c,
            // FAIL-CLOSED: a key bound to a group this node's config does not know cannot be
            // admitted under the chain's caps, so it is not admitted at all.
            Err(missing) => return Err(LimitBlocked::MissingGroup(missing.to_string())),
        };
        let groups = cost.groups();

        // 1. FREEZE check: any `enabled: false` group in the chain rejects (C10) - checked before
        // any gauge or charge so a frozen chain mutates nothing.
        for &gi in chain.group_indices() {
            if !groups[gi].enabled {
                return Err(LimitBlocked::Disabled(groups[gi].name.clone()));
            }
        }

        // 2. CONCURRENT holds, innermost-first. `fetch_update` is a CAS loop: the increment lands
        // only while strictly under the cap, so N racing admissions can never jointly overshoot.
        // On a full gauge, roll back the holds already taken (the grant drop) and name the group.
        let mut grant = AdmitGrant::default();
        for &gi in chain.group_indices() {
            let Some(cap) = groups[gi].concurrent_cap else {
                continue;
            };
            let gauge = self.concurrent_gauge(&groups[gi].name);
            let cap = i64::try_from(cap).unwrap_or(i64::MAX);
            let admitted = gauge
                .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |v| {
                    (v < cap).then_some(v + 1)
                })
                .is_ok();
            if !admitted {
                drop(grant); // release the holds taken so far
                return Err(LimitBlocked::Limit {
                    group: groups[gi].name.clone(),
                    metric: "concurrent",
                    window: None,
                    retry_after: None,
                });
            }
            grant.gauges.push(gauge);
        }

        // 3. WINDOWED limits: acquire every involved shard's write lock in ASCENDING shard order
        // (dedup) - scratch sized by the chain actually resolved. `guard_shards[j]` = the shard
        // whose guard sits at position j in `guards`.
        let fee = cost.price_per_request_cents();
        let n = chain.len();
        let mut shard_idx: Vec<usize> = Vec::with_capacity(n);
        for bucket in chain.iter() {
            shard_idx.push(self.budget.shard_index(bucket.bucket_id));
        }
        let mut order = shard_idx.clone();
        order.sort_unstable();
        let mut guards: Vec<Option<std::sync::RwLockWriteGuard<'_, HashMap<String, BudgetCell>>>> =
            Vec::new();
        guards.resize_with(n, || None);
        let mut guard_shards = vec![usize::MAX; n];
        let mut g = 0usize;
        for &sh in order.iter() {
            if g > 0 && guard_shards[g - 1] == sh {
                continue; // dedup: two buckets sharing a shard use one guard
            }
            let shard = self.budget.shard_at(sh);
            // Amortized bounded eviction of stale cells, per acquired shard - identical rationale
            // to the old rate-map sweep (POST-increment ticker; age-based, window-agnostic retain
            // so no still-current cell of ANY window is evicted; `window_start == 0` = the
            // all-time window, never aged out).
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
            guard_shards[g] = sh;
            g += 1;
        }
        let guard_for = |shards: &[usize], target: usize| -> usize {
            shards[..g]
                .iter()
                .position(|&sh| sh == target)
                .expect("every bucket's shard was acquired")
        };

        // PASS 1 - CHECK every bucket under the held guards: resolve its cell for ITS OWN current
        // window (missing/stale cells read as empty) and test each configured cap. The blocking
        // bucket is named exactly: (group, metric, window) + retry-after for a rolling window.
        for (bi, bucket) in chain.iter().enumerate() {
            if bucket.requests_cap.is_none()
                && bucket.tokens_cap.is_none()
                && bucket.budget_cap.is_none()
            {
                continue; // uncapped bucket (e.g. the key's attribution bucket) never blocks
            }
            let gi = guard_for(&guard_shards, shard_idx[bi]);
            let window = budget_window(bucket.window, now);
            let map = guards[gi].as_deref().expect("guard held");
            // Read the LIVE cell when it holds this window OR a NEWER one (the straddle: `now` is
            // the pinned `charged_at`, so a request admitted just before a boundary can arrive
            // after a concurrent admission already rolled the cell forward - its charge lands on
            // the live cell in PASS 2, so the check must read that same cell, never treat it as a
            // fresh window). Only a genuinely STALE (older-window) or absent cell reads as empty.
            let (requests, tokens, derived) = match map.get(bucket.bucket_id) {
                Some(cell) if cell.window_start >= window => (
                    cell.requests,
                    if bucket.tokens_cap.is_some() {
                        cell.total_tokens()
                    } else {
                        0
                    },
                    if bucket.budget_cap.is_some() {
                        cost.derive_spend_cents(cell.model_views(), cell.billable_requests, true)
                    } else {
                        0
                    },
                ),
                _ => (0, 0, 0), // stale or absent cell = fresh window = nothing used
            };
            let blocked_metric = if bucket
                .requests_cap
                .is_some_and(|cap| requests.saturating_add(1) > cap)
            {
                Some("requests")
            } else if bucket.tokens_cap.is_some_and(|cap| tokens >= cap) {
                Some("tokens")
            } else if bucket
                .budget_cap
                .is_some_and(|cap| derived >= cap || derived.saturating_add(fee) > cap)
            {
                Some("budget")
            } else {
                None
            };
            if let Some(metric) = blocked_metric {
                drop(guards); // release the shard locks before the (cold) rejection build
                drop(grant); // release the concurrent holds - nothing was admitted
                return Err(LimitBlocked::Limit {
                    group: bucket
                        .group_name
                        .expect("only group buckets carry caps")
                        .to_string(),
                    metric,
                    window: Some(bucket.window),
                    retry_after: super::window_end(bucket.window, now)
                        .map(|end| end.saturating_sub(now).max(1)),
                });
            }
        }

        // PASS 2 - CHARGE every bucket (+1 request, dirty) under the SAME held guards: atomic
        // all-or-nothing with the checks above. STRADDLE-SAFE cell resolution (mirrors
        // `accrue_bucket`): reset ONLY a genuinely stale cell (this window strictly newer); a cell
        // holding the SAME or a NEWER window is charged IN PLACE.
        for (bi, bucket) in chain.iter().enumerate() {
            let gi = guard_for(&guard_shards, shard_idx[bi]);
            let window = budget_window(bucket.window, now);
            let map = guards[gi].as_deref_mut().expect("guard held");
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
            cell.billable_requests = cell.billable_requests.saturating_add(1);
            cell.dirty = true;
        }
        Ok(grant)
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
            self.refund_bucket(&key.id, super::WINDOW_TOTAL, now);
            return;
        };
        for bucket in chain.iter() {
            self.refund_bucket(bucket.bucket_id, bucket.window, now);
        }
    }

    fn refund_bucket(&self, bucket_id: &str, budget_period: &str, now: u64) {
        let window = budget_window(budget_period, now);
        let mut map = self.budget.write(bucket_id);
        if let Some(cell) = map.get_mut(bucket_id) {
            if cell.window_start == window {
                // Refund ONLY the billable (fee-base) counter - the flat fee bills 2xx only. The
                // admission `requests` counter is NEVER refunded, so a failed request still
                // consumed its requests-limit slot (a caller cannot escape the requests cap by
                // hammering failures).
                cell.billable_requests = cell.billable_requests.saturating_sub(1);
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
            cur_billable_requests: u64,
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
                        billable_requests: signed(cell.billable_requests)
                            - signed(cell.flushed_billable_requests),
                        models,
                    },
                    cur_requests: cell.requests,
                    cur_billable_requests: cell.billable_requests,
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
                            cell.flushed_billable_requests = snap.cur_billable_requests;
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
