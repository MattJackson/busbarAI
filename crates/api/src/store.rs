// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The durable-store CONTRACT — the data types a `db` plugin (SQLite built-in, Postgres, Redis, …)
//! reads and writes. The `Store` trait itself and its error type join this module in a following
//! step; this file holds the plain records that cross the seam, so a plugin crate can name them
//! without depending on the engine.
//!
//! These are the same records the admin API and governance enforcement speak, moved here so the
//! contract — not the engine — owns them. No I/O, no engine state: pure data.

/// A virtual key issued by busbar (distinct from upstream provider keys). Maps a caller to the
/// pools they may use plus their budget/rate-limit policy.
#[derive(Clone, PartialEq)]
pub struct VirtualKey {
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
pub struct AwsCredential {
    /// The plaintext AccessKeyId carried in the inbound SigV4 `Authorization` header (not secret).
    pub access_key_id: String,
    /// The owning `VirtualKey.id`.
    pub key_id: String,
    /// The symmetric SigV4 secret access key — SECRET-EQUIVALENT (never log it).
    pub secret_access_key: String,
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
pub struct AwsKeyEntry {
    pub key: VirtualKey,
    /// The symmetric SigV4 secret access key — SECRET-EQUIVALENT (never log it).
    pub secret_access_key: String,
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
pub struct Usage {
    pub spend_cents: i64,
    pub tokens: u64,
    pub requests: u64,
}

/// One per-(key, model, provider) metering accumulation from a completed response — RAW consumption
/// counts, never money. Spend is DERIVED at read time from the operator's configured prices, and a
/// third party with its own (special/negotiated) price catalog reconstructs cost from these counts:
/// input, output, cache-read, and cache-creation tokens all price differently, so each is carried
/// separately (design: expose the inputs of the cost computation, not just busbar's own result).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MeteringDelta {
    pub key_id: String,
    /// The UTC-day bucket this response is attributed to; derived from the request's pinned
    /// header-arrival epoch, same as the budget charges.
    pub bucket: u64,
    /// The SERVING lane's configured model name (post-failover — the lane that actually answered).
    pub model: String,
    /// The serving lane's provider name.
    pub provider: String,
    /// Uncached input tokens (the normalized additive-cache convention, per `billing::TokenUsage`).
    pub tokens_input: u64,
    pub tokens_output: u64,
    pub tokens_cache_read: u64,
    pub tokens_cache_creation: u64,
}

/// One accumulated metering row read back for a bucket (the raw material of `GET usage` by_model /
/// by_key aggregations — the service aggregates in memory; buckets are bounded by (keys × models)).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MeteringRow {
    pub key_id: String,
    pub model: String,
    pub provider: String,
    pub tokens_input: u64,
    pub tokens_output: u64,
    pub tokens_cache_read: u64,
    pub tokens_cache_creation: u64,
    pub requests: u64,
}

/// The result type every `Store` method returns.
pub type StoreResult<T> = Result<T, StoreError>;

/// A durable-store failure, carried as a human-readable message. Deliberately backend-agnostic: a
/// plugin converts its own driver error (rusqlite, a Postgres driver, …) into this at the seam, so
/// this contract crate stays free of any storage dependency. The message must never carry a secret.
#[derive(Debug)]
pub struct StoreError(pub String);

impl std::fmt::Display for StoreError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "store error: {}", self.0)
    }
}
impl std::error::Error for StoreError {}

impl From<String> for StoreError {
    fn from(s: String) -> Self {
        StoreError(s)
    }
}
impl From<&str> for StoreError {
    fn from(s: &str) -> Self {
        StoreError(s.to_string())
    }
}

/// The durable governance store — the `db` plugin contract. A backend (the built-in `SqliteStore`,
/// or a plugin `PostgresStore`/`RedisStore`/…) implements this to persist the bounded ENFORCEMENT
/// state: virtual keys + AWS credentials, and per-key usage counters per budget window.
///
/// The engine keeps the AUTHORITATIVE enforcement counters in memory and treats this store as a
/// write-behind durability layer (boot-hydrate + periodic flush), so every method here is off the
/// request hot path — a plain synchronous call is fine, and a backend that needs async I/O runs it
/// on its own runtime behind the sync signature. The four AWS-credential methods are DEFAULTED so a
/// backend with no SigV4 support (or a lightweight test double) need not implement them.
pub trait Store: Send + Sync + 'static {
    fn put_key(&self, key: &VirtualKey) -> StoreResult<()>;
    fn get_key(&self, id: &str) -> StoreResult<Option<VirtualKey>>;
    fn list_keys(&self) -> StoreResult<Vec<VirtualKey>>;
    fn delete_key(&self, id: &str) -> StoreResult<()>;
    fn get_usage(&self, key_id: &str, window_start: u64) -> StoreResult<Usage>;

    /// Write-behind ABSOLUTE set of a key's window counter (memory is authoritative). SETS (not adds)
    /// spend/tokens/requests to the given values. Used only by the budget flusher.
    fn put_usage(
        &self,
        key_id: &str,
        window_start: u64,
        spend_cents: i64,
        tokens: u64,
        requests: u64,
    ) -> StoreResult<()>;

    /// Accumulate one completed response's RAW consumption into the per-(key, bucket, model,
    /// provider) metering row (UPSERT/add; +1 request). Metering is observability — best-effort,
    /// never consulted for enforcement.
    fn add_metering(&self, delta: &MeteringDelta) -> StoreResult<()>;

    /// Every metering row accumulated in `bucket` (a metering-bucket day start), for the usage read's
    /// by-model / by-key aggregations.
    fn list_metering(&self, bucket: u64) -> StoreResult<Vec<MeteringRow>>;

    /// Persist an AWS-style credential (the MinIO/S3-compatible model) for inbound SigV4 verification.
    /// UPSERTs on the `access_key_id` PRIMARY KEY. The `secret_access_key` is the symmetric SigV4
    /// signing secret stored in plaintext (HMAC verification needs the same value the client signs
    /// with); callers must never log it.
    ///
    /// DEFAULTED so the (many) lightweight test-double stores need not implement the AWS surface —
    /// only a real backend does. The default is a no-op-shaped error so a misconfigured store that
    /// silently dropped a credential cannot pass as success.
    fn put_aws_credential(&self, _cred: &AwsCredential) -> StoreResult<()> {
        Err(StoreError(
            "this Store does not support AWS credentials".to_string(),
        ))
    }

    /// ATOMIC key+credential mint. Persist the bearer `VirtualKey` row AND its paired `AwsCredential`
    /// row together or not at all. A real transactional backend overrides this to wrap both writes in
    /// one transaction. DEFAULT fallback: sequential writes (for test doubles with no transaction).
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
    /// DEFAULTED to an empty list: a store with no AWS-credential support simply has none to index, so
    /// SigV4 ingress is unavailable — never an auth bypass.
    fn list_aws_credentials(&self) -> StoreResult<Vec<AwsCredential>> {
        Ok(Vec::new())
    }
}
