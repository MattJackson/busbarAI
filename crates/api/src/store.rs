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
