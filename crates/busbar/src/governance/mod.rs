// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Governance persistence. A durable `Store` seam — SEPARATE from the hot in-memory `StateStore`
//! (breaker/lane health) — holding only bounded ENFORCEMENT state: virtual keys + config, and
//! per-key usage counters (spend/tokens/requests) per budget window. Historical request logs are
//! NOT stored here (they go to the observability pipeline). The `Store` CONTRACT lives in
//! `busbar-api`; the DEFAULT backend is the in-memory `MemoryStore` (ephemeral, zero-setup), with
//! `SqliteStore` (durable) and future backends as swappable plugin crates chosen by `store.module`.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, RwLock};

/// Seconds in a UTC day, for `budget_window`'s day/month arithmetic. `pub(crate)` so cross-module
/// TEST code can reference it as `crate::governance::SECS_PER_DAY`; production modules that need the
/// same value independently (e.g. `sigv4.rs`) keep a private copy where layering prohibits importing
/// it for a one-line constant.
pub(crate) const SECS_PER_DAY: u64 = 86_400;

// ── Window sentinel tokens (C8 nouns; matched in `budget_window`). The SAME strings are the
// `groups:` config vocabulary (`per: minute|hour|day|month|total`), the ledger-bucket window
// suffix, and the metrics/error dimension - one vocabulary everywhere. ─────────────────────────────
/// The "all-time" window sentinel: a single window from epoch 0.
pub(crate) const WINDOW_TOTAL: &str = "total";
/// The "day" window sentinel: resets at UTC midnight.
pub(crate) const WINDOW_DAY: &str = "day";
/// The "month" window sentinel: resets at UTC first-of-month.
pub(crate) const WINDOW_MONTH: &str = "month";
/// The "minute" window sentinel: resets each UTC minute.
pub(crate) const WINDOW_MINUTE: &str = "minute";
/// The "hour" window sentinel: resets each UTC hour.
pub(crate) const WINDOW_HOUR: &str = "hour";

// ── Virtual-key / bearer-secret formats ──────────────────────────────────────────────────────────
/// The `"vk_"` prefix prepended to the 16-hex-char hash prefix to form a virtual-key id.
const VK_ID_PREFIX: &str = "vk_";
/// Number of hex characters from the SHA-256 hash used as the suffix of a virtual-key id.
#[cfg_attr(not(test), allow(dead_code))]
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
// via the store module's own `settings.busy_timeout_ms` (default 5000).

/// One model's in-cell token counters: the CURRENT tier tokens plus the last durably-ACKNOWLEDGED
/// (flushed) tier tokens - the additive-flush baseline, per model. The model name is an
/// `Arc<str>` interned ONCE per (bucket, model) on first sight (allocate-on-miss); the per-request
/// accrual after that is a linear scan over the few models the bucket actually used plus integer
/// adds - no hashing, no allocation.
#[derive(Clone)]
struct ModelCell {
    model: std::sync::Arc<str>,
    cur: busbar_api::TierTokens,
    flushed: busbar_api::TierTokens,
}

/// In-memory TOKEN-LEDGER cell for a bucket's CURRENT window - the AUTHORITATIVE hot-path
/// enforcement state. A bucket is a key's own budget bucket OR a budget-group bucket (same shape).
/// NO SPEND FIELD: dollars are derived at check time as `cell tokens x rate card` (+ the flat fee
/// x requests on the key bucket) - tokens are the only stored truth, so a rate-card correction
/// reprices everything on the next read with no data fix. The durable store is a write-behind
/// layer flushed off the request path. One cell per bucket (current window only; reset on
/// rollover), so growth is bucket-count-bounded (keys + group-window buckets).
#[derive(Clone, Default)]
struct BudgetCell {
    window_start: u64,
    /// ADMISSION count: incremented once per admitted request, NEVER refunded. This backs the
    /// `requests`-LIMIT metric, so a caller cannot escape the requests cap by hammering failing
    /// requests (each still consumed a request slot at admission).
    requests: u64,
    /// BILLABLE request count: admitted requests MINUS non-2xx refunds. This backs the flat
    /// per-request-FEE component of the `budget` metric (the fee bills 2xx only), so budget spend
    /// derives from this, never from `requests`. Charged with `requests` at admission; a non-2xx
    /// outcome decrements ONLY this via `refund_bucket`.
    billable_requests: u64,
    /// The last durably-acknowledged admission-request count - the additive-flush baseline. Each
    /// flush writes only the DELTA (current - flushed) via `Store::add_usage`, then advances the
    /// baselines on success, so a shared store accumulates the TRUE fleet total across nodes. On
    /// a failed flush the baseline does not advance and the cell is re-marked dirty, so the
    /// unacked delta is retried (at-least-once: an ack lost after the write landed can
    /// double-count at most one flush interval - documented).
    flushed_requests: u64,
    /// The billable-request flush baseline (twin of `flushed_requests` for the fee-base counter).
    flushed_billable_requests: u64,
    /// Per-(model, tier) token counters + flush baselines. Small Vec (the models this bucket
    /// actually used), scanned linearly.
    models: Vec<ModelCell>,
    dirty: bool,
}

impl BudgetCell {
    fn fresh(window_start: u64) -> Self {
        Self {
            window_start,
            ..Self::default()
        }
    }

    /// Accrue one response's tier tokens under `model`, interning the model name on first sight.
    fn accrue(&mut self, model: &str, t: &busbar_api::TierTokens) {
        let cell = match self.models.iter_mut().find(|m| &*m.model == model) {
            Some(m) => m,
            None => {
                // Allocate ONLY on the first sight of a (bucket, model) pair.
                self.models.push(ModelCell {
                    model: std::sync::Arc::from(model),
                    cur: busbar_api::TierTokens::default(),
                    flushed: busbar_api::TierTokens::default(),
                });
                self.models.last_mut().expect("just pushed")
            }
        };
        cell.cur.input = cell.cur.input.saturating_add(t.input);
        cell.cur.output = cell.cur.output.saturating_add(t.output);
        cell.cur.cache_read = cell.cur.cache_read.saturating_add(t.cache_read);
        cell.cur.cache_write = cell.cur.cache_write.saturating_add(t.cache_write);
    }

    /// Borrowed (model, current tokens) view for the spend derivation - the few multiply-adds the
    /// admission check runs.
    fn model_views(&self) -> impl Iterator<Item = (&str, &busbar_api::TierTokens)> {
        self.models.iter().map(|m| (&*m.model, &m.cur))
    }

    /// Total current tokens across models and tiers (the legacy scalar view for admin reads).
    fn total_tokens(&self) -> u64 {
        self.models
            .iter()
            .fold(0u64, |acc, m| acc.saturating_add(m.cur.total()))
    }
}

/// Why an admission was refused by the group limit chain - carried to ingress so the rejection
/// NAMES the exact blocking bucket (group + metric + window). Built only on the rejection path
/// (cold), so the owned Strings are off the admit hot path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum LimitBlocked {
    /// A specific limit bucket blocked: the owning group, the metric (`requests` | `tokens` |
    /// `budget` | `concurrent`), the window word (`None` for the instantaneous `concurrent`
    /// gauge), the pool scope (`Some` when a pool-qualified limit blocked - only that pool's
    /// traffic is capped), and - for a windowed limit - the seconds until its window rolls
    /// (`None` for `total`, which never rolls).
    Limit {
        group: String,
        metric: &'static str,
        window: Option<&'static str>,
        pool: Option<String>,
        /// For a BUDGET block whose limit declared `on_exhaust: downgrade`: the pool ingress
        /// should re-admit + dispatch through instead of refusing (§6c). `None` = block.
        downgrade_to: Option<String>,
        retry_after: Option<u64>,
    },
    /// A group in the chain is FROZEN (`enabled: false`): every request charging through it is
    /// rejected while its history is kept (C10).
    Disabled(String),
    /// The key names a `group` that does not exist in this node's config - FAIL-CLOSED
    /// (mint and boot validate this; it can only arise from a shared durable store whose keys
    /// reference a group another node's config no longer has).
    MissingGroup(String),
}

/// The in-flight HOLD an admission acquires on every `concurrent`-capped group in the key's chain.
/// RAII: dropping the grant releases the gauges, so the in-flight count can never leak - the grant
/// rides inside the request's `UsageSink` (dropped when the response stream completes / the request
/// context unwinds on any error path). The Vec is EMPTY (no allocation) for the common chain with
/// no concurrent caps.
#[derive(Default)]
pub(crate) struct AdmitGrant {
    gauges: Vec<Arc<std::sync::atomic::AtomicI64>>,
}

impl AdmitGrant {
    /// TEST-ONLY: how many gauges this grant holds.
    #[cfg(test)]
    pub(crate) fn held(&self) -> usize {
        self.gauges.len()
    }
}

impl Drop for AdmitGrant {
    fn drop(&mut self) {
        for g in &self.gauges {
            g.fetch_sub(1, Ordering::Relaxed);
        }
    }
}

impl std::fmt::Debug for AdmitGrant {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AdmitGrant")
            .field("gauges", &self.gauges.len())
            .finish()
    }
}

/// A derived (read-time) usage view for admin/metrics consumers: `spend_cents` is COMPUTED from
/// the token ledger x the current rate card at the moment of the read - never stored.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub(crate) struct DerivedUsage {
    pub(crate) spend_cents: i64,
    pub(crate) tokens: u64,
    pub(crate) requests: u64,
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

    /// The shard INDEX owning `key_id` - for the budget-chain charge, which must acquire SEVERAL
    /// shards' locks in ascending index order (a canonical order makes the multi-shard critical
    /// section deadlock-free).
    #[inline]
    fn shard_index(&self, key_id: &str) -> usize {
        (crate::store::fnv1a_u64(key_id) as usize) & (GOV_SHARDS - 1)
    }

    /// The shard at a known index (see [`Sharded::shard_index`]).
    #[inline]
    fn shard_at(&self, idx: usize) -> &MapShard<V> {
        &self.shards[idx]
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
    /// Per-GROUP in-flight gauges for the `concurrent` limit metric (instantaneous - no window).
    /// Keyed by group NAME (stable across config applies, while `CostModel` group indices are
    /// not); values are `Arc`ed atomics so an [`AdmitGrant`] holds its release handles without
    /// touching the map again. Read-locked on the hot path (atomics mutate through a shared ref);
    /// write-locked only to materialise a gauge on first sight.
    concurrent: RwLock<HashMap<String, Arc<std::sync::atomic::AtomicI64>>>,
    /// SHA-256 hex digest of the configured /admin bearer token, computed once at construction. The
    /// plaintext token is NOT retained — only its digest, which is all the constant-time compare on
    /// the /admin path needs (less plaintext secret held in memory). `None` = admin API disabled.
    admin_token_hash: Option<String>,
    /// AUTHORITATIVE in-memory TOKEN-LEDGER cells - the hard-cap admission state consulted (and
    /// charged) on the request hot path with NO await and NO store round-trip. Keyed by BUCKET id:
    /// a virtual key's id, or `group:<name>` for a budget-group bucket - key buckets and group
    /// buckets are the same machinery. One `BudgetCell` per bucket for its CURRENT window (reset on
    /// rollover), so the map is bucket-count-bounded (keys + group-window buckets). The durable store is a
    /// WRITE-BEHIND layer: `flush_budgets` pushes each dirty cell's per-model TOKEN deltas
    /// additively off the request path, and boot `hydrate_budgets` re-loads accrued ledgers so a
    /// restart forgets nothing. The atomic chain check-and-charge acquires every involved shard
    /// lock in ascending shard order (deadlock-free), so admission against the whole chain is one
    /// indivisible critical section per node.
    /// NOTE (perf, playbook): the old `token_spend_carry` sub-cent carry map is GONE - the ledger
    /// stores raw tokens and spend derives at read time, so there is no remainder to carry and no
    /// O(n) carry sweep to amortize.
    budget: Sharded<BudgetCell>,
    /// The busbar TOKEN SIGNER (1.5.0, S1/S2): mints signed `{sub, exp, kid}` key tokens. `Some`
    /// once a signing key is resolved/generated at boot; `None` in the (test) path that constructs
    /// GovState without signing (SigV4-only / legacy-hash tests).
    signer: Option<crate::governance::signing::TokenSigner>,
    /// The STATELESS token VERIFIER (public keyset). Verifies a presented token's signature + expiry
    /// before any store read; policy is then resolved by `sub`. `Some` iff `signer` is.
    verifier: Option<crate::governance::signing::TokenVerifier>,
    /// The revocation DENYLIST as an in-memory set of subject ids, hydrated from the store at boot
    /// and updated live on revoke. A verified token whose `sub` is present is rejected - the ONLY
    /// state the otherwise-stateless verify path reads. Under an `RwLock` (read on the hot path,
    /// write only on revoke).
    denylist: RwLock<std::collections::HashSet<String>>,
}

/// Parameters for minting a new virtual key (from the management API) - PURE AUTH (S1): identity,
/// pool grants, at most one group binding, labels. No limits: they live on the bound group.
pub(crate) struct NewKeySpec {
    pub(crate) name: String,
    /// Pool grants with the C6 intent carried intact: `None` = the mint body OMITTED
    /// `allowed_pools` = ALL pools; `Some(list)` = exactly those; `Some([])` = NO pools.
    pub(crate) allowed_pools: Option<Vec<String>>,
    /// Optional `groups:` binding (validated to exist at mint).
    pub(crate) group: Option<String>,
    /// Optional mint-time labels echoed onto metrics (never interpreted by enforcement).
    pub(crate) labels: std::collections::BTreeMap<String, String>,
}

pub(crate) mod signing;
mod state;

/// THE GOVERNANCE RE-KEY for a ROLE-CARRYING principal (an external auth module's verdict): a
/// synthesized `VirtualKey` built from the principal's roles under the identifying MODULE's
/// `role_bindings` table (S4: bindings are nested by module - `bindings` here is
/// `role_bindings.<identifying module>`; a role asserted by another module never rides it).
/// An SSO user and a virtual key then get identical enforcement (pool ACL, group limits, usage
/// attribution, the hook `send_user` projection) through identical code.
///
/// Fail-closed: `None` when no role of the principal is bound (an unbound role grants nothing),
/// or when the bound pool grants union to the EMPTY SET (C6: `allowed_pools: []` = NO pools).
/// Pool semantics per C6: a binding that OMITS `allowed_pools` grants ALL pools; lists union.
/// Limits come ONLY from the bound `group:` (keys/principals carry no inline caps); with several
/// bound groups the first in role order wins (one group per principal - the chain is a tree).
pub(crate) fn synthesize_principal_key(
    principal: &crate::auth::Principal,
    bindings: Option<&std::collections::BTreeMap<String, crate::config::RoleBindingCfg>>,
) -> Option<Arc<VirtualKey>> {
    // BUCKET-NAMESPACE GUARD (audit cost-1.5.0): the synthesized key's `id` becomes its LEDGER
    // BUCKET id, and group buckets live in the same store namespace as `group:<name>`. A
    // principal id (attacker-influenced at the IdP) literally starting with `group:` would alias a
    // group's cell - charging it, reading it, and corrupting group enforcement. Fail closed:
    // such a principal gets NO synthetic key (no data-plane access), never a colliding bucket.
    //
    // The SAME hazard applies to the `vk_` prefix: a real virtual key's id is `vk_<16 hex>` and is
    // its ledger/rate bucket id. An IdP subject shaped `vk_<...>` would alias a real virtual key's
    // ledger + rate bucket (charging/reading it, or riding its rate window). Reserve `vk_` too.
    if principal.id.starts_with(crate::cost::GROUP_BUCKET_PREFIX)
        || principal.id.starts_with(VK_ID_PREFIX)
    {
        tracing::warn!(
            principal = %principal.id,
            "refusing to synthesize a governance key: principal id collides with a reserved bucket \
             namespace (group: or vk_)"
        );
        return None;
    }
    let table = bindings?;
    let granting: Vec<&crate::config::RoleBindingCfg> = principal
        .roles
        .iter()
        .filter_map(|role| table.get(role))
        .collect();
    if granting.is_empty() {
        return None;
    }
    // Pool union under C6 semantics: OMITTED `allowed_pools` on any granting binding = ALL pools
    // (`None` in the runtime encoding too); an explicit list contributes its entries; an explicit
    // `[]` contributes nothing. An all-bindings-empty union = the EMPTY SET = no data-plane access
    // (fail closed: no key at all - nothing to admit).
    let mut pools: Vec<String> = Vec::new();
    let mut all_pools = false;
    for b in &granting {
        match b.allowed_pools.as_deref() {
            None => all_pools = true,
            Some(list) => {
                for p in list {
                    if !pools.contains(p) {
                        pools.push(p.clone());
                    }
                }
            }
        }
    }
    let allowed_pools = if all_pools {
        None // any omitted grant widens the union to ALL pools
    } else if pools.is_empty() {
        // Every granting binding said `allowed_pools: []` - the empty set. No access (C6).
        return None;
    } else {
        Some(pools)
    };
    // The bound group (first in role order). Group limits are enforced through the group chain;
    // the key itself carries NO inline caps (keys are pure auth).
    let group = granting.iter().find_map(|b| b.group.clone());
    Some(Arc::new(VirtualKey {
        id: principal.id.clone(),
        // NOT a credential hash — a marker. The synthetic key never authenticates anything (the
        // auth module already did); it exists purely to carry grants through enforcement.
        key_hash: format!("principal:{}", principal.id),
        name: principal
            .name
            .clone()
            .unwrap_or_else(|| principal.id.clone()),
        allowed_pools,
        enabled: true,
        created_at: 0,
        group,
        labels: std::collections::BTreeMap::new(),
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

/// Whether `key` may target `pool` (C6: an OMITTED grant = all pools; an explicit list is
/// exhaustive; an explicit `[]` = NO pools). Delegates to the contract crate's encoding.
pub(crate) fn pool_allowed(key: &VirtualKey, pool: &str) -> bool {
    key.pool_allowed(pool)
}

/// The epoch start of the window containing `now` for a given window word (C8 nouns): `total` = a
/// single all-time window (0); `day` = UTC midnight; `month` = UTC first-of-month.
pub(crate) fn budget_window(period: &str, now: u64) -> u64 {
    match period {
        WINDOW_MINUTE => now / 60 * 60,
        WINDOW_HOUR => now / 3600 * 3600,
        WINDOW_DAY => now / SECS_PER_DAY * SECS_PER_DAY,
        WINDOW_MONTH => {
            let days = (now / SECS_PER_DAY) as i64;
            let (y, m, _) = civil_from_days(days);
            (days_from_civil(y, m, 1) as u64) * SECS_PER_DAY
        }
        WINDOW_TOTAL => 0, // explicit all-time window (the documented sentinel)
        // An unrecognized window word can only arise from a corrupt/foreign store row (config
        // parse rejects it). Fail SAFE to the all-time window (0), the tightest enforcement,
        // never wider, with a diagnostic so the corruption is visible instead of silent.
        other => {
            tracing::warn!(
                window = other,
                "unrecognized limit window; enforcing as all-time ('total') window"
            );
            0
        }
    }
}

/// The epoch at which `period`'s window containing `now` ROLLS to the next window - the
/// `Retry-After` source for a windowed-limit rejection. `None` for `total` (never rolls) and for
/// an unrecognized word (backstopped to `total` above).
pub(crate) fn window_end(period: &str, now: u64) -> Option<u64> {
    match period {
        WINDOW_MINUTE => Some(now / 60 * 60 + 60),
        WINDOW_HOUR => Some(now / 3600 * 3600 + 3600),
        WINDOW_DAY => Some(now / SECS_PER_DAY * SECS_PER_DAY + SECS_PER_DAY),
        WINDOW_MONTH => {
            let days = (now / SECS_PER_DAY) as i64;
            let (y, m, _) = civil_from_days(days);
            let (ny, nm) = if m == 12 { (y + 1, 1) } else { (y, m + 1) };
            Some((days_from_civil(ny, nm, 1) as u64) * SECS_PER_DAY)
        }
        _ => None,
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
    AwsCredential, AwsKeyEntry, MeteringDelta, MeteringRow, Store, StoreError, StoreResult,
    TierTokens, UsageDelta, VirtualKey,
};
// The full-ledger record is consumed only by TEST assertions (production reads go through the
// derived views); scoping the re-export keeps the release build warning-free.
#[cfg(test)]
pub(crate) use busbar_api::UsageLedger;

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
    // SERIALIZE flushes: `flush_budgets` snapshots each dirty cell's DELTA against its acked
    // baseline and `add_usage`-accumulates it, advancing the baseline only on success. If a slow
    // flush outlasts a tick, a second concurrent flush would snapshot against the SAME un-advanced
    // baseline and re-send the first flush's still-in-flight delta - a durable DOUBLE-COUNT. A
    // single-permit async gate makes at most one flush in flight at a time: the periodic tick SKIPS
    // if a flush is still running (`try_lock`), and the shutdown arm WAITS for the in-flight flush to
    // drain (`lock().await`) before its final flush, so shutdown never overlaps and never loses the
    // last window's spend.
    let flush_gate = std::sync::Arc::new(tokio::sync::Mutex::new(()));
    tokio::spawn(async move {
        loop {
            tokio::select! {
                _ = tokio::time::sleep(interval) => {
                    // `flush_budgets` runs SYNCHRONOUS SQLite writes (store `*_inner` on a std Mutex);
                    // calling it inline here would block a Tokio worker thread for the duration of the
                    // durable write. Offload to the blocking pool so the async runtime keeps serving
                    // requests. `gov` is an Arc, so clone the handle into the blocking task; we do not
                    // await the join (write-behind is fire-and-forget - a store error re-marks the cell
                    // dirty and the next tick retries).
                    //
                    // SKIP-IF-STILL-FLUSHING: acquire the flush gate with `try_lock`; if a prior flush
                    // is still in flight, this tick is a no-op (its dirty cells stay dirty and the next
                    // free tick flushes them) rather than racing a second overlapping flush. The guard
                    // is moved INTO the blocking task and dropped when the flush returns, releasing the
                    // gate for the next tick.
                    let Ok(guard) = flush_gate.clone().try_lock_owned() else {
                        continue;
                    };
                    let gov = gov.clone();
                    tokio::task::spawn_blocking(move || {
                        gov.flush_budgets();
                        drop(guard);
                    });
                }
                _ = shutdown.recv() => {
                    // Graceful shutdown: one FINAL flush so no accrued spend/requests is lost, then exit.
                    // WAIT for any in-flight periodic flush to drain first (`lock().await`) so the final
                    // flush never overlaps one - otherwise the final flush's newer snapshot could be
                    // overwritten by the older in-flight flush completing after it. This one is AWAITED
                    // (via spawn_blocking + join) rather than fire-and-forget: the task is about to break
                    // and stop ticking, so the final durable write must COMPLETE before we exit or the
                    // last window's accrued spend is lost. It still runs on the blocking pool (not inline
                    // on the worker), and a join error falls back to nothing flushed - best-effort.
                    let guard = flush_gate.clone().lock_owned().await;
                    let gov = gov.clone();
                    let _ = tokio::task::spawn_blocking(move || {
                        gov.flush_budgets();
                        drop(guard);
                    })
                    .await;
                    break;
                }
            }
        }
    });
}

#[cfg(test)]
#[path = "tests/tests.rs"]
mod tests;

#[cfg(test)]
#[path = "tests/limits_tests.rs"]
mod limits_tests;
