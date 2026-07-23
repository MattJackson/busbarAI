// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The **Redis** backend for busbar's durable governance store - the shared, multi-node `db` plugin
//! over a KEY-VALUE data model. Implements `busbar_api::Store` on a mutex-guarded SYNCHRONOUS redis
//! connection, depending only on the `busbar-api` contract (plus the `redis` driver), never on the
//! engine.
//!
//! Redis has no tables, so the relational schema the SQLite/Postgres backends use is modeled in KV:
//!
//! - **virtual keys** - `busbar:key:<id>` holds the JSON [`VirtualKey`]; the set `busbar:keys` indexes
//!   every id so `list_keys` is a SMEMBERS + per-id GET.
//! - **AWS credentials** - `busbar:awscred:<access_key_id>` holds the JSON credential; `busbar:awscreds`
//!   indexes them; `busbar:awscred_ids:<key_id>` maps a virtual key to its AccessKeyIds so a key delete
//!   removes them (a revoked key's SigV4 credential must never outlive it - the same guarantee the SQL
//!   backends enforce with a `DELETE … WHERE key_id`).
//! - **token ledger** - `busbar:usage:<bucket_id>:<window_start>` is a HASH holding `requests` plus
//!   per-(model, tier) token fields `m:<model>:input|output|cache_read|cache_write`. `put_usage`
//!   replaces the hash with absolute values; `add_usage` HINCRBYs the signed deltas (the
//!   fleet-additive flush, so concurrent nodes accumulate instead of overwriting each other);
//!   `get_usage` HGETALLs and parses the model fields. NO spend field: dollars are derived at read
//!   time from `ledger x rate_card` in the engine. (Floor-at-zero parity note: the SQL backends
//!   floor each counter at 0 IN THE WRITE; HINCRBY has no atomic floor, so a transient negative is
//!   possible in the stored hash and is clamped to 0 ON READ - same observable floor.)
//! - **metering** - `busbar:metering:<bucket>` is a SET of row keys; each row is a HASH accumulated
//!   with HINCRBY (add), so concurrent responses accumulate without a read-modify-write race.
//! - **audit** - `busbar:audit` is a SORTED SET scored by `seq`, each member the JSON [`AuditRecord`].
//!
//! ## Atomicity
//!
//! Every MULTI-KEY write cascade runs as ONE atomic `MULTI`/`EXEC` pipeline
//! ([`redis::Pipeline::atomic`]): `put_key_with_aws_credential` (key + credential + all three
//! indexes) and the `delete_key` cascade (key row, key index, usage windows, credentials, credential
//! indexes). A mid-cascade failure therefore can NEVER orphan a SigV4 credential behind a deleted
//! key or publish a credential for a key that was not stored - the transactional parity of the SQL
//! backends' `BEGIN`/`COMMIT`.
//!
//! ## Connections, TLS, reconnect
//!
//! A single mutex-guarded synchronous connection used off the request hot path (key CRUD + the
//! write-behind usage flush). A DROPPED connection (server restart, idle timeout, network blip) is
//! transparently re-established: a READ / idempotent op retries exactly ONCE on a connection-level
//! error by reopening from the client before failing. A NON-IDEMPOTENT write cascade
//! (`add_usage`/`add_metering`: HINCRBY `MULTI`/`EXEC`) does NOT auto-retry - a lost-reply timeout
//! may have already committed the EXEC server-side, so a retry would double-apply the delta; instead
//! the error surfaces and the write-behind flusher re-derives the correct total from the baseline on
//! the next tick (exactly-once on error). `rediss://` URLs use TLS (rustls, ring provider, OS-native
//! roots). Error strings are SCRUBBED of the URL password before they leave this crate, so a
//! connection failure can never leak the secret into logs.
//!
//! ## Data growth (documented, deliberate)
//!
//! Rows are written WITHOUT a TTL: usage windows, metering buckets, and audit entries accumulate
//! unboundedly by design - the store is the durable system of record and busbar never silently
//! expires governance data. Operators who want bounded growth should reap old
//! `busbar:usage:*`/`busbar:metering:*` keys (or apply `EXPIRE` out-of-band) on their own retention
//! schedule; the audit zset should be archived, not expired.

use busbar_api::{
    AuditRecord, AwsCredential, MeteringDelta, MeteringRow, ModelTokens, Store, StoreError,
    StoreResult, TierTokens, UsageDelta, UsageLedger, VirtualKey,
};
use redis::{Commands, Connection};
use std::sync::Mutex;

// ── Key-space helpers (one namespace prefix so a Redis shared with other apps never collides) ──────
const KEY_PREFIX: &str = "busbar:key:";
const KEYS_INDEX: &str = "busbar:keys";
const AWSCRED_PREFIX: &str = "busbar:awscred:";
const AWSCRED_INDEX: &str = "busbar:awscreds";
const AWSCRED_IDS_PREFIX: &str = "busbar:awscred_ids:";
const AUDIT_ZSET: &str = "busbar:audit";
/// The schema-version marker key (mirrors the SQLite `PRAGMA user_version`). v2 = the 1.5.0
/// token-ledger cost model. A pre-v2 namespace is WIPED on connect (1.5.0 unreleased: bump, not
/// migrate).
const SCHEMA_KEY: &str = "busbar:schema";
const SCHEMA_VERSION: i64 = 2;

fn usage_key(bucket_id: &str, window_start: u64) -> String {
    format!("busbar:usage:{bucket_id}:{window_start}")
}

/// Hash field for one (model, tier) token counter: `m:<model>:<tier>`. Parsed with a RIGHT split on
/// the tier so a model name containing `:` still round-trips.
fn model_field(model: &str, tier: &str) -> String {
    format!("m:{model}:{tier}")
}

/// Parse a `m:<model>:<tier>` hash field back into `(model, tier)`.
fn parse_model_field(field: &str) -> Option<(&str, &str)> {
    field.strip_prefix("m:")?.rsplit_once(':')
}
fn metering_set(bucket: u64) -> String {
    format!("busbar:metering:{bucket}")
}
fn metering_row(bucket: u64, key_id: &str, model: &str, provider: &str) -> String {
    // `|` joins the composite row identity; it is not a legal character in a model/provider name in
    // practice, and even if present it only affects the row's own key (never cross-row correctness).
    format!("busbar:metering:{bucket}:{key_id}|{model}|{provider}")
}

/// Clamp a `u64` into `i64` for Redis integer ops (HINCRBY is signed) - a value above `i64::MAX` pins
/// to `i64::MAX`, never wraps. Mirrors the SQL backends.
fn clamp(v: u64) -> i64 {
    i64::try_from(v).unwrap_or(i64::MAX)
}

/// Read a signed counter back as a `u64`, clamping a (corrupt / direct-DB) negative to 0 instead of
/// wrapping via `as` - mirrors the SQL backends' DI-3 posture.
fn read_u64(v: i64) -> u64 {
    v.max(0) as u64
}

/// Extract the PASSWORD component from a redis URL (`redis://user:pass@host/...` or
/// `redis://:pass@host/...`), if any - the secret that must never appear in an error string.
fn url_password(url: &str) -> Option<String> {
    let rest = url.split("://").nth(1)?;
    let userinfo = rest.rsplit_once('@').map(|(u, _)| u)?;
    let pass = match userinfo.split_once(':') {
        Some((_, p)) => p,
        None => return None, // user only, no password
    };
    (!pass.is_empty()).then(|| pass.to_string())
}

/// Replace every occurrence of `secret` in `msg` with `<redacted>` - the password-in-error scrub.
fn scrub(msg: String, secret: Option<&str>) -> String {
    match secret {
        Some(s) if !s.is_empty() && msg.contains(s) => msg.replace(s, "<redacted>"),
        _ => msg,
    }
}

/// Is this a CONNECTION-LEVEL error worth one reconnect-and-retry (dropped socket, IO failure,
/// server going away) as opposed to a command/data error that would fail identically on a fresh
/// connection?
fn is_connection_error(e: &redis::RedisError) -> bool {
    e.is_io_error() || e.is_connection_dropped() || e.is_connection_refusal() || e.is_timeout()
}

/// Redis `Store` backend (durable, shared across a cluster). A single mutex-guarded synchronous
/// connection with one-shot reconnect - governance is off the request hot path, so serializing
/// access is fine.
pub struct RedisStore {
    client: redis::Client,
    /// The live connection, lazily (re)established. `None` after a detected drop.
    conn: Mutex<Option<Connection>>,
    /// The URL password (if any), scrubbed out of every error string this crate emits.
    secret: Option<String>,
}

impl RedisStore {
    /// Connect to Redis with the given URL (e.g. `redis://:pass@host:6379/0`, or
    /// `rediss://:pass@host:6380/0` for TLS via rustls + OS-native roots).
    pub fn connect(url: &str) -> StoreResult<Self> {
        let secret = url_password(url);
        // TLS (`rediss://`): the redis driver builds its rustls config against the PROCESS default
        // crypto provider. This crate can live inside a plugin cdylib with its own rustls state, so
        // install the ring provider here explicitly (idempotent; an already-installed provider wins).
        if url.starts_with("rediss://") {
            let _ = rustls::crypto::ring::default_provider().install_default();
        }
        let client = redis::Client::open(url)
            .map_err(|e| StoreError(scrub(e.to_string(), secret.as_deref())))?;
        let conn = client
            .get_connection()
            .map_err(|e| StoreError(scrub(e.to_string(), secret.as_deref())))?;
        let store = Self {
            client,
            conn: Mutex::new(Some(conn)),
            secret,
        };
        store.migrate()?;
        Ok(store)
    }

    /// SCHEMA-VERSION BUMP (v2, the 1.5.0 token-ledger cost model): a `busbar:*` namespace written
    /// by a pre-v2 build (no/older `busbar:schema` marker but governance keys present) is WIPED and
    /// re-marked - 1.5.0 is unreleased, so this is a bump, never a migration. A fresh namespace is
    /// simply marked; a v2 namespace passes through untouched.
    fn migrate(&self) -> StoreResult<()> {
        let version: i64 = self
            .with_conn(|c| c.get::<_, Option<i64>>(SCHEMA_KEY))?
            .unwrap_or(0);
        if version >= SCHEMA_VERSION {
            return Ok(());
        }
        let existing: Vec<String> = self.with_conn(|c| {
            c.scan_match::<_, String>("busbar:*")?
                .collect::<Result<Vec<String>, _>>()
        })?;
        if existing.is_empty() {
            // A fresh namespace: just mark it v2.
            return self.with_conn(|c| c.set::<_, _, ()>(SCHEMA_KEY, SCHEMA_VERSION));
        }
        // M2 (data-loss): the marker is absent (or pre-v2) but `busbar:*` DATA exists. The old code
        // WIPED the whole namespace unconditionally - so a marker EVICTED under `maxmemory
        // allkeys-*` (while the v2 data survived) destroyed a healthy database on the next boot.
        // Only wipe when LEGACY-SHAPED keys are actually present (a pre-v2 build's `busbar:usage:*`
        // HASH carried a `spend_cents` field that the v2 token-ledger shape never has). If data
        // exists but is NOT legacy-shaped and the marker is absent, we CANNOT prove it is safe to
        // wipe - REFUSE to boot loudly rather than silently destroy it.
        if !self.namespace_is_legacy_shaped(&existing)? {
            return Err(StoreError(format!(
                "redis: found {} busbar:* keys but no '{SCHEMA_KEY}' marker, and the data is NOT \
                 legacy (pre-1.5.0) shaped. Refusing to wipe a namespace that may be a healthy v2 \
                 database whose schema marker was evicted (e.g. under `maxmemory allkeys-*`). \
                 Restore the marker with `SET {SCHEMA_KEY} {SCHEMA_VERSION}` if this IS a v2 \
                 database, or clear the busbar:* namespace deliberately if it is not.",
                existing.len()
            )));
        }
        // Confirmed legacy: a bump-not-migrate wipe (1.5.0 is unreleased).
        self.with_conn(|c| {
            let mut pipe = redis::pipe();
            pipe.atomic();
            for k in &existing {
                pipe.del(k).ignore();
            }
            pipe.query::<()>(c)
        })?;
        self.with_conn(|c| c.set::<_, _, ()>(SCHEMA_KEY, SCHEMA_VERSION))
    }

    /// M2: is the `busbar:*` namespace shaped like a PRE-v2 (legacy 1.4.x) store? The distinguishing
    /// marker is a `busbar:usage:*` HASH carrying the legacy `spend_cents` field, which the v2
    /// token-ledger usage shape (`requests` + `m:<model>:<tier>`) never has. Returns true only when
    /// such a key is actually observed - so an ambiguous/unknown namespace is treated as NOT legacy
    /// (fail-closed: refuse to wipe rather than guess).
    fn namespace_is_legacy_shaped(&self, existing: &[String]) -> StoreResult<bool> {
        for k in existing {
            // Only usage hashes carried the legacy field; skip everything else quickly.
            if !k.starts_with("busbar:usage:") {
                continue;
            }
            let has_legacy: bool = self
                .with_conn(|c| c.hexists(k, "spend_cents"))
                .unwrap_or(false);
            if has_legacy {
                return Ok(true);
            }
        }
        Ok(false)
    }

    /// Run `f` against the live connection, transparently reconnecting ONCE on a connection-level
    /// error (dropped socket / IO / timeout). The single retry re-runs `f` on the fresh connection;
    /// a second failure (or any command-level error) surfaces, password-scrubbed.
    ///
    /// M3 (over-bill): the one-shot retry is SAFE ONLY for READ / idempotent ops. It is UNSAFE for a
    /// non-idempotent write cascade (`add_usage`/`add_metering` are HINCRBY MULTI/EXEC): a LOST-REPLY
    /// TIMEOUT means the EXEC may already have committed on the server, so re-running `f` would
    /// DOUBLE-APPLY the delta permanently (over-bill). Mutating cascades therefore use
    /// `with_conn_no_retry`, which returns the error so the write-behind flusher re-derives the
    /// correct total from the baseline on the next tick (exactly-once on error).
    fn with_conn<T>(
        &self,
        f: impl FnMut(&mut Connection) -> redis::RedisResult<T>,
    ) -> StoreResult<T> {
        self.run(f, true)
    }

    /// Like `with_conn` but with NO reconnect-retry - for non-idempotent write cascades where a
    /// lost-reply timeout must NOT be retried (see the M3 note on `with_conn`). A connection-level
    /// error surfaces so the caller (the flusher) re-derives from baseline instead of double-applying.
    fn with_conn_no_retry<T>(
        &self,
        f: impl FnMut(&mut Connection) -> redis::RedisResult<T>,
    ) -> StoreResult<T> {
        self.run(f, false)
    }

    /// Shared connection driver. `retry` gates the one-shot reconnect-and-retry (safe only for
    /// idempotent ops - see `with_conn`). Every operation in this crate funnels through here, so
    /// reconnect + scrub are uniform.
    fn run<T>(
        &self,
        mut f: impl FnMut(&mut Connection) -> redis::RedisResult<T>,
        retry: bool,
    ) -> StoreResult<T> {
        let mut guard = self.conn.lock().unwrap_or_else(|p| p.into_inner());
        // (Re)establish if the previous operation dropped the connection.
        if guard.is_none() {
            *guard = Some(
                self.client
                    .get_connection()
                    .map_err(|e| self.err(e, "reconnect"))?,
            );
        }
        let conn = guard.as_mut().expect("connection just ensured");
        match f(conn) {
            Ok(v) => Ok(v),
            Err(e) if retry && is_connection_error(&e) => {
                // Drop the dead connection and retry exactly once on a fresh one.
                *guard = None;
                let mut fresh = self
                    .client
                    .get_connection()
                    .map_err(|e2| self.err(e2, "reconnect after drop"))?;
                match f(&mut fresh) {
                    Ok(v) => {
                        *guard = Some(fresh);
                        Ok(v)
                    }
                    Err(e2) => Err(self.err(e2, "retry after reconnect")),
                }
            }
            Err(e) => {
                // A connection-level failure (retried or not) leaves the guard's connection suspect;
                // drop it so the NEXT op reconnects cleanly rather than reusing a dead socket.
                if is_connection_error(&e) {
                    *guard = None;
                }
                Err(self.err(e, "command"))
            }
        }
    }

    /// Map a redis error into the api error, scrubbing the URL password.
    fn err(&self, e: redis::RedisError, ctx: &str) -> StoreError {
        StoreError(scrub(format!("redis {ctx}: {e}"), self.secret.as_deref()))
    }
}

// `allowed_pools` encoding - identical to the SQL backends: the whole key rides as JSON, so pool
// names with commas are delimiter-safe.
fn key_to_json(key: &VirtualKey) -> StoreResult<String> {
    serde_json::to_string(key).map_err(|e| StoreError(format!("key encode failed: {e}")))
}
fn key_from_json(raw: &str) -> StoreResult<VirtualKey> {
    serde_json::from_str(raw).map_err(|e| StoreError(format!("key decode failed: {e}")))
}

impl Store for RedisStore {
    fn put_key(&self, key: &VirtualKey) -> StoreResult<()> {
        let json = key_to_json(key)?;
        // Row + index as ONE atomic MULTI/EXEC - a re-put is idempotent (SET overwrites, SADD is a
        // set member).
        self.with_conn(|c| {
            redis::pipe()
                .atomic()
                .set(format!("{KEY_PREFIX}{}", key.id), &json)
                .ignore()
                .sadd(KEYS_INDEX, &key.id)
                .ignore()
                .query(c)
        })
    }

    fn get_key(&self, id: &str) -> StoreResult<Option<VirtualKey>> {
        let raw: Option<String> = self.with_conn(|c| c.get(format!("{KEY_PREFIX}{id}")))?;
        raw.map(|r| key_from_json(&r)).transpose()
    }

    fn list_keys(&self) -> StoreResult<Vec<VirtualKey>> {
        let ids: Vec<String> = self.with_conn(|c| c.smembers(KEYS_INDEX))?;
        let mut out = Vec::with_capacity(ids.len());
        for id in ids {
            // A dangling index member (row removed out-of-band) is skipped, not an error.
            if let Some(raw) =
                self.with_conn(|c| c.get::<_, Option<String>>(format!("{KEY_PREFIX}{id}")))?
            {
                out.push(key_from_json(&raw)?);
            }
        }
        // Deterministic order (mirrors the SQL backends' ORDER BY created_at, then id as a tiebreak).
        out.sort_by(|a, b| {
            a.created_at
                .cmp(&b.created_at)
                .then_with(|| a.id.cmp(&b.id))
        });
        Ok(out)
    }

    fn delete_key(&self, id: &str) -> StoreResult<()> {
        // READ phase: collect everything the cascade must remove (usage windows via a non-blocking
        // SCAN; the key's AccessKeyIds via SMEMBERS). Reads are outside the transaction - the
        // in-memory engine is the sole writer for a key's lifecycle, and a concurrent write after
        // the read would at worst leave a benign dangling index member that list paths skip.
        let pattern = format!("busbar:usage:{id}:*");
        let usage_keys: Vec<String> = self.with_conn(|c| {
            c.scan_match::<_, String>(&pattern)?
                .collect::<Result<Vec<String>, _>>()
        })?;
        let cred_ids: Vec<String> =
            self.with_conn(|c| c.smembers(format!("{AWSCRED_IDS_PREFIX}{id}")))?;

        // WRITE phase: the ENTIRE delete cascade as ONE atomic MULTI/EXEC. Either everything goes
        // (key row, key index, usage windows, every credential + its index memberships, the id map)
        // or nothing does - a mid-cascade failure can never orphan a SigV4 credential behind a
        // deleted key (the bug this replaces: N independent commands).
        self.with_conn(|c| {
            let mut pipe = redis::pipe();
            pipe.atomic();
            pipe.del(format!("{KEY_PREFIX}{id}")).ignore();
            pipe.srem(KEYS_INDEX, id).ignore();
            for k in &usage_keys {
                pipe.del(k).ignore();
            }
            for akid in &cred_ids {
                pipe.del(format!("{AWSCRED_PREFIX}{akid}")).ignore();
                pipe.srem(AWSCRED_INDEX, akid).ignore();
            }
            pipe.del(format!("{AWSCRED_IDS_PREFIX}{id}")).ignore();
            pipe.query(c)
        })
    }

    fn get_usage(&self, bucket_id: &str, window_start: u64) -> StoreResult<UsageLedger> {
        let k = usage_key(bucket_id, window_start);
        let fields: Vec<(String, i64)> = self.with_conn(|c| c.hgetall(&k))?;
        if fields.is_empty() {
            return Ok(UsageLedger::default());
        }
        let mut ledger = UsageLedger::default();
        for (name, v) in fields {
            if name == "requests" {
                ledger.requests = read_u64(v);
                continue;
            }
            let Some((model, tier)) = parse_model_field(&name) else {
                continue;
            };
            let entry = match ledger.models.iter_mut().find(|m| m.model == model) {
                Some(m) => m,
                None => {
                    ledger.models.push(ModelTokens {
                        model: model.to_string(),
                        tokens: TierTokens::default(),
                    });
                    ledger.models.last_mut().expect("just pushed")
                }
            };
            match tier {
                "input" => entry.tokens.input = read_u64(v),
                "output" => entry.tokens.output = read_u64(v),
                "cache_read" => entry.tokens.cache_read = read_u64(v),
                "cache_write" => entry.tokens.cache_write = read_u64(v),
                _ => {}
            }
        }
        // Deterministic order (mirrors the SQL backends' ORDER BY model).
        ledger.models.sort_by(|a, b| a.model.cmp(&b.model));
        Ok(ledger)
    }

    fn put_usage(
        &self,
        bucket_id: &str,
        window_start: u64,
        ledger: &UsageLedger,
    ) -> StoreResult<()> {
        // ABSOLUTE set: DEL + HSET the whole ledger in ONE atomic MULTI/EXEC so a re-put is
        // idempotent, a stale model field never lingers, and a reader never sees half a ledger.
        // The fleet-additive flush path uses `add_usage` instead.
        let k = usage_key(bucket_id, window_start);
        self.with_conn(|c| {
            let mut pipe = redis::pipe();
            pipe.atomic();
            pipe.del(&k).ignore();
            pipe.hset(&k, "requests", clamp(ledger.requests)).ignore();
            for m in &ledger.models {
                pipe.hset(&k, model_field(&m.model, "input"), clamp(m.tokens.input))
                    .ignore();
                pipe.hset(&k, model_field(&m.model, "output"), clamp(m.tokens.output))
                    .ignore();
                pipe.hset(
                    &k,
                    model_field(&m.model, "cache_read"),
                    clamp(m.tokens.cache_read),
                )
                .ignore();
                pipe.hset(
                    &k,
                    model_field(&m.model, "cache_write"),
                    clamp(m.tokens.cache_write),
                )
                .ignore();
            }
            pipe.query(c)
        })
    }

    fn add_usage(&self, bucket_id: &str, window_start: u64, delta: &UsageDelta) -> StoreResult<()> {
        // ADDITIVE accumulate: HINCRBY the requests delta plus every per-(model, tier) token delta,
        // atomically as one MULTI/EXEC - the fleet-honest write: N nodes flushing deltas sum to the
        // true fleet total instead of last-writer-wins overwriting each other. No dollar delta
        // crosses this wire. (A transient negative is clamped to 0 on read - see the crate doc.)
        let k = usage_key(bucket_id, window_start);
        // M3: NON-IDEMPOTENT HINCRBY cascade - no auto-retry (a lost-reply timeout must not
        // double-apply; the flusher re-derives from baseline on error).
        self.with_conn_no_retry(|c| {
            let mut pipe = redis::pipe();
            pipe.atomic();
            pipe.cmd("HINCRBY")
                .arg(&k)
                .arg("requests")
                .arg(delta.requests)
                .ignore();
            for m in &delta.models {
                for (tier, v) in [
                    ("input", m.tokens.input),
                    ("output", m.tokens.output),
                    ("cache_read", m.tokens.cache_read),
                    ("cache_write", m.tokens.cache_write),
                ] {
                    if v != 0 {
                        pipe.cmd("HINCRBY")
                            .arg(&k)
                            .arg(model_field(&m.model, tier))
                            .arg(v)
                            .ignore();
                    }
                }
            }
            pipe.query(c)
        })
    }

    fn add_metering(&self, d: &MeteringDelta) -> StoreResult<()> {
        let row = metering_row(d.bucket, &d.key_id, &d.model, &d.provider);
        let set = metering_set(d.bucket);
        // One atomic MULTI/EXEC: index the row + HINCRBY the four token fields and the request
        // count + persist the identity fields (idempotent HSET). Accumulation without a
        // read-modify-write race, and no partially-written row on failure.
        // M3: NON-IDEMPOTENT HINCRBY cascade - no auto-retry (a lost-reply timeout must not
        // double-apply; the flusher re-derives from baseline on error).
        self.with_conn_no_retry(|c| {
            redis::pipe()
                .atomic()
                .sadd(&set, &row)
                .ignore()
                .cmd("HINCRBY")
                .arg(&row)
                .arg("tokens_input")
                .arg(clamp(d.tokens_input))
                .ignore()
                .cmd("HINCRBY")
                .arg(&row)
                .arg("tokens_output")
                .arg(clamp(d.tokens_output))
                .ignore()
                .cmd("HINCRBY")
                .arg(&row)
                .arg("tokens_cache_read")
                .arg(clamp(d.tokens_cache_read))
                .ignore()
                .cmd("HINCRBY")
                .arg(&row)
                .arg("tokens_cache_creation")
                .arg(clamp(d.tokens_cache_creation))
                .ignore()
                .cmd("HINCRBY")
                .arg(&row)
                .arg("requests")
                .arg(1i64)
                .ignore()
                .hset_multiple(
                    &row,
                    &[
                        ("key_id", d.key_id.as_str()),
                        ("model", d.model.as_str()),
                        ("provider", d.provider.as_str()),
                    ],
                )
                .ignore()
                .query(c)
        })
    }

    fn list_metering(&self, bucket: u64) -> StoreResult<Vec<MeteringRow>> {
        let set = metering_set(bucket);
        let rows: Vec<String> = self.with_conn(|c| c.smembers(&set))?;
        let mut out = Vec::with_capacity(rows.len());
        for row_key in rows {
            let fields: Vec<(String, String)> = self.with_conn(|c| c.hgetall(&row_key))?;
            if fields.is_empty() {
                continue; // a stale index member with no hash - skip
            }
            let mut m = MeteringRow {
                key_id: String::new(),
                model: String::new(),
                provider: String::new(),
                tokens_input: 0,
                tokens_output: 0,
                tokens_cache_read: 0,
                tokens_cache_creation: 0,
                requests: 0,
            };
            for (name, val) in fields {
                let num = || val.parse::<i64>().unwrap_or(0);
                match name.as_str() {
                    "key_id" => m.key_id = val.clone(),
                    "model" => m.model = val.clone(),
                    "provider" => m.provider = val.clone(),
                    "tokens_input" => m.tokens_input = read_u64(num()),
                    "tokens_output" => m.tokens_output = read_u64(num()),
                    "tokens_cache_read" => m.tokens_cache_read = read_u64(num()),
                    "tokens_cache_creation" => m.tokens_cache_creation = read_u64(num()),
                    "requests" => m.requests = read_u64(num()),
                    _ => {}
                }
            }
            out.push(m);
        }
        Ok(out)
    }

    fn put_aws_credential(&self, cred: &AwsCredential) -> StoreResult<()> {
        let json = serde_json::to_string(cred)
            .map_err(|e| StoreError(format!("aws credential encode failed: {e}")))?;
        // Credential row + both indexes as ONE atomic MULTI/EXEC (no partially-indexed credential).
        self.with_conn(|c| {
            redis::pipe()
                .atomic()
                .set(format!("{AWSCRED_PREFIX}{}", cred.access_key_id), &json)
                .ignore()
                .sadd(AWSCRED_INDEX, &cred.access_key_id)
                .ignore()
                .sadd(
                    format!("{AWSCRED_IDS_PREFIX}{}", cred.key_id),
                    &cred.access_key_id,
                )
                .ignore()
                .query(c)
        })
    }

    fn put_key_with_aws_credential(
        &self,
        key: &VirtualKey,
        cred: &AwsCredential,
    ) -> StoreResult<()> {
        // The WHOLE key+credential publish as ONE atomic MULTI/EXEC - either both the key and its
        // SigV4 credential (with every index) exist, or neither does. This replaces the old
        // sequential put_key-then-put_aws_credential, whose mid-sequence failure could mint a key
        // with no credential (or, reversed, a credential for a key that failed to store).
        let key_json = key_to_json(key)?;
        let cred_json = serde_json::to_string(cred)
            .map_err(|e| StoreError(format!("aws credential encode failed: {e}")))?;
        self.with_conn(|c| {
            redis::pipe()
                .atomic()
                .set(format!("{KEY_PREFIX}{}", key.id), &key_json)
                .ignore()
                .sadd(KEYS_INDEX, &key.id)
                .ignore()
                .set(
                    format!("{AWSCRED_PREFIX}{}", cred.access_key_id),
                    &cred_json,
                )
                .ignore()
                .sadd(AWSCRED_INDEX, &cred.access_key_id)
                .ignore()
                .sadd(
                    format!("{AWSCRED_IDS_PREFIX}{}", cred.key_id),
                    &cred.access_key_id,
                )
                .ignore()
                .query(c)
        })
    }

    fn list_aws_credentials(&self) -> StoreResult<Vec<AwsCredential>> {
        let ids: Vec<String> = self.with_conn(|c| c.smembers(AWSCRED_INDEX))?;
        let mut out = Vec::with_capacity(ids.len());
        for akid in ids {
            if let Some(raw) =
                self.with_conn(|c| c.get::<_, Option<String>>(format!("{AWSCRED_PREFIX}{akid}")))?
            {
                let cred: AwsCredential = serde_json::from_str(&raw)
                    .map_err(|e| StoreError(format!("aws credential decode failed: {e}")))?;
                out.push(cred);
            }
        }
        Ok(out)
    }

    fn append_audit(&self, entry: &AuditRecord) -> StoreResult<()> {
        // The audit log's durable home: a SORTED SET scored by `seq` (the engine's monotonic
        // sequence), each member the JSON record. `seq` is the record's IDENTITY (the SQL backends'
        // PRIMARY KEY), so a re-append of an existing seq must UPSERT ON seq - overwriting whatever
        // record currently sits at that score. A bare ZADD upserts on the MEMBER (the JSON bytes),
        // so re-appending the same seq with a DIFFERENT payload (e.g. a corrected hash) would leave
        // TWO members at one score - a duplicate audit entry and a divergence from the SQL backends
        // (whose test asserts the replay overwrites the digest). Do it as ONE atomic MULTI/EXEC:
        // drop any member already at this exact score, then add the new one.
        let json = serde_json::to_string(entry)
            .map_err(|e| StoreError(format!("audit encode failed: {e}")))?;
        let score = clamp(entry.seq);
        self.with_conn(|c| {
            redis::pipe()
                .atomic()
                .cmd("ZREMRANGEBYSCORE")
                .arg(AUDIT_ZSET)
                .arg(score)
                .arg(score)
                .ignore()
                .zadd(AUDIT_ZSET, &json, score)
                .ignore()
                .query(c)
        })
    }

    fn list_audit(&self) -> StoreResult<Vec<AuditRecord>> {
        // ZRANGE 0..-1 returns members ordered by score (seq) ascending = oldest-first, the boot
        // restore order the engine expects.
        let members: Vec<String> = self.with_conn(|c| c.zrange(AUDIT_ZSET, 0, -1))?;
        let mut out = Vec::with_capacity(members.len());
        for m in members {
            let rec: AuditRecord = serde_json::from_str(&m)
                .map_err(|e| StoreError(format!("audit decode failed: {e}")))?;
            out.push(rec);
        }
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The password-scrub never lets the URL secret out in an error string, and the URL password
    /// extractor handles every URL shape.
    #[test]
    fn password_scrub_and_extraction() {
        assert_eq!(
            url_password("redis://:s3cr3t@host:6379/0").as_deref(),
            Some("s3cr3t")
        );
        assert_eq!(
            url_password("rediss://user:p%40ss@host:6380").as_deref(),
            Some("p%40ss")
        );
        assert_eq!(url_password("redis://host:6379"), None);
        assert_eq!(url_password("redis://user@host:6379"), None);
        assert_eq!(url_password("not a url"), None);

        let msg = "connection refused for redis://:s3cr3t@host:6379/0".to_string();
        let scrubbed = scrub(msg, Some("s3cr3t"));
        assert!(!scrubbed.contains("s3cr3t"), "got {scrubbed}");
        assert!(scrubbed.contains("<redacted>"));
        // No secret / secret absent: untouched.
        assert_eq!(scrub("plain".into(), None), "plain");
        assert_eq!(scrub("plain".into(), Some("zz")), "plain");
    }

    /// A `rediss://` (TLS) URL parses into a client without connecting - the TLS feature is
    /// compiled in and the scheme is accepted (a live TLS round-trip needs a TLS redis, which the
    /// live test covers when REDIS_URL is rediss).
    #[test]
    fn rediss_url_is_accepted() {
        assert!(redis::Client::open("rediss://:pw@localhost:6380/0").is_ok());
    }

    /// End-to-end against a REAL Redis, gated on `REDIS_URL` (a docker `redis:7` service in CI).
    /// Skips cleanly when unset LOCALLY so the default `cargo test` needs no server - but MUST NOT
    /// silently skip in CI: CI provisions the service and sets `REDIS_URL` (see
    /// .github/workflows/ci.yml), so when `CI` is set the missing URL is a HARD FAILURE rather than
    /// a silent skip (same discipline as the Postgres backend's `BUSBAR_TEST_POSTGRES_URL`).
    fn live_store() -> Option<RedisStore> {
        let url = match std::env::var("REDIS_URL") {
            Ok(url) => url,
            Err(_) if std::env::var_os("CI").is_some() => {
                panic!(
                    "REDIS_URL is unset under CI: the Redis service container must provision it \
                     (see .github/workflows/ci.yml). Refusing to silently skip the only live-DB \
                     coverage in CI."
                );
            }
            Err(_) => {
                eprintln!("skip: set REDIS_URL to run the Redis store tests");
                return None;
            }
        };
        Some(RedisStore::connect(&url).expect("connect"))
    }

    fn vk(id: &str) -> VirtualKey {
        VirtualKey {
            id: id.into(),
            key_hash: "h".into(),
            name: id.into(),
            allowed_pools: vec!["prod,special".into()],
            max_budget_cents: Some(1234),
            budget_period: "total".into(),
            rpm_limit: Some(60),
            tpm_limit: None,
            enabled: true,
            created_at: 99,
            budget_group: Some("growth".into()),
            labels: std::collections::BTreeMap::from([("team".into(), "growth".into())]),
        }
    }

    #[test]
    fn roundtrip_against_live_redis() {
        let Some(store) = live_store() else { return };
        // Isolate from any prior run.
        let _ = store.delete_key("vk_redis");

        let key = vk("vk_redis");
        store.put_key(&key).unwrap();
        let got = store.get_key("vk_redis").unwrap().unwrap();
        assert_eq!(got.max_budget_cents, Some(1234));
        // The comma-bearing pool name survives (whole-key JSON, not a bare comma split).
        assert_eq!(got.allowed_pools, vec!["prod,special".to_string()]);
        assert_eq!(got.rpm_limit, Some(60));
        assert_eq!(
            got.budget_group.as_deref(),
            Some("growth"),
            "budget_group survives the redis JSON round-trip"
        );
        assert_eq!(got.labels.get("team").map(String::as_str), Some("growth"));
        assert!(store
            .list_keys()
            .unwrap()
            .iter()
            .any(|k| k.id == "vk_redis"));

        // Token ledger: absolute put (DEL + HSET) round-trips; additive HINCRBY accumulates on top.
        let base = UsageLedger {
            requests: 3,
            models: vec![ModelTokens {
                model: "gpt-5".into(),
                tokens: TierTokens {
                    input: 9,
                    output: 4,
                    cache_read: 2,
                    cache_write: 1,
                },
            }],
        };
        store.put_usage("vk_redis", 100, &base).unwrap();
        let u = store.get_usage("vk_redis", 100).unwrap();
        assert_eq!(u.requests, 3);
        let t = u.tokens_for("gpt-5").unwrap();
        assert_eq!(
            (t.input, t.output, t.cache_read, t.cache_write),
            (9, 4, 2, 1)
        );
        store
            .add_usage(
                "vk_redis",
                100,
                &busbar_api::UsageDelta {
                    requests: 2,
                    models: vec![busbar_api::ModelTokensDelta {
                        model: "gpt-5".into(),
                        tokens: busbar_api::TierTokensDelta {
                            input: 1,
                            output: 1,
                            cache_read: 0,
                            cache_write: 0,
                        },
                    }],
                },
            )
            .unwrap();
        let u = store.get_usage("vk_redis", 100).unwrap();
        assert_eq!(u.requests, 5, "add_usage accumulates the requests delta");
        let t = u.tokens_for("gpt-5").unwrap();
        assert_eq!(
            (t.input, t.output),
            (10, 5),
            "add_usage accumulates per-model tier deltas onto the durable record"
        );
        // A second model materializes its own fields; a model name CONTAINING ':' round-trips.
        store
            .add_usage(
                "vk_redis",
                100,
                &busbar_api::UsageDelta {
                    requests: 0,
                    models: vec![busbar_api::ModelTokensDelta {
                        model: "org:custom:model".into(),
                        tokens: busbar_api::TierTokensDelta {
                            input: 7,
                            output: 0,
                            cache_read: 0,
                            cache_write: 0,
                        },
                    }],
                },
            )
            .unwrap();
        let u = store.get_usage("vk_redis", 100).unwrap();
        assert_eq!(u.models.len(), 2);
        assert_eq!(
            u.tokens_for("org:custom:model").unwrap().input,
            7,
            "a colon-bearing model name survives the hash-field encoding"
        );

        // Metering: HINCRBY accumulation across two responses on the same row.
        let delta = |ti: u64| MeteringDelta {
            key_id: "vk_redis".into(),
            bucket: 7,
            model: "m".into(),
            provider: "p".into(),
            tokens_input: ti,
            tokens_output: 0,
            tokens_cache_read: 0,
            tokens_cache_creation: 0,
        };
        // Clear the bucket rows from a prior run.
        let _ = store.with_conn(|c| {
            let row = metering_row(7, "vk_redis", "m", "p");
            redis::pipe()
                .atomic()
                .del(&row)
                .ignore()
                .srem(metering_set(7), &row)
                .ignore()
                .query::<()>(c)
        });
        store.add_metering(&delta(10)).unwrap();
        store.add_metering(&delta(5)).unwrap();
        let rows = store.list_metering(7).unwrap();
        let row = rows.iter().find(|r| r.key_id == "vk_redis").unwrap();
        assert_eq!(row.tokens_input, 15, "HINCRBY accumulated across responses");
        assert_eq!(row.requests, 2);

        // Audit: ZADD by seq, ZRANGE oldest-first.
        let rec = |seq: u64, prev: &str, hash: &str| AuditRecord {
            seq,
            ts: 1000 + seq,
            action: "hook.register".into(),
            resource: format!("hook:{seq}"),
            outcome: "applied".into(),
            principal: "admin".into(),
            prev_hash: prev.into(),
            hash: hash.into(),
        };
        store.with_conn(|c| c.del::<_, ()>(AUDIT_ZSET)).unwrap();
        store.append_audit(&rec(1, "", "h1")).unwrap();
        store.append_audit(&rec(2, "h1", "h2")).unwrap();
        let audit = store.list_audit().unwrap();
        assert_eq!(audit.len(), 2);
        assert_eq!((audit[0].seq, audit[1].seq), (1, 2), "oldest-first by seq");
        assert_eq!(audit[1].prev_hash, "h1");

        // REGRESSION (append_audit upserts on SEQ, not member): a re-append of an EXISTING seq with a
        // DIFFERENT payload (a corrected hash) must OVERWRITE the record at that seq, never leave two
        // members at one score. A bare ZADD (upsert-on-member) would produce a duplicate seq-2 row and
        // diverge from the SQL backends (whose replay overwrites the digest). ZREMRANGEBYSCORE+ZADD.
        store.append_audit(&rec(2, "h1", "h2b")).unwrap();
        let replayed = store.list_audit().unwrap();
        assert_eq!(
            replayed.len(),
            2,
            "re-appending an existing seq must upsert on seq, never add a duplicate"
        );
        assert_eq!(
            replayed[1].hash, "h2b",
            "the replayed record overwrites the prior digest (SQL-backend parity)"
        );

        // Attach an AWS credential so the delete cascade over credentials is actually exercised.
        let cred = AwsCredential {
            access_key_id: "AKIA_REDIS_TEST".into(),
            key_id: "vk_redis".into(),
            secret_access_key: "s3cr3t".into(),
        };
        store.put_aws_credential(&cred).unwrap();
        assert!(store
            .list_aws_credentials()
            .unwrap()
            .iter()
            .any(|c| c.access_key_id == "AKIA_REDIS_TEST"));

        // Delete removes the key, its usage, and its AWS creds - atomically (one MULTI/EXEC).
        store.delete_key("vk_redis").unwrap();
        assert!(store.get_key("vk_redis").unwrap().is_none());
        assert_eq!(
            store.get_usage("vk_redis", 100).unwrap(),
            UsageLedger::default()
        );
        assert!(
            !store
                .list_aws_credentials()
                .unwrap()
                .iter()
                .any(|c| c.access_key_id == "AKIA_REDIS_TEST"),
            "delete_key must cascade to the AWS credentials"
        );
    }

    /// ATOMIC key+credential publish: `put_key_with_aws_credential` writes both (and all three
    /// indexes) in ONE MULTI/EXEC, and the delete cascade removes every trace in ONE MULTI/EXEC -
    /// no orphaned SigV4 credential, no dangling index member.
    #[test]
    fn atomic_key_with_credential_and_cascade_against_live_redis() {
        let Some(store) = live_store() else { return };
        let _ = store.delete_key("vk_atomic");

        let key = vk("vk_atomic");
        let cred = AwsCredential {
            access_key_id: "AKIA_ATOMIC_TEST".into(),
            key_id: "vk_atomic".into(),
            secret_access_key: "sekrit".into(),
        };
        store.put_key_with_aws_credential(&key, &cred).unwrap();
        assert!(store.get_key("vk_atomic").unwrap().is_some());
        assert!(store
            .list_aws_credentials()
            .unwrap()
            .iter()
            .any(|c| c.access_key_id == "AKIA_ATOMIC_TEST"));

        store.delete_key("vk_atomic").unwrap();
        // NOTHING remains: key row, key index, credential row, credential index, id map.
        assert!(store.get_key("vk_atomic").unwrap().is_none());
        assert!(!store
            .list_aws_credentials()
            .unwrap()
            .iter()
            .any(|c| c.access_key_id == "AKIA_ATOMIC_TEST"));
        let leftovers: bool = store
            .with_conn(|c| {
                let a: bool = c.exists(format!("{AWSCRED_PREFIX}AKIA_ATOMIC_TEST"))?;
                let b: bool = c.exists(format!("{AWSCRED_IDS_PREFIX}vk_atomic"))?;
                let idx: bool = c.sismember(AWSCRED_INDEX, "AKIA_ATOMIC_TEST")?;
                Ok(a || b || idx)
            })
            .unwrap();
        assert!(!leftovers, "the atomic cascade leaves zero residue");
    }

    /// RECONNECT: after the server closes our connection (`QUIT`), the next operation transparently
    /// reopens and succeeds instead of failing with a broken-pipe error.
    #[test]
    fn reconnects_after_dropped_connection_against_live_redis() {
        let Some(store) = live_store() else { return };
        let _ = store.delete_key("vk_reconn");
        store.put_key(&vk("vk_reconn")).unwrap();

        // Ask the server to close OUR connection: QUIT makes the server hang up after replying, so
        // the connection in the pool is dead for the next command.
        {
            let mut guard = store.conn.lock().unwrap();
            if let Some(conn) = guard.as_mut() {
                let _ = redis::cmd("QUIT").query::<String>(conn);
            }
        }
        // The next operation must reconnect-and-retry, not error.
        let got = store
            .get_key("vk_reconn")
            .expect("operation after a dropped connection must transparently reconnect");
        assert!(got.is_some());
        store.delete_key("vk_reconn").unwrap();
    }

    /// M3 (over-bill): a NON-IDEMPOTENT write cascade (add_usage / add_metering) must NOT auto-retry
    /// on a connection error - a lost-reply timeout could have already committed the EXEC server-side,
    /// so a retry would DOUBLE-APPLY the delta permanently. We drop the pooled connection (server-side
    /// QUIT), then a mutating op must ERROR (no transparent retry) while a subsequent READ reconnects.
    #[test]
    fn mutating_op_does_not_auto_retry_after_dropped_connection() {
        let Some(store) = live_store() else { return };
        let bucket_id = "vk_m3_noretry";
        let window = 1_700_000_000_u64;
        let _ = store.with_conn(|c| c.del::<_, ()>(usage_key(bucket_id, window)));

        let delta = || busbar_api::UsageDelta {
            requests: 1,
            models: vec![busbar_api::ModelTokensDelta {
                model: "gpt-x".into(),
                tokens: busbar_api::TierTokensDelta {
                    input: 10,
                    output: 0,
                    cache_read: 0,
                    cache_write: 0,
                },
            }],
        };

        // Kill the pooled connection so the very next command hits a dead socket.
        {
            let mut guard = store.conn.lock().unwrap();
            if let Some(conn) = guard.as_mut() {
                let _ = redis::cmd("QUIT").query::<String>(conn);
            }
        }
        // The mutating op must ERROR (a read WOULD have transparently reconnected). If it instead
        // returned Ok, that means a silent reconnect+retry ran - the exact double-apply hazard.
        let res = store.add_usage(bucket_id, window, &delta());
        assert!(
            res.is_err(),
            "a non-idempotent write cascade must NOT auto-retry on a connection error (over-bill \
             hazard); it must surface the error so the flusher re-derives from baseline"
        );

        // A subsequent READ reconnects cleanly (the dropped connection was cleared), and - proof the
        // failed write did NOT apply - the counter is still absent/zero.
        let ledger = store.get_usage(bucket_id, window).expect("read reconnects");
        assert_eq!(
            ledger.requests, 0,
            "the un-retried write must not have applied (exactly-once on error)"
        );

        // A fresh mutating op now succeeds on the healthy connection (baseline re-derive path).
        store
            .add_usage(bucket_id, window, &delta())
            .expect("write succeeds on a healthy connection");
        assert_eq!(store.get_usage(bucket_id, window).unwrap().requests, 1);
        let _ = store.with_conn(|c| c.del::<_, ()>(usage_key(bucket_id, window)));
    }

    /// M2 (data-loss): busbar:* DATA present + schema marker ABSENT + the data is NOT legacy-shaped
    /// (a healthy v2 namespace whose marker was evicted under `maxmemory allkeys-*`) must REFUSE to
    /// boot - never silently WIPE. And the inverse: a genuinely legacy-shaped namespace (a
    /// `busbar:usage:*` HASH carrying the pre-v2 `spend_cents` field) IS wiped and re-marked.
    #[test]
    fn migrate_refuses_to_wipe_non_legacy_namespace_with_missing_marker() {
        let Some(store) = live_store() else { return };
        // Simulate a v2 namespace whose marker was evicted: v2-shaped usage data, no busbar:schema.
        let vk_id = "vk_m2_v2";
        let ukey = usage_key(vk_id, 1_700_000_100);
        store
            .with_conn(|c| {
                redis::pipe()
                    .hset(&ukey, "requests", 5_i64)
                    .ignore()
                    .hset(&ukey, model_field("gpt-x", "input"), 10_i64)
                    .ignore()
                    .del(SCHEMA_KEY)
                    .ignore()
                    .query::<()>(c)
            })
            .unwrap();

        // migrate() must REFUSE (Err), leaving the data intact - not wipe it.
        let err = store
            .migrate()
            .expect_err("a non-legacy namespace with a missing marker must refuse to boot");
        assert!(
            err.0.contains("Refusing to wipe"),
            "expected a loud refuse-to-wipe error, got: {}",
            err.0
        );
        let still: i64 = store.with_conn(|c| c.hget(&ukey, "requests")).unwrap();
        assert_eq!(
            still, 5,
            "the v2 data must survive - migrate() must not wipe it"
        );

        // Now make it genuinely LEGACY-shaped (add the pre-v2 spend_cents field) and confirm a wipe.
        store
            .with_conn(|c| c.hset::<_, _, _, ()>(&ukey, "spend_cents", 42_i64))
            .unwrap();
        store.with_conn(|c| c.del::<_, ()>(SCHEMA_KEY)).unwrap();
        store
            .migrate()
            .expect("a legacy-shaped namespace migrates (wipe + re-mark)");
        let gone: Option<i64> = store.with_conn(|c| c.hget(&ukey, "requests")).unwrap();
        assert!(gone.is_none(), "the legacy key must be wiped");
        let marker: Option<i64> = store.with_conn(|c| c.get(SCHEMA_KEY)).unwrap();
        assert_eq!(marker, Some(SCHEMA_VERSION), "re-marked v2 after the wipe");
    }
}
