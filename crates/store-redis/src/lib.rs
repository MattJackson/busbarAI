// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The **Redis** backend for busbar's durable governance store — the shared, multi-node `db` plugin
//! over a KEY-VALUE data model. Implements `busbar_api::Store` on a mutex-guarded SYNCHRONOUS redis
//! connection, depending only on the `busbar-api` contract (plus the `redis` driver), never on the
//! engine.
//!
//! Redis has no tables, so the relational schema the SQLite/Postgres backends use is modeled in KV:
//!
//! - **virtual keys** — `busbar:key:<id>` holds the JSON [`VirtualKey`]; the set `busbar:keys` indexes
//!   every id so `list_keys` is a SMEMBERS + per-id GET.
//! - **AWS credentials** — `busbar:awscred:<access_key_id>` holds the JSON credential; `busbar:awscreds`
//!   indexes them; `busbar:awscred_ids:<key_id>` maps a virtual key to its AccessKeyIds so a key delete
//!   removes them (a revoked key's SigV4 credential must never outlive it — the same guarantee the SQL
//!   backends enforce with a `DELETE … WHERE key_id`).
//! - **usage counters** — `busbar:usage:<key_id>:<window_start>` is a HASH `{spend_cents, tokens,
//!   requests}`. `put_usage` HSETs absolute values; `add_usage` HINCRBYs deltas (the fleet-additive
//!   flush, so concurrent nodes accumulate instead of overwriting each other); `get_usage` HGETALLs.
//! - **metering** — `busbar:metering:<bucket>` is a SET of row keys; each row is a HASH accumulated
//!   with HINCRBY (add), so concurrent responses accumulate without a read-modify-write race.
//! - **audit** — `busbar:audit` is a SORTED SET scored by `seq`, each member the JSON [`AuditRecord`].
//!
//! ## Atomicity
//!
//! Every MULTI-KEY write cascade runs as ONE atomic `MULTI`/`EXEC` pipeline
//! ([`redis::Pipeline::atomic`]): `put_key_with_aws_credential` (key + credential + all three
//! indexes) and the `delete_key` cascade (key row, key index, usage windows, credentials, credential
//! indexes). A mid-cascade failure therefore can NEVER orphan a SigV4 credential behind a deleted
//! key or publish a credential for a key that was not stored — the transactional parity of the SQL
//! backends' `BEGIN`/`COMMIT`.
//!
//! ## Connections, TLS, reconnect
//!
//! A single mutex-guarded synchronous connection used off the request hot path (key CRUD + the
//! write-behind usage flush). A DROPPED connection (server restart, idle timeout, network blip) is
//! transparently re-established: each operation retries exactly ONCE on a connection-level error by
//! reopening from the client before failing. `rediss://` URLs use TLS (rustls, ring provider,
//! OS-native roots). Error strings are SCRUBBED of the URL password before they leave this crate,
//! so a connection failure can never leak the secret into logs.
//!
//! ## Data growth (documented, deliberate)
//!
//! Rows are written WITHOUT a TTL: usage windows, metering buckets, and audit entries accumulate
//! unboundedly by design — the store is the durable system of record and busbar never silently
//! expires governance data. Operators who want bounded growth should reap old
//! `busbar:usage:*`/`busbar:metering:*` keys (or apply `EXPIRE` out-of-band) on their own retention
//! schedule; the audit zset should be archived, not expired.

use busbar_api::{
    AuditRecord, AwsCredential, MeteringDelta, MeteringRow, Store, StoreError, StoreResult, Usage,
    VirtualKey,
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

fn usage_key(key_id: &str, window_start: u64) -> String {
    format!("busbar:usage:{key_id}:{window_start}")
}
fn metering_set(bucket: u64) -> String {
    format!("busbar:metering:{bucket}")
}
fn metering_row(bucket: u64, key_id: &str, model: &str, provider: &str) -> String {
    // `|` joins the composite row identity; it is not a legal character in a model/provider name in
    // practice, and even if present it only affects the row's own key (never cross-row correctness).
    format!("busbar:metering:{bucket}:{key_id}|{model}|{provider}")
}

/// Clamp a `u64` into `i64` for Redis integer ops (HINCRBY is signed) — a value above `i64::MAX` pins
/// to `i64::MAX`, never wraps. Mirrors the SQL backends.
fn clamp(v: u64) -> i64 {
    i64::try_from(v).unwrap_or(i64::MAX)
}

/// Read a signed counter back as a `u64`, clamping a (corrupt / direct-DB) negative to 0 instead of
/// wrapping via `as` — mirrors the SQL backends' DI-3 posture.
fn read_u64(v: i64) -> u64 {
    v.max(0) as u64
}

/// Extract the PASSWORD component from a redis URL (`redis://user:pass@host/...` or
/// `redis://:pass@host/...`), if any — the secret that must never appear in an error string.
fn url_password(url: &str) -> Option<String> {
    let rest = url.split("://").nth(1)?;
    let userinfo = rest.rsplit_once('@').map(|(u, _)| u)?;
    let pass = match userinfo.split_once(':') {
        Some((_, p)) => p,
        None => return None, // user only, no password
    };
    (!pass.is_empty()).then(|| pass.to_string())
}

/// Replace every occurrence of `secret` in `msg` with `<redacted>` — the password-in-error scrub.
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
/// connection with one-shot reconnect — governance is off the request hot path, so serializing
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
        Ok(Self {
            client,
            conn: Mutex::new(Some(conn)),
            secret,
        })
    }

    /// Run `f` against the live connection, transparently reconnecting ONCE on a connection-level
    /// error (dropped socket / IO / timeout). The single retry re-runs `f` on the fresh connection;
    /// a second failure (or any command-level error) surfaces, password-scrubbed. Every operation
    /// in this crate funnels through here, so reconnect + scrub are uniform.
    fn with_conn<T>(
        &self,
        mut f: impl FnMut(&mut Connection) -> redis::RedisResult<T>,
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
            Err(e) if is_connection_error(&e) => {
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
            Err(e) => Err(self.err(e, "command")),
        }
    }

    /// Map a redis error into the api error, scrubbing the URL password.
    fn err(&self, e: redis::RedisError, ctx: &str) -> StoreError {
        StoreError(scrub(format!("redis {ctx}: {e}"), self.secret.as_deref()))
    }
}

// `allowed_pools` encoding — identical to the SQL backends: the whole key rides as JSON, so pool
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
        // Row + index as ONE atomic MULTI/EXEC — a re-put is idempotent (SET overwrites, SADD is a
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
        // SCAN; the key's AccessKeyIds via SMEMBERS). Reads are outside the transaction — the
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
        // or nothing does — a mid-cascade failure can never orphan a SigV4 credential behind a
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

    fn get_usage(&self, key_id: &str, window_start: u64) -> StoreResult<Usage> {
        let k = usage_key(key_id, window_start);
        let fields: Vec<(String, i64)> = self.with_conn(|c| c.hgetall(&k))?;
        if fields.is_empty() {
            return Ok(Usage::default());
        }
        let mut u = Usage::default();
        for (name, v) in fields {
            match name.as_str() {
                "spend_cents" => u.spend_cents = v,
                "tokens" => u.tokens = read_u64(v),
                "requests" => u.requests = read_u64(v),
                _ => {}
            }
        }
        Ok(u)
    }

    fn put_usage(
        &self,
        key_id: &str,
        window_start: u64,
        spend_cents: i64,
        tokens: u64,
        requests: u64,
    ) -> StoreResult<()> {
        // ABSOLUTE set: HSET the three fields to the caller's snapshot (idempotent re-put). The
        // fleet-additive flush path uses `add_usage` instead.
        let k = usage_key(key_id, window_start);
        let items: [(&str, i64); 3] = [
            ("spend_cents", spend_cents),
            ("tokens", clamp(tokens)),
            ("requests", clamp(requests)),
        ];
        self.with_conn(|c| c.hset_multiple(&k, &items))
    }

    fn add_usage(
        &self,
        key_id: &str,
        window_start: u64,
        delta_spend_cents: i64,
        delta_tokens: i64,
        delta_requests: i64,
    ) -> StoreResult<()> {
        // ADDITIVE accumulate: HINCRBY each field by the caller's DELTA, atomically as one
        // MULTI/EXEC — the fleet-honest write: N nodes flushing deltas sum to the true fleet total
        // instead of last-writer-wins overwriting each other.
        let k = usage_key(key_id, window_start);
        self.with_conn(|c| {
            redis::pipe()
                .atomic()
                .cmd("HINCRBY")
                .arg(&k)
                .arg("spend_cents")
                .arg(delta_spend_cents)
                .ignore()
                .cmd("HINCRBY")
                .arg(&k)
                .arg("tokens")
                .arg(delta_tokens)
                .ignore()
                .cmd("HINCRBY")
                .arg(&k)
                .arg("requests")
                .arg(delta_requests)
                .ignore()
                .query(c)
        })
    }

    fn add_metering(&self, d: &MeteringDelta) -> StoreResult<()> {
        let row = metering_row(d.bucket, &d.key_id, &d.model, &d.provider);
        let set = metering_set(d.bucket);
        // One atomic MULTI/EXEC: index the row + HINCRBY the four token fields and the request
        // count + persist the identity fields (idempotent HSET). Accumulation without a
        // read-modify-write race, and no partially-written row on failure.
        self.with_conn(|c| {
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
                continue; // a stale index member with no hash — skip
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
        // The WHOLE key+credential publish as ONE atomic MULTI/EXEC — either both the key and its
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
        // sequence), each member the JSON record. ZADD upserts on the member; using `seq` as the
        // score keeps the set ordered for list_audit. A replay of the same record is a no-op.
        let json = serde_json::to_string(entry)
            .map_err(|e| StoreError(format!("audit encode failed: {e}")))?;
        self.with_conn(|c| c.zadd(AUDIT_ZSET, &json, clamp(entry.seq)))
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

    /// A `rediss://` (TLS) URL parses into a client without connecting — the TLS feature is
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
        assert!(store
            .list_keys()
            .unwrap()
            .iter()
            .any(|k| k.id == "vk_redis"));

        // Usage: absolute HSET round-trips; additive HINCRBY accumulates on top.
        store.put_usage("vk_redis", 100, 42, 9, 3).unwrap();
        let u = store.get_usage("vk_redis", 100).unwrap();
        assert_eq!((u.spend_cents, u.tokens, u.requests), (42, 9, 3));
        store.add_usage("vk_redis", 100, 8, 1, 2).unwrap();
        let u = store.get_usage("vk_redis", 100).unwrap();
        assert_eq!(
            (u.spend_cents, u.tokens, u.requests),
            (50, 10, 5),
            "add_usage accumulates deltas onto the durable record"
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

        // Delete removes the key, its usage, and its AWS creds — atomically (one MULTI/EXEC).
        store.delete_key("vk_redis").unwrap();
        assert!(store.get_key("vk_redis").unwrap().is_none());
        assert_eq!(store.get_usage("vk_redis", 100).unwrap(), Usage::default());
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
    /// indexes) in ONE MULTI/EXEC, and the delete cascade removes every trace in ONE MULTI/EXEC —
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
}
