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
//!   every id so `list_keys` is a SMEMBERS + MGET.
//! - **AWS credentials** — `busbar:awscred:<access_key_id>` holds the JSON credential; `busbar:awscreds`
//!   indexes them; `busbar:awscred_ids:<key_id>` maps a virtual key to its AccessKeyIds so a key delete
//!   removes them (a revoked key's SigV4 credential must never outlive it — the same guarantee the SQL
//!   backends enforce with a `DELETE … WHERE key_id`).
//! - **usage counters** — `busbar:usage:<key_id>:<window_start>` is a HASH `{spend_cents, tokens,
//!   requests}`. `put_usage` HSETs absolute values (memory is authoritative — a re-flush is idempotent);
//!   `get_usage` HGETALLs.
//! - **metering** — `busbar:metering:<bucket>` is a SET of row keys; each row is a HASH
//!   `busbar:metering:<bucket>:<key_id>|<model>|<provider>` accumulated with HINCRBY (add), so
//!   concurrent responses accumulate without a read-modify-write race.
//! - **audit** — `busbar:audit` is a SORTED SET scored by `seq`, each member the JSON [`AuditRecord`];
//!   `append_audit` ZADDs (idempotent on the member; the score is the seq) and `list_audit` ZRANGEs
//!   oldest-first. The engine owns the hash chain — the store persists records verbatim.
//!
//! Like the SQL backends it is a SINGLE mutex-guarded connection used off the request hot path (key
//! CRUD + the write-behind usage flush), so serializing access on one connection is correct and simple.

use busbar_api::{
    AuditRecord, AwsCredential, MeteringDelta, MeteringRow, Store, StoreError, StoreResult, Usage,
    VirtualKey,
};
use redis::{Commands, Connection};
use std::sync::Mutex;

// redis driver error -> the api's backend-agnostic `StoreError` (the contract crate stays storage-free,
// so the `From` impl that powers `?` cannot live there).
trait IntoStoreResult<T> {
    fn store(self) -> StoreResult<T>;
}
impl<T> IntoStoreResult<T> for Result<T, redis::RedisError> {
    fn store(self) -> StoreResult<T> {
        self.map_err(|e| StoreError(e.to_string()))
    }
}

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

/// Redis `Store` backend (durable, shared across a cluster). A single mutex-guarded synchronous
/// connection — governance is off the request hot path, so serializing access is fine.
pub struct RedisStore {
    conn: Mutex<Connection>,
}

impl RedisStore {
    /// Connect to Redis with the given URL (e.g. `redis://:pass@host:6379/0`). No TLS in this build
    /// (front Redis with a TLS-terminating proxy), mirroring the Postgres backend's `NoTls` posture.
    pub fn connect(url: &str) -> StoreResult<Self> {
        let client = redis::Client::open(url).store()?;
        let conn = client.get_connection().store()?;
        Ok(Self {
            conn: Mutex::new(conn),
        })
    }

    /// Poison-recovering lock of the connection (mirrors the SQL backends): the guard is reachable off
    /// the hot path, and continuing after a recovered guard is safe.
    fn lock(&self) -> std::sync::MutexGuard<'_, Connection> {
        self.conn.lock().unwrap_or_else(|p| p.into_inner())
    }
}

// `allowed_pools` encoding — identical to the SQL backends: JSON array of strings (delimiter-safe),
// reading legacy bare comma-delimited values transparently. Here it rides inside the whole-key JSON,
// so it is already delimiter-safe; these helpers exist only for parity / a future column split and to
// keep the VirtualKey serialization identical across backends.
fn key_to_json(key: &VirtualKey) -> StoreResult<String> {
    serde_json::to_string(key).map_err(|e| StoreError(format!("key encode failed: {e}")))
}
fn key_from_json(raw: &str) -> StoreResult<VirtualKey> {
    serde_json::from_str(raw).map_err(|e| StoreError(format!("key decode failed: {e}")))
}

impl Store for RedisStore {
    fn put_key(&self, key: &VirtualKey) -> StoreResult<()> {
        let json = key_to_json(key)?;
        let mut c = self.lock();
        // SET the row + index the id. Two commands (Redis is single-threaded per connection, so they
        // apply in order); the index is a SET so a re-put is idempotent.
        let _: () = c.set(format!("{KEY_PREFIX}{}", key.id), json).store()?;
        let _: () = c.sadd(KEYS_INDEX, &key.id).store()?;
        Ok(())
    }

    fn get_key(&self, id: &str) -> StoreResult<Option<VirtualKey>> {
        let raw: Option<String> = self.lock().get(format!("{KEY_PREFIX}{id}")).store()?;
        raw.map(|r| key_from_json(&r)).transpose()
    }

    fn list_keys(&self) -> StoreResult<Vec<VirtualKey>> {
        let mut c = self.lock();
        let ids: Vec<String> = c.smembers(KEYS_INDEX).store()?;
        let mut out = Vec::with_capacity(ids.len());
        for id in ids {
            // A dangling index member (row expired/removed out-of-band) is skipped, not an error.
            if let Some(raw) = c
                .get::<_, Option<String>>(format!("{KEY_PREFIX}{id}"))
                .store()?
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
        let mut c = self.lock();
        // Drop the key row + its index membership.
        let _: () = c.del(format!("{KEY_PREFIX}{id}")).store()?;
        let _: () = c.srem(KEYS_INDEX, id).store()?;
        // Drop every usage window for this key. SCAN (not KEYS — non-blocking) for the id's usage keys.
        // Collect the matched keys fully before deleting (the SCAN cursor and the DELs share one
        // connection, so we must not interleave other commands mid-scan).
        let pattern = format!("busbar:usage:{id}:*");
        let usage_keys: Vec<String> = c
            .scan_match::<_, String>(&pattern)
            .store()?
            .collect::<Result<Vec<String>, _>>()
            .store()?;
        for k in usage_keys {
            let _: () = c.del(k).store()?;
        }
        // Drop this key's AWS credentials (a revoked key's SigV4 credential must not outlive it).
        let cred_ids: Vec<String> = c.smembers(format!("{AWSCRED_IDS_PREFIX}{id}")).store()?;
        for akid in &cred_ids {
            let _: () = c.del(format!("{AWSCRED_PREFIX}{akid}")).store()?;
            let _: () = c.srem(AWSCRED_INDEX, akid).store()?;
        }
        let _: () = c.del(format!("{AWSCRED_IDS_PREFIX}{id}")).store()?;
        Ok(())
    }

    fn get_usage(&self, key_id: &str, window_start: u64) -> StoreResult<Usage> {
        let k = usage_key(key_id, window_start);
        let mut c = self.lock();
        let fields: Vec<(String, i64)> = c.hgetall(&k).store()?;
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
        // ABSOLUTE set (memory is authoritative): HSET the three fields to the flusher's snapshot, so a
        // re-flush of the same cell is idempotent and never double-counts.
        let k = usage_key(key_id, window_start);
        let items: [(&str, i64); 3] = [
            ("spend_cents", spend_cents),
            ("tokens", clamp(tokens)),
            ("requests", clamp(requests)),
        ];
        let _: () = self.lock().hset_multiple(&k, &items).store()?;
        Ok(())
    }

    fn add_metering(&self, d: &MeteringDelta) -> StoreResult<()> {
        let row = metering_row(d.bucket, &d.key_id, &d.model, &d.provider);
        let set = metering_set(d.bucket);
        let mut c = self.lock();
        // Index the row under its bucket (SET member is idempotent), then HINCRBY each token field +1
        // request — accumulation without a read-modify-write race (Redis applies each HINCRBY atomically).
        let _: () = c.sadd(&set, &row).store()?;
        let _: () = c
            .hincr(&row, "tokens_input", clamp(d.tokens_input))
            .store()?;
        let _: () = c
            .hincr(&row, "tokens_output", clamp(d.tokens_output))
            .store()?;
        let _: () = c
            .hincr(&row, "tokens_cache_read", clamp(d.tokens_cache_read))
            .store()?;
        let _: () = c
            .hincr(
                &row,
                "tokens_cache_creation",
                clamp(d.tokens_cache_creation),
            )
            .store()?;
        let _: () = c.hincr(&row, "requests", 1i64).store()?;
        // Persist the row's identity fields once (idempotent HSET) so list_metering can reconstruct
        // (key_id, model, provider) without parsing the composite row key.
        let _: () = c
            .hset_multiple(
                &row,
                &[
                    ("key_id", d.key_id.as_str()),
                    ("model", d.model.as_str()),
                    ("provider", d.provider.as_str()),
                ],
            )
            .store()?;
        Ok(())
    }

    fn list_metering(&self, bucket: u64) -> StoreResult<Vec<MeteringRow>> {
        let set = metering_set(bucket);
        let mut c = self.lock();
        let rows: Vec<String> = c.smembers(&set).store()?;
        let mut out = Vec::with_capacity(rows.len());
        for row_key in rows {
            let fields: Vec<(String, String)> = c.hgetall(&row_key).store()?;
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
        let mut c = self.lock();
        let _: () = c
            .set(format!("{AWSCRED_PREFIX}{}", cred.access_key_id), json)
            .store()?;
        let _: () = c.sadd(AWSCRED_INDEX, &cred.access_key_id).store()?;
        // Map the owning virtual key → its AccessKeyIds so delete_key can remove them.
        let _: () = c
            .sadd(
                format!("{AWSCRED_IDS_PREFIX}{}", cred.key_id),
                &cred.access_key_id,
            )
            .store()?;
        Ok(())
    }

    fn put_key_with_aws_credential(
        &self,
        key: &VirtualKey,
        cred: &AwsCredential,
    ) -> StoreResult<()> {
        // Redis has no cross-key transaction in this sync build; put both, key first. If the second
        // write fails the caller sees the error and can retry — the same at-least-once posture the
        // trait's default sequential fallback provides, made explicit here to also index the credential.
        self.put_key(key)?;
        self.put_aws_credential(cred)?;
        Ok(())
    }

    fn list_aws_credentials(&self) -> StoreResult<Vec<AwsCredential>> {
        let mut c = self.lock();
        let ids: Vec<String> = c.smembers(AWSCRED_INDEX).store()?;
        let mut out = Vec::with_capacity(ids.len());
        for akid in ids {
            if let Some(raw) = c
                .get::<_, Option<String>>(format!("{AWSCRED_PREFIX}{akid}"))
                .store()?
            {
                let cred: AwsCredential = serde_json::from_str(&raw)
                    .map_err(|e| StoreError(format!("aws credential decode failed: {e}")))?;
                out.push(cred);
            }
        }
        Ok(out)
    }

    fn append_audit(&self, entry: &AuditRecord) -> StoreResult<()> {
        // The audit log's durable home: a SORTED SET scored by `seq` (the engine's monotonic sequence),
        // each member the JSON record. ZADD upserts on the member; using `seq` as the score keeps the
        // set ordered for list_audit. A replay of the same record is a no-op re-add (idempotent).
        let json = serde_json::to_string(entry)
            .map_err(|e| StoreError(format!("audit encode failed: {e}")))?;
        let _: () = self
            .lock()
            .zadd(AUDIT_ZSET, json, clamp(entry.seq))
            .store()?;
        Ok(())
    }

    fn list_audit(&self) -> StoreResult<Vec<AuditRecord>> {
        // ZRANGE 0..-1 returns members ordered by score (seq) ascending = oldest-first, the boot
        // restore order the engine expects.
        let members: Vec<String> = self.lock().zrange(AUDIT_ZSET, 0, -1).store()?;
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

    /// End-to-end against a REAL Redis, gated on `REDIS_URL` (a docker `redis:7` service in CI).
    /// Skips cleanly when unset LOCALLY so the default `cargo test` needs no server — but MUST NOT
    /// silently skip in CI: CI provisions the service and sets `REDIS_URL` (see
    /// .github/workflows/ci.yml), so when `CI` is set the missing URL is a HARD FAILURE rather than a
    /// silent skip (P1 #6 — same discipline as the Postgres backend's `BUSBAR_TEST_POSTGRES_URL`).
    #[test]
    fn roundtrip_against_live_redis() {
        let url = match std::env::var("REDIS_URL") {
            Ok(url) => url,
            Err(_) if std::env::var_os("CI").is_some() => {
                panic!(
                    "REDIS_URL is unset under CI: the Redis service container must provision it (see \
                     .github/workflows/ci.yml). Refusing to silently skip the only live-DB coverage \
                     in CI."
                );
            }
            Err(_) => {
                eprintln!("skip: set REDIS_URL to run the Redis store test");
                return;
            }
        };
        let store = RedisStore::connect(&url).expect("connect");
        // Isolate from any prior run.
        let _ = store.delete_key("vk_redis");

        let key = VirtualKey {
            id: "vk_redis".into(),
            key_hash: "h".into(),
            name: "redis".into(),
            allowed_pools: vec!["prod,special".into()],
            max_budget_cents: Some(1234),
            budget_period: "total".into(),
            rpm_limit: Some(60),
            tpm_limit: None,
            enabled: true,
            created_at: 99,
        };
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

        // Usage: absolute HSET round-trips.
        store.put_usage("vk_redis", 100, 42, 9, 3).unwrap();
        let u = store.get_usage("vk_redis", 100).unwrap();
        assert_eq!((u.spend_cents, u.tokens, u.requests), (42, 9, 3));

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
        // Clear any prior audit from a previous run first.
        let mut c = store.lock();
        let _: () = c.del(AUDIT_ZSET).store().unwrap();
        drop(c);
        store.append_audit(&rec(1, "", "h1")).unwrap();
        store.append_audit(&rec(2, "h1", "h2")).unwrap();
        let audit = store.list_audit().unwrap();
        assert_eq!(audit.len(), 2);
        assert_eq!((audit[0].seq, audit[1].seq), (1, 2), "oldest-first by seq");
        assert_eq!(audit[1].prev_hash, "h1");

        // Attach an AWS credential so the delete cascade over credentials is actually exercised —
        // the credential-cleanup path P1 #6 flagged as untested.
        let cred = AwsCredential {
            access_key_id: "AKIA_REDIS_TEST".into(),
            key_id: "vk_redis".into(),
            secret_access_key: "s3cr3t".into(),
        };
        store.put_aws_credential(&cred).unwrap();
        assert!(
            store
                .list_aws_credentials()
                .unwrap()
                .iter()
                .any(|c| c.access_key_id == "AKIA_REDIS_TEST"),
            "the AWS credential must be present before delete_key"
        );

        // Delete removes the key, its usage, and its AWS creds.
        store.delete_key("vk_redis").unwrap();
        assert!(store.get_key("vk_redis").unwrap().is_none());
        assert_eq!(store.get_usage("vk_redis", 100).unwrap(), Usage::default());
        assert!(
            !store
                .list_aws_credentials()
                .unwrap()
                .iter()
                .any(|c| c.access_key_id == "AKIA_REDIS_TEST"),
            "delete_key must cascade to the AWS credentials (credential cleanup, P1 #6)"
        );
    }
}
