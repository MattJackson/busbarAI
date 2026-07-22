// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The DEFAULT `db` backend: an in-memory (RAM) store. Zero setup, no dependencies beyond the
//! `busbar-api` contract — governance works out of the box. EPHEMERAL: every counter, key, and
//! credential is lost on restart; configure a durable backend (e.g. `store-sqlite`/`store-postgres`)
//! for persistence. Poison-recovering locks (the governance surface must never panic on a request).

use busbar_api::{
    AwsCredential, MeteringDelta, MeteringRow, Store, StoreResult, UsageDelta, UsageLedger,
    VirtualKey,
};
use std::collections::HashMap;
use std::sync::RwLock;

/// In-memory `Store`: keys by id, AWS credentials by access-key-id, token ledgers keyed by
/// (bucket_id, window_start), metering rows keyed by (key_id, bucket, model, provider).
#[derive(Default)]
pub struct MemoryStore {
    keys: RwLock<HashMap<String, VirtualKey>>,
    creds: RwLock<HashMap<String, AwsCredential>>,
    usage: RwLock<HashMap<(String, u64), UsageLedger>>,
    metering: RwLock<HashMap<(String, u64, String, String), MeteringRow>>,
}

impl MemoryStore {
    pub fn new() -> Self {
        Self::default()
    }
    fn keys(&self) -> std::sync::RwLockWriteGuard<'_, HashMap<String, VirtualKey>> {
        self.keys.write().unwrap_or_else(|e| e.into_inner())
    }
    fn creds(&self) -> std::sync::RwLockWriteGuard<'_, HashMap<String, AwsCredential>> {
        self.creds.write().unwrap_or_else(|e| e.into_inner())
    }
    fn usage(&self) -> std::sync::RwLockWriteGuard<'_, HashMap<(String, u64), UsageLedger>> {
        self.usage.write().unwrap_or_else(|e| e.into_inner())
    }
    fn metering(
        &self,
    ) -> std::sync::RwLockWriteGuard<'_, HashMap<(String, u64, String, String), MeteringRow>> {
        self.metering.write().unwrap_or_else(|e| e.into_inner())
    }
}

impl Store for MemoryStore {
    fn put_key(&self, key: &VirtualKey) -> StoreResult<()> {
        self.keys().insert(key.id.clone(), key.clone());
        Ok(())
    }

    fn get_key(&self, id: &str) -> StoreResult<Option<VirtualKey>> {
        Ok(self.keys().get(id).cloned())
    }

    fn list_keys(&self) -> StoreResult<Vec<VirtualKey>> {
        let mut v: Vec<VirtualKey> = self.keys().values().cloned().collect();
        v.sort_by_key(|k| k.created_at); // mirror SqliteStore's ORDER BY created_at
        Ok(v)
    }

    fn delete_key(&self, id: &str) -> StoreResult<()> {
        // Cascade, mirroring SqliteStore::delete_key: the key, its usage counters, and its AWS
        // credentials go together — a revoked key's credential must not outlive it.
        self.keys().remove(id);
        self.usage().retain(|(k, _), _| k != id);
        self.creds().retain(|_, c| c.key_id != id);
        Ok(())
    }

    fn get_usage(&self, bucket_id: &str, window_start: u64) -> StoreResult<UsageLedger> {
        Ok(self
            .usage()
            .get(&(bucket_id.to_string(), window_start))
            .cloned()
            .unwrap_or_default())
    }

    fn put_usage(
        &self,
        bucket_id: &str,
        window_start: u64,
        ledger: &UsageLedger,
    ) -> StoreResult<()> {
        // Write-behind ABSOLUTE set (memory is authoritative in the engine; this is durability only).
        self.usage()
            .insert((bucket_id.to_string(), window_start), ledger.clone());
        Ok(())
    }

    fn add_usage(&self, bucket_id: &str, window_start: u64, delta: &UsageDelta) -> StoreResult<()> {
        // ADDITIVE accumulate under the write lock (atomic within this process), floored at 0.
        let mut usage = self.usage();
        let u = usage
            .entry((bucket_id.to_string(), window_start))
            .or_default();
        u.apply_delta(delta);
        Ok(())
    }

    fn add_metering(&self, d: &MeteringDelta) -> StoreResult<()> {
        let mut m = self.metering();
        let e = m
            .entry((
                d.key_id.clone(),
                d.bucket,
                d.model.clone(),
                d.provider.clone(),
            ))
            .or_insert_with(|| MeteringRow {
                key_id: d.key_id.clone(),
                model: d.model.clone(),
                provider: d.provider.clone(),
                tokens_input: 0,
                tokens_output: 0,
                tokens_cache_read: 0,
                tokens_cache_creation: 0,
                requests: 0,
            });
        e.tokens_input = e.tokens_input.saturating_add(d.tokens_input);
        e.tokens_output = e.tokens_output.saturating_add(d.tokens_output);
        e.tokens_cache_read = e.tokens_cache_read.saturating_add(d.tokens_cache_read);
        e.tokens_cache_creation = e
            .tokens_cache_creation
            .saturating_add(d.tokens_cache_creation);
        e.requests = e.requests.saturating_add(1);
        Ok(())
    }

    fn list_metering(&self, bucket: u64) -> StoreResult<Vec<MeteringRow>> {
        Ok(self
            .metering()
            .iter()
            .filter(|((_, b, _, _), _)| *b == bucket)
            .map(|(_, row)| row.clone())
            .collect())
    }

    fn put_aws_credential(&self, cred: &AwsCredential) -> StoreResult<()> {
        self.creds()
            .insert(cred.access_key_id.clone(), cred.clone());
        Ok(())
    }

    fn list_aws_credentials(&self) -> StoreResult<Vec<AwsCredential>> {
        Ok(self.creds().values().cloned().collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(id: &str) -> VirtualKey {
        VirtualKey {
            id: id.to_string(),
            key_hash: format!("h_{id}"),
            name: "t".to_string(),
            allowed_pools: vec![],
            max_budget_cents: None,
            budget_period: "total".to_string(),
            rpm_limit: None,
            tpm_limit: None,
            enabled: true,
            created_at: 0,
            budget_group: None,
            labels: std::collections::BTreeMap::new(),
        }
    }

    fn ledger(requests: u64, model: &str, input: u64, output: u64) -> UsageLedger {
        UsageLedger {
            requests,
            models: vec![busbar_api::ModelTokens {
                model: model.to_string(),
                tokens: busbar_api::TierTokens {
                    input,
                    output,
                    cache_read: 0,
                    cache_write: 0,
                },
            }],
        }
    }

    #[test]
    fn key_crud_and_ledger_roundtrip() {
        let s = MemoryStore::new();
        s.put_key(&key("a")).unwrap();
        assert_eq!(s.get_key("a").unwrap().unwrap().id, "a");
        assert_eq!(s.list_keys().unwrap().len(), 1);
        // absolute put_usage then read back
        s.put_usage("a", 0, &ledger(3, "m", 100, 40)).unwrap();
        let u = s.get_usage("a", 0).unwrap();
        assert_eq!(u.requests, 3);
        assert_eq!(u.tokens_for("m").unwrap().input, 100);
        // absolute overwrite (not additive)
        s.put_usage("a", 0, &ledger(1, "m", 20, 0)).unwrap();
        assert_eq!(
            s.get_usage("a", 0).unwrap().tokens_for("m").unwrap().input,
            20
        );
        // unknown window is default-empty
        assert_eq!(s.get_usage("a", 999).unwrap(), UsageLedger::default());
    }

    /// Additive per-model delta accumulate: two adds sum, a second model materializes its own row,
    /// and negative deltas floor at 0 (parity contract with sqlite/postgres/redis).
    #[test]
    fn add_usage_accumulates_per_model() {
        let s = MemoryStore::new();
        let d = UsageDelta {
            requests: 1,
            models: vec![busbar_api::ModelTokensDelta {
                model: "gpt-5".to_string(),
                tokens: busbar_api::TierTokensDelta {
                    input: 10,
                    output: 5,
                    cache_read: 1,
                    cache_write: 0,
                },
            }],
        };
        s.add_usage("bucket", 100, &d).unwrap();
        s.add_usage("bucket", 100, &d).unwrap();
        let u = s.get_usage("bucket", 100).unwrap();
        assert_eq!(u.requests, 2);
        let t = u.tokens_for("gpt-5").unwrap();
        assert_eq!((t.input, t.output, t.cache_read), (20, 10, 2));
        // Refund floors at zero.
        s.add_usage(
            "bucket",
            100,
            &UsageDelta {
                requests: -5,
                models: vec![],
            },
        )
        .unwrap();
        assert_eq!(s.get_usage("bucket", 100).unwrap().requests, 0);
    }

    #[test]
    fn delete_key_cascades_usage_and_creds() {
        let s = MemoryStore::new();
        s.put_key(&key("a")).unwrap();
        s.put_usage("a", 0, &ledger(1, "m", 5, 0)).unwrap();
        s.put_aws_credential(&AwsCredential {
            access_key_id: "AKIA1".to_string(),
            key_id: "a".to_string(),
            secret_access_key: "sek".to_string(),
        })
        .unwrap();
        s.delete_key("a").unwrap();
        assert!(s.get_key("a").unwrap().is_none());
        assert_eq!(s.get_usage("a", 0).unwrap(), UsageLedger::default());
        assert!(s.list_aws_credentials().unwrap().is_empty());
    }

    #[test]
    fn metering_accumulates_per_bucket() {
        let s = MemoryStore::new();
        let d = MeteringDelta {
            key_id: "a".to_string(),
            bucket: 7,
            model: "m".to_string(),
            provider: "p".to_string(),
            tokens_input: 10,
            tokens_output: 5,
            tokens_cache_read: 0,
            tokens_cache_creation: 0,
        };
        s.add_metering(&d).unwrap();
        s.add_metering(&d).unwrap();
        let rows = s.list_metering(7).unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].tokens_input, 20);
        assert_eq!(rows[0].requests, 2);
        assert!(s.list_metering(999).unwrap().is_empty());
    }
}
