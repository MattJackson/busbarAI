// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The CREDENTIAL CACHE (design-hooks-v2 §2.5): short-circuit repeat authentications so an
//! external auth module (a directory lookup over a socket) is consulted once per credential per
//! TTL, not once per request. In-process modules are microseconds and gain nothing, but they ride
//! the same seam — the cache is engine machinery, not module policy.
//!
//! Rules (spec-fixed):
//! - Key = `(module_name, SHA-256(credential bytes))` — the credential itself is NEVER stored.
//! - `Identify` cached with the module-suggested TTL (`Principal::ttl_secs`), clamped to a hard
//!   engine cap; absent = the engine default.
//! - `Pass` ("not mine") cached with a short jittered TTL so a prober can't use cache hits as a
//!   recently-probed timing oracle.
//! - `Reject` is NEVER cached: an invalid credential re-runs the module every time (fail-closed,
//!   and revocation is instant for the deny path by construction).
//! - Bounded: at capacity, expired entries are swept, then the oldest-inserted evicted.
//! - `flush(module)` / `flush_all()` — wired to the admin flush endpoint for instant revocation
//!   of the CACHED-ALLOW window.

use crate::auth::{AuthOutcome, Principal};
use std::collections::HashMap;
use std::sync::Mutex;

/// Default TTL for a cached `Identify` when the module suggests none, seconds.
const DEFAULT_IDENTIFY_TTL_SECS: u64 = 300;
/// Hard cap on any module-suggested `Identify` TTL, seconds — a module cannot pin a credential
/// valid for longer than this, no matter what it asks for.
const MAX_IDENTIFY_TTL_SECS: u64 = 3600;
/// Base TTL for a cached `Pass`, seconds (short: "not mine" can become "mine" after a directory
/// change, and the window bounds the staleness).
const PASS_TTL_SECS: u64 = 5;
/// Maximum cached entries across all modules.
const MAX_ENTRIES: usize = 4096;

/// A cacheable verdict: only the two outcomes the rules allow.
#[derive(Clone)]
enum CachedVerdict {
    Identify(Principal),
    Pass,
}

struct Entry {
    expires_at: u64,
    inserted_seq: u64,
    verdict: CachedVerdict,
}

/// The cache key: `(module_name, sha256_hex(credential))`.
type CacheKey = (String, String);

pub(crate) struct CredentialCache {
    /// The entry map plus a monotonic insert counter (the eviction ordering).
    entries: Mutex<(HashMap<CacheKey, Entry>, u64)>,
}

impl CredentialCache {
    pub(crate) fn new() -> Self {
        Self {
            entries: Mutex::new((HashMap::new(), 0)),
        }
    }

    /// Look up a cached verdict for `(module, credential)` at time `now`. `None` = miss (expired
    /// entries are treated as misses and removed).
    pub(crate) fn get(&self, module: &str, credential: &str, now: u64) -> Option<AuthOutcome> {
        let key = (
            module.to_string(),
            crate::sigv4::sha256_hex(credential.as_bytes()),
        );
        let mut guard = self.entries.lock().unwrap_or_else(|e| e.into_inner());
        match guard.0.get(&key) {
            Some(e) if e.expires_at > now => Some(match &e.verdict {
                CachedVerdict::Identify(p) => AuthOutcome::Identify(p.clone()),
                CachedVerdict::Pass => AuthOutcome::Pass,
            }),
            Some(_) => {
                guard.0.remove(&key);
                None
            }
            None => None,
        }
    }

    /// Store a module's verdict per the §2.5 rules. `Reject` is dropped on the floor — never
    /// cached. The `Identify` TTL is the module's suggestion clamped to the hard cap; `Pass` gets
    /// the short base TTL plus a per-key jitter (derived from the credential hash — deterministic,
    /// no clock/RNG — so distinct credentials expire at distinct offsets).
    pub(crate) fn put(&self, module: &str, credential: &str, outcome: &AuthOutcome, now: u64) {
        let hash = crate::sigv4::sha256_hex(credential.as_bytes());
        let (verdict, ttl) = match outcome {
            AuthOutcome::Identify(p) => (
                CachedVerdict::Identify(p.clone()),
                p.ttl_secs
                    .unwrap_or(DEFAULT_IDENTIFY_TTL_SECS)
                    .min(MAX_IDENTIFY_TTL_SECS),
            ),
            AuthOutcome::Pass => {
                // 0..=2s of deterministic per-key jitter on top of the base.
                let jitter = u64::from(hash.as_bytes()[0] % 3);
                (CachedVerdict::Pass, PASS_TTL_SECS + jitter)
            }
            AuthOutcome::Reject => return,
        };
        let mut guard = self.entries.lock().unwrap_or_else(|e| e.into_inner());
        let (map, seq) = &mut *guard;
        if map.len() >= MAX_ENTRIES {
            map.retain(|_, e| e.expires_at > now);
            if map.len() >= MAX_ENTRIES {
                // Still full of live entries: evict the oldest-inserted (bounded > perfect LRU).
                if let Some(k) = map
                    .iter()
                    .min_by_key(|(_, e)| e.inserted_seq)
                    .map(|(k, _)| k.clone())
                {
                    map.remove(&k);
                }
            }
        }
        *seq += 1;
        map.insert(
            (module.to_string(), hash),
            Entry {
                expires_at: now + ttl,
                inserted_seq: *seq,
                verdict,
            },
        );
    }

    /// Drop every cached verdict for one module (its partition) — the settings-change /
    /// revocation seam.
    pub(crate) fn flush_module(&self, module: &str) -> usize {
        let mut guard = self.entries.lock().unwrap_or_else(|e| e.into_inner());
        let before = guard.0.len();
        guard.0.retain(|(m, _), _| m != module);
        before - guard.0.len()
    }

    /// Drop everything — the admin flush endpoint's no-body form (instant revocation of every
    /// cached-allow window).
    pub(crate) fn flush_all(&self) -> usize {
        let mut guard = self.entries.lock().unwrap_or_else(|e| e.into_inner());
        let n = guard.0.len();
        guard.0.clear();
        n
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ident(ttl: Option<u64>) -> AuthOutcome {
        let mut p = Principal::from_id("u1");
        p.ttl_secs = ttl;
        AuthOutcome::Identify(p)
    }

    /// The §2.5 verdict rules: Identify cached (module TTL clamped), Pass cached short,
    /// Reject NEVER cached; expiry is a miss.
    #[test]
    fn verdict_rules_and_expiry() {
        let c = CredentialCache::new();
        let t = 1_000_000;

        c.put("m", "cred-a", &ident(None), t);
        assert!(matches!(
            c.get("m", "cred-a", t + DEFAULT_IDENTIFY_TTL_SECS - 1),
            Some(AuthOutcome::Identify(_))
        ));
        assert!(
            c.get("m", "cred-a", t + DEFAULT_IDENTIFY_TTL_SECS + 1)
                .is_none(),
            "expired Identify is a miss"
        );

        // Module-suggested TTL is CLAMPED to the hard cap.
        c.put("m", "cred-b", &ident(Some(999_999)), t);
        assert!(
            c.get("m", "cred-b", t + MAX_IDENTIFY_TTL_SECS + 1)
                .is_none(),
            "a module cannot exceed the hard TTL cap"
        );

        // Pass cached briefly (base + ≤2s jitter)…
        c.put("m", "cred-c", &AuthOutcome::Pass, t);
        assert!(matches!(
            c.get("m", "cred-c", t + 1),
            Some(AuthOutcome::Pass)
        ));
        assert!(c.get("m", "cred-c", t + PASS_TTL_SECS + 3).is_none());

        // …and Reject NEVER lands.
        c.put("m", "cred-d", &AuthOutcome::Reject, t);
        assert!(
            c.get("m", "cred-d", t + 1).is_none(),
            "Reject is never cached"
        );
    }

    /// Partitions are per-module: same credential under two modules is two entries, and a module
    /// flush drops exactly its own.
    #[test]
    fn module_partitions_and_flush() {
        let c = CredentialCache::new();
        let t = 1_000_000;
        c.put("m1", "cred", &ident(None), t);
        c.put("m2", "cred", &ident(None), t);
        assert_eq!(c.flush_module("m1"), 1);
        assert!(c.get("m1", "cred", t + 1).is_none());
        assert!(
            c.get("m2", "cred", t + 1).is_some(),
            "other partitions untouched"
        );
        assert_eq!(c.flush_all(), 1);
        assert!(c.get("m2", "cred", t + 1).is_none());
    }

    /// The bound holds: at capacity the oldest-inserted live entry is evicted, never unbounded
    /// growth.
    #[test]
    fn bounded_eviction() {
        let c = CredentialCache::new();
        let t = 1_000_000;
        for i in 0..MAX_ENTRIES {
            c.put("m", &format!("cred-{i}"), &ident(Some(3600)), t);
        }
        c.put("m", "one-more", &ident(Some(3600)), t);
        let guard = c.entries.lock().unwrap();
        assert!(guard.0.len() <= MAX_ENTRIES, "cap held: {}", guard.0.len());
        drop(guard);
        assert!(
            c.get("m", "cred-0", t + 1).is_none(),
            "the oldest-inserted entry was the eviction victim"
        );
        assert!(c.get("m", "one-more", t + 1).is_some());
    }
}
