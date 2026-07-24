// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The JWKS cache: fetch-on-demand, TTL refresh, and a BOUNDED **kid-rotation refetch** — when a
//! token names a `kid` absent from the cached set (the provider rotated its signing key), refetch
//! once, rate-limited, and retry. Guards against a bogus-`kid` flood turning into a fetch storm.

use crate::jwks::JwkSet;
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// How a JWKS is fetched. A trait so the verification logic is testable WITHOUT network: the plugin
/// wires an HTTPS-fetching implementor; tests wire a fixture.
pub trait JwksFetcher: Send + Sync {
    /// GET the JWKS document body from the configured `jwks_uri`. Returns the raw JSON text or an
    /// error message. MUST be bounded (a timeout) — a hung provider must not hang auth.
    fn fetch(&self, url: &str) -> Result<String, String>;
}

/// A JWKS cache over a fetcher. Holds the last-fetched key set and the timestamps that bound refresh.
pub struct JwksCache {
    url: String,
    fetcher: Box<dyn JwksFetcher>,
    /// Minimum gap between refetches — the bound on the kid-rotation refetch (so a flood of tokens
    /// with unknown kids can force at most one fetch per this interval).
    min_refetch_interval: Duration,
    /// TTL after which the cached set is considered stale and proactively refetched on next use.
    ttl: Duration,
    inner: Mutex<Inner>,
}

struct Inner {
    keys: Option<JwkSet>,
    /// When the current `keys` were fetched.
    fetched_at: Option<Instant>,
    /// When the last fetch ATTEMPT ran (success or failure) — the rate-limit anchor.
    last_attempt: Option<Instant>,
}

impl JwksCache {
    /// A cache for `url` over `fetcher`, with the given rotation-refetch bound and TTL.
    pub fn new(
        url: impl Into<String>,
        fetcher: Box<dyn JwksFetcher>,
        min_refetch_interval: Duration,
        ttl: Duration,
    ) -> Self {
        Self {
            url: url.into(),
            fetcher,
            min_refetch_interval,
            ttl,
            inner: Mutex::new(Inner {
                keys: None,
                fetched_at: None,
                last_attempt: None,
            }),
        }
    }

    /// Run `f` against the key matching `kid`. If the cache is empty or stale, fetch first. If `kid`
    /// still misses after that (key ROTATION), refetch ONCE — rate-limited by `min_refetch_interval`
    /// — and retry. `f` receives the found key; a miss after the bounded refetch is a precise error.
    ///
    /// The whole operation holds the cache lock: JWKS fetches are infrequent (cached), and serializing
    /// them prevents a thundering-herd refetch when many requests arrive after a rotation.
    pub fn with_key<T>(
        &self,
        kid: &str,
        now: Instant,
        f: impl FnOnce(&crate::jwks::Jwk) -> Result<T, String>,
    ) -> Result<T, String> {
        let mut inner = self
            .inner
            .lock()
            .map_err(|_| "JWKS cache poisoned".to_string())?;

        // Ensure we have a (fresh enough) key set. Fetch when empty or past TTL.
        let stale = match inner.fetched_at {
            None => true,
            Some(t) => now.saturating_duration_since(t) >= self.ttl,
        };
        if inner.keys.is_none() || stale {
            self.try_fetch(&mut inner, now)?;
        }

        // First lookup.
        if let Some(set) = &inner.keys {
            if let Some(k) = set.find(kid) {
                return f(k);
            }
        }

        // Miss ⇒ possible key rotation. Refetch ONCE if the rate-limit permits, then retry.
        let may_refetch = match inner.last_attempt {
            None => true,
            Some(t) => now.saturating_duration_since(t) >= self.min_refetch_interval,
        };
        if may_refetch {
            self.try_fetch(&mut inner, now)?;
            if let Some(set) = &inner.keys {
                if let Some(k) = set.find(kid) {
                    return f(k);
                }
            }
        }

        Err(format!(
            "no JWKS key matches the token's kid '{kid}' (after a bounded rotation refetch); the \
             signing key is unknown to the configured jwks_url"
        ))
    }

    /// Fetch + parse the JWKS, updating the cache. Records the attempt time even on failure (so the
    /// rate limit applies to failures too). On a fetch/parse error the previous keys are KEPT (a
    /// transient provider blip must not blow away a working key set).
    fn try_fetch(&self, inner: &mut Inner, now: Instant) -> Result<(), String> {
        inner.last_attempt = Some(now);
        let body = self.fetcher.fetch(&self.url)?;
        let set = JwkSet::parse(&body)?;
        inner.keys = Some(set);
        inner.fetched_at = Some(now);
        Ok(())
    }
}
