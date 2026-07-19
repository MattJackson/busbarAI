// SPDX-License-Identifier: Apache-2.0
//! Shared machinery for self-minting, auto-refreshing **bearer-token** egress credentials.
//!
//! Both OAuth mechanisms busbar ships — `jwt-bearer` (RFC 7523) and `oauth-client-credentials`
//! (RFC 6749 §4.4) — obtain a short-lived bearer from a token endpoint and attach it as
//! `Authorization: Bearer <token>`. They differ ONLY in how a token is minted (sign a JWT vs. POST
//! client credentials). This module owns everything else: the cached token, the `headers_for`
//! read, and the background refresh loop. A mechanism supplies a [`Minter`] closure and gets a ready
//! [`CredentialProvider`] back.
//!
//! [`CredentialProvider::headers_for`] is SYNCHRONOUS and runs inline on the hot path, so minting (an
//! async round-trip) happens in a background task, not there. The task holds a `Weak` to the provider,
//! so a config reload that drops the lane also stops its refresher (no task leak).

use super::CredentialProvider;
use crate::proto::SigningContext;
use axum::http::{HeaderName, HeaderValue};
use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, RwLock, Weak};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// Refresh this many seconds BEFORE the token's stated expiry, so a request never races an expired
/// token across the refresh boundary.
const REFRESH_SKEW_SECS: u64 = 300;
/// Floor on the refresh sleep so a short-lived / already-near-expiry token can't spin the loop hot,
/// and the retry delay after a mint failure.
const MIN_SLEEP_SECS: u64 = 30;

/// A minted access token and the wall-clock epoch second it expires at.
pub(crate) struct CachedToken {
    pub(crate) token: String,
    pub(crate) expires_at: u64,
}

/// The future a [`Minter`] returns — a fresh token or a human-readable error.
pub(crate) type MintFuture = Pin<Box<dyn Future<Output = Result<CachedToken, String>> + Send>>;
/// A mechanism's "get me a fresh token" hook. Called on entry and before each expiry.
pub(crate) type Minter = Arc<dyn Fn() -> MintFuture + Send + Sync>;
/// The boot-path return shape shared by the OAuth `build` functions and `egress_auth::resolve`.
pub(crate) type CredentialProviderArc = Arc<dyn CredentialProvider>;

/// A bearer credential backed by a background-refreshed cached token.
pub(crate) struct BearerToken {
    token: RwLock<Arc<CachedToken>>,
}

impl CredentialProvider for BearerToken {
    fn headers_for(&self, _key: &str, _ctx: &SigningContext) -> Vec<(HeaderName, HeaderValue)> {
        // A self-minting credential ignores the per-request `key`. Read the current cached token; if
        // it is empty (the boot window before the first mint) or un-encodable, emit NO auth header
        // (upstream 401 — the same fail-closed shape as an un-encodable static key).
        // Recover from a poisoned lock rather than panic: the guarded value is always a valid
        // `Arc<CachedToken>`, and this runs inline on the request hot path — a panic here would 500 a
        // request over a lock another thread poisoned. (The critical sections are a trivial Arc clone
        // and an Arc assignment, neither of which can panic, so poisoning is effectively unreachable.)
        let cached = self.token.read().unwrap_or_else(|e| e.into_inner()).clone();
        if cached.token.is_empty() {
            return Vec::new();
        }
        match HeaderValue::from_str(&format!("Bearer {}", cached.token)) {
            Ok(v) => vec![(HeaderName::from_static("authorization"), v)],
            Err(_) => {
                tracing::warn!(
                    "minted an OAuth token with bytes invalid for an HTTP header value; omitting the \
                     auth header — upstream will reject with 401"
                );
                Vec::new()
            }
        }
    }

    /// Ready once the first mint has populated a non-empty token. Before that (the boot/reload window)
    /// `headers_for` emits no auth header, so the prober skips this lane rather than 401-parking it.
    fn is_ready(&self) -> bool {
        !self
            .token
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .token
            .is_empty()
    }
}

/// Build a bearer credential from a [`Minter`]: start with an empty token and spawn the background
/// refresher (which mints immediately and re-mints before expiry). When no tokio runtime is present
/// (e.g. a sync construction test) the refresher is skipped and the credential simply holds no token.
pub(crate) fn spawn(minter: Minter) -> CredentialProviderArc {
    let provider = Arc::new(BearerToken {
        token: RwLock::new(Arc::new(CachedToken {
            token: String::new(),
            expires_at: 0,
        })),
    });
    if let Ok(handle) = tokio::runtime::Handle::try_current() {
        let weak = Arc::downgrade(&provider);
        handle.spawn(async move { refresh_loop(minter, weak).await });
    }
    provider
}

/// Seconds to sleep before the next re-mint, given a token that expires at `expires_at` (epoch secs).
///
/// Refresh `REFRESH_SKEW_SECS` BEFORE expiry for a normally-lived token so a request never races the
/// expiry boundary. But that skew cannot be honored for a SHORT-TTL token: the old
/// `(ttl - SKEW).max(MIN_SLEEP)` floored the sleep back up to `MIN_SLEEP_SECS` (30s) even for a token
/// that expired in, say, 10s — so `headers_for` served an EXPIRED bearer for ~20s and the upstream 401'd
/// (1.4.0 audit, egress-auth). Instead:
///   - `ttl == 0` (already expired / garbage `expires_in ≈ 0`): back off `MIN_SLEEP_SECS` so the mint
///     loop cannot spin hot — nothing useful to serve, fail safe.
///   - `ttl <= REFRESH_SKEW_SECS` (too short to refresh a full skew early): re-mint at ~half the
///     remaining life, so the refresh always lands BEFORE expiry (never past `ttl`), and never below 1s.
///   - otherwise: the normal `ttl - REFRESH_SKEW_SECS`, with `MIN_SLEEP_SECS` as a hot-loop floor near
///     the skew boundary.
///
/// Guarantees: for any `ttl > 0` the next mint is scheduled strictly before expiry (no expired token is
/// served); for `ttl == 0` the loop is rate-limited to `MIN_SLEEP_SECS`.
fn next_refresh_secs(expires_at: u64, now: u64) -> u64 {
    let ttl = expires_at.saturating_sub(now);
    if ttl == 0 {
        MIN_SLEEP_SECS
    } else if ttl <= REFRESH_SKEW_SECS {
        (ttl / 2).max(1)
    } else {
        (ttl - REFRESH_SKEW_SECS).max(MIN_SLEEP_SECS)
    }
}

/// Mint (immediately on entry), store, then sleep until shortly before expiry and repeat. Exits when
/// the provider is dropped (config reload) so the task never outlives its lane.
async fn refresh_loop(minter: Minter, weak: Weak<BearerToken>) {
    loop {
        match minter().await {
            Ok(fresh) => {
                let expires_at = fresh.expires_at;
                match weak.upgrade() {
                    Some(p) => {
                        *p.token.write().unwrap_or_else(|e| e.into_inner()) = Arc::new(fresh)
                    }
                    None => return, // provider dropped — stop refreshing
                }
                let sleep_secs = next_refresh_secs(expires_at, now_epoch());
                tokio::time::sleep(Duration::from_secs(sleep_secs)).await;
            }
            Err(e) => {
                // Keep serving whatever token is current; retry soon. If retries keep failing past
                // expiry, `headers_for` emits a stale/empty token → upstream 401, classified like any
                // auth failure by the breaker.
                tracing::warn!(error = %e, "OAuth token mint failed; will retry");
                if weak.upgrade().is_none() {
                    return;
                }
                tokio::time::sleep(Duration::from_secs(MIN_SLEEP_SECS)).await;
            }
        }
    }
}

pub(crate) fn now_epoch() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    impl BearerToken {
        pub(crate) fn with_token_for_test(token: &str) -> Self {
            BearerToken {
                token: RwLock::new(Arc::new(CachedToken {
                    token: token.to_string(),
                    expires_at: 0,
                })),
            }
        }
    }

    fn ctx() -> SigningContext<'static> {
        SigningContext {
            host: "example.com".to_string(),
            canonical_uri: "/x".to_string(),
            body: b"{}",
            timestamp_epoch: 0,
            upstream_creds: crate::auth::UpstreamCreds::Own,
        }
    }

    #[test]
    fn headers_for_emits_bearer_and_ignores_key() {
        let c = BearerToken::with_token_for_test("tok-abc");
        let h = c.headers_for("ignored", &ctx());
        assert_eq!(h.len(), 1);
        assert_eq!(h[0].0.as_str(), "authorization");
        assert_eq!(h[0].1.to_str().unwrap(), "Bearer tok-abc");
    }

    #[test]
    fn headers_for_emits_nothing_before_first_mint() {
        assert!(BearerToken::with_token_for_test("")
            .headers_for("k", &ctx())
            .is_empty());
    }

    // 1.4.0 audit: the prober consults `is_ready` to SKIP an OAuth lane whose first token has not
    // minted (empty token) — probing it would send no auth header and the guaranteed 401 could
    // HardDown-park a healthy lane. Ready only once a non-empty token is present.
    #[test]
    fn is_ready_false_before_first_mint_true_after() {
        assert!(!BearerToken::with_token_for_test("").is_ready());
        assert!(BearerToken::with_token_for_test("tok").is_ready());
    }

    // 1.4.0 audit (egress-auth): a short-TTL token must be re-minted BEFORE it expires — the old
    // `(ttl - SKEW).max(MIN_SLEEP)` floored the sleep to 30s even for a 10s token, serving it expired.
    #[test]
    fn next_refresh_never_sleeps_past_a_live_token_expiry() {
        let now = 1_000_000;
        // Long TTL: refresh REFRESH_SKEW early, floored at MIN_SLEEP.
        assert_eq!(next_refresh_secs(now + 3600, now), 3600 - REFRESH_SKEW_SECS);
        // Short TTL (< skew): refresh at ~half-life — strictly before expiry, NOT floored to 30s.
        assert_eq!(next_refresh_secs(now + 10, now), 5);
        assert!(
            next_refresh_secs(now + 10, now) < 10,
            "must land before the 10s expiry"
        );
        assert_eq!(next_refresh_secs(now + 60, now), 30);
        assert_eq!(next_refresh_secs(now + 1, now), 1);
        // Already-expired / garbage (ttl==0): back off MIN_SLEEP so the mint loop can't spin hot.
        assert_eq!(next_refresh_secs(now, now), MIN_SLEEP_SECS);
        assert_eq!(next_refresh_secs(now - 100, now), MIN_SLEEP_SECS);
    }

    /// LOW: `headers_for` runs inline on the request hot path, so a POISONED lock must be recovered,
    /// not panicked over (a panic there would 500 a request because some other thread poisoned the
    /// lock). Poison the RwLock by panicking while holding the write guard, then assert `headers_for`
    /// still returns the Bearer (via `into_inner`). Red-before: with `.expect(...)` instead of
    /// `.unwrap_or_else(|e| e.into_inner())` this call panics on the poisoned lock.
    #[test]
    fn headers_for_recovers_from_poisoned_lock() {
        let c = Arc::new(BearerToken::with_token_for_test("tok-poison"));
        let c2 = c.clone();
        let _ = std::thread::spawn(move || {
            let _g = c2.token.write().unwrap();
            panic!("poison the lock");
        })
        .join();
        assert!(
            c.token.read().is_err(),
            "precondition: the write-guard panic must have poisoned the lock"
        );
        let h = c.headers_for("k", &ctx());
        assert_eq!(h.len(), 1, "poisoned lock must still yield the auth header");
        assert_eq!(h[0].1.to_str().unwrap(), "Bearer tok-poison");
    }
}
