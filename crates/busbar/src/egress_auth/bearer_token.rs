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
        let cached = self
            .token
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .clone();
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
                let sleep_secs = expires_at
                    .saturating_sub(now_epoch())
                    .saturating_sub(REFRESH_SKEW_SECS)
                    .max(MIN_SLEEP_SECS);
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
}
