// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The real HTTPS [`JwksFetcher`] over `reqwest`'s BLOCKING client (rustls/ring TLS — the same stack
//! busbar already uses; no second TLS/crypto backend). Blocking because the auth `authenticate` path
//! is synchronous; JWKS fetches are rare (cached + TTL'd), so a blocking GET behind the cache lock is
//! fine and keeps the plugin free of an async runtime, matching the store plugins' synchronous
//! posture.

use crate::cache::JwksFetcher;
use std::time::Duration;

/// Bounded HTTPS fetcher. Holds one reusable blocking client with a connect + total timeout so a hung
/// or slow IdP can never hang auth.
pub struct ReqwestFetcher {
    client: reqwest::blocking::Client,
}

impl ReqwestFetcher {
    /// Build a fetcher with the given total request timeout.
    pub fn new(timeout: Duration) -> Result<Self, String> {
        let client = reqwest::blocking::Client::builder()
            .timeout(timeout)
            .connect_timeout(timeout)
            // HTTPS-only: a JWKS/discovery endpoint fetched over plaintext could be MITM'd to serve
            // attacker keys. `https_only` refuses any non-TLS URL.
            .https_only(true)
            .build()
            .map_err(|e| format!("failed to build JWKS HTTP client: {e}"))?;
        Ok(Self { client })
    }
}

impl JwksFetcher for ReqwestFetcher {
    fn fetch(&self, url: &str) -> Result<String, String> {
        let resp = self
            .client
            .get(url)
            .send()
            .map_err(|e| format!("request to {url} failed: {e}"))?;
        if !resp.status().is_success() {
            return Err(format!("{url} returned HTTP {}", resp.status()));
        }
        resp.text()
            .map_err(|e| format!("reading {url} response body failed: {e}"))
    }
}
