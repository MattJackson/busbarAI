// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The **OIDC auth module as a droppable busbar plugin** — a `cdylib` that exports the auth C ABI
//! ([`busbar_plugin_abi::auth`]). Build it, drop the resulting `.so`/`.dll`/`.dylib` into the engine's
//! plugins folder, add `oidc` to `auth.chain`, and configure `auth.modules.oidc.config`; the engine
//! loads it in-process at boot over the auth ABI.
//!
//! All the OIDC logic (JWKS, JWT verification on `ring`, claim policy) lives in the `busbar-auth-oidc`
//! `lib` crate (which a custom build can also link statically). Here we only adapt the engine's JSON
//! config into an `OidcModule` — resolving the JWKS url (explicit or via OIDC discovery) with a real
//! HTTPS fetcher — and hand the trait object to the SDK, which emits the five extern-C symbols the
//! loader resolves.

use busbar_api::AuthModule;
use busbar_auth_oidc::{resolve_jwks_url, OidcConfig, OidcModule, ReqwestFetcher};
use std::time::Duration;

/// The bound on a JWKS / discovery HTTP fetch. Generous enough for a cold DNS + TLS handshake to a
/// public IdP, short enough that a hung endpoint can't wedge boot or the (cached) auth path.
const JWKS_FETCH_TIMEOUT: Duration = Duration::from_secs(10);

/// Construct an OIDC auth module from the JSON config the engine passes through `open`. Shape:
///
/// ```json
/// {
///   "issuer": "https://login.microsoftonline.com/<tenant-id>/v2.0",
///   "audience": "api://<client-id>",
///   "jwks_url": "https://login.microsoftonline.com/<tenant-id>/discovery/v2.0/keys",
///   "role_claim": "groups"
/// }
/// ```
///
/// `jwks_url` is optional — when omitted it is discovered from the issuer's OIDC discovery document.
fn open(cfg: &str) -> Result<Box<dyn AuthModule>, String> {
    let cfg: OidcConfig = if cfg.trim().is_empty() {
        return Err("oidc plugin requires config (issuer, audience); none provided".to_string());
    } else {
        serde_json::from_str(cfg).map_err(|e| format!("invalid oidc plugin config: {e}"))?
    };

    // The fetcher used both for discovery (if needed) and for JWKS refreshes.
    let fetcher = ReqwestFetcher::new(JWKS_FETCH_TIMEOUT)?;
    // Resolve the JWKS url at construction (fail boot loudly if discovery can't find it), so the hot
    // path never does discovery.
    let jwks_url = resolve_jwks_url(&cfg, &fetcher)?;
    // A SECOND fetcher instance for the live cache (the first was a borrow for discovery).
    let cache_fetcher = ReqwestFetcher::new(JWKS_FETCH_TIMEOUT)?;
    Ok(Box::new(OidcModule::new(
        &cfg,
        jwks_url,
        Box::new(cache_fetcher),
    )))
}

busbar_plugin_sdk::export_auth_plugin!(open);
