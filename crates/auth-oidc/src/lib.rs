// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! **OIDC auth module** for busbar — the first identity-provider auth PLUGIN. Validates an OpenID
//! Connect JWT (ID or access token) a caller presents as its bearer credential and maps it to a
//! [`busbar_api::Principal`]: verify the signature against the provider's JWKS, check `iss`/`aud`/
//! `exp`/`nbf`, and read the configured role claim (`groups` by default, or `roles` for Entra
//! app-roles) into the principal's GROUPS. busbar's own `group_map:` / `auth.modules.oidc:` config
//! then resolves those groups to governance grants and admin scope — the module asserts identity
//! only, never policy (design-hooks-v2 §2.3).
//!
//! This crate is the reusable LOGIC (usable statically). The dynamic `cdylib` that exports the auth C
//! ABI is the sibling `busbar-auth-oidc-plugin` crate.
//!
//! ## Crypto & dependencies
//!
//! Signature verification runs on `ring` — the crypto backend the whole workspace already uses (via
//! rustls). NO `jsonwebtoken`/`rsa`: that avoids RUSTSEC-2023-0071 (the Marvin RSA-timing advisory the
//! plugin-signing spike documented) and a second crypto stack. Crypto lives HERE in the plugin crate,
//! never in busbar core.
//!
//! ## Microsoft Entra ID (Azure AD) gotchas — handled here
//!
//! - **issuer** is `https://login.microsoftonline.com/<tenant-id>/v2.0`, **aud** is the app's
//!   client-id. Both are exact-matched.
//! - **group claims are GUIDs**, not names — the operator maps those GUIDs in `group_map:`.
//! - **>200 groups overage**: Entra omits the `groups` claim and instead emits `_claim_names` /
//!   `_claim_sources` markers pointing at the Graph API. busbar does NOT call Graph and does NOT
//!   silently degrade: [`OidcVerifier`] REJECTS such a token with a precise error pointing the
//!   operator at **app-roles** (`role_claim: roles`), whose count is bounded.

use busbar_api::{AuthModule, AuthOutcome, Principal};
use serde::Deserialize;
use serde_json::Value;
use std::time::{Duration, Instant};

pub mod cache;
pub mod jwks;
pub mod jwt;
mod reqwest_fetcher;

pub use cache::{JwksCache, JwksFetcher};
pub use reqwest_fetcher::ReqwestFetcher;

/// Default JWKS refetch bound (the kid-rotation rate limit) and TTL.
const DEFAULT_MIN_REFETCH_SECS: u64 = 60;
const DEFAULT_TTL_SECS: u64 = 3600;
/// Small clock-skew tolerance applied to `exp`/`nbf` (seconds) — standard practice so a few seconds of
/// clock drift between busbar and the IdP does not spuriously reject a just-issued / near-expiry token.
const CLOCK_SKEW_SECS: i64 = 60;

/// The operator's `auth.modules.oidc.config` settings, deserialized from the JSON the engine passes to
/// the plugin's `open`.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OidcConfig {
    /// The token `iss` to require, EXACT match. For Entra:
    /// `https://login.microsoftonline.com/<tenant-id>/v2.0`.
    pub issuer: String,
    /// The token `aud` to require, EXACT match. For Entra this is the application (client) id.
    pub audience: String,
    /// The JWKS endpoint. Optional: when absent it is derived from the issuer's OIDC discovery
    /// document (`<issuer>/.well-known/openid-configuration` → `jwks_uri`) at construction.
    #[serde(default)]
    pub jwks_url: Option<String>,
    /// Which token claim carries the caller's roles/groups → the principal's GROUPS. Default
    /// `groups`; set `roles` to use Entra app-roles (the bounded-count alternative that sidesteps the
    /// >200-groups overage).
    #[serde(default = "default_role_claim")]
    pub role_claim: String,
    /// JWKS refetch rate-limit (seconds) — the bound on the kid-rotation refetch. Default 60.
    #[serde(default = "default_min_refetch_secs")]
    pub jwks_min_refetch_secs: u64,
    /// JWKS cache TTL (seconds). Default 3600.
    #[serde(default = "default_ttl_secs")]
    pub jwks_ttl_secs: u64,
}

fn default_role_claim() -> String {
    "groups".to_string()
}
fn default_min_refetch_secs() -> u64 {
    DEFAULT_MIN_REFETCH_SECS
}
fn default_ttl_secs() -> u64 {
    DEFAULT_TTL_SECS
}

/// The pure token VERIFIER: config-derived policy (issuer/audience/role_claim) plus the current time
/// source. Separated from the module + JWKS cache so the whole verify path — signature aside — is unit
/// testable with plain claim maps. Signature verification is [`jwt::verify_signature`].
pub struct OidcVerifier {
    issuer: String,
    audience: String,
    role_claim: String,
}

/// The result of validating a token's CLAIMS (post-signature): the resolved principal, or a denial
/// reason. Kept separate from the signature step so tests can exercise claim policy directly.
impl OidcVerifier {
    pub fn new(
        issuer: impl Into<String>,
        audience: impl Into<String>,
        role_claim: impl Into<String>,
    ) -> Self {
        Self {
            issuer: issuer.into(),
            audience: audience.into(),
            role_claim: role_claim.into(),
        }
    }

    /// Validate a decoded claims object (signature ALREADY verified) and build the [`Principal`].
    /// Checks `iss`/`aud`/`exp`/`nbf` (with a small skew tolerance), detects the Entra >200-groups
    /// overage marker (REJECT, never call Graph), and reads `role_claim` into the principal's groups.
    /// `now_unix` is the current UNIX time in seconds.
    pub fn validate_claims(&self, claims: &Value, now_unix: i64) -> Result<Principal, String> {
        // iss — exact match. A wrong issuer is a different tenant / a token minted elsewhere.
        match claims.get("iss").and_then(Value::as_str) {
            Some(iss) if iss == self.issuer => {}
            Some(other) => {
                return Err(format!(
                    "token issuer '{other}' does not match the configured issuer"
                ))
            }
            None => return Err("token has no 'iss' claim".to_string()),
        }

        // aud — exact match. `aud` may be a string or an array of strings (RFC 7519); accept either
        // form and require the configured audience to be present.
        let aud_ok = match claims.get("aud") {
            Some(Value::String(s)) => s == &self.audience,
            Some(Value::Array(a)) => a.iter().any(|v| v.as_str() == Some(self.audience.as_str())),
            _ => false,
        };
        if !aud_ok {
            return Err("token audience does not match the configured audience".to_string());
        }

        // exp — required, must be in the future (with skew tolerance). A token with no exp is refused
        // (an unbounded credential).
        match claims.get("exp").and_then(Value::as_i64) {
            Some(exp) if exp + CLOCK_SKEW_SECS >= now_unix => {}
            Some(_) => return Err("token has expired".to_string()),
            None => return Err("token has no 'exp' claim".to_string()),
        }

        // nbf — optional; if present, must not be in the future (with skew tolerance).
        if let Some(nbf) = claims.get("nbf").and_then(Value::as_i64) {
            if nbf - CLOCK_SKEW_SECS > now_unix {
                return Err("token is not yet valid (nbf in the future)".to_string());
            }
        }

        // ENTRA >200-GROUPS OVERAGE: when a user is in more groups than the token can carry, Entra
        // omits the groups claim and emits `_claim_names` + `_claim_sources` pointing at Graph. We do
        // NOT call Graph and MUST NOT silently proceed with an empty group set (which would strip the
        // user's authorization). Reject with a precise pointer to app-roles — UNLESS the operator is
        // already using a role claim other than `groups` (app-roles don't overflow), in which case the
        // marker is irrelevant.
        if self.role_claim == "groups" && is_groups_overage(claims) {
            return Err(
                "token carries an Entra groups OVERAGE marker (_claim_names/_claim_sources): the \
                 user is in too many groups to fit the token, so the 'groups' claim was omitted. \
                 busbar does not call the Graph API to expand it. Switch this app to APP-ROLES and \
                 set role_claim: roles (app-role assignments are bounded and ride in the token), or \
                 reduce the user's group count."
                    .to_string(),
            );
        }

        // Roles/groups claim → principal ROLES (1.5.0: the field was renamed groups->roles). A missing/empty claim is NOT an error here (an unmapped
        // principal is denied downstream by group_map when default:deny); it just yields no groups.
        let groups = extract_string_list(claims.get(&self.role_claim));

        // Subject → stable principal id. Prefer a human-recognizable handle for audit
        // (`preferred_username` / `upn` / `email`), falling back to `oid` (Entra's stable object id)
        // or `sub`. Prefixed with the module name so ids never collide with a virtual-key id.
        let subject = claims
            .get("preferred_username")
            .and_then(Value::as_str)
            .or_else(|| claims.get("upn").and_then(Value::as_str))
            .or_else(|| claims.get("email").and_then(Value::as_str))
            .or_else(|| claims.get("oid").and_then(Value::as_str))
            .or_else(|| claims.get("sub").and_then(Value::as_str))
            .ok_or("token has no usable subject claim (sub/oid/upn/email)")?;

        let name = claims
            .get("name")
            .and_then(Value::as_str)
            .map(str::to_string);

        let mut principal = Principal::from_id(format!("oidc:{subject}"));
        principal.name = name;
        principal.roles = groups;
        Ok(principal)
    }
}

/// Detect the Entra groups-overage markers. Present ⇒ the token deliberately omitted the groups claim.
fn is_groups_overage(claims: &Value) -> bool {
    let names_has_groups = claims
        .get("_claim_names")
        .and_then(Value::as_object)
        .is_some_and(|o| o.contains_key("groups"));
    names_has_groups
        || claims.get("_claim_sources").is_some()
            && claims.get("groups").is_none()
            && claims.get("_claim_names").is_some()
}

/// Read a claim as a list of strings. Accepts a JSON array of strings OR a single string (a
/// space-free scalar role). Anything else yields an empty list.
fn extract_string_list(v: Option<&Value>) -> Vec<String> {
    match v {
        Some(Value::Array(a)) => a
            .iter()
            .filter_map(|x| x.as_str().map(str::to_string))
            .collect(),
        Some(Value::String(s)) => vec![s.clone()],
        _ => Vec::new(),
    }
}

/// The runtime OIDC auth module: a verifier + a JWKS cache. Implements [`busbar_api::AuthModule`].
pub struct OidcModule {
    verifier: OidcVerifier,
    jwks: JwksCache,
}

impl OidcModule {
    /// Construct from parsed config + an already-resolved JWKS url + a fetcher. The plugin's `open`
    /// resolves the JWKS url (explicit or via discovery) and supplies a real HTTPS fetcher; tests
    /// supply a fixture fetcher.
    pub fn new(cfg: &OidcConfig, jwks_url: String, fetcher: Box<dyn JwksFetcher>) -> Self {
        let jwks = JwksCache::new(
            jwks_url,
            fetcher,
            Duration::from_secs(cfg.jwks_min_refetch_secs),
            Duration::from_secs(cfg.jwks_ttl_secs),
        );
        Self {
            verifier: OidcVerifier::new(&cfg.issuer, &cfg.audience, &cfg.role_claim),
            jwks,
        }
    }

    /// The full verification of one presented bearer token → an [`AuthOutcome`]. Split from
    /// `authenticate` so it can be driven with an injected `now` in tests.
    fn verify(&self, token: &str, now_unix: i64, now_mono: Instant) -> AuthOutcome {
        let parts = match jwt::split(token) {
            Ok(p) => p,
            // Not a well-formed JWT ⇒ not our credential shape. `Pass` so a later chain module (or
            // the mode default) can handle it — a random opaque bearer is not an OIDC failure.
            Err(_) => return AuthOutcome::Pass,
        };
        let kid = parts.header.kid.clone().unwrap_or_default();

        // Verify the signature against the JWKS key for this kid (fetching / rotation-refetching as
        // needed). A signature or key error is a REJECT — a presented-but-invalid credential.
        if let Err(e) = self
            .jwks
            .with_key(&kid, now_mono, |key| jwt::verify_signature(&parts, key))
        {
            tracing::warn!(module = "oidc", error = %e, "OIDC token signature verification failed");
            return AuthOutcome::Reject;
        }

        let claims = match jwt::claims(&parts) {
            Ok(c) => c,
            Err(e) => {
                tracing::warn!(module = "oidc", error = %e, "OIDC token claims are malformed");
                return AuthOutcome::Reject;
            }
        };

        match self.verifier.validate_claims(&claims, now_unix) {
            Ok(principal) => AuthOutcome::Identify(principal),
            Err(e) => {
                tracing::warn!(module = "oidc", error = %e, "OIDC token claim validation failed");
                AuthOutcome::Reject
            }
        }
    }
}

impl AuthModule for OidcModule {
    fn name(&self) -> &'static str {
        "oidc"
    }

    fn authenticate(&self, candidate: Option<&str>) -> AuthOutcome {
        let Some(token) = candidate else {
            // No credential presented ⇒ not ours; defer.
            return AuthOutcome::Pass;
        };
        self.verify(token, now_unix(), Instant::now())
    }

    /// OIDC does real I/O (JWKS fetch) and its verdicts are safe to cache for the token's short life,
    /// so the engine's credential cache is worth using.
    fn cacheable(&self) -> bool {
        true
    }
}

/// Current UNIX time in seconds.
fn now_unix() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// Resolve the JWKS url from config: the explicit `jwks_url`, or discovered from the issuer's OIDC
/// discovery document. `fetcher` performs the discovery GET when needed.
pub fn resolve_jwks_url(cfg: &OidcConfig, fetcher: &dyn JwksFetcher) -> Result<String, String> {
    if let Some(url) = &cfg.jwks_url {
        return Ok(url.clone());
    }
    let discovery_url = format!(
        "{}/.well-known/openid-configuration",
        cfg.issuer.trim_end_matches('/')
    );
    let body = fetcher.fetch(&discovery_url).map_err(|e| {
        format!("OIDC discovery fetch failed ({discovery_url}): {e}; set jwks_url explicitly")
    })?;
    let doc: Value = serde_json::from_str(&body)
        .map_err(|e| format!("OIDC discovery document is not JSON: {e}"))?;
    doc.get("jwks_uri")
        .and_then(Value::as_str)
        .map(str::to_string)
        .ok_or_else(|| {
            "OIDC discovery document has no 'jwks_uri'; set jwks_url explicitly".to_string()
        })
}

#[cfg(test)]
mod tests;
