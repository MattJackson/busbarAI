// SPDX-License-Identifier: Apache-2.0
//! `oauth-client-credentials` egress auth — OAuth 2.0 client-credentials grant (RFC 6749 §4.4).
//!
//! The simplest OAuth machine-to-machine flow: POST `client_id` + `client_secret` (+ `scope`) to a
//! token endpoint and receive a short-lived bearer. No signing (unlike `jwt-bearer`). GENERIC —
//! **Azure OpenAI via Microsoft Entra ID / AAD** is the first consumer (token_url =
//! `https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token`, scope =
//! `https://cognitiveservices.azure.com/.default`), but any client-credentials backend works by
//! config.
//!
//! This module owns only the token exchange (the `mint`); the token cache, `headers_for` read, and
//! background refresh live in [`super::bearer_token`], shared with `jwt-bearer`.

use super::bearer_token::{now_epoch, CachedToken, CredentialProviderArc, Minter};
use std::sync::Arc;

/// The exchange material for one lane. Held in an `Arc` shared by the refresh task's mint calls.
struct ClientCreds {
    client_id: String,
    client_secret: String,
    token_url: String,
    scope: String,
    http: reqwest::Client,
}

/// Build an `oauth-client-credentials` credential. SYNCHRONOUS (runs on the shared
/// `build_app_from_config` path). `credential` is `client_id:client_secret` (the first `:` splits
/// them, so a secret may itself contain `:`). `token_url` and `scope` come from the provider config.
/// Fails loud on a malformed credential; the token itself mints in the background.
pub(crate) fn build(
    credential: &str,
    token_url: &str,
    scope: &str,
) -> Result<CredentialProviderArc, String> {
    let (client_id, client_secret) = split_credential(credential)?;
    validate_token_url(token_url)?;
    let creds = Arc::new(ClientCreds {
        client_id: client_id.to_string(),
        client_secret: client_secret.to_string(),
        token_url: token_url.to_string(),
        scope: scope.to_string(),
        http: super::minter_client(),
    });
    let minter: Minter = Arc::new(move || {
        let creds = creds.clone();
        Box::pin(async move { creds.mint().await })
    });
    Ok(super::bearer_token::spawn(minter))
}

/// Split + check a `client_id:client_secret` credential (the first `:` splits, so a secret may contain
/// `:`). Shared by [`build`] and [`validate_credential`] so the boot/apply path and the config
/// `--validate` dry-run enforce identical checks with identical messages.
fn split_credential(credential: &str) -> Result<(&str, &str), String> {
    let (client_id, client_secret) = credential
        .split_once(':')
        .ok_or("oauth-client-credentials key must be `client_id:client_secret`")?;
    if client_id.is_empty() || client_secret.is_empty() {
        return Err(
            "oauth-client-credentials key has an empty client_id or client_secret".to_string(),
        );
    }
    Ok((client_id, client_secret))
}

/// Validate an `oauth-client-credentials` credential WITHOUT constructing the provider — the config
/// `--validate` dry-run entry point (mirrors `jwt_bearer::validate_credential`, so a malformed
/// credential is caught at validate time for BOTH OAuth mechanisms, not only jwt-bearer). (found: 1.4.0
/// audit, egress-auth.)
pub(crate) fn validate_credential(credential: &str) -> Result<(), String> {
    split_credential(credential).map(|_| ())
}

/// Vet the `token_url` (the POST target for `client_id`/`client_secret`) for SSRF/https the same way
/// `jwt_bearer::validate_token_uri` vets the SA `token_uri`: https for a public host (http only for a
/// loopback/private endpoint), never a cloud-metadata/IMDS host. Called from [`build`] as
/// defense-in-depth so the check holds even if a future caller reaches `build` without config_validate
/// running first (the minter client already refuses redirects; this closes the direct-target case).
/// (found: 1.4.0 audit, egress-auth — parity with jwt-bearer, which validated its token endpoint but
/// oauth-client-credentials did not.)
fn validate_token_url(token_url: &str) -> Result<(), String> {
    use crate::config_validate::{
        extract_normalized_host, host_is_private_or_loopback, scheme_is, ssrf_blocked_host,
    };
    let host_private = extract_normalized_host(token_url)
        .as_deref()
        .map(host_is_private_or_loopback)
        .unwrap_or(false);
    if !(scheme_is(token_url, "https") || (host_private && scheme_is(token_url, "http"))) {
        return Err(format!(
            "oauth-client-credentials token_url must use https for a public host (got '{token_url}'); it receives the client_id/client_secret, so plaintext http is permitted only for a private/loopback endpoint"
        ));
    }
    if let Some(host) = ssrf_blocked_host(token_url, &[], false, &[]) {
        return Err(format!(
            "oauth-client-credentials token_url '{token_url}' targets a blocked cloud-metadata host '{host}' (the client credentials would be POSTed there; cloud-metadata/IMDS endpoints are denied)"
        ));
    }
    Ok(())
}

impl ClientCreds {
    /// Exchange the client credentials for an access token (RFC 6749 §4.4).
    async fn mint(&self) -> Result<CachedToken, String> {
        let now = now_epoch();
        // reqwest is built without the `json` feature here, so parse the response body manually.
        let resp = self
            .http
            .post(&self.token_url)
            .form(&[
                ("grant_type", "client_credentials"),
                ("client_id", self.client_id.as_str()),
                ("client_secret", self.client_secret.as_str()),
                ("scope", self.scope.as_str()),
            ])
            .send()
            .await
            .map_err(|e| format!("token endpoint request failed: {e}"))?;
        let status = resp.status();
        let body = resp
            .text()
            .await
            .map_err(|e| format!("reading token response failed: {e}"))?;
        if !status.is_success() {
            // Never echo the request (carries the client_secret); status + a short snippet only.
            return Err(format!(
                "token endpoint returned {status}: {}",
                body.chars().take(200).collect::<String>()
            ));
        }
        let tok: TokenResponse =
            serde_json::from_str(&body).map_err(|e| format!("token response JSON invalid: {e}"))?;
        Ok(CachedToken {
            token: tok.access_token,
            // saturating_add: `expires_in` is attacker-influenced (comes off the token endpoint), so a
            // huge value must clamp to u64::MAX rather than wrap/panic (1.4.0 audit, egress-auth).
            expires_at: now.saturating_add(tok.expires_in),
        })
    }
}

#[derive(serde::Deserialize)]
struct TokenResponse {
    access_token: String,
    #[serde(
        default = "super::default_expires_in",
        deserialize_with = "super::deserialize_expires_in"
    )]
    expires_in: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_rejects_a_credential_without_a_colon() {
        assert!(build("no-colon-here", "https://t", "s").is_err());
        assert!(build(":secret-only", "https://t", "s").is_err());
        assert!(build("id-only:", "https://t", "s").is_err());
    }

    // 1.4.0 audit (egress-auth): build() re-validates token_url for SSRF/https as defense-in-depth
    // (parity with jwt-bearer). A plaintext-http public token_url and a cloud-metadata/IMDS host are
    // rejected even with a well-formed credential; loopback http is allowed (local dev IdP).
    #[test]
    fn build_rejects_unsafe_token_url() {
        assert!(build("id:secret", "http://login.example.com/token", "s").is_err());
        assert!(build("id:secret", "https://169.254.169.254/token", "s").is_err());
        assert!(build("id:secret", "http://127.0.0.1:8080/token", "s").is_ok());
    }

    #[test]
    fn build_accepts_a_secret_containing_a_colon() {
        // Only the FIRST colon splits id:secret, so a secret with colons is preserved. Constructed
        // outside a runtime, so no mint is spawned — this just checks the credential parse.
        assert!(build("client-abc:secret:with:colons", "https://t", "s").is_ok());
    }

    // 1.4.0 audit (egress-auth): `expires_in` must tolerate a JSON number, a numeric string (ADFS /
    // Azure AD v1), and absence (defaulting to 1 h) — a strict u64 breaks minting for those IdPs.
    #[test]
    fn token_response_tolerates_expires_in_as_number_string_or_absent() {
        let num: TokenResponse =
            serde_json::from_str(r#"{"access_token":"a","expires_in":3600}"#).unwrap();
        assert_eq!(num.expires_in, 3600);
        let s: TokenResponse =
            serde_json::from_str(r#"{"access_token":"a","expires_in":"7200"}"#).unwrap();
        assert_eq!(s.expires_in, 7200);
        let absent: TokenResponse = serde_json::from_str(r#"{"access_token":"a"}"#).unwrap();
        assert_eq!(absent.expires_in, super::super::default_expires_in());
    }
}
