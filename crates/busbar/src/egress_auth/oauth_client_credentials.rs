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
    let (client_id, client_secret) = credential
        .split_once(':')
        .ok_or("oauth-client-credentials key must be `client_id:client_secret`")?;
    if client_id.is_empty() || client_secret.is_empty() {
        return Err(
            "oauth-client-credentials key has an empty client_id or client_secret".to_string(),
        );
    }
    let creds = Arc::new(ClientCreds {
        client_id: client_id.to_string(),
        client_secret: client_secret.to_string(),
        token_url: token_url.to_string(),
        scope: scope.to_string(),
        http: reqwest::Client::new(),
    });
    let minter: Minter = Arc::new(move || {
        let creds = creds.clone();
        Box::pin(async move { creds.mint().await })
    });
    Ok(super::bearer_token::spawn(minter))
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
            expires_at: now + tok.expires_in,
        })
    }
}

#[derive(serde::Deserialize)]
struct TokenResponse {
    access_token: String,
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

    #[test]
    fn build_accepts_a_secret_containing_a_colon() {
        // Only the FIRST colon splits id:secret, so a secret with colons is preserved. Constructed
        // outside a runtime, so no mint is spawned — this just checks the credential parse.
        assert!(build("client-abc:secret:with:colons", "https://t", "s").is_ok());
    }
}
