// SPDX-License-Identifier: Apache-2.0
//! `jwt-bearer` egress auth — OAuth 2.0 JWT-bearer grant (RFC 7523), one of busbar's OAuth auth
//! mechanisms.
//!
//! GENERIC, not Google-specific: the flow is the standard `urn:ietf:params:oauth:grant-type:jwt-bearer`
//! grant — sign a JWT with a private key, POST the assertion to a token endpoint, receive a short-lived
//! bearer. The Google service-account JSON is merely a recognized *container* for the signing material
//! (`client_email` → JWT `iss`, `private_key` → the RS256 key, `token_uri` → JWT `aud`); the scope
//! defaults to `cloud-platform`. Vertex AI is the first provider to select `auth: jwt-bearer`.
//!
//! This module owns only the JWT signing + token exchange (the `mint`); the token cache, `headers_for`
//! read, and background refresh live in [`super::bearer_token`], shared with `oauth-client-credentials`.

use super::bearer_token::{now_epoch, CachedToken, CredentialProviderArc, Minter};
use base64::Engine as _;
use std::sync::Arc;

/// Default OAuth scope when the provider does not override it — the Vertex/GCP common case.
const DEFAULT_SCOPE: &str = "https://www.googleapis.com/auth/cloud-platform";

/// The signing + exchange material for one lane. Held in an `Arc` shared by the refresh task's mint
/// calls. Immutable after construction.
struct Signer {
    key_pair: ring::signature::RsaKeyPair,
    rng: ring::rand::SystemRandom,
    /// JWT `iss`/`sub` — the service account's `client_email`.
    issuer: String,
    /// JWT `aud` AND the POST target — the SA JSON `token_uri`.
    token_uri: String,
    scope: String,
    http: reqwest::Client,
}

/// Build a `jwt-bearer` credential. SYNCHRONOUS by design — it runs on the shared
/// `build_app_from_config` path (boot AND admin config-reload/dry-run), so it must not block on the
/// network. It PARSES the key material (failing loud on a malformed service-account JSON / PKCS#8 key,
/// the common misconfig) and hands a `mint` closure to [`super::bearer_token::spawn`], which mints the
/// first token in the background and refreshes it thereafter. `credential` is the SA JSON — inline
/// (starts with `{`) or a path to a key file. `scope_override` replaces the default `cloud-platform`
/// scope when set.
pub(crate) fn build(
    credential: &str,
    scope_override: Option<&str>,
) -> Result<CredentialProviderArc, String> {
    let sa_json = read_credential(credential)?;
    let sa: ServiceAccount = serde_json::from_str(&sa_json)
        .map_err(|e| format!("service-account JSON is invalid: {e}"))?;
    let der = pem_to_pkcs8_der(&sa.private_key)?;
    let key_pair = ring::signature::RsaKeyPair::from_pkcs8(&der)
        .map_err(|e| format!("service-account private_key is not a valid PKCS#8 RSA key: {e}"))?;

    let signer = Arc::new(Signer {
        key_pair,
        rng: ring::rand::SystemRandom::new(),
        issuer: sa.client_email,
        token_uri: sa.token_uri,
        scope: scope_override.unwrap_or(DEFAULT_SCOPE).to_string(),
        http: reqwest::Client::new(),
    });

    let minter: Minter = Arc::new(move || {
        let signer = signer.clone();
        Box::pin(async move { signer.mint().await })
    });
    Ok(super::bearer_token::spawn(minter))
}

impl Signer {
    /// Sign a JWT-bearer assertion and exchange it for an access token (RFC 7523).
    async fn mint(&self) -> Result<CachedToken, String> {
        let now = now_epoch();
        let exp = now + 3600; // 1h assertion; the returned token's own TTL governs refresh
        let header = b64url(br#"{"alg":"RS256","typ":"JWT"}"#);
        // Build claims with a JSON serializer, not string interpolation: a `"`/`\` in `issuer`
        // (client_email) or `scope` would otherwise produce malformed JSON or splice into the claim
        // set. Values are operator-trusted today, but the serializer makes the seam injection-proof.
        let claims_value = serde_json::json!({
            "iss": self.issuer,
            "scope": self.scope,
            "aud": self.token_uri,
            "iat": now,
            "exp": exp,
        });
        let claims_json = serde_json::to_string(&claims_value)
            .map_err(|e| format!("serializing JWT claims failed: {e}"))?;
        let claims = b64url(claims_json.as_bytes());
        let signing_input = format!("{header}.{claims}");

        let mut sig = vec![0u8; self.key_pair.public().modulus_len()];
        self.key_pair
            .sign(
                &ring::signature::RSA_PKCS1_SHA256,
                &self.rng,
                signing_input.as_bytes(),
                &mut sig,
            )
            .map_err(|_| "RS256 signing failed".to_string())?;
        let assertion = format!("{signing_input}.{}", b64url(&sig));

        // reqwest is built without the `json` feature here, so parse the response body manually.
        let resp = self
            .http
            .post(&self.token_uri)
            .form(&[
                ("grant_type", "urn:ietf:params:oauth:grant-type:jwt-bearer"),
                ("assertion", &assertion),
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
            // Never log the assertion/body wholesale (may echo claims); status + a short snippet only.
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

/// SA-JSON credential material: inline JSON (`{...}`) or a filesystem path to a key file.
fn read_credential(credential: &str) -> Result<String, String> {
    let trimmed = credential.trim_start();
    if trimmed.starts_with('{') {
        return Ok(credential.to_string());
    }
    std::fs::read_to_string(credential)
        .map_err(|e| format!("could not read service-account key file '{credential}': {e}"))
}

/// Strip the PEM armor from a PKCS#8 private key and base64-decode the body to DER.
fn pem_to_pkcs8_der(pem: &str) -> Result<Vec<u8>, String> {
    let body: String = pem
        .lines()
        .filter(|l| !l.starts_with("-----"))
        .flat_map(|l| l.chars())
        .filter(|c| !c.is_whitespace())
        .collect();
    if body.is_empty() {
        return Err("service-account private_key is empty or not PEM-armored".to_string());
    }
    base64::engine::general_purpose::STANDARD
        .decode(body.as_bytes())
        .map_err(|e| format!("service-account private_key base64 is invalid: {e}"))
}

fn b64url(bytes: &[u8]) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

#[derive(serde::Deserialize)]
struct ServiceAccount {
    client_email: String,
    private_key: String,
    #[serde(default = "default_token_uri")]
    token_uri: String,
}

fn default_token_uri() -> String {
    "https://oauth2.googleapis.com/token".to_string()
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
    fn pem_to_pkcs8_der_strips_armor_and_decodes() {
        // The function only strips the PEM armor and base64-decodes the body — it does not require a
        // real key, so a known base64 payload round-trips to its bytes.
        let pem = "-----BEGIN PRIVATE KEY-----\nSGVsbG8sIFBLQ1M4\n-----END PRIVATE KEY-----\n";
        assert_eq!(pem_to_pkcs8_der(pem).unwrap(), b"Hello, PKCS8");
    }

    #[test]
    fn pem_to_pkcs8_der_rejects_empty_and_garbage() {
        assert!(
            pem_to_pkcs8_der("-----BEGIN PRIVATE KEY-----\n-----END PRIVATE KEY-----").is_err()
        );
        assert!(pem_to_pkcs8_der(
            "-----BEGIN PRIVATE KEY-----\n!!!not base64!!!\n-----END PRIVATE KEY-----"
        )
        .is_err());
    }

    #[test]
    fn b64url_is_url_safe_and_unpadded() {
        // 0xFB 0xFF encodes to "+/8=" in standard base64; url-safe-no-pad must yield "-_8".
        assert_eq!(b64url(&[0xFB, 0xFF]), "-_8");
    }

    #[test]
    fn read_credential_passes_inline_json_through() {
        let json = r#"{"client_email":"x@y.iam.gserviceaccount.com"}"#;
        assert_eq!(read_credential(json).unwrap(), json);
        assert_eq!(read_credential("  {\"a\":1}").unwrap(), "  {\"a\":1}");
    }
}
