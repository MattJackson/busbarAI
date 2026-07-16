// SPDX-License-Identifier: AGPL-3.0-or-later
//! `jwt-bearer` egress auth — OAuth 2.0 JWT-bearer grant (RFC 7523), busbar's 5th auth mechanism.
//!
//! GENERIC, not Google-specific: the flow is the standard `urn:ietf:params:oauth:grant-type:jwt-bearer`
//! grant — sign a JWT with a private key, POST the assertion to a token endpoint, receive a short-lived
//! bearer. The Google service-account JSON is merely a recognized *container* for the signing material
//! (`client_email` → JWT `iss`, `private_key` → the RS256 key, `token_uri` → JWT `aud`); the scope
//! defaults to `cloud-platform`. Vertex AI is the first provider to select `auth: jwt-bearer`.
//!
//! Because [`CredentialProvider::headers_for`] is SYNCHRONOUS and runs inline on the hot path, minting
//! (an async HTTP round-trip) cannot happen there. Instead the initial token is minted once at boot
//! (async, so a bad key fails boot loudly — the `--validate` ethos), then a background task refreshes
//! it a few minutes before expiry into an `RwLock<Arc<CachedToken>>`; `headers_for` only reads the
//! current token. The refresh task holds a `Weak` to the provider, so a config reload that drops the
//! lane also stops its refresher (no task leak).

use super::CredentialProvider;
use crate::proto::SigningContext;
use axum::http::{HeaderName, HeaderValue};
use base64::Engine as _;
use std::sync::{Arc, RwLock, Weak};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// Default OAuth scope when the provider does not override it — the Vertex/GCP common case.
const DEFAULT_SCOPE: &str = "https://www.googleapis.com/auth/cloud-platform";
/// Refresh this many seconds BEFORE the token's stated expiry, so a request never races an expired
/// token across the refresh boundary.
const REFRESH_SKEW_SECS: u64 = 300;
/// Floor on the refresh sleep so a short-lived / already-near-expiry token can't spin the loop hot,
/// and the retry delay after a mint failure.
const MIN_SLEEP_SECS: u64 = 30;

/// A minted access token and the wall-clock epoch second it expires at.
struct CachedToken {
    token: String,
    expires_at: u64,
}

/// The signing + exchange material for one lane. Held in an `Arc` shared by the provider's initial
/// mint and the background refresh task. Immutable after construction.
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

/// The `jwt-bearer` credential provider. `headers_for` reads the cached bearer; a background task
/// keeps it fresh.
pub(crate) struct JwtBearer {
    token: RwLock<Arc<CachedToken>>,
}

impl CredentialProvider for JwtBearer {
    fn headers_for(&self, _key: &str, _ctx: &SigningContext) -> Vec<(HeaderName, HeaderValue)> {
        // A self-minting credential ignores the per-request `key`. Read the current cached token; if
        // it is empty or somehow un-encodable, emit NO auth header (upstream 401 — same fail-closed
        // shape as an un-encodable static key), rather than sending a malformed one.
        let cached = self
            .token
            .read()
            .expect("jwt-bearer token lock poisoned")
            .clone();
        if cached.token.is_empty() {
            return Vec::new();
        }
        match HeaderValue::from_str(&format!("Bearer {}", cached.token)) {
            Ok(v) => vec![(HeaderName::from_static("authorization"), v)],
            Err(_) => {
                tracing::warn!(
                    "jwt-bearer minted a token with bytes invalid for an HTTP header value; omitting \
                     the auth header — upstream will reject with 401"
                );
                Vec::new()
            }
        }
    }
}

/// Build a `jwt-bearer` credential. SYNCHRONOUS by design — it runs on the shared
/// `build_app_from_config` path (boot AND admin config-reload/dry-run), so it must not block on the
/// network. It PARSES the key material (failing loud on a malformed service-account JSON / PKCS#8 key,
/// the common misconfig) and then spawns a background task that mints the first token immediately and
/// refreshes it thereafter. This keeps a transient token-endpoint outage from blocking boot or a
/// reload; the brief window before the first token lands emits no auth header (upstream 401), the same
/// fail-closed shape as any missing credential. `credential` is the SA JSON — inline (starts with `{`)
/// or a path to a key file. `scope_override` replaces the default `cloud-platform` scope when set.
pub(crate) fn build(
    credential: &str,
    scope_override: Option<&str>,
) -> Result<Arc<JwtBearer>, String> {
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
    // Start empty; the refresher mints immediately.
    let provider = Arc::new(JwtBearer {
        token: RwLock::new(Arc::new(CachedToken {
            token: String::new(),
            expires_at: 0,
        })),
    });

    // Spawn the refresher when inside a tokio runtime (boot + admin reload always are). Without one
    // (e.g. a sync construction test) skip it — the credential simply holds no token.
    if let Ok(handle) = tokio::runtime::Handle::try_current() {
        let weak = Arc::downgrade(&provider);
        handle.spawn(async move { refresh_loop(signer, weak).await });
    }

    Ok(provider)
}

/// The background refresh loop: mint (immediately on entry), store, then sleep until shortly before
/// expiry and repeat. Exits when the provider is dropped (config reload) so the task never outlives
/// its lane.
async fn refresh_loop(signer: Arc<Signer>, weak: Weak<JwtBearer>) {
    loop {
        match signer.mint().await {
            Ok(fresh) => {
                let expires_at = fresh.expires_at;
                match weak.upgrade() {
                    Some(p) => {
                        *p.token.write().expect("jwt-bearer token lock poisoned") = Arc::new(fresh)
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
                tracing::warn!(error = %e, "jwt-bearer token mint failed; will retry");
                if weak.upgrade().is_none() {
                    return;
                }
                tokio::time::sleep(Duration::from_secs(MIN_SLEEP_SECS)).await;
            }
        }
    }
}

impl Signer {
    /// Sign a JWT-bearer assertion and exchange it for an access token (RFC 7523).
    async fn mint(&self) -> Result<CachedToken, String> {
        let now = now_epoch();
        let exp = now + 3600; // 1h assertion; the returned token's own TTL governs refresh
        let header = b64url(br#"{"alg":"RS256","typ":"JWT"}"#);
        let claims = b64url(
            format!(
                r#"{{"iss":"{iss}","scope":"{scope}","aud":"{aud}","iat":{iat},"exp":{exp}}}"#,
                iss = self.issuer,
                scope = self.scope,
                aud = self.token_uri,
                iat = now,
            )
            .as_bytes(),
        );
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

fn now_epoch() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
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

    impl JwtBearer {
        fn with_token(token: &str) -> Self {
            JwtBearer {
                token: RwLock::new(Arc::new(CachedToken {
                    token: token.to_string(),
                    expires_at: 0,
                })),
            }
        }
    }

    fn ctx() -> SigningContext<'static> {
        SigningContext {
            host: "us-central1-aiplatform.googleapis.com".to_string(),
            canonical_uri:
                "/v1/projects/p/locations/us-central1/publishers/google/models/x:generateContent"
                    .to_string(),
            body: b"{}",
            timestamp_epoch: 0,
            upstream_creds: crate::auth::UpstreamCreds::Own,
        }
    }

    #[test]
    fn headers_for_emits_bearer_and_ignores_per_request_key() {
        let cred = JwtBearer::with_token("ya29.some-access-token");
        let headers = cred.headers_for("ignored-per-request-key", &ctx());
        assert_eq!(headers.len(), 1);
        assert_eq!(headers[0].0.as_str(), "authorization");
        assert_eq!(
            headers[0].1.to_str().unwrap(),
            "Bearer ya29.some-access-token"
        );
    }

    #[test]
    fn headers_for_emits_nothing_before_a_token_is_minted() {
        // Empty token (the boot window before the first mint) → NO auth header (upstream 401), never
        // a malformed one.
        let cred = JwtBearer::with_token("");
        assert!(cred.headers_for("k", &ctx()).is_empty());
    }

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
        // A leading-whitespace inline JSON is still recognized as inline (not a path).
        assert_eq!(read_credential("  {\"a\":1}").unwrap(), "  {\"a\":1}");
    }
}
