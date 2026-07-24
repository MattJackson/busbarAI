// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! JWT parsing + **signature verification** over `ring` (the workspace's single, already-vendored
//! crypto backend — no `jsonwebtoken`/`rsa`, so no new crypto dependency and no RUSTSEC-2023-0071
//! surface). Supports the two algorithms OIDC identity providers actually sign ID/access tokens with:
//! `RS256` (RSA-PKCS1-SHA256 — Entra, Google, Okta default) and `ES256` (ECDSA-P256-SHA256).
//!
//! This module is PURE: it verifies a token against an already-fetched key and returns the decoded
//! claims, or a precise error. iss/aud/exp/nbf policy and JWKS fetching live in [`crate`].

use crate::jwks::Jwk;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use serde::Deserialize;
use serde_json::Value;

/// The decoded JWT header — the fields that select verification.
#[derive(Debug, Deserialize)]
pub struct Header {
    /// Signature algorithm. Only `RS256` and `ES256` are accepted; `none` (unsigned) and HMAC
    /// (`HS*` — a symmetric key we must never accept from a JWKS) are REJECTED, closing the classic
    /// "alg: none" and "RS256→HS256 key-confusion" JWT attacks.
    pub alg: String,
    /// Key id selecting which JWKS key signed this token. Absent ⇒ the empty id (matches a keyless
    /// JWKS key only).
    #[serde(default)]
    pub kid: Option<String>,
}

/// The three base64url segments of a compact JWS, plus the signing input (`header.payload`) the
/// signature covers. Produced by [`split`], consumed by [`verify_signature`].
pub struct Parts<'a> {
    pub header: Header,
    /// The raw decoded payload bytes (the claims JSON) — decoded once here, deserialized by the caller.
    pub payload: Vec<u8>,
    /// The decoded signature bytes.
    pub signature: Vec<u8>,
    /// `header_b64 + "." + payload_b64` — exactly the bytes the signature is computed over. Borrowed
    /// from the original token string.
    pub signing_input: &'a str,
}

/// Split and base64url-decode a compact JWT (`header.payload.signature`), decoding the header enough
/// to select verification. Does NOT verify — that is [`verify_signature`]. Rejects a token that isn't
/// exactly three segments (a classic malformed-input guard).
pub fn split(token: &str) -> Result<Parts<'_>, String> {
    let mut it = token.split('.');
    let (h, p, s) = match (it.next(), it.next(), it.next(), it.next()) {
        (Some(h), Some(p), Some(s), None) => (h, p, s),
        _ => return Err("malformed JWT: expected three dot-separated segments".to_string()),
    };
    let header_bytes = URL_SAFE_NO_PAD
        .decode(h)
        .map_err(|_| "malformed JWT: header is not base64url".to_string())?;
    let header: Header =
        serde_json::from_slice(&header_bytes).map_err(|e| format!("malformed JWT header: {e}"))?;
    let payload = URL_SAFE_NO_PAD
        .decode(p)
        .map_err(|_| "malformed JWT: payload is not base64url".to_string())?;
    let signature = URL_SAFE_NO_PAD
        .decode(s)
        .map_err(|_| "malformed JWT: signature is not base64url".to_string())?;
    // The signing input is the original header + "." + payload substring (pre-decode bytes), i.e. the
    // token up to the last '.'. Slice it from the source so we sign the EXACT transmitted bytes.
    let last_dot = token.rfind('.').expect("token has at least two dots here");
    let signing_input = &token[..last_dot];
    Ok(Parts {
        header,
        payload,
        signature,
        signing_input,
    })
}

/// Verify the JWS signature of `parts` against the JWKS key `key`, enforcing that the token's `alg`
/// matches the key type (RS256↔RSA, ES256↔EC) — the alg-confusion guard. Returns `Ok(())` on a valid
/// signature, a precise `Err` otherwise. Uses `ring`'s constant-time verifiers.
pub fn verify_signature(parts: &Parts, key: &Jwk) -> Result<(), String> {
    match parts.header.alg.as_str() {
        "RS256" => {
            if key.kty != "RSA" {
                return Err(format!(
                    "token alg RS256 but JWKS key kid is {} (alg/key-type mismatch)",
                    key.kty
                ));
            }
            let n = b64(key.n.as_deref(), "RSA modulus n")?;
            let e = b64(key.e.as_deref(), "RSA exponent e")?;
            let pubkey = ring::signature::RsaPublicKeyComponents { n: &n, e: &e };
            pubkey
                .verify(
                    &ring::signature::RSA_PKCS1_2048_8192_SHA256,
                    parts.signing_input.as_bytes(),
                    &parts.signature,
                )
                .map_err(|_| "JWT signature verification failed".to_string())
        }
        "ES256" => {
            if key.kty != "EC" {
                return Err(format!(
                    "token alg ES256 but JWKS key kty is {} (alg/key-type mismatch)",
                    key.kty
                ));
            }
            if key.crv.as_deref() != Some("P-256") {
                return Err(format!(
                    "ES256 requires curve P-256, JWKS key has crv {:?}",
                    key.crv
                ));
            }
            let x = b64(key.x.as_deref(), "EC coordinate x")?;
            let y = b64(key.y.as_deref(), "EC coordinate y")?;
            // ring wants the uncompressed SEC1 point: 0x04 || X || Y.
            let mut point = Vec::with_capacity(1 + x.len() + y.len());
            point.push(0x04);
            point.extend_from_slice(&x);
            point.extend_from_slice(&y);
            let pubkey = ring::signature::UnparsedPublicKey::new(
                &ring::signature::ECDSA_P256_SHA256_FIXED,
                point,
            );
            pubkey
                .verify(parts.signing_input.as_bytes(), &parts.signature)
                .map_err(|_| "JWT signature verification failed".to_string())
        }
        // `none` (unsigned), `HS*` (HMAC — accepting a symmetric alg against an asymmetric JWKS key is
        // the RS256→HS256 key-confusion attack), and any other alg are REFUSED.
        other => Err(format!(
            "unsupported/forbidden JWT alg '{other}': only RS256 and ES256 are accepted"
        )),
    }
}

/// base64url-decode a required JWK field, with a naming error on absence/format.
fn b64(field: Option<&str>, what: &str) -> Result<Vec<u8>, String> {
    let s = field.ok_or_else(|| format!("JWKS key missing {what}"))?;
    URL_SAFE_NO_PAD
        .decode(s)
        .map_err(|_| format!("JWKS key {what} is not base64url"))
}

/// Deserialize the token's claims payload as a JSON object.
pub fn claims(parts: &Parts) -> Result<Value, String> {
    serde_json::from_slice(&parts.payload).map_err(|e| format!("malformed JWT claims: {e}"))
}
