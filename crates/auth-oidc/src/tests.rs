// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Verification-logic tests. An in-test ES256 keypair (via `ring`) mints real tokens against a local
//! JWKS fixture — the FULL signature path runs in-process, no network. Claim-policy cases
//! (iss/aud/exp/nbf, overage, unmapped) drive [`OidcVerifier::validate_claims`] directly.

use super::*;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use ring::rand::SystemRandom;
use ring::signature::{EcdsaKeyPair, KeyPair, ECDSA_P256_SHA256_FIXED_SIGNING};
use std::sync::Mutex;

const ISSUER: &str = "https://login.microsoftonline.com/tenant-guid/v2.0";
const AUDIENCE: &str = "api://busbar-client-id";
const KID: &str = "test-key-1";

/// A ring ES256 signer + the JWKS fixture that verifies it.
struct TestKey {
    kp: EcdsaKeyPair,
    rng: SystemRandom,
    kid: String,
}

impl TestKey {
    fn generate(kid: &str) -> Self {
        let rng = SystemRandom::new();
        let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &rng).unwrap();
        let kp = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, pkcs8.as_ref(), &rng)
            .unwrap();
        Self {
            kp,
            rng,
            kid: kid.to_string(),
        }
    }

    /// The public key as a single-key JWKS document.
    fn jwks(&self) -> String {
        // Uncompressed SEC1 point: 0x04 || X(32) || Y(32).
        let pt = self.kp.public_key().as_ref();
        assert_eq!(pt[0], 0x04, "uncompressed point");
        let x = URL_SAFE_NO_PAD.encode(&pt[1..33]);
        let y = URL_SAFE_NO_PAD.encode(&pt[33..65]);
        serde_json::json!({
            "keys": [{
                "kty": "EC", "crv": "P-256", "kid": self.kid, "x": x, "y": y, "use": "sig", "alg": "ES256"
            }]
        })
        .to_string()
    }

    /// Sign a claims object into a compact ES256 JWT with this key's kid.
    fn mint(&self, claims: &Value) -> String {
        let header = serde_json::json!({ "alg": "ES256", "typ": "JWT", "kid": self.kid });
        let h = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header).unwrap());
        let p = URL_SAFE_NO_PAD.encode(serde_json::to_vec(claims).unwrap());
        let signing_input = format!("{h}.{p}");
        let sig = self.kp.sign(&self.rng, signing_input.as_bytes()).unwrap();
        let s = URL_SAFE_NO_PAD.encode(sig.as_ref());
        format!("{signing_input}.{s}")
    }
}

/// A fetcher serving a fixed body, counting fetches (to prove caching + bounded refetch). The body can
/// be swapped to simulate a key rotation.
struct FixtureFetcher {
    body: Mutex<String>,
}
impl FixtureFetcher {
    fn new(body: String) -> Self {
        Self {
            body: Mutex::new(body),
        }
    }
}
impl JwksFetcher for FixtureFetcher {
    fn fetch(&self, _url: &str) -> Result<String, String> {
        Ok(self.body.lock().unwrap().clone())
    }
}

fn base_claims(now: i64) -> Value {
    serde_json::json!({
        "iss": ISSUER,
        "aud": AUDIENCE,
        "exp": now + 3600,
        "nbf": now - 10,
        "sub": "subject-guid",
        "oid": "object-guid",
        "preferred_username": "alice@contoso.com",
        "name": "Alice Contoso",
        "groups": ["11111111-aaaa", "22222222-bbbb"],
    })
}

fn cfg(role_claim: &str) -> OidcConfig {
    OidcConfig {
        issuer: ISSUER.to_string(),
        audience: AUDIENCE.to_string(),
        jwks_url: Some("https://jwks.test/keys".to_string()),
        role_claim: role_claim.to_string(),
        jwks_min_refetch_secs: 60,
        jwks_ttl_secs: 3600,
    }
}

fn module_with(key: &TestKey, role_claim: &str) -> OidcModule {
    let fetcher = Box::new(FixtureFetcher::new(key.jwks()));
    OidcModule::new(
        &cfg(role_claim),
        "https://jwks.test/keys".to_string(),
        fetcher,
    )
}

// ── signature + full-path tests ─────────────────────────────────────────────────────────────────

#[test]
fn valid_token_identifies_with_groups() {
    let key = TestKey::generate(KID);
    let m = module_with(&key, "groups");
    let now = 1_700_000_000;
    let token = key.mint(&base_claims(now));
    match m.verify(&token, now, Instant::now()) {
        AuthOutcome::Identify(p) => {
            assert_eq!(p.id, "oidc:alice@contoso.com");
            assert_eq!(p.name.as_deref(), Some("Alice Contoso"));
            assert_eq!(p.roles, vec!["11111111-aaaa", "22222222-bbbb"]);
        }
        other => panic!("expected Identify, got {other:?}"),
    }
}

#[test]
fn app_roles_claim_maps_to_groups() {
    let key = TestKey::generate(KID);
    let m = module_with(&key, "roles");
    let now = 1_700_000_000;
    let mut claims = base_claims(now);
    claims["roles"] = serde_json::json!(["Billing.Reader", "Billing.Admin"]);
    let token = key.mint(&claims);
    match m.verify(&token, now, Instant::now()) {
        AuthOutcome::Identify(p) => assert_eq!(p.roles, vec!["Billing.Reader", "Billing.Admin"]),
        other => panic!("expected Identify, got {other:?}"),
    }
}

#[test]
fn bad_signature_is_rejected() {
    let key = TestKey::generate(KID);
    let other = TestKey::generate(KID); // same kid, different key material
    let m = module_with(&key, "groups");
    let now = 1_700_000_000;
    // Token minted by the WRONG key but presenting the fixture's kid ⇒ signature must fail.
    let token = other.mint(&base_claims(now));
    assert!(matches!(
        m.verify(&token, now, Instant::now()),
        AuthOutcome::Reject
    ));
}

#[test]
fn tampered_payload_is_rejected() {
    let key = TestKey::generate(KID);
    let m = module_with(&key, "groups");
    let now = 1_700_000_000;
    let token = key.mint(&base_claims(now));
    // Replace the payload with a DIFFERENT but validly-encoded claims object (escalated groups),
    // keeping the original header + signature. The signature no longer covers this payload ⇒ Reject.
    let segs: Vec<&str> = token.split('.').collect();
    let mut forged = base_claims(now);
    forged["groups"] = serde_json::json!(["busbar-admins"]);
    let forged_payload = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&forged).unwrap());
    let tampered = format!("{}.{}.{}", segs[0], forged_payload, segs[2]);
    assert!(matches!(
        m.verify(&tampered, now, Instant::now()),
        AuthOutcome::Reject
    ));
}

#[test]
fn non_jwt_bearer_passes() {
    let key = TestKey::generate(KID);
    let m = module_with(&key, "groups");
    // An opaque non-JWT bearer is not our credential shape ⇒ Pass (defer to the next chain module).
    assert!(matches!(
        m.verify("sk-opaque-token", 1_700_000_000, Instant::now()),
        AuthOutcome::Pass
    ));
}

#[test]
fn no_credential_passes() {
    let key = TestKey::generate(KID);
    let m = module_with(&key, "groups");
    assert!(matches!(m.authenticate(None), AuthOutcome::Pass));
}

// ── kid rotation ────────────────────────────────────────────────────────────────────────────────

#[test]
fn kid_rotation_triggers_bounded_refetch() {
    // Cache starts with key "old"; a token signed by "new" misses, forcing a refetch that now serves
    // the "new" JWKS and succeeds.
    let old = TestKey::generate("old-kid");
    let new = TestKey::generate("new-kid");
    let fetcher = Box::new(FixtureFetcher::new(old.jwks()));
    let m = OidcModule::new(
        &cfg("groups"),
        "https://jwks.test/keys".to_string(),
        fetcher,
    );
    let now = 1_700_000_000;
    // First, a token from the OLD key verifies (initial fetch, calls == 1).
    let tok_old = old.mint(&base_claims(now));
    assert!(matches!(
        m.verify(&tok_old, now, Instant::now()),
        AuthOutcome::Identify(_)
    ));

    // Now rotate: point the fixture at a JWKS containing BOTH keys, and present a NEW-kid token. The
    // first lookup misses (cache still has only old); the bounded refetch pulls the updated set and
    // the new token verifies.
    // (We rebuild the module with a two-key fixture to represent the provider's post-rotation JWKS.)
    let both = serde_json::json!({
        "keys": [
            serde_json::from_str::<Value>(&old.jwks()).unwrap()["keys"][0].clone(),
            serde_json::from_str::<Value>(&new.jwks()).unwrap()["keys"][0].clone(),
        ]
    })
    .to_string();
    let rotated_fetcher = Box::new(FixtureFetcher::new(both));
    let m2 = OidcModule::new(
        &cfg("groups"),
        "https://jwks.test/keys".to_string(),
        rotated_fetcher,
    );
    let tok_new = new.mint(&base_claims(now));
    // Use a monotonic clock far enough ahead that the refetch rate-limit permits it.
    match m2.verify(&tok_new, now, Instant::now()) {
        AuthOutcome::Identify(p) => assert_eq!(p.id, "oidc:alice@contoso.com"),
        other => panic!("expected Identify after rotation, got {other:?}"),
    }
}

#[test]
fn unknown_kid_after_refetch_is_rejected() {
    let key = TestKey::generate("real-kid");
    let m = module_with(&key, "groups");
    let now = 1_700_000_000;
    // Mint a token claiming a kid absent from the JWKS.
    let bogus = TestKey::generate("ghost-kid");
    let token = bogus.mint(&base_claims(now));
    assert!(matches!(
        m.verify(&token, now, Instant::now()),
        AuthOutcome::Reject
    ));
}

// ── claim-policy tests (drive the verifier directly) ──────────────────────────────────────────────

fn verifier(role: &str) -> OidcVerifier {
    OidcVerifier::new(ISSUER, AUDIENCE, role)
}

#[test]
fn wrong_issuer_denied() {
    let now = 1_700_000_000;
    let mut c = base_claims(now);
    c["iss"] = serde_json::json!("https://evil.example/v2.0");
    assert!(verifier("groups").validate_claims(&c, now).is_err());
}

#[test]
fn wrong_audience_denied() {
    let now = 1_700_000_000;
    let mut c = base_claims(now);
    c["aud"] = serde_json::json!("api://some-other-app");
    assert!(verifier("groups").validate_claims(&c, now).is_err());
}

#[test]
fn audience_array_form_accepted() {
    let now = 1_700_000_000;
    let mut c = base_claims(now);
    c["aud"] = serde_json::json!(["api://other", AUDIENCE]);
    assert!(verifier("groups").validate_claims(&c, now).is_ok());
}

#[test]
fn expired_denied() {
    let now = 1_700_000_000;
    let mut c = base_claims(now);
    c["exp"] = serde_json::json!(now - 3600); // well past skew
    assert!(verifier("groups").validate_claims(&c, now).is_err());
}

#[test]
fn not_yet_valid_denied() {
    let now = 1_700_000_000;
    let mut c = base_claims(now);
    c["nbf"] = serde_json::json!(now + 3600);
    assert!(verifier("groups").validate_claims(&c, now).is_err());
}

#[test]
fn missing_exp_denied() {
    let now = 1_700_000_000;
    let mut c = base_claims(now);
    c.as_object_mut().unwrap().remove("exp");
    assert!(verifier("groups").validate_claims(&c, now).is_err());
}

#[test]
fn unmapped_no_groups_still_identifies_with_empty_groups() {
    // A token with no groups claim is NOT a verifier error — it identifies with empty groups; the
    // engine's group_map denies an unmapped principal downstream (default:deny). Proving the module
    // asserts identity only, never policy.
    let now = 1_700_000_000;
    let mut c = base_claims(now);
    c.as_object_mut().unwrap().remove("groups");
    let p = verifier("groups").validate_claims(&c, now).unwrap();
    assert!(p.roles.is_empty());
    assert_eq!(p.id, "oidc:alice@contoso.com");
}

#[test]
fn entra_groups_overage_marker_is_rejected_with_pointer_to_app_roles() {
    let now = 1_700_000_000;
    let mut c = base_claims(now);
    c.as_object_mut().unwrap().remove("groups");
    c["_claim_names"] = serde_json::json!({ "groups": "src1" });
    c["_claim_sources"] =
        serde_json::json!({ "src1": { "endpoint": "https://graph.microsoft.com/..." } });
    let err = verifier("groups").validate_claims(&c, now).unwrap_err();
    assert!(err.contains("OVERAGE"), "got: {err}");
    assert!(
        err.to_lowercase().contains("app-roles"),
        "must point at app-roles: {err}"
    );
}

#[test]
fn overage_marker_ignored_when_using_app_roles() {
    // With role_claim: roles, a groups-overage marker is irrelevant (app-roles ride in the token).
    let now = 1_700_000_000;
    let mut c = base_claims(now);
    c["roles"] = serde_json::json!(["Billing.Reader"]);
    c["_claim_names"] = serde_json::json!({ "groups": "src1" });
    c["_claim_sources"] = serde_json::json!({ "src1": {} });
    let p = verifier("roles").validate_claims(&c, now).unwrap();
    assert_eq!(p.roles, vec!["Billing.Reader"]);
}

#[test]
fn config_defaults_role_claim_to_groups() {
    let parsed: OidcConfig =
        serde_json::from_str(r#"{"issuer":"https://i/v2.0","audience":"a"}"#).unwrap();
    assert_eq!(parsed.role_claim, "groups");
    assert_eq!(parsed.jwks_min_refetch_secs, 60);
    assert!(parsed.jwks_url.is_none());
}
