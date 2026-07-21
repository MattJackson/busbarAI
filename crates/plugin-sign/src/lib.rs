// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Plugin artifact **signing + trust evaluation** for busbar.
//!
//! An approved plugin ships a [`Manifest`] — `{name, version, kind, publisher, abi_version, sha256,
//! signature}` — where `signature` is an **ed25519** signature over the artifact's SHA-256, made with
//! the publisher's PRIVATE key (which never touches busbar). busbar holds only the PUBLIC keys of
//! approved publishers (config `plugins.trust.publishers` + the embedded Busbar release key), and on
//! both upload and boot-load it:
//!
//! 1. recomputes `sha256(bytes)` and checks it equals the manifest's (integrity),
//! 2. verifies the signature over that hash with the named publisher's public key (authenticity).
//!
//! "Approved" = the signature verifies against a key in your allowlist. Anything else — no manifest,
//! unknown publisher, tampered bytes — is UNTRUSTED, and the [`OnUntrusted`] posture decides whether
//! to `Halt` (the strict "only approved plugins" mode), `Alert`/`Log` (load but flag), or `Allow`
//! (dev). A signature — not a bare checksum — is what makes this hold even against a MITM: the bytes
//! AND a request-supplied hash can be rewritten in transit, but the signature cannot be forged
//! without the private key.
//!
//! This crate is pure crypto + policy: no I/O, no engine state. The engine only ever calls
//! [`evaluate`] (verification) before writing/loading. [`sign`] exists for the release pipeline /
//! enterprise signing tooling — OSS ships verification, not a signing CLI. Key generation lives in
//! that tooling (it owns the RNG this engine-facing crate deliberately avoids).

// `SigningKey`/`VerifyingKey` are re-exported so external signing tooling can name them via this
// crate.
use ed25519_dalek::{Signature, Signer, Verifier};
pub use ed25519_dalek::{SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

/// The signed manifest that travels beside a plugin artifact (as `<library>.manifest.json`, or the
/// fields in the upload request). Every field except `signature` is covered by the signature via the
/// artifact hash + this crate's canonical signing input, so none can be altered without detection.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Manifest {
    /// Logical plugin name, e.g. `store-sqlite`.
    pub name: String,
    /// The plugin's own release version (semver, e.g. `1.2.3`) — surfaced by the admin API so an
    /// upstream dashboard can compare against the latest and flag "update available". Signed, so it
    /// can't be spoofed. (Distinct from `abi_version`, which is the wire-compat version.)
    pub version: String,
    /// Plugin category: `store` | `auth` | `hook`.
    pub kind: String,
    /// The publisher identity whose key signed this — must resolve to an allowlisted public key.
    pub publisher: String,
    /// The store/plugin ABI version the artifact targets (informational; the loader also checks it).
    pub abi_version: u32,
    /// Lowercase hex SHA-256 of the artifact bytes.
    pub sha256: String,
    /// Lowercase hex ed25519 signature (64 bytes) over the canonical signing input (see [`signing_input`]).
    pub signature: String,
}

/// What to do with a plugin that is not trusted (no valid signature from an allowlisted publisher).
/// This is the `plugins.trust.on_untrusted` posture; `require_signed=true` is equivalent to `Halt`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum OnUntrusted {
    /// Refuse to install/load it. The strict "only approved plugins" mode (`allow3rdparties=false`).
    Halt,
    /// Install/load it, but emit a security event + audit entry.
    Alert,
    /// Install/load it, logging a warning. A safe-ish default: nothing is silent.
    #[default]
    Log,
    /// Install/load it with no fuss (`allow3rdparties=true`; dev/loose).
    Allow,
}

/// The resolved trust policy: the allowlisted publisher public keys plus the posture. Built from
/// `plugins.trust` config (plus the embedded Busbar release key) by the engine.
#[derive(Clone, Default)]
pub struct TrustPolicy {
    /// publisher name -> ed25519 public key.
    pub publishers: BTreeMap<String, VerifyingKey>,
    /// Posture for an untrusted artifact.
    pub on_untrusted: OnUntrusted,
}

/// The verdict for one artifact.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verdict {
    /// A valid signature from an allowlisted publisher. Always safe to install/load.
    Trusted { publisher: String },
    /// Not trusted, but the posture permits proceeding — the caller should log/alert per `action`.
    Allowed { reason: String, action: OnUntrusted },
}

/// Signing/trust failure. `Rejected` means the posture (or `require_signed`) forbids installing this
/// artifact; the message is safe to surface (never a secret).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Rejected(pub String);

impl std::fmt::Display for Rejected {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "plugin rejected: {}", self.0)
    }
}
impl std::error::Error for Rejected {}

/// Lowercase-hex SHA-256 of `bytes` — the artifact digest used everywhere (manifest, signing input).
pub fn sha256_hex(bytes: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(bytes);
    hex::encode(h.finalize())
}

/// The canonical byte string that is actually signed/verified: binds the signature to the artifact
/// hash AND the manifest's identity fields, so none of them can be swapped independently. Ordering
/// and separators are fixed forever (v1).
pub fn signing_input(
    name: &str,
    version: &str,
    kind: &str,
    publisher: &str,
    abi_version: u32,
    sha256: &str,
) -> Vec<u8> {
    format!("busbar-plugin-v1|{name}|{version}|{kind}|{publisher}|{abi_version}|{sha256}")
        .into_bytes()
}

/// Sign an artifact with a publisher's key, producing a ready-to-ship [`Manifest`]. For the release
/// pipeline / external signing tooling — never runs in the engine (which only verifies).
#[allow(clippy::too_many_arguments)]
pub fn sign(
    key: &SigningKey,
    name: &str,
    version: &str,
    kind: &str,
    publisher: &str,
    abi_version: u32,
    artifact: &[u8],
) -> Manifest {
    let sha256 = sha256_hex(artifact);
    let msg = signing_input(name, version, kind, publisher, abi_version, &sha256);
    let sig = key.sign(&msg);
    Manifest {
        name: name.to_string(),
        version: version.to_string(),
        kind: kind.to_string(),
        publisher: publisher.to_string(),
        abi_version,
        sha256,
        signature: hex::encode(sig.to_bytes()),
    }
}

/// Parse a hex-encoded 32-byte ed25519 public key (as configured in `plugins.trust.publishers`).
pub fn public_key_from_hex(s: &str) -> Result<VerifyingKey, String> {
    let bytes = hex::decode(s.trim()).map_err(|e| format!("public key not valid hex: {e}"))?;
    let arr: [u8; 32] = bytes
        .as_slice()
        .try_into()
        .map_err(|_| format!("public key must be 32 bytes, got {}", bytes.len()))?;
    VerifyingKey::from_bytes(&arr).map_err(|e| format!("invalid ed25519 public key: {e}"))
}

/// Whether a well-formed manifest's signature verifies against `bytes` using `key`. Returns the
/// low-level reason on failure (used by [`evaluate`]).
fn signature_ok(manifest: &Manifest, bytes: &[u8], key: &VerifyingKey) -> Result<(), String> {
    let actual = sha256_hex(bytes);
    if actual != manifest.sha256 {
        return Err("artifact hash does not match the manifest".to_string());
    }
    let sig_bytes =
        hex::decode(&manifest.signature).map_err(|e| format!("signature not hex: {e}"))?;
    let sig_arr: [u8; 64] = sig_bytes
        .as_slice()
        .try_into()
        .map_err(|_| "signature must be 64 bytes".to_string())?;
    let sig = Signature::from_bytes(&sig_arr);
    let msg = signing_input(
        &manifest.name,
        &manifest.version,
        &manifest.kind,
        &manifest.publisher,
        manifest.abi_version,
        &manifest.sha256,
    );
    key.verify(&msg, &sig)
        .map_err(|_| "signature does not verify".to_string())
}

/// Evaluate an artifact against the trust policy. `manifest` is `None` when the artifact arrived
/// unsigned. Returns [`Verdict`] when it may proceed (trusted, or untrusted-but-posture-permits), or
/// [`Rejected`] when the posture forbids it.
pub fn evaluate(
    bytes: &[u8],
    manifest: Option<&Manifest>,
    policy: &TrustPolicy,
) -> Result<Verdict, Rejected> {
    // Determine the untrusted reason (if any); a valid signature from an allowlisted publisher is the
    // only path to Trusted.
    let untrusted_reason: Option<String> = match manifest {
        None => Some("artifact is unsigned (no manifest)".to_string()),
        Some(m) => match policy.publishers.get(&m.publisher) {
            None => Some(format!(
                "publisher '{}' is not in the allowlist",
                m.publisher
            )),
            Some(key) => signature_ok(m, bytes, key).err(),
        },
    };

    match untrusted_reason {
        None => Ok(Verdict::Trusted {
            publisher: manifest.map(|m| m.publisher.clone()).unwrap_or_default(),
        }),
        Some(reason) => match policy.on_untrusted {
            OnUntrusted::Halt => Err(Rejected(reason)),
            action => Ok(Verdict::Allowed { reason, action }),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Deterministic test key from a seed byte (no RNG needed in this crate's tests).
    fn test_key(seed: u8) -> SigningKey {
        SigningKey::from_bytes(&[seed; 32])
    }

    fn policy(pairs: &[(&str, &VerifyingKey)], on_untrusted: OnUntrusted) -> TrustPolicy {
        TrustPolicy {
            publishers: pairs.iter().map(|(n, k)| (n.to_string(), **k)).collect(),
            on_untrusted,
        }
    }

    #[test]
    fn sign_then_verify_is_trusted() {
        let key = test_key(1);
        let pubk = key.verifying_key();
        let artifact = b"\x7fELF fake plugin bytes";
        let m = sign(
            &key,
            "store-sqlite",
            "1.0.0",
            "store",
            "busbar",
            1,
            artifact,
        );
        // manifest is serde-round-trippable (it travels as JSON).
        let j = serde_json::to_string(&m).unwrap();
        let m2: Manifest = serde_json::from_str(&j).unwrap();
        assert_eq!(m, m2);

        let pol = policy(&[("busbar", &pubk)], OnUntrusted::Halt);
        assert_eq!(
            evaluate(artifact, Some(&m), &pol).unwrap(),
            Verdict::Trusted {
                publisher: "busbar".into()
            }
        );
    }

    #[test]
    fn tampered_bytes_fail_even_under_halt() {
        let key = test_key(1);
        let pubk = key.verifying_key();
        let m = sign(&key, "p", "1.0.0", "store", "busbar", 1, b"original");
        let pol = policy(&[("busbar", &pubk)], OnUntrusted::Halt);
        // Flip the artifact: hash no longer matches the (signed) manifest -> rejected.
        let err = evaluate(b"tampered!", Some(&m), &pol).unwrap_err();
        assert!(err.0.contains("hash does not match"), "got {err:?}");
    }

    #[test]
    fn wrong_publisher_key_does_not_verify() {
        let key = test_key(1);
        let attacker = test_key(2);
        let artifact = b"bytes";
        // Signed by `key`, but the allowlist maps 'busbar' to the ATTACKER's key -> signature fails.
        let m = sign(&key, "p", "1.0.0", "store", "busbar", 1, artifact);
        let pol = policy(&[("busbar", &attacker.verifying_key())], OnUntrusted::Halt);
        assert!(evaluate(artifact, Some(&m), &pol).is_err());
    }

    #[test]
    fn unknown_publisher_is_untrusted() {
        let key = test_key(1);
        let artifact = b"bytes";
        let m = sign(&key, "p", "1.0.0", "store", "acme", 1, artifact);
        let pol = policy(&[("busbar", &key.verifying_key())], OnUntrusted::Halt);
        let err = evaluate(artifact, Some(&m), &pol).unwrap_err();
        assert!(err.0.contains("not in the allowlist"), "got {err:?}");
    }

    #[test]
    fn posture_allow_and_log_permit_unsigned() {
        let pol_allow = policy(&[], OnUntrusted::Allow);
        match evaluate(b"x", None, &pol_allow).unwrap() {
            Verdict::Allowed { action, .. } => assert_eq!(action, OnUntrusted::Allow),
            v => panic!("expected Allowed, got {v:?}"),
        }
        let pol_log = policy(&[], OnUntrusted::Log);
        assert!(matches!(
            evaluate(b"x", None, &pol_log).unwrap(),
            Verdict::Allowed { .. }
        ));
        // Halt refuses the same unsigned artifact.
        let pol_halt = policy(&[], OnUntrusted::Halt);
        assert!(evaluate(b"x", None, &pol_halt).is_err());
    }

    #[test]
    fn public_key_hex_roundtrip() {
        let key = test_key(1);
        let hex = hex::encode(key.verifying_key().to_bytes());
        let back = public_key_from_hex(&hex).unwrap();
        assert_eq!(back, key.verifying_key());
        assert!(public_key_from_hex("zz").is_err());
    }
}
