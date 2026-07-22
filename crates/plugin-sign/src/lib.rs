// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Plugin artifact **manifest, signing input, and trust evaluation** for busbar.
//!
//! Every plugin ships a signed **`plugin.json`** manifest (a *sidecar* file — so it can be read and
//! verified WITHOUT loading the library; you never `dlopen` untrusted code just to read its name).
//! The manifest describes the plugin for the operator's "are you sure you want to install X by Y
//! from Z?" confirmation AND carries the security fields:
//!
//! - **provenance/display** (all signed, so the confirmation card can't be spoofed): `name`,
//!   `version`, `kind`, `author`, `homepage`, `source_url`, `description`, `license`;
//! - **binding + compat**: `sha256` (of the library bytes — pins the manifest to that exact binary),
//!   `interface_version` (which busbar plugin interface it targets);
//! - **authenticity**: `publisher` + `signature` over the *canonical whole manifest*.
//!
//! The signature covers the entire manifest (every field except `signature` itself) via
//! [`canonical_manifest_bytes`], and the manifest pins the library by `sha256`, so **neither the
//! manifest nor the library can be altered or swapped independently** — a bad manifest on a good
//! library has no valid signature, and a good manifest on a swapped library fails the hash check.
//!
//! "Approved" = the signature verifies against an allowlisted publisher. Anything else — unsigned,
//! unknown publisher, tampered — is UNTRUSTED, and the [`OnUntrusted`] posture decides `Halt` (only
//! approved plugins), `Alert`/`Log` (load but flag), or `Allow` (dev). A signature — not a bare
//! checksum — is what holds against a MITM: bytes and a request-supplied hash can both be rewritten
//! in transit, but the signature can't be forged.
//!
//! This crate is pure data + policy: no I/O, no engine state. The engine only ever calls [`evaluate`]
//! (verification). [`sign`] is for the release pipeline / external signing tooling — OSS ships
//! verification, not a signing CLI. The signing PRIMITIVE is INTERIM **ed25519**; only the verify
//! internals of [`evaluate`] (and the `sign` helper) would swap for another primitive — the manifest,
//! canonical bytes, and posture are primitive-independent and stay.
//!
//! ## Why NOT Sigstore keyless yet (1.5.0 spike outcome — deferred)
//!
//! Sigstore keyless was the intended direction (it matches busbar's existing build-provenance and has
//! nothing to leak). A 1.5.0 spike of the `sigstore` crate (v0.14) found it **cannot be adopted on a
//! release-held branch without regressing the security gates**, so the interim ed25519 path stays:
//!
//! - **cargo-deny advisories FAIL.** `sigstore → oci-client → jsonwebtoken → rsa 0.9.10` carries
//!   **RUSTSEC-2023-0071** (the "Marvin Attack" RSA timing sidechannel) with *"No safe upgrade is
//!   available"* — an unpatched vulnerability busbar's `cargo deny check advisories` gate rejects.
//!   (`openidconnect` pulls the same `rsa` too.) Ironically, adopting a *signing* dependency would
//!   INTRODUCE a known crypto vulnerability into the trust path.
//! - **Dependency-surface blow-up.** The tree resolves ~389 packages and adds ~26 duplicate-major
//!   crates (vs ~13 today) — the whole TUF/Fulcio/Rekor + OCI-registry + OIDC stack — cutting against
//!   the workspace's "single stack" goal.
//! - Licenses and sources were clean (the tree is allow-list compatible, no git deps), so the blocker
//!   is squarely the `rsa` advisory + the dependency weight, not licensing.
//!
//! When `sigstore` (or `jsonwebtoken`/`rsa`) ships a Marvin-mitigated release and the dep tree slims,
//! the swap is localized to `evaluate`'s signature check — trust becomes "a valid Sigstore cosign
//! bundle over the canonical manifest, from an allowlisted OIDC identity" — with no change to the
//! manifest shape, the posture, or any caller.

// `SigningKey`/`VerifyingKey` are re-exported so external signing tooling can name them via this crate.
use ed25519_dalek::{Signature, Signer, Verifier};
pub use ed25519_dalek::{SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

/// The signed `plugin.json` manifest that travels beside a plugin library. Every field except
/// `signature` is covered by the signature (via [`canonical_manifest_bytes`]), so none can be altered
/// without detection.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Manifest {
    /// Logical plugin name, e.g. `store-postgres`.
    pub name: String,
    /// The plugin's own release version (semver, e.g. `1.4.0`) — surfaced by the admin API so an
    /// upstream dashboard can compare against the latest and flag "update available".
    pub version: String,
    /// Plugin category: `store` | `auth` | `hook`.
    pub kind: String,
    /// The developer/author, shown on the install-confirmation card (e.g. `Acme Corp`).
    #[serde(default)]
    pub author: String,
    /// The plugin's homepage/website, shown on the confirmation card.
    #[serde(default)]
    pub homepage: String,
    /// Where the artifact came from (release URL / repo), shown on the confirmation card and recorded
    /// as provenance.
    #[serde(default)]
    pub source_url: String,
    /// One-line description, shown on the confirmation card.
    #[serde(default)]
    pub description: String,
    /// SPDX license id, shown on the confirmation card.
    #[serde(default)]
    pub license: String,
    /// The publisher identity whose key signed this — must resolve to an allowlisted public key.
    pub publisher: String,
    /// Which version of busbar's plugin INTERFACE (the low-level C calling contract) the library was
    /// built for. The engine also checks this at load. (Called the "ABI version" inside the code.)
    pub interface_version: u32,
    /// Lowercase hex SHA-256 of the library bytes — binds this manifest to that exact binary.
    pub sha256: String,
    /// Lowercase hex ed25519 signature over [`canonical_manifest_bytes`] (every field but this one).
    #[serde(default)]
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
    /// ANTI-DOWNGRADE floor: plugin `name` -> the minimum acceptable `version`. A manifest whose
    /// `version` parses BELOW the pinned floor is REJECTED even when its signature verifies against an
    /// allowlisted publisher — this stops a replay/rollback of an older, validly-signed (possibly
    /// vulnerable) release of the SAME plugin. Empty (the default) pins nothing, so behaviour is
    /// unchanged until an operator sets a floor. See [`version_at_least`] for the comparison.
    pub min_versions: BTreeMap<String, String>,
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

/// Lowercase-hex SHA-256 of `bytes` — the library digest stored in the manifest.
pub fn sha256_hex(bytes: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(bytes);
    hex::encode(h.finalize())
}

/// The canonical byte string that is signed/verified: the whole manifest MINUS its `signature`, as
/// deterministic sorted-key JSON. Using a `BTreeMap` makes the key order deterministic INDEPENDENT of
/// serde_json's `preserve_order` feature (which cargo feature-unification could flip on elsewhere in
/// the workspace) — so the signer and the verifier always agree, in any build. Any field added to the
/// manifest is automatically covered.
pub fn canonical_manifest_bytes(m: &Manifest) -> Vec<u8> {
    let value = serde_json::to_value(m).expect("manifest is serializable");
    let obj = value
        .as_object()
        .expect("manifest serializes to a JSON object");
    let sorted: BTreeMap<&str, &serde_json::Value> = obj
        .iter()
        .filter(|(k, _)| k.as_str() != "signature")
        .map(|(k, v)| (k.as_str(), v))
        .collect();
    serde_json::to_vec(&sorted).expect("canonical manifest serializes")
}

/// Sign a manifest with a publisher's key: set `sha256` from the artifact, clear any existing
/// `signature`, sign the canonical bytes, and return the completed [`Manifest`]. For the release
/// pipeline / external signing tooling — never runs in the engine (which only verifies).
pub fn sign(key: &SigningKey, mut manifest: Manifest, artifact: &[u8]) -> Manifest {
    manifest.sha256 = sha256_hex(artifact);
    manifest.signature = String::new();
    let sig = key.sign(&canonical_manifest_bytes(&manifest));
    manifest.signature = hex::encode(sig.to_bytes());
    manifest
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

/// Whether a manifest's signature verifies against `bytes` using `key`: the library hash must match
/// the manifest's `sha256` (binding), and the signature must verify over the canonical manifest
/// (authenticity + integrity).
fn signature_ok(manifest: &Manifest, bytes: &[u8], key: &VerifyingKey) -> Result<(), String> {
    if sha256_hex(bytes) != manifest.sha256 {
        return Err("library hash does not match the manifest".to_string());
    }
    let sig_bytes =
        hex::decode(&manifest.signature).map_err(|e| format!("signature not hex: {e}"))?;
    let sig_arr: [u8; 64] = sig_bytes
        .as_slice()
        .try_into()
        .map_err(|_| "signature must be 64 bytes".to_string())?;
    let sig = Signature::from_bytes(&sig_arr);
    key.verify(&canonical_manifest_bytes(manifest), &sig)
        .map_err(|_| "signature does not verify".to_string())
}

/// Parse a dotted version into its leading numeric components (`major.minor.patch`), ignoring any
/// pre-release/build suffix (`-rc1`, `+meta`) for the floor comparison. Dependency-free on purpose —
/// the crate deliberately keeps a minimal surface — and sufficient for an anti-downgrade floor, which
/// only needs a monotonic numeric ordering of releases. A component that isn't a number stops the
/// parse (later components are treated as 0), so a garbage version compares as `0.0.0` and can never
/// slip past a non-zero floor.
fn version_components(v: &str) -> [u64; 3] {
    let mut out = [0u64; 3];
    // Cut off any pre-release / build metadata before parsing the numeric core.
    let core = v.trim().split(['-', '+']).next().unwrap_or("");
    for (i, part) in core.split('.').take(3).enumerate() {
        match part.parse::<u64>() {
            Ok(n) => out[i] = n,
            Err(_) => break,
        }
    }
    out
}

/// True when `have` is greater-than-or-equal-to `floor` under [`version_components`] ordering. Used to
/// enforce the anti-downgrade floor: a manifest version below the pinned floor is a rollback attempt.
pub fn version_at_least(have: &str, floor: &str) -> bool {
    version_components(have) >= version_components(floor)
}

/// Evaluate an artifact against the trust policy. `manifest` is `None` when the artifact arrived
/// unsigned. `load_identity` is the identity the engine will actually LOAD this artifact by (the
/// library filename such as `libx.so`), NOT the manifest's self-declared `name`. Returns [`Verdict`]
/// when it may proceed (trusted, or untrusted-but-posture-permits), or [`Rejected`] when the posture
/// (or the anti-downgrade floor) forbids it.
///
/// Anti-downgrade (hard reject, un-bypassable): if `policy.min_versions` pins a floor for
/// `load_identity`, the load must PROVE (via a valid signature from an allowlisted publisher over a
/// manifest whose `version` is at or above the floor) that it meets the floor. A load that cannot
/// prove this is REJECTED regardless of `on_untrusted`. This closes three bypasses that keying the
/// floor on the manifest's self-declared `name` (and only checking it when a manifest was present)
/// left open:
///   * NO-MANIFEST: deleting the sidecar makes `manifest = None`; the floor still fires on
///     `load_identity` and rejects (an unsigned artifact cannot prove it meets the floor).
///   * NAME-MISMATCH: `manifest.name` is attacker-controlled; keying on `load_identity` (the engine's
///     resolved filename) means renaming the manifest's `name` no longer dodges the floor.
///   * LOOSE POSTURE: the floor is checked BEFORE any posture relaxation and requires a *trusted*
///     manifest, so `log`/`alert`/`allow` cannot launder a stripped-signature downgrade past it.
///
/// The `version` field is signature-covered, so an attacker cannot forge a higher one to clear a floor.
pub fn evaluate(
    bytes: &[u8],
    manifest: Option<&Manifest>,
    load_identity: &str,
    policy: &TrustPolicy,
) -> Result<Verdict, Rejected> {
    // Trust determination first: a manifest is TRUSTED only when a signature from an allowlisted
    // publisher verifies over these exact bytes. That verification is the sole thing that makes
    // `version` (and any other manifest field) trustworthy, so the floor below leans on it rather than
    // on unverified self-declared fields.
    let trusted_or_reason: Result<&Manifest, String> = match manifest {
        None => Err("artifact is unsigned (no manifest)".to_string()),
        Some(m) => match policy.publishers.get(&m.publisher) {
            None => Err(format!(
                "publisher '{}' is not in the allowlist",
                m.publisher
            )),
            Some(key) => match signature_ok(m, bytes, key) {
                Ok(()) => Ok(m),
                Err(reason) => Err(reason),
            },
        },
    };

    // Anti-downgrade floor (hard reject, BEFORE any posture relaxation). Keyed on `load_identity` (the
    // engine's resolved library filename), NOT the manifest's self-declared `name`. If a floor is
    // pinned for this identity, the load must be TRUSTED and its now-verified version must clear the
    // floor. Anything else (no manifest, an untrusted manifest, or a trusted-but-too-old version) is a
    // hard reject that no `on_untrusted` posture can relax.
    if let Some(floor) = policy.min_versions.get(load_identity) {
        match &trusted_or_reason {
            Ok(m) if version_at_least(&m.version, floor) => { /* proven at/above floor; proceed */ }
            Ok(m) => {
                return Err(Rejected(format!(
                    "plugin '{load_identity}' version {} is below the pinned minimum {floor} \
                     (anti-downgrade)",
                    m.version
                )));
            }
            Err(reason) => {
                return Err(Rejected(format!(
                    "plugin '{load_identity}' has a pinned minimum version {floor} but the load could \
                     not prove it meets the floor ({reason}); a signed manifest at or above the floor \
                     is required (anti-downgrade)"
                )));
            }
        }
    }

    match trusted_or_reason {
        Ok(m) => Ok(Verdict::Trusted {
            publisher: m.publisher.clone(),
        }),
        Err(reason) => match policy.on_untrusted {
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

    /// A manifest with the rich metadata filled (sha256/signature set by `sign`).
    fn manifest(name: &str, publisher: &str) -> Manifest {
        Manifest {
            name: name.to_string(),
            version: "1.4.0".to_string(),
            kind: "store".to_string(),
            author: "Acme Corp".to_string(),
            homepage: "https://acme.dev".to_string(),
            source_url: "https://github.com/acme/plugin".to_string(),
            description: "A store plugin".to_string(),
            license: "Apache-2.0".to_string(),
            publisher: publisher.to_string(),
            interface_version: 1,
            sha256: String::new(),
            signature: String::new(),
        }
    }

    fn policy(pairs: &[(&str, &VerifyingKey)], on_untrusted: OnUntrusted) -> TrustPolicy {
        TrustPolicy {
            publishers: pairs.iter().map(|(n, k)| (n.to_string(), **k)).collect(),
            on_untrusted,
            min_versions: BTreeMap::new(),
        }
    }

    #[test]
    fn sign_then_verify_is_trusted() {
        let key = test_key(1);
        let pubk = key.verifying_key();
        let artifact = b"\x7fELF fake plugin bytes";
        let m = sign(&key, manifest("store-sqlite", "busbar"), artifact);
        // manifest round-trips through JSON (it travels as plugin.json).
        let j = serde_json::to_string(&m).unwrap();
        assert_eq!(serde_json::from_str::<Manifest>(&j).unwrap(), m);

        let pol = policy(&[("busbar", &pubk)], OnUntrusted::Halt);
        assert_eq!(
            evaluate(artifact, Some(&m), "libstore.so", &pol).unwrap(),
            Verdict::Trusted {
                publisher: "busbar".into()
            }
        );
    }

    #[test]
    fn tampering_any_signed_field_fails() {
        let key = test_key(1);
        let pubk = key.verifying_key();
        let artifact = b"bytes";
        let m = sign(&key, manifest("p", "busbar"), artifact);
        let pol = policy(&[("busbar", &pubk)], OnUntrusted::Halt);

        // Flip a DISPLAY field the confirm-card shows: signature must break (card can't be spoofed).
        let mut forged = m.clone();
        forged.author = "Busbar Official".into();
        assert!(evaluate(artifact, Some(&forged), "libp.so", &pol).is_err());

        // Swap the library under a good manifest -> hash mismatch.
        assert!(evaluate(b"different!", Some(&m), "libp.so", &pol).is_err());
    }

    #[test]
    fn wrong_publisher_key_does_not_verify() {
        let key = test_key(1);
        let attacker = test_key(2);
        let artifact = b"bytes";
        let m = sign(&key, manifest("p", "busbar"), artifact);
        let pol = policy(&[("busbar", &attacker.verifying_key())], OnUntrusted::Halt);
        assert!(evaluate(artifact, Some(&m), "libp.so", &pol).is_err());
    }

    #[test]
    fn unknown_publisher_is_untrusted() {
        let key = test_key(1);
        let artifact = b"bytes";
        let m = sign(&key, manifest("p", "acme"), artifact);
        let pol = policy(&[("busbar", &key.verifying_key())], OnUntrusted::Halt);
        let err = evaluate(artifact, Some(&m), "libp.so", &pol).unwrap_err();
        assert!(err.0.contains("not in the allowlist"), "got {err:?}");
    }

    #[test]
    fn posture_allow_and_log_permit_unsigned_but_halt_refuses() {
        assert!(matches!(
            evaluate(b"x", None, "libp.so", &policy(&[], OnUntrusted::Allow)).unwrap(),
            Verdict::Allowed {
                action: OnUntrusted::Allow,
                ..
            }
        ));
        assert!(matches!(
            evaluate(b"x", None, "libp.so", &policy(&[], OnUntrusted::Log)).unwrap(),
            Verdict::Allowed { .. }
        ));
        assert!(evaluate(b"x", None, "libp.so", &policy(&[], OnUntrusted::Halt)).is_err());
    }

    #[test]
    fn canonical_bytes_are_stable_and_exclude_signature() {
        let key = test_key(1);
        let m = sign(&key, manifest("p", "busbar"), b"bytes");
        let a = canonical_manifest_bytes(&m);
        // Changing ONLY the signature does not change the canonical bytes (signature is excluded).
        let mut m2 = m.clone();
        m2.signature = "deadbeef".into();
        assert_eq!(a, canonical_manifest_bytes(&m2));
        // The canonical form is sorted-key JSON (author sorts before version).
        let s = String::from_utf8(a).unwrap();
        assert!(s.find("\"author\"").unwrap() < s.find("\"version\"").unwrap());
    }

    #[test]
    fn public_key_hex_roundtrip() {
        let key = test_key(1);
        let hex = hex::encode(key.verifying_key().to_bytes());
        assert_eq!(public_key_from_hex(&hex).unwrap(), key.verifying_key());
        assert!(public_key_from_hex("zz").is_err());
    }

    #[test]
    fn version_ordering_is_numeric_not_lexical() {
        assert!(version_at_least("1.10.0", "1.9.0"), "10 > 9 numerically");
        assert!(version_at_least("2.0.0", "1.99.99"));
        assert!(version_at_least("1.4.0", "1.4.0"), "equal clears the floor");
        assert!(!version_at_least("1.3.9", "1.4.0"));
        // Pre-release / build metadata is ignored for the floor core.
        assert!(version_at_least("1.4.0-rc1", "1.4.0"));
        // Garbage parses as 0.0.0 and cannot clear a non-zero floor.
        assert!(!version_at_least("not-a-version", "0.0.1"));
    }

    /// ANTI-DOWNGRADE: an OLDER but validly-signed manifest for a floored LOAD IDENTITY is REJECTED
    /// once a floor is pinned, even though its signature verifies against the allowlisted publisher.
    /// This is the rollback/replay attack: re-presenting a known-vulnerable prior release the vendor
    /// really did sign. Bumping the version to meet the floor is impossible without re-signing (version
    /// is a signed field), so the floor holds. The floor keys on the load identity (library filename),
    /// not the manifest's self-declared name.
    #[test]
    fn signed_but_downgraded_version_is_rejected() {
        let key = test_key(1);
        let pubk = key.verifying_key();
        let artifact = b"older vulnerable build";
        // A genuinely, validly-signed v1.0.0 loaded as "libstore.so".
        let mut old = manifest("store-sqlite", "busbar");
        old.version = "1.0.0".into();
        let old = sign(&key, old, artifact);

        // With NO floor it verifies as trusted (baseline).
        let mut pol = policy(&[("busbar", &pubk)], OnUntrusted::Halt);
        assert!(matches!(
            evaluate(artifact, Some(&old), "libstore.so", &pol).unwrap(),
            Verdict::Trusted { .. }
        ));

        // Pin the floor to 1.4.0 for the LOAD IDENTITY: the old validly-signed 1.0.0 is now rejected.
        pol.min_versions
            .insert("libstore.so".to_string(), "1.4.0".to_string());
        let err = evaluate(artifact, Some(&old), "libstore.so", &pol).unwrap_err();
        assert!(err.0.contains("anti-downgrade"), "got {err:?}");

        // A current, validly-signed 1.4.0 loaded under the same identity still passes the floor.
        let mut cur = manifest("store-sqlite", "busbar");
        cur.version = "1.4.0".into();
        let cur = sign(&key, cur, artifact);
        assert!(matches!(
            evaluate(artifact, Some(&cur), "libstore.so", &pol).unwrap(),
            Verdict::Trusted { .. }
        ));
    }

    /// The floor is a HARD reject that a loose posture cannot bypass: a stripped-signature (untrusted)
    /// older manifest under `on_untrusted: allow` is STILL refused when the load identity is floored,
    /// so a downgrade can't be laundered through a relaxed posture.
    #[test]
    fn downgrade_floor_is_not_bypassable_by_loose_posture() {
        let key = test_key(1);
        let artifact = b"older build";
        let mut old = manifest("store-sqlite", "busbar");
        old.version = "1.0.0".into();
        let old = sign(&key, old, artifact);
        // Strip the signature to make it "untrusted": a loose posture would normally allow it.
        let mut stripped = old.clone();
        stripped.signature = String::new();

        let mut pol = policy(&[], OnUntrusted::Allow);
        pol.min_versions
            .insert("libstore.so".to_string(), "1.4.0".to_string());
        // Even under `allow`, the floored downgrade is rejected outright.
        assert!(evaluate(artifact, Some(&stripped), "libstore.so", &pol).is_err());
    }

    /// FIX 1 (a) NO-MANIFEST bypass: deleting the sidecar makes `manifest = None`. Under a loose
    /// posture that would normally load an unsigned artifact, a floored load identity must STILL be
    /// rejected: an unsigned artifact cannot PROVE it meets the floor, so old vulnerable bytes cannot
    /// be loaded by dropping the manifest.
    #[test]
    fn floor_rejects_missing_manifest_even_under_loose_posture() {
        let artifact = b"old vulnerable bytes, no manifest";
        // Loose posture (`allow`) would load an unsigned artifact with no floor...
        let mut pol = policy(&[], OnUntrusted::Allow);
        assert!(matches!(
            evaluate(artifact, None, "libstore.so", &pol).unwrap(),
            Verdict::Allowed { .. }
        ));
        // ...but once the load identity is floored, a manifest-less load is a HARD reject.
        pol.min_versions
            .insert("libstore.so".to_string(), "1.4.0".to_string());
        let err = evaluate(artifact, None, "libstore.so", &pol).unwrap_err();
        assert!(err.0.contains("anti-downgrade"), "got {err:?}");
        assert!(
            err.0.contains("could not prove") || err.0.contains("unsigned"),
            "reason should say the load could not prove the floor: {err:?}"
        );
    }

    /// FIX 1 (b) NAME-MISMATCH bypass: an untrusted manifest's `name` is attacker-controlled. Renaming
    /// it to a non-floored string no longer dodges the floor, because the floor now keys on the LOAD
    /// IDENTITY (the library filename the engine resolves it by), not the manifest's self-declared
    /// name. A floored library with a renamed manifest is REJECTED even under a loose posture.
    #[test]
    fn floor_rejects_name_mismatch_manifest() {
        let key = test_key(1);
        let artifact = b"old build, manifest renamed to dodge the floor";
        // A stripped/untrusted manifest whose self-declared name is a non-floored string.
        let mut m = manifest("totally-different-name", "busbar");
        m.version = "1.0.0".into();
        let mut m = sign(&key, m, artifact);
        m.signature = String::new(); // untrusted

        let mut pol = policy(&[], OnUntrusted::Allow);
        // Floor is pinned on the LOAD IDENTITY, which the attacker cannot rename.
        pol.min_versions
            .insert("libstore.so".to_string(), "1.4.0".to_string());
        let err = evaluate(artifact, Some(&m), "libstore.so", &pol).unwrap_err();
        assert!(err.0.contains("anti-downgrade"), "got {err:?}");
        // And with NO floor on the load identity, the renamed manifest name is irrelevant: the floor
        // pinned under the OLD (self-declared) key does not fire, confirming the floor no longer keys
        // on `manifest.name`.
        let mut pol2 = policy(&[], OnUntrusted::Allow);
        pol2.min_versions
            .insert("totally-different-name".to_string(), "1.4.0".to_string());
        assert!(
            matches!(
                evaluate(artifact, Some(&m), "libstore.so", &pol2).unwrap(),
                Verdict::Allowed { .. }
            ),
            "a floor keyed on the manifest's self-declared name must NOT gate a differently-named \
             load identity"
        );
    }

    /// FIX 1 positive control: a legitimately-signed plugin at or above the floor, loaded under the
    /// floored identity, still loads as Trusted (the hardening does not break the happy path).
    #[test]
    fn floored_identity_accepts_signed_at_or_above_floor() {
        let key = test_key(1);
        let pubk = key.verifying_key();
        let artifact = b"current good build";
        let mut cur = manifest("store-sqlite", "busbar");
        cur.version = "1.4.0".into();
        let cur = sign(&key, cur, artifact);

        let mut pol = policy(&[("busbar", &pubk)], OnUntrusted::Halt);
        pol.min_versions
            .insert("libstore.so".to_string(), "1.4.0".to_string());
        assert!(matches!(
            evaluate(artifact, Some(&cur), "libstore.so", &pol).unwrap(),
            Verdict::Trusted { .. }
        ));
    }
}
