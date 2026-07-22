// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Plugin **manifest, signing input, structural validation, and trust evaluation** for busbar.
//!
//! A PLUGIN IS A PLUGIN: store, auth, and hook plugins share ONE manifest format and ONE trust
//! model, discriminated only by the manifest `kind` field. Every plugin ships as a signed tarball
//! containing exactly the cdylib and this manifest; identity comes from the SIGNED manifest, never
//! from the filename.
//!
//! The manifest carries:
//!
//! - **identity**: `name` (canonical, e.g. `busbar-store-redis`), `alias` (the short config name,
//!   e.g. `redis`), `kind` (`store` | `auth` | `hook`), `version` (semver);
//! - **binding + compat**: `sha256` (of the library bytes, pinning the manifest to that exact
//!   binary) and `abi_version` (which busbar C ABI the cdylib exports for its `kind`);
//! - **authenticity**: `publisher` + `signature` over the *canonical whole manifest*;
//! - **display**: `description`, `homepage`, `license` (all signed, so they cannot be spoofed).
//!
//! The signature covers the entire manifest (every field except `signature` itself) via
//! [`canonical_manifest_bytes`], and the manifest pins the library by `sha256`, so **neither the
//! manifest nor the library can be altered or swapped independently**.
//!
//! ## Trust model
//!
//! - **First-party**: a manifest whose `publisher` is `busbar` verifies against the release public
//!   key EMBEDDED in the binary ([`embedded_release_pubkey`]) — trusted with ZERO configuration.
//!   First-party anti-downgrade is AUTOMATIC: the plugin `version` must be at or above the running
//!   binary's version (no `min_versions` entry needed), so a validly-signed but OLD first-party
//!   release cannot be replayed against a newer binary.
//! - **Third-party**: `plugins.trust.publishers` allowlists third-party signing keys. A valid
//!   signature from an allowlisted publisher is TRUSTED. `plugins.min_versions` pins per-plugin
//!   anti-downgrade floors (third-party only in practice; first-party is automatic).
//! - **Everything else** (unsigned, tampered, unknown publisher) is UNTRUSTED and, by DEFAULT,
//!   rejected. The operator opts in per category via [`TrustPolicy::allow_unsigned`] and
//!   [`TrustPolicy::allow_third_party`].
//!
//! This crate is pure data + policy: no I/O, no engine state. Discovery, unpacking, and loading
//! live in `busbar-plugin-loader`; the engine sees neither. [`sign`] exists for the release
//! pipeline / packaging tooling — OSS ships verification, not a signing service.
//!
//! ## Why NOT Sigstore keyless yet (1.5.0 spike outcome — deferred)
//!
//! A 1.5.0 spike of the `sigstore` crate (v0.14) found it cannot be adopted without regressing the
//! security gates: its tree carries `rsa 0.9.10` with RUSTSEC-2023-0071 (the Marvin RSA timing
//! sidechannel, "no safe upgrade available"), which `cargo deny check advisories` rejects, and it
//! roughly triples the dependency surface. When a mitigated release ships, the swap is localized to
//! [`evaluate`]'s signature check; the manifest shape and posture are primitive-independent.

// `SigningKey`/`VerifyingKey` are re-exported so external signing tooling can name them via this crate.
use ed25519_dalek::{Signature, Signer, Verifier};
pub use ed25519_dalek::{SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

/// The reserved first-party publisher name. A manifest carrying this publisher verifies against the
/// EMBEDDED release key ([`TrustPolicy::first_party_key`]), never against `publishers` — an operator
/// cannot (and need not) allowlist a key named `busbar`.
pub const FIRST_PARTY_PUBLISHER: &str = "busbar";

/// The plugin kinds this binary understands. ONE plugin subsystem: `kind` only selects which C ABI
/// the cdylib exports and which engine subsystem consumes it; discovery/trust/validation are shared.
pub const KNOWN_KINDS: &[&str] = &["store", "auth", "hook"];

/// The busbar release ed25519 PUBLIC key embedded at BUILD time via the `BUSBAR_RELEASE_PUBKEY`
/// environment variable (64 hex chars). `None` in a build where it was not provided (local dev
/// builds): first-party verification is then impossible and a `publisher: busbar` plugin is treated
/// as unsigned (loadable only under `allow_unsigned`).
///
/// TODO(release-keys): the REAL release keypair is generated separately by the release orchestrator;
/// CI must export `BUSBAR_RELEASE_PUBKEY=<hex public key>` when building release binaries (the
/// private half lives only in the `BUSBAR_SIGN_KEY` CI secret). Do NOT hardcode a key here.
pub fn embedded_release_pubkey() -> Option<VerifyingKey> {
    let hex_key: &str = option_env!("BUSBAR_RELEASE_PUBKEY")?;
    // A malformed build-time key is a build/packaging bug; fail closed to "no first-party key"
    // rather than panic in the engine (the plugin then simply cannot verify as first-party).
    public_key_from_hex(hex_key).ok()
}

/// The signed manifest that travels inside every plugin tarball. Every field except `signature` is
/// covered by the signature (via [`canonical_manifest_bytes`]), so none can be altered undetected.
///
/// `deny_unknown_fields`: a manifest with fields this binary does not understand FAILS structural
/// validation (fail-closed) rather than silently dropping content the signature may cover.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Manifest {
    /// Canonical plugin name, e.g. `busbar-store-redis`. Lowercase `[a-z0-9-]+`.
    pub name: String,
    /// Short config alias, e.g. `redis` — what `governance.store:` may reference. Lowercase
    /// `[a-z0-9-]+`. May equal `name`.
    pub alias: String,
    /// Plugin category: `store` | `auth` | `hook`. Selects the C ABI the cdylib exports and the
    /// engine subsystem that consumes it; everything else about the plugin machinery is shared.
    pub kind: String,
    /// The plugin's release version (semver, e.g. `1.5.0`).
    pub version: String,
    /// The publisher identity whose key signed this. `busbar` is reserved for first-party plugins
    /// (verified against the embedded release key); anything else resolves via
    /// `plugins.trust.publishers`.
    pub publisher: String,
    /// Which version of busbar's C plugin ABI (for this `kind`) the cdylib was built against.
    pub abi_version: u32,
    /// Lowercase hex SHA-256 of the library bytes — binds this manifest to that exact binary.
    pub sha256: String,
    /// Lowercase hex ed25519 signature over [`canonical_manifest_bytes`] (every field but this one).
    #[serde(default)]
    pub signature: String,
    /// One-line description (display only; signed).
    #[serde(default)]
    pub description: String,
    /// Homepage/website (display only; signed).
    #[serde(default)]
    pub homepage: String,
    /// SPDX license id (display only; signed).
    #[serde(default)]
    pub license: String,
}

/// How a plugin was permitted to load when it is NOT signed by a trusted key - the operator's
/// EXPLICIT opt-in (never a silent default).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AllowReason {
    /// The artifact carries no valid signature (unsigned / tampered) and `allow_unsigned` is set.
    Unsigned,
    /// The artifact is VALIDLY signed but by a publisher NOT in the allowlist, and
    /// `allow_third_party` is set.
    ThirdParty,
}

/// The resolved trust policy: the embedded first-party key, the allowlisted third-party publisher
/// keys, the EXPLICIT opt-in flags, and the anti-downgrade floors. Built from `plugins.trust` +
/// `plugins.min_versions` config (plus the embedded release key and the binary's own version).
///
/// DEFAULT posture (both flags `false`): an untrusted plugin (unsigned OR signed by a
/// non-allowlisted publisher) is REJECTED - logged and skipped, never `dlopen`ed.
#[derive(Clone, Default)]
pub struct TrustPolicy {
    /// The embedded busbar release public key ([`embedded_release_pubkey`]). `None` in a build with
    /// no embedded key: first-party plugins then cannot verify (they are treated as unsigned).
    pub first_party_key: Option<VerifyingKey>,
    /// The running binary's version (`CARGO_PKG_VERSION`) — the AUTOMATIC first-party
    /// anti-downgrade floor: a `publisher: busbar` plugin whose `version` is below this is rejected
    /// even with a valid signature. Empty disables the automatic floor (tests only).
    pub binary_version: String,
    /// THIRD-PARTY allowlist: publisher name -> ed25519 public key. The first-party publisher
    /// (`busbar`) never resolves here.
    pub publishers: BTreeMap<String, VerifyingKey>,
    /// Opt-in: load plugins that carry NO valid signature (unsigned / tampered). Default `false`.
    pub allow_unsigned: bool,
    /// Opt-in: load plugins validly signed by a publisher NOT in `publishers`. Default `false`.
    pub allow_third_party: bool,
    /// ANTI-DOWNGRADE floors: plugin `name` -> minimum acceptable `version`. A floored name must
    /// PROVE (via a trusted signature over a manifest at/above the floor) that it meets the floor;
    /// anything else is a hard reject no opt-in flag can relax. Third-party only in practice —
    /// first-party is automatic via `binary_version`.
    pub min_versions: BTreeMap<String, String>,
}

/// The verdict for one plugin artifact that MAY proceed to load.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verdict {
    /// A valid signature from a trusted key. `first_party` distinguishes the embedded busbar key
    /// from an allowlisted third-party publisher (display + logging).
    Trusted {
        publisher: String,
        first_party: bool,
    },
    /// Not trusted, but an EXPLICIT opt-in flag permits proceeding - the caller should log a
    /// warning naming `reason`.
    Allowed { reason: String, allow: AllowReason },
}

/// Trust failure. The posture forbids loading this plugin; the message is safe to surface.
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
/// deterministic sorted-key JSON. Using a `BTreeMap` makes the key order deterministic INDEPENDENT
/// of serde_json's `preserve_order` feature, so the signer and verifier always agree in any build.
/// Any field added to the manifest is automatically covered.
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
/// pipeline / packaging tooling — never runs in the engine (which only verifies).
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
/// pre-release/build suffix (`-rc1`, `+meta`) for the floor comparison. Dependency-free on purpose;
/// sufficient for an anti-downgrade floor, which only needs a monotonic numeric ordering. A
/// component that isn't a number stops the parse, so a garbage version compares as `0.0.0` and can
/// never slip past a non-zero floor.
fn version_components(v: &str) -> [u64; 3] {
    let mut out = [0u64; 3];
    let core = v.trim().split(['-', '+']).next().unwrap_or("");
    for (i, part) in core.split('.').take(3).enumerate() {
        match part.parse::<u64>() {
            Ok(n) => out[i] = n,
            Err(_) => break,
        }
    }
    out
}

/// True when `have` is greater-than-or-equal-to `floor` under [`version_components`] ordering.
pub fn version_at_least(have: &str, floor: &str) -> bool {
    version_components(have) >= version_components(floor)
}

/// Is `s` a well-formed plugin name/alias: non-empty lowercase `[a-z0-9-]+`, no leading/trailing
/// dash. The tight charset keeps names filesystem-, config-, and log-safe.
pub fn valid_name(s: &str) -> bool {
    !s.is_empty()
        && !s.starts_with('-')
        && !s.ends_with('-')
        && s.bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}

/// Is `v` a well-formed semver core (`MAJOR.MINOR.PATCH`, each a decimal integer, with an optional
/// `-pre`/`+meta` suffix)? The strict three-component core is what the anti-downgrade ordering
/// depends on, so it is validated structurally rather than best-effort parsed.
pub fn valid_semver(v: &str) -> bool {
    let core = v.split(['-', '+']).next().unwrap_or("");
    let parts: Vec<&str> = core.split('.').collect();
    parts.len() == 3
        && parts
            .iter()
            .all(|p| !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit()))
}

/// PHASE 1 — STRUCTURAL validation of a manifest + its library bytes, INDEPENDENT of trust: a
/// signed-but-malformed manifest still fails here. Checks every required field is present and
/// well-formed, the `sha256` integrity binding holds against `lib_bytes`, and the declared
/// `abi_version` is one this binary supports for the declared `kind` (`supported_abi`). Returns the
/// FIRST failure as a specific, named reason. Parse errors are the caller's (the manifest must
/// already have deserialized to call this).
pub fn validate_structure(
    m: &Manifest,
    lib_bytes: &[u8],
    supported_abi: &dyn Fn(&str) -> &'static [u32],
) -> Result<(), String> {
    if !valid_name(&m.name) {
        return Err(format!(
            "manifest name '{}' is not a valid plugin name (lowercase [a-z0-9-]+)",
            m.name
        ));
    }
    if !valid_name(&m.alias) {
        return Err(format!(
            "manifest alias '{}' is not a valid plugin alias (lowercase [a-z0-9-]+)",
            m.alias
        ));
    }
    if !KNOWN_KINDS.contains(&m.kind.as_str()) {
        return Err(format!(
            "manifest kind '{}' is not one of {KNOWN_KINDS:?}",
            m.kind
        ));
    }
    if !valid_semver(&m.version) {
        return Err(format!(
            "manifest version '{}' is not a semver version (MAJOR.MINOR.PATCH)",
            m.version
        ));
    }
    if m.publisher.trim().is_empty() {
        return Err("manifest publisher is empty".to_string());
    }
    if m.sha256.len() != 64 || !m.sha256.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(format!(
            "manifest sha256 '{}' is not a 64-char hex digest",
            m.sha256
        ));
    }
    if sha256_hex(lib_bytes) != m.sha256.to_ascii_lowercase() {
        return Err(
            "library bytes do not match the manifest sha256 (integrity failure)".to_string(),
        );
    }
    let supported = supported_abi(&m.kind);
    if !supported.contains(&m.abi_version) {
        return Err(format!(
            "manifest abi_version {} is not supported for kind '{}' by this binary (supported: {supported:?})",
            m.abi_version, m.kind
        ));
    }
    Ok(())
}

/// The untrusted category of an artifact that is NOT signed by a trusted key - decides which
/// explicit opt-in flag (if any) could permit it.
enum Untrusted {
    /// No valid signature: empty/tampered signature, or a first-party manifest in a build with no
    /// embedded key. Opt-in is `allow_unsigned`. A tamper of a KNOWN key's signature is still
    /// "unsigned" for opt-in purposes - it never counts as third-party.
    Unsigned { reason: String },
    /// A manifest whose `publisher` is NOT `busbar` and NOT in the allowlist. Its signature cannot
    /// be verified here (no key held), so it is a third-party artifact. Opt-in is
    /// `allow_third_party`.
    ThirdParty { publisher: String },
}

/// PHASE 2 — TRUST evaluation of a structurally-valid manifest + its exact library bytes against
/// the policy. Returns [`Verdict`] when the plugin may proceed (trusted, or
/// untrusted-but-explicitly-opted-in), or [`Rejected`] when it must NOT load — the DEFAULT for any
/// untrusted artifact, and ALWAYS for an anti-downgrade violation (which no opt-in can relax).
///
/// TRUST MODEL:
///   * `publisher: busbar` verifies against the EMBEDDED release key -> first-party TRUSTED with
///     zero config. Anti-downgrade is AUTOMATIC: `version` must be at/above
///     [`TrustPolicy::binary_version`].
///   * A publisher in `publishers` whose signature verifies -> TRUSTED (third-party allowlisted).
///   * Unsigned/tampered -> [`Verdict::Allowed`] only under `allow_unsigned`; else [`Rejected`].
///   * Signed by an unknown publisher -> [`Verdict::Allowed`] only under `allow_third_party`; else
///     [`Rejected`].
///
/// Anti-downgrade floors (`min_versions`, keyed by manifest `name`) are checked BEFORE any opt-in
/// relaxation and require a TRUSTED manifest at/above the floor — so a stripped-signature or
/// unknown-publisher downgrade cannot be laundered through a loose posture. The `version` field is
/// signature-covered, so it cannot be forged upward.
pub fn evaluate(
    bytes: &[u8],
    manifest: &Manifest,
    policy: &TrustPolicy,
) -> Result<Verdict, Rejected> {
    // Trust determination first: which key (if any) proves this manifest? A manifest with NO
    // signature at all is UNSIGNED regardless of its (unverifiable, self-declared) publisher —
    // only a PRESENT signature from a non-allowlisted publisher counts as third-party.
    let trusted_or_untrusted: Result<bool, Untrusted> = if manifest.signature.trim().is_empty() {
        Err(Untrusted::Unsigned {
            reason: "manifest carries no signature".to_string(),
        })
    } else if manifest.publisher == FIRST_PARTY_PUBLISHER {
        match &policy.first_party_key {
            None => Err(Untrusted::Unsigned {
                reason: format!(
                    "manifest claims first-party publisher '{FIRST_PARTY_PUBLISHER}' but this \
                     build embeds no busbar release key, so it cannot be verified"
                ),
            }),
            Some(key) => match signature_ok(manifest, bytes, key) {
                Ok(()) => Ok(true),
                Err(reason) => Err(Untrusted::Unsigned {
                    reason: format!("first-party signature failed: {reason}"),
                }),
            },
        }
    } else {
        match policy.publishers.get(&manifest.publisher) {
            None => Err(Untrusted::ThirdParty {
                publisher: manifest.publisher.clone(),
            }),
            Some(key) => match signature_ok(manifest, bytes, key) {
                Ok(()) => Ok(false),
                Err(reason) => Err(Untrusted::Unsigned {
                    reason: format!(
                        "signature from allowlisted publisher '{}' failed: {reason}",
                        manifest.publisher
                    ),
                }),
            },
        }
    };

    // FIRST-PARTY AUTOMATIC anti-downgrade: a VERIFIED first-party plugin must be at or above the
    // running binary's version. A hard reject (a validly-signed but old first-party release is
    // exactly the rollback/replay this stops); no opt-in flag applies to a verified first-party.
    if let Ok(true) = trusted_or_untrusted {
        if !policy.binary_version.is_empty()
            && !version_at_least(&manifest.version, &policy.binary_version)
        {
            return Err(Rejected(format!(
                "first-party plugin '{}' version {} is below this busbar binary's version {} \
                 (automatic first-party anti-downgrade)",
                manifest.name, manifest.version, policy.binary_version
            )));
        }
    }

    // CONFIGURED anti-downgrade floor (hard reject, BEFORE any opt-in relaxation), keyed by the
    // manifest name. A floored name must be TRUSTED and its (now-verified) version must clear the
    // floor; anything else is a hard reject no opt-in flag can relax.
    if let Some(floor) = policy.min_versions.get(&manifest.name) {
        match &trusted_or_untrusted {
            Ok(_) if version_at_least(&manifest.version, floor) => {}
            Ok(_) => {
                return Err(Rejected(format!(
                    "plugin '{}' version {} is below the pinned minimum {floor} (anti-downgrade)",
                    manifest.name, manifest.version
                )));
            }
            Err(_) => {
                return Err(Rejected(format!(
                    "plugin '{}' has a pinned minimum version {floor} but the load could not prove \
                     it meets the floor (not signed by a trusted key); a trusted manifest at or \
                     above the floor is required (anti-downgrade)",
                    manifest.name
                )));
            }
        }
    }

    match trusted_or_untrusted {
        Ok(first_party) => Ok(Verdict::Trusted {
            publisher: manifest.publisher.clone(),
            first_party,
        }),
        Err(Untrusted::Unsigned { reason }) => {
            if policy.allow_unsigned {
                Ok(Verdict::Allowed {
                    reason,
                    allow: AllowReason::Unsigned,
                })
            } else {
                Err(Rejected(format!(
                    "{reason}; refusing to load an unsigned plugin. Set \
                     plugins.trust.allow_unsigned=true to permit unsigned plugins."
                )))
            }
        }
        Err(Untrusted::ThirdParty { publisher }) => {
            if policy.allow_third_party {
                Ok(Verdict::Allowed {
                    reason: format!("signed by non-allowlisted publisher '{publisher}'"),
                    allow: AllowReason::ThirdParty,
                })
            } else {
                Err(Rejected(format!(
                    "publisher '{publisher}' is not in the allowlist; refusing to load a \
                     third-party plugin. Add the publisher to plugins.trust.publishers, or set \
                     plugins.trust.allow_third_party=true to permit third-party plugins."
                )))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Deterministic test key from a seed byte (no RNG needed in this crate's tests).
    fn test_key(seed: u8) -> SigningKey {
        SigningKey::from_bytes(&[seed; 32])
    }

    /// A well-formed manifest (sha256/signature set by `sign`).
    fn manifest(name: &str, alias: &str, publisher: &str) -> Manifest {
        Manifest {
            name: name.to_string(),
            alias: alias.to_string(),
            kind: "store".to_string(),
            version: "1.5.0".to_string(),
            publisher: publisher.to_string(),
            abi_version: 1,
            sha256: String::new(),
            signature: String::new(),
            description: "A store plugin".to_string(),
            homepage: "https://example.dev".to_string(),
            license: "Apache-2.0".to_string(),
        }
    }

    fn abi(_kind: &str) -> &'static [u32] {
        &[1]
    }

    /// A policy with the given first-party key, third-party publishers, and opt-in flags.
    fn policy(
        first_party: Option<&SigningKey>,
        pairs: &[(&str, &VerifyingKey)],
        allow_unsigned: bool,
        allow_third_party: bool,
    ) -> TrustPolicy {
        TrustPolicy {
            first_party_key: first_party.map(|k| k.verifying_key()),
            binary_version: "1.5.0".to_string(),
            publishers: pairs.iter().map(|(n, k)| (n.to_string(), **k)).collect(),
            allow_unsigned,
            allow_third_party,
            min_versions: BTreeMap::new(),
        }
    }

    #[test]
    fn first_party_signed_is_trusted_with_zero_config() {
        let release = test_key(1);
        let artifact = b"\x7fELF first-party plugin";
        let m = sign(
            &release,
            manifest("busbar-store-redis", "redis", FIRST_PARTY_PUBLISHER),
            artifact,
        );
        // Manifest round-trips through JSON (it travels inside the tarball).
        let j = serde_json::to_string(&m).unwrap();
        assert_eq!(serde_json::from_str::<Manifest>(&j).unwrap(), m);

        // ZERO configured publishers: the embedded key alone proves first-party.
        let pol = policy(Some(&release), &[], false, false);
        assert_eq!(
            evaluate(artifact, &m, &pol).unwrap(),
            Verdict::Trusted {
                publisher: FIRST_PARTY_PUBLISHER.into(),
                first_party: true
            }
        );
    }

    #[test]
    fn first_party_below_binary_version_is_auto_rejected() {
        let release = test_key(1);
        let artifact = b"old first-party build";
        let mut m = manifest("busbar-store-redis", "redis", FIRST_PARTY_PUBLISHER);
        m.version = "1.4.0".into(); // binary is 1.5.0
        let m = sign(&release, m, artifact);
        let pol = policy(Some(&release), &[], false, false);
        let err = evaluate(artifact, &m, &pol).unwrap_err();
        assert!(err.0.contains("first-party anti-downgrade"), "got {err:?}");

        // Loose posture cannot launder it either (verified first-party never consults opt-ins).
        let loose = policy(Some(&release), &[], true, true);
        assert!(evaluate(artifact, &m, &loose).is_err());
    }

    #[test]
    fn first_party_claim_without_embedded_key_is_unsigned() {
        let release = test_key(1);
        let artifact = b"bytes";
        let m = sign(
            &release,
            manifest("busbar-store-redis", "redis", FIRST_PARTY_PUBLISHER),
            artifact,
        );
        // No embedded key in this build: default posture rejects, naming the situation.
        let pol = policy(None, &[], false, false);
        let err = evaluate(artifact, &m, &pol).unwrap_err();
        assert!(
            err.0.contains("embeds no busbar release key"),
            "got {err:?}"
        );
        // allow_unsigned permits it (dev builds), as the Unsigned category.
        let loose = policy(None, &[], true, false);
        assert!(matches!(
            evaluate(artifact, &m, &loose).unwrap(),
            Verdict::Allowed {
                allow: AllowReason::Unsigned,
                ..
            }
        ));
    }

    #[test]
    fn third_party_allowlisted_publisher_is_trusted() {
        let acme = test_key(2);
        let artifact = b"third-party bytes";
        let m = sign(
            &acme,
            manifest("acme-store-dynamo", "dynamo", "acme"),
            artifact,
        );
        let pol = policy(None, &[("acme", &acme.verifying_key())], false, false);
        assert_eq!(
            evaluate(artifact, &m, &pol).unwrap(),
            Verdict::Trusted {
                publisher: "acme".into(),
                first_party: false
            }
        );
    }

    #[test]
    fn tampering_any_signed_field_fails() {
        let key = test_key(1);
        let artifact = b"bytes";
        let m = sign(&key, manifest("acme-p", "p", "acme"), artifact);
        let pol = policy(None, &[("acme", &key.verifying_key())], false, false);

        // Flip a DISPLAY field: signature must break (the display card cannot be spoofed).
        let mut forged = m.clone();
        forged.description = "Busbar Official".into();
        assert!(evaluate(artifact, &forged, &pol).is_err());
        // Flip the ALIAS (the config-selection identity): signature must break.
        let mut forged = m.clone();
        forged.alias = "redis".into();
        assert!(evaluate(artifact, &forged, &pol).is_err());
        // Swap the library under a good manifest -> hash mismatch.
        assert!(evaluate(b"different!", &m, &pol).is_err());
    }

    #[test]
    fn wrong_publisher_key_does_not_verify() {
        let key = test_key(1);
        let attacker = test_key(2);
        let artifact = b"bytes";
        let m = sign(&key, manifest("acme-p", "p", "acme"), artifact);
        let pol = policy(None, &[("acme", &attacker.verifying_key())], false, false);
        assert!(evaluate(artifact, &m, &pol).is_err());
    }

    #[test]
    fn unknown_publisher_needs_allow_third_party() {
        let key = test_key(3);
        let artifact = b"third-party bytes";
        let m = sign(&key, manifest("acme-p", "p", "acme"), artifact);

        // Default: refused, naming allow_third_party (NOT allow_unsigned).
        let err = evaluate(artifact, &m, &policy(None, &[], false, false)).unwrap_err();
        assert!(err.0.contains("allow_third_party"), "got {err:?}");
        // allow_unsigned alone does NOT permit a third-party-signed plugin.
        assert!(evaluate(artifact, &m, &policy(None, &[], true, false)).is_err());
        // allow_third_party permits it.
        assert!(matches!(
            evaluate(artifact, &m, &policy(None, &[], false, true)).unwrap(),
            Verdict::Allowed {
                allow: AllowReason::ThirdParty,
                ..
            }
        ));
    }

    #[test]
    fn unsigned_needs_allow_unsigned() {
        let artifact = b"unsigned bytes";
        let mut m = manifest("acme-p", "p", "acme");
        m.sha256 = sha256_hex(artifact);
        // Publisher IS allowlisted but the signature is empty -> tamper/unsigned category.
        let key = test_key(1);
        let pol = policy(None, &[("acme", &key.verifying_key())], false, false);
        let err = evaluate(artifact, &m, &pol).unwrap_err();
        assert!(err.0.contains("allow_unsigned"), "got {err:?}");
        let loose = policy(None, &[("acme", &key.verifying_key())], true, false);
        assert!(matches!(
            evaluate(artifact, &m, &loose).unwrap(),
            Verdict::Allowed {
                allow: AllowReason::Unsigned,
                ..
            }
        ));
    }

    #[test]
    fn canonical_bytes_are_stable_and_exclude_signature() {
        let key = test_key(1);
        let m = sign(&key, manifest("acme-p", "p", "acme"), b"bytes");
        let a = canonical_manifest_bytes(&m);
        let mut m2 = m.clone();
        m2.signature = "deadbeef".into();
        assert_eq!(a, canonical_manifest_bytes(&m2));
        // Sorted-key JSON: abi_version sorts before alias before name.
        let s = String::from_utf8(a).unwrap();
        assert!(s.find("\"abi_version\"").unwrap() < s.find("\"alias\"").unwrap());
        assert!(s.find("\"alias\"").unwrap() < s.find("\"name\"").unwrap());
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
        assert!(version_at_least("1.4.0-rc1", "1.4.0"));
        assert!(!version_at_least("not-a-version", "0.0.1"));
    }

    #[test]
    fn name_and_semver_validators() {
        assert!(valid_name("busbar-store-redis"));
        assert!(valid_name("redis"));
        assert!(!valid_name(""));
        assert!(!valid_name("Redis"));
        assert!(!valid_name("re dis"));
        assert!(!valid_name("-redis"));
        assert!(!valid_name("redis-"));
        assert!(!valid_name("../evil"));
        assert!(valid_semver("1.5.0"));
        assert!(valid_semver("1.5.0-rc1"));
        assert!(!valid_semver("1.5"));
        assert!(!valid_semver("1.5.x"));
        assert!(!valid_semver(""));
    }

    /// Phase-1 structural validation catches each malformation with a specific reason, independent
    /// of trust (a validly-signed malformed manifest still fails).
    #[test]
    fn structural_validation_names_each_failure() {
        let key = test_key(1);
        let bytes = b"lib bytes";
        let good = sign(&key, manifest("acme-p", "p", "acme"), bytes);
        assert!(validate_structure(&good, bytes, &abi).is_ok());

        let mut bad = good.clone();
        bad.name = "Bad Name".into();
        assert!(validate_structure(&bad, bytes, &abi)
            .unwrap_err()
            .contains("not a valid plugin name"));

        let mut bad = good.clone();
        bad.alias = "UP".into();
        assert!(validate_structure(&bad, bytes, &abi)
            .unwrap_err()
            .contains("alias"));

        let mut bad = good.clone();
        bad.kind = "widget".into();
        assert!(validate_structure(&bad, bytes, &abi)
            .unwrap_err()
            .contains("kind"));

        let mut bad = good.clone();
        bad.version = "latest".into();
        assert!(validate_structure(&bad, bytes, &abi)
            .unwrap_err()
            .contains("semver"));

        let mut bad = good.clone();
        bad.publisher = " ".into();
        assert!(validate_structure(&bad, bytes, &abi)
            .unwrap_err()
            .contains("publisher"));

        let mut bad = good.clone();
        bad.sha256 = "abc".into();
        assert!(validate_structure(&bad, bytes, &abi)
            .unwrap_err()
            .contains("64-char hex"));

        // Integrity: right shape, wrong digest.
        let mut bad = good.clone();
        bad.sha256 = sha256_hex(b"other bytes");
        assert!(validate_structure(&bad, bytes, &abi)
            .unwrap_err()
            .contains("integrity"));

        let mut bad = good.clone();
        bad.abi_version = 99;
        assert!(validate_structure(&bad, bytes, &abi)
            .unwrap_err()
            .contains("abi_version"));
    }

    /// A manifest with an UNKNOWN field fails to parse at all (deny_unknown_fields): fail-closed
    /// against content this binary does not understand.
    #[test]
    fn unknown_manifest_field_fails_parse() {
        let key = test_key(1);
        let m = sign(&key, manifest("acme-p", "p", "acme"), b"bytes");
        let mut v = serde_json::to_value(&m).unwrap();
        v.as_object_mut()
            .unwrap()
            .insert("surprise".into(), serde_json::json!(true));
        assert!(serde_json::from_value::<Manifest>(v).is_err());
    }

    /// Configured floor: a validly-signed-but-old third-party release is rejected once floored, and
    /// a stripped-signature copy cannot be laundered past the floor by a loose posture.
    #[test]
    fn configured_floor_rejects_downgrade_and_is_not_bypassable() {
        let acme = test_key(2);
        let artifact = b"older vulnerable build";
        let mut old = manifest("acme-store-dynamo", "dynamo", "acme");
        old.version = "1.0.0".into();
        let old = sign(&acme, old, artifact);

        // No floor: trusted (baseline).
        let mut pol = policy(None, &[("acme", &acme.verifying_key())], false, false);
        assert!(matches!(
            evaluate(artifact, &old, &pol).unwrap(),
            Verdict::Trusted { .. }
        ));

        // Floor pinned: the old validly-signed release is rejected.
        pol.min_versions
            .insert("acme-store-dynamo".to_string(), "2.0.0".to_string());
        let err = evaluate(artifact, &old, &pol).unwrap_err();
        assert!(err.0.contains("anti-downgrade"), "got {err:?}");

        // Stripped signature + both opt-ins: STILL rejected (the floor requires trusted proof).
        let mut stripped = old.clone();
        stripped.signature = String::new();
        let mut loose = policy(None, &[], true, true);
        loose
            .min_versions
            .insert("acme-store-dynamo".to_string(), "2.0.0".to_string());
        let err = evaluate(artifact, &stripped, &loose).unwrap_err();
        assert!(err.0.contains("anti-downgrade"), "got {err:?}");

        // A current signed release at the floor still passes.
        let mut cur = manifest("acme-store-dynamo", "dynamo", "acme");
        cur.version = "2.0.0".into();
        let cur = sign(&acme, cur, artifact);
        assert!(matches!(
            evaluate(artifact, &cur, &pol).unwrap(),
            Verdict::Trusted { .. }
        ));
    }

    /// The embedded-release-key accessor parses a build-time hex key. In this test build the env is
    /// absent, so it returns None (a dev build has no first-party key).
    #[test]
    fn embedded_key_absent_in_dev_builds() {
        // The build for tests does not set BUSBAR_RELEASE_PUBKEY.
        assert!(embedded_release_pubkey().is_none());
    }
}
