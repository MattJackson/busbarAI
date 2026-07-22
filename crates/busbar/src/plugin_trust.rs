// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Trust verification for loadable plugins — the engine side of "only approved plugins load".
//!
//! A plugin ships a signed sidecar manifest (`<library>.manifest.json`). Before the engine loads a
//! plugin (at boot for the store, and at admin-install for any upload), it reads the library bytes +
//! the sidecar manifest and asks [`busbar_plugin_sign::evaluate`] to judge them against the configured
//! [`busbar_plugin_sign::TrustPolicy`]:
//!
//! - **Trusted** — a valid signature from an allowlisted publisher → load, log at info.
//! - **Allowed** - untrusted (unsigned or third-party-signed) but the matching EXPLICIT opt-in flag
//!   (`allow_unsigned_plugins` / `allow_third_party`) permits it → load, log a warning.
//! - **Rejected** - untrusted with no matching opt-in (the DEFAULT), or an anti-downgrade violation →
//!   do NOT load; the caller aborts (boot fails / install 4xx) and NO library code runs.
//!
//! The manifest is read WITHOUT loading the library (a sidecar file), so untrusted code is never
//! `dlopen`ed just to inspect it. This module is pure verification + policy; no `unsafe`.

use busbar_plugin_sign::{evaluate, AllowReason, Manifest, TrustPolicy, Verdict};
use std::path::{Path, PathBuf};

/// The sidecar manifest path for a plugin library: `<library>.manifest.json`.
pub(crate) fn manifest_path_for(lib_path: &Path) -> PathBuf {
    let mut s = lib_path.as_os_str().to_owned();
    s.push(".manifest.json");
    PathBuf::from(s)
}

/// Verify a plugin library at `lib_path` against `policy`. On success returns a short human note about
/// the trust outcome (for the caller's log line); on the `halt` posture with an untrusted artifact,
/// returns `Err(reason)` and the caller MUST NOT load it. This is the DISPLAY/inventory path — it does
/// not load the library, so it discards the bytes it read.
///
/// A load path must NOT re-read the file afterwards (that would reopen a TOCTOU window). It calls
/// [`verify_read`] instead and loads the returned bytes verbatim via
/// [`busbar_plugin_loader::load_store_from_bytes`].
pub(crate) fn verify(lib_path: &Path, policy: &TrustPolicy) -> Result<String, String> {
    verify_read(lib_path, policy).map(|(note, _bytes)| note)
}

/// Verify a plugin library at `lib_path` against `policy` AND return the exact bytes that were
/// verified, so a caller can load THOSE bytes (never re-reading the path). This is the TOCTOU-safe
/// half: the hash/signature is checked over these bytes, and the same `Vec<u8>` is what gets loaded —
/// nothing on disk is read a second time between check and use, so a file swap in `plugins_dir`
/// cannot slip an unverified library past the gate.
///
/// Emits the trust decision to tracing itself (info for trusted, warn for loaded-but-unverified) so
/// every load path logs consistently — this is the "log all of this" surface.
pub(crate) fn verify_read(
    lib_path: &Path,
    policy: &TrustPolicy,
) -> Result<(String, Vec<u8>), String> {
    let bytes =
        std::fs::read(lib_path).map_err(|e| format!("cannot read {}: {e}", lib_path.display()))?;

    let manifest_path = manifest_path_for(lib_path);
    let manifest: Option<Manifest> = match std::fs::read(&manifest_path) {
        Ok(raw) => Some(
            serde_json::from_slice(&raw)
                .map_err(|e| format!("invalid manifest {}: {e}", manifest_path.display()))?,
        ),
        Err(_) => None, // no sidecar manifest ⇒ unsigned; the policy decides what that means
    };

    let name = lib_path
        .file_name()
        .and_then(|f| f.to_str())
        .unwrap_or("plugin");

    match evaluate(&bytes, manifest.as_ref(), name, policy) {
        Ok(Verdict::Trusted { publisher }) => {
            tracing::info!(plugin = name, publisher = %publisher, "plugin trust: signed by an allowlisted publisher");
            Ok((format!("signed by '{publisher}'"), bytes))
        }
        Ok(Verdict::Allowed { reason, allow }) => {
            let flag = match allow {
                AllowReason::Unsigned => "allow_unsigned_plugins",
                AllowReason::ThirdParty => "allow_third_party",
            };
            tracing::warn!(
                plugin = name,
                opt_in = flag,
                reason = %reason,
                "plugin trust: loading an UNVERIFIED plugin (permitted by an explicit opt-in flag)"
            );
            Ok((format!("unverified — {reason}"), bytes))
        }
        Err(rejected) => Err(rejected.0),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use busbar_plugin_sign::{sign, Manifest, SigningKey, TrustPolicy};
    use std::collections::BTreeMap;

    fn write_plugin(dir: &Path, name: &str, bytes: &[u8], manifest: Option<&Manifest>) -> PathBuf {
        let lib = dir.join(name);
        std::fs::write(&lib, bytes).unwrap();
        if let Some(m) = manifest {
            std::fs::write(manifest_path_for(&lib), serde_json::to_vec(m).unwrap()).unwrap();
        }
        lib
    }

    fn tmp() -> PathBuf {
        let base = std::env::temp_dir().join(format!("busbar-trust-{}", std::process::id()));
        // Unique-ish per test via a counter file is overkill; use a nanoseconds-free unique dir.
        let d = base.join(format!("{:p}", &base));
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn signed_by_allowlisted_publisher_is_trusted() {
        let dir = tmp();
        let key = SigningKey::from_bytes(&[9u8; 32]);
        let bytes = b"\x7fELF plugin";
        let m = sign(
            &key,
            Manifest {
                name: "store-x".into(),
                version: "1.0.0".into(),
                kind: "store".into(),
                author: "Acme".into(),
                homepage: String::new(),
                source_url: String::new(),
                description: String::new(),
                license: String::new(),
                publisher: "acme".into(),
                interface_version: 1,
                sha256: String::new(),
                signature: String::new(),
            },
            bytes,
        );
        let lib = write_plugin(&dir, "libx.so", bytes, Some(&m));

        let mut publishers = BTreeMap::new();
        publishers.insert("acme".to_string(), key.verifying_key());
        let policy = TrustPolicy {
            publishers,
            allow_unsigned: false,
            allow_third_party: false,
            min_versions: BTreeMap::new(),
        };
        assert!(verify(&lib, &policy).unwrap().contains("signed by 'acme'"));
    }

    #[test]
    fn unsigned_is_rejected_by_default_but_loaded_with_allow_unsigned() {
        let dir = tmp();
        let lib = write_plugin(&dir, "libun.so", b"bytes", None);

        // DEFAULT (no opt-in): an unsigned plugin is rejected, and the error names the opt-in flag.
        let strict = TrustPolicy {
            publishers: BTreeMap::new(),
            allow_unsigned: false,
            allow_third_party: false,
            min_versions: BTreeMap::new(),
        };
        let err = verify(&lib, &strict).unwrap_err();
        assert!(err.contains("allow_unsigned_plugins"), "got {err}");

        // With allow_unsigned set, the same unsigned plugin loads (unverified).
        let allow = TrustPolicy {
            publishers: BTreeMap::new(),
            allow_unsigned: true,
            allow_third_party: false,
            min_versions: BTreeMap::new(),
        };
        assert!(verify(&lib, &allow).unwrap().contains("unverified"));
    }

    /// FIX 1 at the engine boundary: the anti-downgrade floor keys on the LIBRARY FILENAME (the
    /// identity the engine resolves the plugin by), so deleting the sidecar manifest cannot slip old
    /// vulnerable bytes past a floor even with the opt-in flags set. Without a floor the unsigned bytes
    /// load (allow_unsigned); with a floor pinned on the filename, a manifest-less load is a HARD reject.
    #[test]
    fn missing_manifest_cannot_bypass_the_floor_keyed_on_filename() {
        let dir = tmp();
        // No sidecar manifest at all.
        let lib = write_plugin(&dir, "libfloored.so", b"old vulnerable bytes", None);

        // Opt-in to unsigned, no floor: an unsigned artifact loads.
        let loose = TrustPolicy {
            publishers: BTreeMap::new(),
            allow_unsigned: true,
            allow_third_party: false,
            min_versions: BTreeMap::new(),
        };
        assert!(verify(&lib, &loose).unwrap().contains("unverified"));

        // Same loose posture, but a floor pinned on the LIBRARY FILENAME: hard reject.
        let mut floored = loose.clone();
        floored
            .min_versions
            .insert("libfloored.so".to_string(), "1.4.0".to_string());
        let err = verify(&lib, &floored).unwrap_err();
        assert!(err.contains("anti-downgrade"), "got {err}");
    }
}
