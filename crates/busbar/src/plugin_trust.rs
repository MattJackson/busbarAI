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
//! - **Allowed** — untrusted (unsigned / unknown publisher / tampered) but the `on_untrusted` posture
//!   permits it (`log`/`alert`/`allow`) → load, log a warning (the operator chose a loose posture).
//! - **Rejected** — the posture is `halt` → do NOT load; the caller aborts (boot fails / install 4xx).
//!
//! The manifest is read WITHOUT loading the library (a sidecar file), so untrusted code is never
//! `dlopen`ed just to inspect it. This module is pure verification + policy; no `unsafe`.

use busbar_plugin_sign::{evaluate, Manifest, TrustPolicy, Verdict};
use std::path::{Path, PathBuf};

/// The sidecar manifest path for a plugin library: `<library>.manifest.json`.
pub(crate) fn manifest_path_for(lib_path: &Path) -> PathBuf {
    let mut s = lib_path.as_os_str().to_owned();
    s.push(".manifest.json");
    PathBuf::from(s)
}

/// Verify a plugin library at `lib_path` against `policy`. On success returns a short human note about
/// the trust outcome (for the caller's log line); on the `halt` posture with an untrusted artifact,
/// returns `Err(reason)` and the caller MUST NOT load it.
///
/// Emits the trust decision to tracing itself (info for trusted, warn for loaded-but-unverified) so
/// every load path logs consistently — this is the "log all of this" surface.
pub(crate) fn verify(lib_path: &Path, policy: &TrustPolicy) -> Result<String, String> {
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

    match evaluate(&bytes, manifest.as_ref(), policy) {
        Ok(Verdict::Trusted { publisher }) => {
            tracing::info!(plugin = name, publisher = %publisher, "plugin trust: signed by an allowlisted publisher");
            Ok(format!("signed by '{publisher}'"))
        }
        Ok(Verdict::Allowed { reason, action }) => {
            tracing::warn!(
                plugin = name,
                posture = ?action,
                reason = %reason,
                "plugin trust: loading an UNVERIFIED plugin (allowed by policy posture)"
            );
            Ok(format!("unverified — {reason}"))
        }
        Err(rejected) => Err(rejected.0),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use busbar_plugin_sign::{sign, Manifest, OnUntrusted, SigningKey, TrustPolicy};
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
            on_untrusted: OnUntrusted::Halt,
        };
        assert!(verify(&lib, &policy).unwrap().contains("signed by 'acme'"));
    }

    #[test]
    fn unsigned_is_rejected_under_halt_but_loaded_under_log() {
        let dir = tmp();
        let lib = write_plugin(&dir, "libun.so", b"bytes", None);

        let halt = TrustPolicy {
            publishers: BTreeMap::new(),
            on_untrusted: OnUntrusted::Halt,
        };
        assert!(verify(&lib, &halt).is_err());

        let log = TrustPolicy {
            publishers: BTreeMap::new(),
            on_untrusted: OnUntrusted::Log,
        };
        assert!(verify(&lib, &log).unwrap().contains("unverified"));
    }
}
