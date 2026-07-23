// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! `busbar-plugin-pack` - the packaging + signing tool for busbar plugins.
//!
//! A busbar plugin ships as ONE signed `.tar.gz` containing exactly the cdylib and its signed
//! `manifest.json`. This tool builds that artifact:
//!
//! ```text
//! busbar-plugin-pack pack \
//!     --lib target/release/libbusbar_store_redis_plugin.so \
//!     --name busbar-store-redis --alias redis --kind store \
//!     --version 1.5.0 --publisher busbar \
//!     --out busbar-store-redis-1.5.0-x86_64-linux.tar.gz
//! ```
//!
//! The ed25519 SIGNING key is read from the `BUSBAR_SIGN_KEY` environment variable (64 hex chars:
//! the 32-byte seed) - in CI this is the release secret; a third-party publisher uses their own.
//! With no key set, `--allow-unsigned` produces an UNSIGNED tarball (dev only: busbar loads it
//! solely under `plugins.trust.allow_unsigned: true`).
//!
//! `busbar-plugin-pack keygen` generates a fresh keypair and prints both halves (hex). The PUBLIC
//! half goes in `plugins.trust.publishers` (third-party) or is embedded into the busbar binary at
//! build time via `BUSBAR_RELEASE_PUBKEY` (first-party); the PRIVATE half is the signing secret.

use busbar_plugin_sign::{sign, Manifest, SigningKey};
use std::collections::HashMap;
use std::process::ExitCode;

const SIGN_KEY_ENV: &str = "BUSBAR_SIGN_KEY";

fn usage() -> &'static str {
    "busbar-plugin-pack - package + sign a busbar plugin tarball

USAGE:
    busbar-plugin-pack pack --lib <cdylib> --name <name> --alias <alias> --kind <store|auth|hook|secret>
                            --version <semver> --publisher <publisher> --out <file.tar.gz>
                            [--description <text>] [--homepage <url>] [--license <spdx>]
                            [--allow-unsigned]
    busbar-plugin-pack keygen

    pack     builds manifest.json over the cdylib (sha256 binding), signs it with the ed25519 seed
             in $BUSBAR_SIGN_KEY (64 hex chars), and writes the {cdylib + manifest.json} .tar.gz.
             --allow-unsigned permits packaging WITHOUT a signature (dev only; busbar loads such a
             tarball only under plugins.trust.allow_unsigned: true).
    keygen   generates a fresh ed25519 keypair and prints both halves as hex. Keep the private half
             secret (it becomes $BUSBAR_SIGN_KEY); publish/allowlist/embed the public half."
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.first().map(String::as_str) {
        Some("keygen") => keygen(),
        Some("pack") => pack(&args[1..]),
        Some("--help" | "-h") | None => {
            println!("{}", usage());
            ExitCode::SUCCESS
        }
        Some(other) => {
            eprintln!("unknown command '{other}'\n\n{}", usage());
            ExitCode::from(2)
        }
    }
}

/// Generate a fresh ed25519 keypair from the OS RNG and print both halves (hex).
fn keygen() -> ExitCode {
    let mut seed = [0u8; 32];
    if let Err(e) = getrandom::fill(&mut seed) {
        eprintln!("error: OS RNG unavailable: {e}");
        return ExitCode::FAILURE;
    }
    let key = SigningKey::from_bytes(&seed);
    println!(
        "private (BUSBAR_SIGN_KEY, keep secret): {}",
        hex::encode(seed)
    );
    println!(
        "public  (publishers allowlist / BUSBAR_RELEASE_PUBKEY): {}",
        hex::encode(key.verifying_key().to_bytes())
    );
    ExitCode::SUCCESS
}

/// Parse `--flag value` pairs plus bare `--allow-unsigned`.
fn parse_flags(args: &[String]) -> Result<(HashMap<String, String>, bool), String> {
    let mut map = HashMap::new();
    let mut allow_unsigned = false;
    let mut it = args.iter();
    while let Some(a) = it.next() {
        if a == "--allow-unsigned" {
            allow_unsigned = true;
            continue;
        }
        let Some(name) = a.strip_prefix("--") else {
            return Err(format!("unexpected argument '{a}'"));
        };
        let Some(v) = it.next() else {
            return Err(format!("--{name} requires a value"));
        };
        map.insert(name.to_string(), v.clone());
    }
    Ok((map, allow_unsigned))
}

fn pack(args: &[String]) -> ExitCode {
    let (flags, allow_unsigned) = match parse_flags(args) {
        Ok(f) => f,
        Err(e) => {
            eprintln!("error: {e}\n\n{}", usage());
            return ExitCode::from(2);
        }
    };
    let required = |k: &str| -> Result<String, String> {
        flags
            .get(k)
            .cloned()
            .ok_or_else(|| format!("missing required --{k}"))
    };
    let run = || -> Result<String, String> {
        let lib_path = required("lib")?;
        let out = required("out")?;
        let kind = required("kind")?;
        // Default the ABI to the NEWEST version this binary's loader supports for the kind, so a
        // plain `pack` of a store plugin stamps the current store ABI (v2, the token-ledger wire)
        // instead of a stale literal. `--abi-version` still overrides for cross-version packaging.
        let default_abi = busbar_plugin_loader::supported_abi(&kind)
            .iter()
            .copied()
            .max()
            .unwrap_or(1);
        let manifest = Manifest {
            name: required("name")?,
            alias: required("alias")?,
            kind,
            version: required("version")?,
            publisher: required("publisher")?,
            abi_version: flags
                .get("abi-version")
                .map(|v| v.parse::<u32>().map_err(|e| format!("--abi-version: {e}")))
                .transpose()?
                .unwrap_or(default_abi),
            sha256: String::new(),
            signature: String::new(),
            description: flags.get("description").cloned().unwrap_or_default(),
            homepage: flags.get("homepage").cloned().unwrap_or_default(),
            license: flags.get("license").cloned().unwrap_or_default(),
        };
        let lib_bytes =
            std::fs::read(&lib_path).map_err(|e| format!("cannot read --lib '{lib_path}': {e}"))?;

        // Sign with $BUSBAR_SIGN_KEY, or package unsigned only under the explicit dev flag.
        let manifest = match std::env::var(SIGN_KEY_ENV) {
            Ok(hex_seed) => {
                let seed = hex::decode(hex_seed.trim())
                    .map_err(|e| format!("{SIGN_KEY_ENV} is not valid hex: {e}"))?;
                let seed: [u8; 32] = seed
                    .as_slice()
                    .try_into()
                    .map_err(|_| format!("{SIGN_KEY_ENV} must be 32 bytes (64 hex chars)"))?;
                sign(&SigningKey::from_bytes(&seed), manifest, &lib_bytes)
            }
            Err(_) if allow_unsigned => {
                let mut m = manifest;
                m.sha256 = busbar_plugin_sign::sha256_hex(&lib_bytes);
                m
            }
            Err(_) => {
                return Err(format!(
                    "{SIGN_KEY_ENV} is not set. Set it to the 64-hex ed25519 seed to sign, or pass \
                     --allow-unsigned to package an UNSIGNED tarball (dev only; busbar loads it \
                     only under plugins.trust.allow_unsigned: true)."
                ));
            }
        };

        // Structural self-check: refuse to package a manifest busbar would refuse to load.
        busbar_plugin_sign::validate_structure(
            &manifest,
            &lib_bytes,
            &busbar_plugin_loader::supported_abi,
        )
        .map_err(|e| format!("manifest would fail busbar's structural validation: {e}"))?;

        let lib_file = std::path::Path::new(&lib_path)
            .file_name()
            .and_then(|f| f.to_str())
            .unwrap_or("plugin-lib")
            .to_string();
        let tarball = busbar_plugin_loader::tarball::package(&manifest, &lib_file, &lib_bytes)?;
        std::fs::write(&out, &tarball).map_err(|e| format!("cannot write '{out}': {e}"))?;
        Ok(format!(
            "packaged {} ({} v{}, kind {}, publisher {}, {}) -> {out}",
            manifest.name,
            manifest.alias,
            manifest.version,
            manifest.kind,
            manifest.publisher,
            if manifest.signature.is_empty() {
                "UNSIGNED"
            } else {
                "signed"
            },
        ))
    };
    match run() {
        Ok(msg) => {
            println!("{msg}");
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `pack`-equivalent flow: a signed manifest packaged here unpacks + verifies as trusted under
    /// the matching public key (the exact artifact contract the engine consumes).
    #[test]
    fn packed_tarball_verifies_end_to_end() {
        let seed = [7u8; 32];
        let key = SigningKey::from_bytes(&seed);
        let lib = b"pretend cdylib bytes";
        let m = Manifest {
            name: "acme-store-x".into(),
            alias: "x".into(),
            kind: "store".into(),
            version: "1.0.0".into(),
            publisher: "acme".into(),
            abi_version: busbar_plugin_loader::supported_abi("store")
                .iter()
                .copied()
                .max()
                .unwrap(),
            sha256: String::new(),
            signature: String::new(),
            description: String::new(),
            homepage: String::new(),
            license: String::new(),
        };
        let signed = sign(&key, m, lib);
        busbar_plugin_sign::validate_structure(&signed, lib, &busbar_plugin_loader::supported_abi)
            .expect("structural");
        let tarball = busbar_plugin_loader::tarball::package(&signed, "lib.so", lib).unwrap();
        let up = busbar_plugin_loader::tarball::unpack(&tarball).unwrap();
        let mut policy = busbar_plugin_sign::TrustPolicy::default();
        policy.publishers.insert("acme".into(), key.verifying_key());
        assert!(matches!(
            busbar_plugin_sign::evaluate(&up.lib_bytes, &up.manifest, &policy).unwrap(),
            busbar_plugin_sign::Verdict::Trusted { .. }
        ));
    }

    #[test]
    fn flag_parsing() {
        let args: Vec<String> = ["--lib", "a.so", "--allow-unsigned", "--name", "n"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        let (flags, unsigned) = parse_flags(&args).unwrap();
        assert!(unsigned);
        assert_eq!(flags["lib"], "a.so");
        assert_eq!(flags["name"], "n");
        assert!(parse_flags(&["--dangling".to_string()]).is_err());
        assert!(parse_flags(&["bare".to_string()]).is_err());
    }
}
