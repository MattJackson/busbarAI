// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The one-file-per-plugin **signed tarball** format: a `.tar.gz` containing EXACTLY
//!
//! - `manifest.json` — the signed [`busbar_plugin_sign::Manifest`];
//! - one library file — the cdylib the manifest's `sha256` pins.
//!
//! [`unpack`] extracts FULLY IN MEMORY on every platform (the manifest never touches disk; the
//! library bytes only ever reach disk as loader staging output, never as trusted input), with hard
//! bounds on member count and decompressed sizes so a hostile archive (zip-bomb, entry flood,
//! path-traversal names) is refused before it can cost anything. [`package`] is the inverse, used
//! by the release pipeline, the packaging CLI, and tests.

use busbar_plugin_sign::Manifest;
use std::io::Read as _;

/// The manifest member name inside every plugin tarball.
pub const MANIFEST_FILE: &str = "manifest.json";

/// Hard cap on the DECOMPRESSED library member — matches the loader's own response cap scale; far
/// beyond any real cdylib (the shipped store plugins are single-digit MiB).
const MAX_LIB_BYTES: u64 = 256 * 1024 * 1024;
/// Hard cap on the DECOMPRESSED manifest member — a manifest is well under 4 KiB.
const MAX_MANIFEST_BYTES: u64 = 1024 * 1024;

/// A plugin tarball unpacked in memory: the parsed signed manifest plus the exact library bytes.
#[derive(Debug)]
pub struct UnpackedPlugin {
    pub manifest: Manifest,
    /// The library member's archived filename (display only — identity comes from the manifest).
    pub lib_name: String,
    pub lib_bytes: Vec<u8>,
}

/// Is this filename a plugin tarball (`.tar.gz` / `.tgz`)?
pub fn is_plugin_tarball(file: &str) -> bool {
    file.ends_with(".tar.gz") || file.ends_with(".tgz")
}

/// Build a plugin tarball: gzip'd tar with `manifest.json` (serialized from `manifest`) and the
/// library under `lib_name`. Deterministic enough for tests; the release pipeline signs the
/// manifest BEFORE packaging (the tarball itself carries no outer signature — the manifest inside
/// is the signed unit and it pins the library by sha256).
pub fn package(manifest: &Manifest, lib_name: &str, lib_bytes: &[u8]) -> Result<Vec<u8>, String> {
    let manifest_json = serde_json::to_vec_pretty(manifest)
        .map_err(|e| format!("manifest serialize failed: {e}"))?;
    let gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    let mut tar = tar::Builder::new(gz);
    let mut add = |name: &str, bytes: &[u8]| -> Result<(), String> {
        let mut header = tar::Header::new_gnu();
        header.set_size(bytes.len() as u64);
        header.set_mode(0o644);
        header.set_mtime(0);
        header.set_cksum();
        tar.append_data(&mut header, name, bytes)
            .map_err(|e| format!("tar append '{name}' failed: {e}"))
    };
    add(MANIFEST_FILE, &manifest_json)?;
    add(lib_name, lib_bytes)?;
    let gz = tar
        .into_inner()
        .map_err(|e| format!("tar finalize failed: {e}"))?;
    gz.finish()
        .map_err(|e| format!("gzip finalize failed: {e}"))
}

/// Read one tar entry fully, bounded at `cap` decompressed bytes. An entry whose DECLARED size
/// exceeds the cap is refused before any read.
fn read_entry_bounded<R: std::io::Read>(
    entry: &mut tar::Entry<'_, R>,
    cap: u64,
    what: &str,
) -> Result<Vec<u8>, String> {
    let size = entry.size();
    if size > cap {
        return Err(format!(
            "{what} member is {size} bytes, exceeding the {cap}-byte cap"
        ));
    }
    let mut buf = Vec::with_capacity(size as usize);
    // `take(cap + 1)`: even a lying header cannot stream more than the cap into memory.
    entry
        .take(cap + 1)
        .read_to_end(&mut buf)
        .map_err(|e| format!("cannot read {what} member: {e}"))?;
    if buf.len() as u64 > cap {
        return Err(format!("{what} member exceeds the {cap}-byte cap"));
    }
    Ok(buf)
}

/// Unpack a plugin tarball FULLY IN MEMORY, fail-closed: the archive must contain EXACTLY one
/// `manifest.json` and EXACTLY one other regular file (the library), nothing else — no
/// directories, links, absolute paths, or parent references. Returns the parsed manifest + the
/// exact library bytes; every failure names the specific violation.
///
/// NOTE: this performs NO signature/trust/structure checks — it is pure decoding. The caller runs
/// phase 1 (structural) and phase 2 (trust) over the returned parts.
pub fn unpack(bytes: &[u8]) -> Result<UnpackedPlugin, String> {
    let gz = flate2::read::GzDecoder::new(bytes);
    let mut archive = tar::Archive::new(gz);
    let mut manifest: Option<Manifest> = None;
    let mut lib: Option<(String, Vec<u8>)> = None;

    let entries = archive
        .entries()
        .map_err(|e| format!("not a readable tar.gz archive: {e}"))?;
    for entry in entries {
        let mut entry = entry.map_err(|e| format!("corrupt tar.gz archive: {e}"))?;
        if entry.header().entry_type() != tar::EntryType::Regular {
            return Err(format!(
                "archive contains a non-regular-file entry ({:?}); a plugin tarball holds exactly \
                 manifest.json and the library",
                entry.header().entry_type()
            ));
        }
        let path = entry
            .path()
            .map_err(|e| format!("archive entry has an unreadable path: {e}"))?;
        // Reject traversal/absolute names outright; then key on the flattened basename.
        if path.components().any(|c| {
            !matches!(
                c,
                std::path::Component::Normal(_) | std::path::Component::CurDir
            )
        }) {
            return Err(format!(
                "archive entry '{}' has an unsafe path (absolute or parent reference)",
                path.display()
            ));
        }
        let name = path
            .file_name()
            .and_then(|f| f.to_str())
            .ok_or_else(|| "archive entry has no usable filename".to_string())?
            .to_string();
        if name == MANIFEST_FILE {
            if manifest.is_some() {
                return Err("archive contains more than one manifest.json".to_string());
            }
            let raw = read_entry_bounded(&mut entry, MAX_MANIFEST_BYTES, "manifest")?;
            let m: Manifest = serde_json::from_slice(&raw)
                .map_err(|e| format!("manifest.json does not parse: {e}"))?;
            manifest = Some(m);
        } else {
            if lib.is_some() {
                return Err(format!(
                    "archive contains more than one library member ('{}' and '{name}'); a plugin \
                     tarball holds exactly one",
                    lib.as_ref().map(|(n, _)| n.as_str()).unwrap_or("?")
                ));
            }
            let raw = read_entry_bounded(&mut entry, MAX_LIB_BYTES, "library")?;
            lib = Some((name, raw));
        }
    }

    let manifest = manifest.ok_or_else(|| "archive has no manifest.json".to_string())?;
    let (lib_name, lib_bytes) = lib.ok_or_else(|| "archive has no library member".to_string())?;
    Ok(UnpackedPlugin {
        manifest,
        lib_name,
        lib_bytes,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use busbar_plugin_sign::{sign, SigningKey};

    fn manifest() -> Manifest {
        Manifest {
            name: "busbar-store-redis".into(),
            alias: "redis".into(),
            kind: "store".into(),
            version: "1.5.0".into(),
            publisher: "busbar".into(),
            abi_version: 1,
            sha256: String::new(),
            signature: String::new(),
            description: String::new(),
            homepage: String::new(),
            license: "Apache-2.0".into(),
        }
    }

    #[test]
    fn package_then_unpack_roundtrips() {
        let key = SigningKey::from_bytes(&[7u8; 32]);
        let lib = b"\x7fELF pretend library";
        let m = sign(&key, manifest(), lib);
        let tarball = package(&m, "libbusbar_store_redis.so", lib).unwrap();
        let up = unpack(&tarball).unwrap();
        assert_eq!(up.manifest, m);
        assert_eq!(up.lib_name, "libbusbar_store_redis.so");
        assert_eq!(up.lib_bytes, lib);
    }

    #[test]
    fn garbage_is_refused() {
        assert!(unpack(b"not a tarball at all").is_err());
        assert!(unpack(&[]).is_err());
    }

    #[test]
    fn missing_manifest_or_lib_is_refused() {
        // Only a library, no manifest.
        let gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        let mut t = tar::Builder::new(gz);
        let mut h = tar::Header::new_gnu();
        h.set_size(3);
        h.set_mode(0o644);
        h.set_cksum();
        t.append_data(&mut h, "lib.so", &b"abc"[..]).unwrap();
        let bytes = t.into_inner().unwrap().finish().unwrap();
        let err = unpack(&bytes).unwrap_err();
        assert!(err.contains("no manifest.json"), "got {err}");

        // Only a manifest, no library.
        let m = manifest();
        let json = serde_json::to_vec(&m).unwrap();
        let gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        let mut t = tar::Builder::new(gz);
        let mut h = tar::Header::new_gnu();
        h.set_size(json.len() as u64);
        h.set_mode(0o644);
        h.set_cksum();
        t.append_data(&mut h, MANIFEST_FILE, json.as_slice())
            .unwrap();
        let bytes = t.into_inner().unwrap().finish().unwrap();
        let err = unpack(&bytes).unwrap_err();
        assert!(err.contains("no library member"), "got {err}");
    }

    #[test]
    fn extra_members_and_traversal_are_refused() {
        // Three regular files: manifest + two libraries.
        let m = manifest();
        let t1 = package(&m, "lib.so", b"abc").unwrap();
        // Rebuild with an extra member by unpacking the raw tar and appending.
        let gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        let mut t = tar::Builder::new(gz);
        let json = serde_json::to_vec(&m).unwrap();
        for (name, data) in [
            (MANIFEST_FILE, json.as_slice()),
            ("lib.so", &b"abc"[..]),
            ("evil.so", &b"def"[..]),
        ] {
            let mut h = tar::Header::new_gnu();
            h.set_size(data.len() as u64);
            h.set_mode(0o644);
            h.set_cksum();
            t.append_data(&mut h, name, data).unwrap();
        }
        let bytes = t.into_inner().unwrap().finish().unwrap();
        let err = unpack(&bytes).unwrap_err();
        assert!(err.contains("more than one library"), "got {err}");
        drop(t1);

        // Parent-reference path. `tar::Builder::append_data` itself refuses `..`, so write the
        // hostile name into the raw 512-byte header directly (what an attacker's tool would emit).
        let gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        let mut t = tar::Builder::new(gz);
        let mut h = tar::Header::new_gnu();
        h.set_size(3);
        h.set_mode(0o644);
        {
            let name = b"../escape.so";
            h.as_mut_bytes()[..name.len()].copy_from_slice(name);
        }
        h.set_cksum();
        t.append(&h, &b"abc"[..]).unwrap();
        let bytes = t.into_inner().unwrap().finish().unwrap();
        let err = unpack(&bytes).unwrap_err();
        assert!(err.contains("unsafe path"), "got {err}");
    }

    #[test]
    fn oversized_manifest_member_is_refused() {
        // A "manifest.json" bigger than the cap is refused by DECLARED size before reading.
        let big = vec![b'x'; (MAX_MANIFEST_BYTES + 1) as usize];
        let gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        let mut t = tar::Builder::new(gz);
        let mut h = tar::Header::new_gnu();
        h.set_size(big.len() as u64);
        h.set_mode(0o644);
        h.set_cksum();
        t.append_data(&mut h, MANIFEST_FILE, big.as_slice())
            .unwrap();
        let bytes = t.into_inner().unwrap().finish().unwrap();
        let err = unpack(&bytes).unwrap_err();
        assert!(err.contains("cap"), "got {err}");
    }

    #[test]
    fn tarball_extension_matcher() {
        assert!(is_plugin_tarball("busbar-store-redis-1.5.0-aarch64.tar.gz"));
        assert!(is_plugin_tarball("x.tgz"));
        assert!(!is_plugin_tarball("x.so"));
        assert!(!is_plugin_tarball("x.tar"));
        assert!(!is_plugin_tarball("x.zip"));
    }
}
