// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Plugin **discovery, three-phase load validation, and the name/alias registry** - the single
//! pipeline behind boot, `--validate`, and `--list-plugins`, so the pre-flight gate can never
//! drift from real boot behavior.
//!
//! Phases (in order, fail-closed):
//!
//! 1. **STRUCTURAL** (trust-independent): the tarball unpacks, the manifest parses, every required
//!    field is present and well-formed, `sha256(lib) == manifest.sha256`, and the `abi_version` is
//!    supported for the `kind`. A failure here is INVALID - at boot/`--validate` it is a HARD
//!    error naming the file and the reason (never a partial boot).
//! 2. **TRUST**: the signature verifies against the embedded busbar release key (first-party) or an
//!    allowlisted publisher - else the plugin loads only under the matching explicit opt-in flag
//!    (`allow_unsigned` / `allow_third_party`), otherwise it is logged and SKIPPED (never
//!    `dlopen`ed). Anti-downgrade floors are hard rejects inside this phase.
//! 3. **CONFLICT** (over the loadable set): no two plugins share a `name`, no two share an `alias`,
//!    and no alias collides with another plugin's `name`. Any collision is a HARD error naming
//!    both plugins - "you can't use redis and a third-party redis".
//!
//! Only after all three phases does a plugin enter the [`PluginRegistry`], addressable by BOTH its
//! canonical name and its alias. Identity comes exclusively from the signed manifest - the tarball
//! filename is irrelevant.

use crate::tarball;
use busbar_plugin_sign::{evaluate, validate_structure, Manifest, TrustPolicy, Verdict};
use std::collections::HashMap;
use std::path::{Path, PathBuf};

/// The C ABI versions this binary supports per plugin kind. ONE subsystem: `kind` selects the ABI
/// contract the cdylib must export; everything else (discovery/trust/conflict/registry) is shared.
pub fn supported_abi(kind: &str) -> &'static [u32] {
    match kind {
        "store" => &[busbar_plugin_abi::ABI_VERSION],
        // auth/hook plugins share the manifest + trust + registry machinery today; their C ABI
        // contracts are v1 placeholders until the engine grows dynamic consumers for those kinds.
        "auth" | "hook" => &[1],
        _ => &[],
    }
}

/// A plugin that passed phases 1 + 2 and MAY load: its signed manifest, the trust verdict, and the
/// exact verified library bytes (what the loader will map - never re-read from disk).
pub struct LoadablePlugin {
    /// The tarball filename (diagnostics only - identity is the manifest).
    pub file: String,
    pub manifest: Manifest,
    pub verdict: Verdict,
    pub lib_bytes: Vec<u8>,
}

/// A plugin that failed phase 2 (untrusted, no matching opt-in; or an anti-downgrade reject) and is
/// SKIPPED: recorded for logging/`--list-plugins`, never a load candidate, never `dlopen`ed.
pub struct SkippedPlugin {
    pub file: String,
    pub manifest: Manifest,
    pub reason: String,
}

/// The registry of validated, loadable plugins, addressable by canonical name OR alias. Built only
/// after all three phases pass; this is the ONLY resolution surface (`governance.store:` etc.), so
/// nothing outside the validated set can ever be selected.
pub struct PluginRegistry {
    loadable: Vec<LoadablePlugin>,
    skipped: Vec<SkippedPlugin>,
    /// name -> index into `loadable`; alias -> index (aliases equal to the own name are fine).
    by_name: HashMap<String, usize>,
    by_alias: HashMap<String, usize>,
}

impl std::fmt::Debug for PluginRegistry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PluginRegistry")
            .field(
                "loadable",
                &self
                    .loadable
                    .iter()
                    .map(|p| p.manifest.name.as_str())
                    .collect::<Vec<_>>(),
            )
            .field(
                "skipped",
                &self
                    .skipped
                    .iter()
                    .map(|p| p.manifest.name.as_str())
                    .collect::<Vec<_>>(),
            )
            .finish()
    }
}

impl PluginRegistry {
    /// An empty registry (plugins disabled / empty dir).
    pub fn empty() -> Self {
        PluginRegistry {
            loadable: Vec::new(),
            skipped: Vec::new(),
            by_name: HashMap::new(),
            by_alias: HashMap::new(),
        }
    }

    /// Resolve `name_or_alias` (canonical name first, then alias) to a loadable plugin.
    pub fn resolve(&self, name_or_alias: &str) -> Option<&LoadablePlugin> {
        self.by_name
            .get(name_or_alias)
            .or_else(|| self.by_alias.get(name_or_alias))
            .map(|&i| &self.loadable[i])
    }

    /// Why a reference cannot be resolved: if a SKIPPED plugin matches it, name the skip reason -
    /// "the plugin you asked for is here, but trust refused it" is the actionable message.
    pub fn unresolved_reason(&self, name_or_alias: &str) -> Option<&SkippedPlugin> {
        self.skipped
            .iter()
            .find(|s| s.manifest.name == name_or_alias || s.manifest.alias == name_or_alias)
    }

    /// Every loadable plugin (for logging / catalog).
    pub fn loadable(&self) -> &[LoadablePlugin] {
        &self.loadable
    }

    /// Every skipped plugin (for logging / catalog).
    pub fn skipped(&self) -> &[SkippedPlugin] {
        &self.skipped
    }

    /// Open a STORE plugin resolved by name or alias: verifies the resolved plugin's `kind` is
    /// `store`, then loads the VERIFIED bytes over the store C ABI (memfd on Linux, private temp
    /// staging elsewhere) and `open`s it with `cfg_json`. The one engine-facing load entrypoint.
    pub fn open_store(
        &self,
        name_or_alias: &str,
        cfg_json: &str,
    ) -> Result<Box<dyn busbar_api::Store>, String> {
        let Some(p) = self.resolve(name_or_alias) else {
            return Err(match self.unresolved_reason(name_or_alias) {
                Some(s) => format!(
                    "plugin '{name_or_alias}' is present ({}) but was not loaded: {}",
                    s.file, s.reason
                ),
                None => format!(
                    "no plugin named or aliased '{name_or_alias}' is available (loadable plugins: \
                     [{}])",
                    self.loadable
                        .iter()
                        .map(|p| p.manifest.name.as_str())
                        .collect::<Vec<_>>()
                        .join(", ")
                ),
            });
        };
        if p.manifest.kind != "store" {
            return Err(format!(
                "plugin '{}' has kind '{}', not 'store' - it cannot back the governance store",
                p.manifest.name, p.manifest.kind
            ));
        }
        crate::load_store_from_bytes(&p.lib_bytes, cfg_json, &p.manifest.name)
    }
}

/// Discover plugin tarballs (`*.tar.gz` / `*.tgz`) in `dir`, sorted by filename. A missing
/// directory is an empty list (drop-is-inert: no dir, no plugins), an unreadable one an error.
pub fn discover(dir: &Path) -> Result<Vec<PathBuf>, String> {
    let mut out = Vec::new();
    let entries = match std::fs::read_dir(dir) {
        Ok(e) => e,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(out),
        Err(e) => return Err(format!("cannot read plugins dir {}: {e}", dir.display())),
    };
    for entry in entries.flatten() {
        let path = entry.path();
        let Some(file) = path.file_name().and_then(|f| f.to_str()) else {
            continue;
        };
        if path.is_file() && tarball::is_plugin_tarball(file) {
            out.push(path);
        }
    }
    out.sort();
    Ok(out)
}

/// One file's outcome through phases 1 + 2 (phase 3 needs the whole set).
enum FileOutcome {
    Loadable(LoadablePlugin),
    Skipped(SkippedPlugin),
    Invalid { file: String, reason: String },
}

/// Run phases 1 (structural) + 2 (trust) over one tarball.
fn examine(path: &Path, policy: &TrustPolicy) -> FileOutcome {
    let file = path
        .file_name()
        .and_then(|f| f.to_str())
        .unwrap_or("plugin")
        .to_string();
    let bytes = match std::fs::read(path) {
        Ok(b) => b,
        Err(e) => {
            return FileOutcome::Invalid {
                file,
                reason: format!("cannot read: {e}"),
            }
        }
    };
    // Phase 1a: unpack in memory (bounded).
    let unpacked = match tarball::unpack(&bytes) {
        Ok(u) => u,
        Err(reason) => return FileOutcome::Invalid { file, reason },
    };
    // Phase 1b: structural completeness + well-formedness + integrity + abi.
    if let Err(reason) = validate_structure(&unpacked.manifest, &unpacked.lib_bytes, &supported_abi)
    {
        return FileOutcome::Invalid { file, reason };
    }
    // Phase 2: trust. A rejection here is a SKIP (logged, never dlopen'ed) - unless the plugin is
    // actually referenced, in which case resolution fails loudly with this reason attached.
    match evaluate(&unpacked.lib_bytes, &unpacked.manifest, policy) {
        Ok(verdict) => FileOutcome::Loadable(LoadablePlugin {
            file,
            manifest: unpacked.manifest,
            verdict,
            lib_bytes: unpacked.lib_bytes,
        }),
        Err(rejected) => FileOutcome::Skipped(SkippedPlugin {
            file,
            manifest: unpacked.manifest,
            reason: rejected.0,
        }),
    }
}

/// Phase 3: cross-plugin conflict detection over the LOADABLE set. Any name/alias collision is a
/// hard error naming BOTH plugins and the colliding identifier.
fn conflicts(loadable: &[LoadablePlugin]) -> Vec<String> {
    let mut errors = Vec::new();
    let mut name_owner: HashMap<&str, &LoadablePlugin> = HashMap::new();
    for p in loadable {
        if let Some(prev) = name_owner.get(p.manifest.name.as_str()) {
            errors.push(format!(
                "plugin name conflict: '{}' is claimed by both {} and {} - remove one \
                 (\"you can't use redis and a third-party redis\")",
                p.manifest.name, prev.file, p.file
            ));
        } else {
            name_owner.insert(&p.manifest.name, p);
        }
    }
    let mut alias_owner: HashMap<&str, &LoadablePlugin> = HashMap::new();
    for p in loadable {
        if let Some(prev) = alias_owner.get(p.manifest.alias.as_str()) {
            errors.push(format!(
                "plugin alias conflict: '{}' is claimed by both {} ({}) and {} ({}) - remove one",
                p.manifest.alias, prev.file, prev.manifest.name, p.file, p.manifest.name
            ));
        } else {
            alias_owner.insert(&p.manifest.alias, p);
        }
        // An alias colliding with ANOTHER plugin's canonical name is equally ambiguous.
        if let Some(other) = name_owner.get(p.manifest.alias.as_str()) {
            if other.manifest.name != p.manifest.name {
                errors.push(format!(
                    "plugin alias/name conflict: alias '{}' of {} ({}) collides with the canonical \
                     name of {} ({}) - remove one",
                    p.manifest.alias, p.file, p.manifest.name, other.file, other.manifest.name
                ));
            }
        }
    }
    errors
}

/// The full boot/validate pipeline: discover -> phase 1 -> phase 2 -> phase 3 -> registry.
/// FAIL-CLOSED: any unreadable/invalid tarball (phase 1) or any conflict (phase 3) returns
/// `Err(errors)` with every problem named - the caller (boot / `--validate`) aborts; there is no
/// partial result. Untrusted plugins (phase 2) are SKIPPED into the registry's skip list (the
/// caller logs them); they only become fatal if actually referenced.
pub fn scan_and_validate(dir: &Path, policy: &TrustPolicy) -> Result<PluginRegistry, Vec<String>> {
    let files = discover(dir).map_err(|e| vec![e])?;
    let mut errors = Vec::new();
    let mut loadable = Vec::new();
    let mut skipped = Vec::new();
    for path in &files {
        match examine(path, policy) {
            FileOutcome::Loadable(p) => loadable.push(p),
            FileOutcome::Skipped(s) => skipped.push(s),
            FileOutcome::Invalid { file, reason } => errors.push(format!(
                "invalid plugin '{}': {reason}",
                dir.join(file).display()
            )),
        }
    }
    errors.extend(conflicts(&loadable));
    if !errors.is_empty() {
        return Err(errors);
    }
    let mut by_name = HashMap::new();
    let mut by_alias = HashMap::new();
    for (i, p) in loadable.iter().enumerate() {
        by_name.insert(p.manifest.name.clone(), i);
        by_alias.insert(p.manifest.alias.clone(), i);
    }
    Ok(PluginRegistry {
        loadable,
        skipped,
        by_name,
        by_alias,
    })
}

/// One row of the MANIFEST-ONLY inventory behind `busbar --list-plugins` and the admin catalog:
/// every tarball in the directory with its identity (when decodable) and its trust/status verdict.
/// NEVER `dlopen`s anything - untrusted code cannot run from listing the directory.
pub struct InventoryEntry {
    pub file: String,
    /// `None` when the tarball/manifest is invalid (see `status`).
    pub manifest: Option<Manifest>,
    /// The signature column: `first-party` / `publisher:<name>` / `unsigned (allowed)` /
    /// `third-party (allowed)` / `unsigned` / `unknown-publisher` / `tampered` / `INVALID`.
    pub signature: String,
    /// The status column: `ready` / `SKIPPED: <reason>` / `REJECTED: <reason>` / `INVALID: <reason>`.
    pub status: String,
}

/// Build the manifest-only inventory of `dir` under `policy`. Never errors, never loads: every
/// tarball yields a row, including invalid ones (with the exact reason). Conflicts across loadable
/// plugins are appended to the affected rows' status.
pub fn inventory(dir: &Path, policy: &TrustPolicy) -> Vec<InventoryEntry> {
    let files = match discover(dir) {
        Ok(f) => f,
        Err(e) => {
            return vec![InventoryEntry {
                file: dir.display().to_string(),
                manifest: None,
                signature: "-".into(),
                status: format!("INVALID: {e}"),
            }]
        }
    };
    let mut loadable = Vec::new();
    let mut rows = Vec::new();
    for path in &files {
        match examine(path, policy) {
            FileOutcome::Loadable(p) => {
                let signature = match &p.verdict {
                    Verdict::Trusted {
                        first_party: true, ..
                    } => "first-party".to_string(),
                    Verdict::Trusted { publisher, .. } => format!("publisher:{publisher}"),
                    Verdict::Allowed {
                        allow: busbar_plugin_sign::AllowReason::Unsigned,
                        ..
                    } => "unsigned (allowed)".to_string(),
                    Verdict::Allowed { .. } => "third-party (allowed)".to_string(),
                };
                rows.push(InventoryEntry {
                    file: p.file.clone(),
                    manifest: Some(p.manifest.clone()),
                    signature,
                    status: "ready".to_string(),
                });
                loadable.push(p);
            }
            FileOutcome::Skipped(s) => {
                let signature = if s.reason.contains("anti-downgrade") {
                    "trusted (below floor)".to_string()
                } else if s.reason.contains("not in the allowlist") {
                    "unknown-publisher".to_string()
                } else if s.reason.contains("signature") && s.reason.contains("failed") {
                    "tampered".to_string()
                } else {
                    "unsigned".to_string()
                };
                let status = if s.reason.contains("anti-downgrade") {
                    format!("REJECTED: {}", s.reason)
                } else {
                    format!("SKIPPED: {}", s.reason)
                };
                rows.push(InventoryEntry {
                    file: s.file,
                    manifest: Some(s.manifest),
                    signature,
                    status,
                });
            }
            FileOutcome::Invalid { file, reason } => rows.push(InventoryEntry {
                file,
                manifest: None,
                signature: "INVALID".to_string(),
                status: format!("INVALID: {reason}"),
            }),
        }
    }
    // Surface phase-3 conflicts on the affected loadable rows.
    for conflict in conflicts(&loadable) {
        for row in rows.iter_mut() {
            if let Some(m) = &row.manifest {
                if conflict.contains(&format!("'{}'", m.name))
                    || conflict.contains(&format!("'{}'", m.alias))
                {
                    row.status = format!("CONFLICT: {conflict}");
                }
            }
        }
    }
    rows
}

#[cfg(test)]
mod tests {
    use super::*;
    use busbar_plugin_sign::{sign, SigningKey};

    fn key(seed: u8) -> SigningKey {
        SigningKey::from_bytes(&[seed; 32])
    }

    fn manifest(name: &str, alias: &str, publisher: &str) -> Manifest {
        Manifest {
            name: name.into(),
            alias: alias.into(),
            kind: "store".into(),
            version: "1.5.0".into(),
            publisher: publisher.into(),
            abi_version: 1,
            sha256: String::new(),
            signature: String::new(),
            description: String::new(),
            homepage: String::new(),
            license: String::new(),
        }
    }

    fn policy(first_party: &SigningKey) -> TrustPolicy {
        TrustPolicy {
            first_party_key: Some(first_party.verifying_key()),
            binary_version: "1.5.0".into(),
            publishers: Default::default(),
            allow_unsigned: false,
            allow_third_party: false,
            min_versions: Default::default(),
        }
    }

    fn tmpdir(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!(
            "busbar-registry-{}-{tag}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    fn write_tarball(dir: &Path, file: &str, m: &Manifest, lib: &[u8]) {
        let bytes = tarball::package(m, "lib.so", lib).unwrap();
        std::fs::write(dir.join(file), bytes).unwrap();
    }

    /// The full happy path: two signed first-party plugins scan into a registry addressable by
    /// name AND alias, with identity from the MANIFEST (the filenames are deliberately wrong).
    #[test]
    fn scan_registers_by_name_and_alias_from_manifest_not_filename() {
        let release = key(1);
        let dir = tmpdir("happy");
        let redis = sign(
            &release,
            manifest("busbar-store-redis", "redis", "busbar"),
            b"redis lib",
        );
        let pg = sign(
            &release,
            manifest("busbar-store-postgres", "postgres", "busbar"),
            b"pg lib",
        );
        // Filenames lie on purpose - identity must come from the signed manifest.
        write_tarball(&dir, "totally-not-redis.tar.gz", &redis, b"redis lib");
        write_tarball(&dir, "misc.tgz", &pg, b"pg lib");

        let reg = scan_and_validate(&dir, &policy(&release)).expect("scan");
        assert_eq!(reg.loadable().len(), 2);
        assert!(reg.resolve("redis").is_some(), "alias resolves");
        assert!(reg.resolve("busbar-store-redis").is_some(), "name resolves");
        assert!(reg.resolve("postgres").is_some());
        assert_eq!(
            reg.resolve("redis").unwrap().manifest.name,
            "busbar-store-redis"
        );
        assert!(reg.resolve("no-such").is_none());
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// FAIL-CLOSED: one invalid tarball in the dir fails the WHOLE scan with a named reason -
    /// never a partial registry.
    #[test]
    fn one_invalid_tarball_fails_the_whole_scan() {
        let release = key(1);
        let dir = tmpdir("invalid");
        let good = sign(
            &release,
            manifest("busbar-store-redis", "redis", "busbar"),
            b"lib",
        );
        write_tarball(&dir, "good.tar.gz", &good, b"lib");
        std::fs::write(dir.join("junk.tar.gz"), b"this is not a tarball").unwrap();

        let errs = scan_and_validate(&dir, &policy(&release)).unwrap_err();
        assert_eq!(errs.len(), 1);
        assert!(
            errs[0].contains("junk.tar.gz"),
            "names the file: {}",
            errs[0]
        );
        assert!(errs[0].contains("invalid plugin"), "got {}", errs[0]);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A structurally-broken manifest (bad kind) fails the scan even though it is validly signed.
    #[test]
    fn signed_but_malformed_manifest_is_invalid() {
        let release = key(1);
        let dir = tmpdir("malformed");
        let mut m = manifest("busbar-store-x", "x", "busbar");
        m.kind = "widget".into();
        let m = sign(&release, m, b"lib");
        write_tarball(&dir, "x.tar.gz", &m, b"lib");
        let errs = scan_and_validate(&dir, &policy(&release)).unwrap_err();
        assert!(errs[0].contains("kind"), "got {}", errs[0]);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Phase 2: an untrusted (third-party, no opt-in) plugin is SKIPPED - the scan succeeds, the
    /// plugin is not loadable, and referencing it fails with the skip reason.
    #[test]
    fn untrusted_is_skipped_not_fatal_but_reference_fails_loud() {
        let release = key(1);
        let acme = key(2);
        let dir = tmpdir("untrusted");
        let third = sign(
            &acme,
            manifest("acme-store-dynamo", "dynamo", "acme"),
            b"lib3",
        );
        write_tarball(&dir, "dynamo.tar.gz", &third, b"lib3");

        let reg = scan_and_validate(&dir, &policy(&release)).expect("scan succeeds");
        assert!(reg.loadable().is_empty());
        assert_eq!(reg.skipped().len(), 1);
        assert!(
            reg.resolve("dynamo").is_none(),
            "a skipped plugin never resolves"
        );
        let err = reg.open_store("dynamo", "{}").map(|_| ()).unwrap_err();
        assert!(err.contains("was not loaded"), "got {err}");
        assert!(err.contains("allowlist"), "carries the trust reason: {err}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Phase 3: two loadable plugins claiming the same ALIAS is a hard error naming both - the
    /// "can't use redis and a third-party redis" case (third-party allowed via opt-in).
    #[test]
    fn alias_conflict_is_a_hard_error_naming_both() {
        let release = key(1);
        let acme = key(2);
        let dir = tmpdir("conflict");
        let first = sign(
            &release,
            manifest("busbar-store-redis", "redis", "busbar"),
            b"lib1",
        );
        let third = sign(
            &acme,
            manifest("acme-store-redis", "redis", "acme"),
            b"lib2",
        );
        write_tarball(&dir, "first.tar.gz", &first, b"lib1");
        write_tarball(&dir, "third.tar.gz", &third, b"lib2");

        let mut pol = policy(&release);
        pol.allow_third_party = true; // both become loadable -> the conflict must fire
        let errs = scan_and_validate(&dir, &pol).unwrap_err();
        assert_eq!(errs.len(), 1, "got {errs:?}");
        assert!(errs[0].contains("alias conflict"), "got {}", errs[0]);
        assert!(
            errs[0].contains("busbar-store-redis"),
            "names first: {}",
            errs[0]
        );
        assert!(
            errs[0].contains("acme-store-redis"),
            "names second: {}",
            errs[0]
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Phase 3: duplicate NAME, and an alias colliding with another plugin's NAME, both hard-error.
    #[test]
    fn name_and_alias_vs_name_conflicts_are_hard_errors() {
        let release = key(1);
        let dir = tmpdir("nameconflict");
        let a = sign(
            &release,
            manifest("busbar-store-redis", "redis", "busbar"),
            b"a",
        );
        let b = sign(
            &release,
            manifest("busbar-store-redis", "redis2", "busbar"),
            b"b",
        );
        write_tarball(&dir, "a.tar.gz", &a, b"a");
        write_tarball(&dir, "b.tar.gz", &b, b"b");
        let errs = scan_and_validate(&dir, &policy(&release)).unwrap_err();
        assert!(
            errs.iter().any(|e| e.contains("name conflict")),
            "got {errs:?}"
        );
        let _ = std::fs::remove_dir_all(&dir);

        // Alias colliding with another plugin's canonical name.
        let dir = tmpdir("aliasvsname");
        let a = sign(
            &release,
            manifest("busbar-store-redis", "redis", "busbar"),
            b"a",
        );
        let b = sign(
            &release,
            manifest("acme-store-x", "busbar-store-redis", "busbar"),
            b"b",
        );
        write_tarball(&dir, "a.tar.gz", &a, b"a");
        write_tarball(&dir, "b.tar.gz", &b, b"b");
        let errs = scan_and_validate(&dir, &policy(&release)).unwrap_err();
        assert!(
            errs.iter().any(|e| e.contains("alias/name conflict")),
            "got {errs:?}"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A missing plugins dir is an EMPTY registry (drop-is-inert), not an error.
    #[test]
    fn missing_dir_is_empty_registry() {
        let reg = scan_and_validate(Path::new("/no/such/busbar/plugins/dir"), &policy(&key(1)))
            .expect("missing dir is fine");
        assert!(reg.loadable().is_empty() && reg.skipped().is_empty());
    }

    /// Kind gating: a non-store plugin resolves but cannot back the governance store.
    #[test]
    fn open_store_refuses_non_store_kind() {
        let release = key(1);
        let dir = tmpdir("kind");
        let mut m = manifest("busbar-hook-ranker", "ranker", "busbar");
        m.kind = "hook".into();
        let m = sign(&release, m, b"hook lib");
        write_tarball(&dir, "hook.tar.gz", &m, b"hook lib");
        let reg = scan_and_validate(&dir, &policy(&release)).expect("scan");
        let err = reg.open_store("ranker", "{}").map(|_| ()).unwrap_err();
        assert!(err.contains("kind 'hook'"), "got {err}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The inventory is MANIFEST-ONLY and covers every row class: ready, skipped (unknown
    /// publisher), and invalid - with the exact reason.
    #[test]
    fn inventory_reports_every_row_class_without_loading() {
        let release = key(1);
        let acme = key(2);
        let dir = tmpdir("inventory");
        let good = sign(
            &release,
            manifest("busbar-store-redis", "redis", "busbar"),
            b"g",
        );
        let third = sign(&acme, manifest("acme-store-dynamo", "dynamo", "acme"), b"t");
        write_tarball(&dir, "good.tar.gz", &good, b"g");
        write_tarball(&dir, "third.tar.gz", &third, b"t");
        std::fs::write(dir.join("junk.tar.gz"), b"garbage").unwrap();

        let rows = inventory(&dir, &policy(&release));
        assert_eq!(rows.len(), 3);
        let by_file = |f: &str| rows.iter().find(|r| r.file == f).unwrap();
        assert_eq!(by_file("good.tar.gz").signature, "first-party");
        assert_eq!(by_file("good.tar.gz").status, "ready");
        assert_eq!(by_file("third.tar.gz").signature, "unknown-publisher");
        assert!(by_file("third.tar.gz").status.starts_with("SKIPPED:"));
        assert_eq!(by_file("junk.tar.gz").signature, "INVALID");
        assert!(by_file("junk.tar.gz").status.starts_with("INVALID:"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Locate the REAL sqlite plugin cdylib in the build's target dir (like the loader tests).
    /// CI hardening: under CI (`cargo test --workspace` always builds it) a missing cdylib is a
    /// HARD failure, never a silent skip.
    fn sqlite_cdylib() -> Option<PathBuf> {
        let candidate = (|| {
            let exe = std::env::current_exe().ok()?;
            let profile_dir = exe.parent()?.parent()?;
            let name = crate::plugin_library_filename("busbar_store_sqlite_plugin");
            let candidate = profile_dir.join(&name);
            candidate.exists().then_some(candidate)
        })();
        if candidate.is_none() && std::env::var_os("CI").is_some() {
            panic!(
                "the sqlite plugin cdylib is not built under CI; refusing to silently skip the                  end-to-end tarball pipeline coverage"
            );
        }
        candidate
    }

    /// END-TO-END, REAL CODE: package the actual sqlite store cdylib into a SIGNED tarball, run
    /// the full three-phase pipeline, resolve by ALIAS, and open a live `dyn Store` through the
    /// memfd (Linux) / private-temp loader - exercising put/get over the C ABI. This is the exact
    /// seam the engine sees: verified bytes in, `Box<dyn Store>` out, indistinguishable from a
    /// compiled-in backend.
    #[test]
    fn end_to_end_open_store_from_signed_tarball() {
        let Some(path) = sqlite_cdylib() else {
            eprintln!("skip: sqlite plugin cdylib not built (run under --workspace)");
            return;
        };
        let lib = std::fs::read(&path).expect("read sqlite cdylib");
        let acme = key(3);
        let dir = tmpdir("e2e");
        let m = sign(&acme, manifest("acme-store-sqlite", "sqlite", "acme"), &lib);
        let bytes = tarball::package(&m, "libbusbar_store_sqlite_plugin.so", &lib).unwrap();
        std::fs::write(dir.join("sqlite.tar.gz"), bytes).unwrap();

        let mut pol = policy(&key(1));
        pol.publishers
            .insert("acme".to_string(), acme.verifying_key());
        let reg = scan_and_validate(&dir, &pol).expect("scan");
        let store = reg
            .open_store("sqlite", r#"{"db_path": ":memory:"}"#)
            .expect("open the real sqlite store through the full pipeline");
        let key = busbar_api::VirtualKey {
            id: "vk_pipeline".into(),
            key_hash: "h".into(),
            name: "pipeline".into(),
            allowed_pools: vec!["p".into()],
            max_budget_cents: Some(9),
            budget_period: "total".into(),
            rpm_limit: None,
            tpm_limit: None,
            enabled: true,
            created_at: 1,
        };
        store.put_key(&key).expect("put over the ABI");
        assert_eq!(
            store
                .get_key("vk_pipeline")
                .unwrap()
                .unwrap()
                .max_budget_cents,
            Some(9)
        );
        drop(store);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// First-party anti-downgrade in the pipeline: an old (validly signed) first-party plugin is
    /// REJECTED (inventory shows below-floor; scan skips it with the anti-downgrade reason).
    #[test]
    fn first_party_downgrade_is_rejected_in_pipeline() {
        let release = key(1);
        let dir = tmpdir("downgrade");
        let mut m = manifest("busbar-store-redis", "redis", "busbar");
        m.version = "1.0.0".into();
        let m = sign(&release, m, b"old lib");
        write_tarball(&dir, "old.tar.gz", &m, b"old lib");
        let reg = scan_and_validate(&dir, &policy(&release)).expect("scan");
        assert!(reg.resolve("redis").is_none());
        assert!(reg.skipped()[0].reason.contains("anti-downgrade"));
        let rows = inventory(&dir, &policy(&release));
        assert!(
            rows[0].status.starts_with("REJECTED:"),
            "got {}",
            rows[0].status
        );
        let _ = std::fs::remove_dir_all(&dir);
    }
}
