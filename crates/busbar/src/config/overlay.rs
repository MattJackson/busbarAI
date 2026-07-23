// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The busbar-owned config OVERLAY — the persistence substrate that lets an API-applied hook survive
//! a restart. Effective config = base (`config.yaml`, hand-written, NEVER touched) + overlay
//! (busbar-owned). Today the overlay carries the runtime hook registry; it grows as more of the config
//! plane becomes API-mutable.
//!
//! This module is the PURE substrate (read/write/merge) — unit-tested in isolation. The wiring (write
//! on apply, read + merge at boot, gated by the overlay path) is layered on top. `write` is atomic
//! (temp + rename) so a crash mid-write never leaves a torn overlay; `read` is fail-soft (a missing or
//! corrupt overlay yields `None` and boot proceeds on base config alone — a bad overlay never bricks
//! startup).

use std::collections::{BTreeMap, HashMap};
use std::path::Path;

use serde::{Deserialize, Serialize};

use super::{GroupCfg, HookCfg, RootCfg};

/// Current overlay schema version. Stamped on every write; a missing field (a pre-versioning overlay)
/// reads as `1`, the additive baseline (hooks + the newly-added groups section, both backward
/// compatible). Bump only on a BREAKING overlay-format change, and add a migration at `read` time.
pub(crate) const OVERLAY_VERSION: u32 = 1;
fn default_overlay_version() -> u32 {
    1
}

/// Persist the current hook state to the overlay at `path`, IF persistence is enabled (`Some`), and
/// update the TOMBSTONE set for this change: `deleted_add` (a just-deleted hook) is tombstoned so the
/// additive boot-merge REMOVES it even if it was defined in base `config.yaml`; `deleted_remove` (a
/// just-registered hook) clears any prior tombstone (a re-add). Read-modify-write so tombstones
/// accumulate across applies. The path is opt-in via `BUSBAR_CONFIG_OVERLAY` and carried on `App`, so
/// the default behavior + config schema are unchanged. Best-effort: the live config already swapped, so
/// the overlay is durability (not correctness) — a write failure is logged, never fatal, never blocks
/// the request. `None` is a no-op (persistence disabled, the default).
pub(crate) fn persist(
    path: Option<&Path>,
    hooks: &HashMap<String, HookCfg>,
    global_hooks: &[String],
    deleted_add: Option<&str>,
    deleted_remove: Option<&str>,
) {
    if let Some(p) = path {
        // Read-modify-WRITE the WHOLE overlay so a hook write preserves the groups section verbatim
        // (and vice-versa in `persist_groups`). `load_for_rmw` refuses on an unreadable overlay —
        // starting empty then overwriting would PERMANENTLY drop accumulated tombstones from BOTH
        // sections and silently resurrect an API-deleted hook/group on restart.
        let Some(mut doc) = load_for_rmw(p) else {
            return;
        };
        if let Some(name) = deleted_add {
            if !doc.deleted.iter().any(|n| n == name) {
                doc.deleted.push(name.to_string());
            }
        }
        if let Some(name) = deleted_remove {
            doc.deleted.retain(|n| n != name);
        }
        doc.hooks = hooks.clone();
        doc.global_hooks = global_hooks.to_vec();
        // INVARIANT: a hook present in the registry being persisted can never ALSO be tombstoned —
        // the boot-merge would insert it then subtract it, silently dropping a live hook. The
        // explicit `deleted_remove` above covers the register-a-name case; this reconciliation also
        // covers the WHOLESALE-registry writes (config ROLLBACK, which passes both args `None`):
        // rollback restores a registry that may contain a name still tombstoned from an earlier
        // API delete, and without this the rollback would not survive a restart (found: audit c1r5).
        doc.deleted.retain(|name| !hooks.contains_key(name));
        doc.version = OVERLAY_VERSION;
        if let Err(e) = write(p, &doc) {
            tracing::warn!(error = %e, path = %p.display(), "failed to persist config overlay");
        }
    }
}

/// Load the existing overlay for a read-modify-WRITE, or `None` to signal REFUSE-to-overwrite.
/// `Absent` -> a fresh default doc (safe to start clean); `Loaded` -> the existing doc (all sections
/// carried forward so a write to one section never clobbers another); `Unreadable` -> `None`, and the
/// caller aborts the write, because overwriting a corrupt overlay would drop the deletion tombstones
/// of EVERY section. `version` is stamped by the caller just before `write`.
fn load_for_rmw(p: &Path) -> Option<OverlayDoc> {
    match read_state(p) {
        OverlayReadState::Absent => Some(OverlayDoc::default()),
        OverlayReadState::Loaded(doc) => Some(doc),
        OverlayReadState::Unreadable => {
            tracing::error!(
                path = %p.display(),
                "config overlay exists but is unreadable/corrupt; REFUSING to overwrite it (would \
                 drop hook AND group deletion tombstones and could resurrect a deleted item). This \
                 apply is NOT persisted — fix or remove the overlay file to restore durability."
            );
            None
        }
    }
}

/// Persist the current GROUPS state to the overlay, mirroring `persist` for the `groups:` section:
/// the API-mutable group registry + its tombstones (`deleted_groups`), read-modify-written so the
/// HOOKS section and its tombstones are preserved untouched. Same durability (not correctness)
/// contract: the live config already swapped; a write failure is logged, never fatal. `None` path is a
/// no-op. `deleted_add`/`deleted_remove` tombstone/untombstone a group name; a wholesale write (both
/// `None`, e.g. rollback) reconciles away any tombstone for a name the restored registry contains.
pub(crate) fn persist_groups(
    path: Option<&Path>,
    groups: &BTreeMap<String, GroupCfg>,
    deleted_add: Option<&str>,
    deleted_remove: Option<&str>,
) {
    if let Some(p) = path {
        let Some(mut doc) = load_for_rmw(p) else {
            return;
        };
        if let Some(name) = deleted_add {
            if !doc.deleted_groups.iter().any(|n| n == name) {
                doc.deleted_groups.push(name.to_string());
            }
        }
        if let Some(name) = deleted_remove {
            doc.deleted_groups.retain(|n| n != name);
        }
        doc.groups = groups.clone();
        doc.deleted_groups.retain(|name| !groups.contains_key(name));
        doc.version = OVERLAY_VERSION;
        if let Err(e) = write(p, &doc) {
            tracing::warn!(error = %e, path = %p.display(), "failed to persist config overlay (groups)");
        }
    }
}

/// The persisted overlay document: the API-applied hook registry + global-hook wiring, plus TOMBSTONES
/// (`deleted`) — hooks removed via the API that must be subtracted from base config at boot. Tombstones
/// are what let the additive `base + overlay` model express a DELETION (an additive merge alone cannot
/// remove a base-defined hook).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub(crate) struct OverlayDoc {
    /// Overlay schema version (see `OVERLAY_VERSION`). Absent in a pre-versioning overlay -> `1`.
    #[serde(default = "default_overlay_version")]
    pub(crate) version: u32,
    #[serde(default)]
    pub(crate) hooks: HashMap<String, HookCfg>,
    #[serde(default)]
    pub(crate) global_hooks: Vec<String>,
    #[serde(default)]
    pub(crate) deleted: Vec<String>,
    /// API-applied `groups:` entries (the second section on the spine). An overlay group with a base
    /// group's name WINS at merge (last-applied definition), matching hook semantics.
    #[serde(default)]
    pub(crate) groups: BTreeMap<String, GroupCfg>,
    /// Group tombstones — groups deleted via the API, subtracted from base config at boot.
    #[serde(default)]
    pub(crate) deleted_groups: Vec<String>,
}

/// Read the overlay at `path`, or `None` if it is absent, unreadable, or malformed. Fail-soft: a
/// corrupt overlay must NEVER brick boot — busbar starts on base config alone and the operator can
/// re-apply. Unlike the old silent-soft read, a present-but-corrupt overlay is now logged LOUD at
/// boot: silently starting on base config alone drops every API-applied hook AND group with no signal,
/// which is exactly the failure that hides overlay corruption.
pub(crate) fn read(path: &Path) -> Option<OverlayDoc> {
    match read_state(path) {
        OverlayReadState::Absent => None,
        OverlayReadState::Loaded(doc) => Some(doc),
        OverlayReadState::Unreadable => {
            tracing::warn!(
                path = %path.display(),
                "config overlay is present but unreadable/corrupt; starting on base config.yaml ALONE \
                 — API-applied hooks and groups are NOT restored. Fix or remove the overlay file to \
                 restore durability."
            );
            None
        }
    }
}

/// Classified overlay read for the read-modify-WRITE path (`persist`), which — unlike the fail-soft
/// boot `read` — MUST tell "absent" (safe to start fresh) apart from "present but unreadable/corrupt"
/// (must NOT overwrite, or accumulated tombstones are lost).
pub(crate) enum OverlayReadState {
    Absent,
    Loaded(OverlayDoc),
    Unreadable,
}

pub(crate) fn read_state(path: &Path) -> OverlayReadState {
    match std::fs::read(path) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => OverlayReadState::Absent,
        Err(_) => OverlayReadState::Unreadable,
        Ok(bytes) => match serde_json::from_slice(&bytes) {
            Ok(doc) => OverlayReadState::Loaded(doc),
            Err(_) => OverlayReadState::Unreadable,
        },
    }
}

/// Atomically write the overlay: serialize to a sibling `.tmp` then rename over `path`, so a reader
/// (or a crash) never observes a half-written file.
pub(crate) fn write(path: &Path, doc: &OverlayDoc) -> std::io::Result<()> {
    let json = serde_json::to_vec_pretty(doc).map_err(std::io::Error::other)?;
    let tmp = path.with_extension("overlay.tmp");
    std::fs::write(&tmp, json)?;
    std::fs::rename(&tmp, path)
}

/// Build an overlay from a hook state (registry + global-hook names), no tombstones — a test helper
/// (the live apply path builds the doc inline in `persist` so it can carry tombstones).
#[cfg(test)]
pub(crate) fn from_state(hooks: &HashMap<String, HookCfg>, global_hooks: &[String]) -> OverlayDoc {
    OverlayDoc {
        hooks: hooks.clone(),
        global_hooks: global_hooks.to_vec(),
        deleted: Vec::new(),
        ..Default::default()
    }
}

/// Merge an overlay into the RESOLVED config (the boot-merge, run AFTER `config::resolve` - the
/// runtime hook registry is synthesized there from the inline refs, so the overlay layers on top
/// of it). Overlay hooks are inserted into the registry (an overlay hook with a base hook's name
/// WINS - the last-applied definition, which matches the live-apply semantics), overlay global
/// names are unioned into `global_hooks`, and finally TOMBSTONES (`deleted`) are subtracted - so a
/// hook the API deleted stays gone across a restart even if it was defined in base `config.yaml`.
/// Tombstones are applied LAST so a delete always wins over a stale add.
pub(crate) fn merge_into(cfg: &mut RootCfg, doc: OverlayDoc) {
    for (name, hook) in doc.hooks {
        cfg.hooks.insert(name, hook);
    }
    for g in doc.global_hooks {
        if !cfg.global_hooks.contains(&g) {
            cfg.global_hooks.push(g);
        }
    }
    // Groups section: same semantics as hooks — an overlay group with a base group's name wins, then
    // group tombstones are subtracted LAST so an API deletion survives a restart even if base defined
    // the group. The parent-chain validity (parents exist, acyclic, depth) is re-checked by
    // `validate_groups` after the merge, exactly as for a hand-written config.
    for (name, group) in doc.groups {
        cfg.groups.insert(name, group);
    }
    // Tombstones LAST: an API deletion removes the hook/group from the effective config even if base
    // defined it.
    for name in &doc.deleted {
        cfg.hooks.remove(name);
        cfg.global_hooks.retain(|g| g != name);
    }
    for name in &doc.deleted_groups {
        cfg.groups.remove(name);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn gate() -> HookCfg {
        serde_json::from_value(serde_json::json!({
            "kind": "gate", "webhook": "http://127.0.0.1:8900/", "prompt": "rw", "global": true
        }))
        .unwrap()
    }

    /// write → read round-trips the overlay through the filesystem (atomic write, fail-soft read).
    #[test]
    fn write_read_round_trip() {
        let dir = std::env::temp_dir();
        let path = dir.join(format!("busbar-overlay-test-{}.json", std::process::id()));
        let doc = from_state(
            &HashMap::from([("compress".to_string(), gate())]),
            &["compress".to_string()],
        );
        write(&path, &doc).expect("atomic write");
        let read_back = read(&path).expect("read back");
        assert!(read_back.hooks.contains_key("compress"));
        assert_eq!(read_back.global_hooks, vec!["compress".to_string()]);
        let _ = std::fs::remove_file(&path);
    }

    /// A missing or corrupt overlay is fail-soft (None), never a panic.
    #[test]
    fn read_absent_or_corrupt_is_none() {
        assert!(read(Path::new("/nonexistent/busbar-overlay-xyz.json")).is_none());
        let dir = std::env::temp_dir();
        let path = dir.join(format!(
            "busbar-overlay-corrupt-{}.json",
            std::process::id()
        ));
        std::fs::write(&path, b"{ this is not json").unwrap();
        assert!(
            read(&path).is_none(),
            "a corrupt overlay must not brick boot"
        );
        let _ = std::fs::remove_file(&path);
    }

    /// A minimal RESOLVED config to merge overlays into (providers/models empty; registry empty).
    fn minimal_cfg() -> RootCfg {
        let deploy: super::super::DeployCfg =
            serde_json::from_value(serde_json::json!({"providers": {}, "models": {}})).unwrap();
        super::super::resolve(&deploy, &HashMap::new()).expect("minimal config resolves")
    }

    /// merge_into adds overlay hooks to the resolved registry + unions global names; an overlay
    /// hook with a base hook's name wins.
    #[test]
    fn merge_into_deploy() {
        let mut cfg = minimal_cfg();
        cfg.hooks.insert("base_hook".to_string(), gate());
        let doc = from_state(
            &HashMap::from([
                ("base_hook".to_string(), gate()), // same name as a base hook → overlay wins
                ("api_hook".to_string(), gate()),
            ]),
            &["api_hook".to_string(), "base_hook".to_string()],
        );
        cfg.global_hooks.push("base_hook".to_string());
        merge_into(&mut cfg, doc);
        assert!(cfg.hooks.contains_key("api_hook"));
        assert!(cfg.hooks.contains_key("base_hook"));
        // global_hooks unioned, no duplicate of base_hook.
        assert_eq!(
            cfg.global_hooks
                .iter()
                .filter(|g| *g == "base_hook")
                .count(),
            1,
            "global union does not duplicate"
        );
        assert!(cfg.global_hooks.iter().any(|g| g == "api_hook"));
    }

    /// TOMBSTONE: a hook the API deleted (recorded in `deleted`) is removed from the effective config at
    /// boot even if it was defined in base config.yaml — so an API deletion survives a restart.
    #[test]
    fn merge_into_applies_tombstones() {
        let mut cfg = minimal_cfg();
        cfg.hooks.insert("base_hook".to_string(), gate());
        cfg.global_hooks.push("base_hook".to_string());
        let doc = OverlayDoc {
            hooks: HashMap::new(),
            global_hooks: Vec::new(),
            deleted: vec!["base_hook".to_string()],
            ..Default::default()
        };
        merge_into(&mut cfg, doc);
        assert!(
            !cfg.hooks.contains_key("base_hook"),
            "a tombstoned base hook is removed from the effective config"
        );
        assert!(!cfg.global_hooks.iter().any(|g| g == "base_hook"));
    }

    /// REGRESSION: `persist` must NOT overwrite a present-but-unreadable/corrupt overlay — that would
    /// drop accumulated deletion tombstones and silently resurrect a deleted hook on restart.
    #[test]
    fn persist_refuses_to_overwrite_unreadable_overlay() {
        let dir = std::env::temp_dir();
        let path = dir.join(format!(
            "busbar-overlay-corrupt-persist-{}.json",
            std::process::id()
        ));
        let corrupt = b"{ this is not valid json and may hide tombstones";
        std::fs::write(&path, corrupt).unwrap();
        persist(
            Some(&path),
            &HashMap::from([("newhook".to_string(), gate())]),
            &["newhook".to_string()],
            Some("deleteme"),
            None,
        );
        let raw = std::fs::read(&path).expect("file still present");
        assert_eq!(
            raw, corrupt,
            "persist must preserve an unreadable overlay verbatim"
        );
        let _ = std::fs::remove_file(&path);
    }

    /// REGRESSION (audit c1r5): a WHOLESALE registry write (config rollback passes both tombstone
    /// args `None`) must reconcile away any tombstone for a name that the restored registry
    /// contains — otherwise the boot-merge inserts the hook then subtracts it, and the rollback
    /// silently vanishes on the next restart. `persist` retains only tombstones whose name is
    /// ABSENT from the persisted registry.
    #[test]
    fn persist_reconciles_tombstone_against_present_hook() {
        let dir = std::env::temp_dir();
        let path = dir.join(format!("busbar-overlay-recon-{}.json", std::process::id()));
        // Seed a prior overlay that tombstoned "x" (an earlier API delete).
        write(
            &path,
            &OverlayDoc {
                hooks: HashMap::new(),
                global_hooks: Vec::new(),
                deleted: vec!["x".to_string()],
                ..Default::default()
            },
        )
        .unwrap();
        // Rollback restores a registry that CONTAINS "x", persisting with both tombstone args None.
        persist(
            Some(&path),
            &HashMap::from([("x".to_string(), gate())]),
            &["x".to_string()],
            None,
            None,
        );
        let doc = read(&path).expect("read back");
        assert!(
            !doc.deleted.iter().any(|n| n == "x"),
            "a restored hook must not remain tombstoned, or it vanishes on restart"
        );
        // And it survives the boot merge (inserted, not subtracted).
        let mut cfg = minimal_cfg();
        merge_into(&mut cfg, doc);
        assert!(
            cfg.hooks.contains_key("x"),
            "rollback is durable across restart"
        );
        let _ = std::fs::remove_file(&path);
    }

    fn group_with_budget() -> GroupCfg {
        serde_json::from_value(serde_json::json!({
            "limits": [ { "budget": 1000, "per": "month" } ]
        }))
        .unwrap()
    }

    /// merge_into inserts overlay groups (an overlay group with a base group's name wins) and applies
    /// group tombstones LAST — an API-deleted group stays gone even if base config.yaml defined it.
    #[test]
    fn merge_into_groups_and_group_tombstones() {
        let mut cfg = minimal_cfg();
        cfg.groups.insert("team".to_string(), group_with_budget());
        cfg.groups.insert("doomed".to_string(), group_with_budget());
        let doc = OverlayDoc {
            groups: BTreeMap::from([("user:alice".to_string(), group_with_budget())]),
            deleted_groups: vec!["doomed".to_string()],
            ..Default::default()
        };
        merge_into(&mut cfg, doc);
        assert!(cfg.groups.contains_key("user:alice"), "overlay group added");
        assert!(cfg.groups.contains_key("team"), "base group untouched");
        assert!(
            !cfg.groups.contains_key("doomed"),
            "tombstoned group removed even though base defined it"
        );
    }

    /// REGRESSION: a HOOK write must PRESERVE the groups section + its tombstones — the read-modify-write
    /// loads the whole doc and mutates only the hook section. Guards against "persist rebuilds the doc
    /// inline and silently drops groups".
    #[test]
    fn persist_hook_preserves_groups_section() {
        let dir = std::env::temp_dir();
        let path = dir.join(format!("busbar-ovl-preserve-{}.json", std::process::id()));
        write(
            &path,
            &OverlayDoc {
                groups: BTreeMap::from([("user:bob".to_string(), group_with_budget())]),
                deleted_groups: vec!["oldteam".to_string()],
                ..Default::default()
            },
        )
        .unwrap();
        persist(
            Some(&path),
            &HashMap::from([("h".to_string(), gate())]),
            &["h".to_string()],
            None,
            None,
        );
        let doc = read(&path).expect("read back");
        assert!(doc.hooks.contains_key("h"), "hook written");
        assert!(
            doc.groups.contains_key("user:bob"),
            "groups section preserved across a hook write"
        );
        assert!(
            doc.deleted_groups.iter().any(|n| n == "oldteam"),
            "group tombstones preserved across a hook write"
        );
        assert_eq!(
            doc.version, OVERLAY_VERSION,
            "schema version stamped on write"
        );
        let _ = std::fs::remove_file(&path);
    }

    /// Symmetric: a GROUP write preserves the hooks section, and reconciles away a group tombstone for a
    /// name the written registry contains (wholesale-rollback safety, mirroring the hook path's c1r5 fix).
    #[test]
    fn persist_groups_preserves_hooks_and_reconciles_tombstone() {
        let dir = std::env::temp_dir();
        let path = dir.join(format!("busbar-ovl-gpreserve-{}.json", std::process::id()));
        write(
            &path,
            &OverlayDoc {
                hooks: HashMap::from([("keepme".to_string(), gate())]),
                deleted_groups: vec!["x".to_string()],
                ..Default::default()
            },
        )
        .unwrap();
        // Persist a group registry that CONTAINS "x" (a rollback), both tombstone args None.
        persist_groups(
            Some(&path),
            &BTreeMap::from([("x".to_string(), group_with_budget())]),
            None,
            None,
        );
        let doc = read(&path).expect("read back");
        assert!(
            doc.hooks.contains_key("keepme"),
            "hooks section preserved across a group write"
        );
        assert!(doc.groups.contains_key("x"), "group written");
        assert!(
            !doc.deleted_groups.iter().any(|n| n == "x"),
            "tombstone reconciled away for a restored group, else it vanishes on restart"
        );
        let _ = std::fs::remove_file(&path);
    }
}
