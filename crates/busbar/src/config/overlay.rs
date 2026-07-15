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

use std::collections::HashMap;
use std::path::Path;

use serde::{Deserialize, Serialize};

use super::{DeployCfg, HookCfg};

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
        // Read-modify-WRITE, not the fail-soft boot read. `read()` collapses absent/unreadable/corrupt
        // to None; starting empty then overwriting would PERMANENTLY drop accumulated deletions and
        // silently resurrect an API-deleted hook on restart. Distinguish: absent -> start fresh;
        // present-but-unreadable -> REFUSE to overwrite, preserving the existing overlay.
        let mut deleted = match read_state(p) {
            OverlayReadState::Absent => Vec::new(),
            OverlayReadState::Loaded(d) => d.deleted,
            OverlayReadState::Unreadable => {
                tracing::error!(
                    path = %p.display(),
                    "config overlay exists but is unreadable/corrupt; REFUSING to overwrite it (would                      drop hook-deletion tombstones and could resurrect a deleted hook). This apply is                      NOT persisted — fix or remove the overlay file to restore durability."
                );
                return;
            }
        };
        if let Some(name) = deleted_add {
            if !deleted.iter().any(|n| n == name) {
                deleted.push(name.to_string());
            }
        }
        if let Some(name) = deleted_remove {
            deleted.retain(|n| n != name);
        }
        // INVARIANT: a hook present in the registry being persisted can never ALSO be tombstoned —
        // the boot-merge would insert it then subtract it, silently dropping a live hook. The
        // explicit `deleted_remove` above covers the register-a-name case; this reconciliation also
        // covers the WHOLESALE-registry writes (config ROLLBACK, which passes both args `None`):
        // rollback restores a registry that may contain a name still tombstoned from an earlier
        // API delete, and without this the rollback would not survive a restart (found: audit c1r5).
        deleted.retain(|name| !hooks.contains_key(name));
        let doc = OverlayDoc {
            hooks: hooks.clone(),
            global_hooks: global_hooks.to_vec(),
            deleted,
        };
        if let Err(e) = write(p, &doc) {
            tracing::warn!(error = %e, path = %p.display(), "failed to persist config overlay");
        }
    }
}

/// The persisted overlay document: the API-applied hook registry + global-hook wiring, plus TOMBSTONES
/// (`deleted`) — hooks removed via the API that must be subtracted from base config at boot. Tombstones
/// are what let the additive `base + overlay` model express a DELETION (an additive merge alone cannot
/// remove a base-defined hook).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub(crate) struct OverlayDoc {
    #[serde(default)]
    pub(crate) hooks: HashMap<String, HookCfg>,
    #[serde(default)]
    pub(crate) global_hooks: Vec<String>,
    #[serde(default)]
    pub(crate) deleted: Vec<String>,
}

/// Read the overlay at `path`, or `None` if it is absent, unreadable, or malformed. Fail-soft: a
/// corrupt overlay must NEVER brick boot — busbar starts on base config alone and the operator can
/// re-apply. (A future durable store surfaces a boot warning; the in-file MVP stays silent-soft.)
pub(crate) fn read(path: &Path) -> Option<OverlayDoc> {
    let bytes = std::fs::read(path).ok()?;
    serde_json::from_slice(&bytes).ok()
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
    }
}

/// Merge an overlay into a deploy config BEFORE resolve (the boot-merge). Overlay hooks are inserted
/// into the registry (an overlay hook with a base hook's name WINS — the last-applied definition, which
/// matches the live-apply semantics), overlay global names are unioned into `global_hooks`, and finally
/// TOMBSTONES (`deleted`) are subtracted — so a hook the API deleted stays gone across a restart even if
/// it was defined in base `config.yaml`. Tombstones are applied LAST so a delete always wins over a
/// stale add.
pub(crate) fn merge_into(deploy: &mut DeployCfg, doc: OverlayDoc) {
    for (name, cfg) in doc.hooks {
        deploy.hooks.insert(name, cfg);
    }
    for g in doc.global_hooks {
        if !deploy.global_hooks.contains(&g) {
            deploy.global_hooks.push(g);
        }
    }
    // Tombstones LAST: an API deletion removes the hook from the effective config even if base defined it.
    for name in &doc.deleted {
        deploy.hooks.remove(name);
        deploy.global_hooks.retain(|g| g != name);
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

    /// merge_into adds overlay hooks to the deploy registry + unions global names; an overlay hook with
    /// a base hook's name wins.
    #[test]
    fn merge_into_deploy() {
        // A minimal deploy config (providers/models required; the rest default).
        let mut deploy: DeployCfg =
            serde_json::from_value(serde_json::json!({"providers": {}, "models": {}})).unwrap();
        deploy.hooks.insert("base_hook".to_string(), gate());
        let doc = from_state(
            &HashMap::from([
                ("base_hook".to_string(), gate()), // same name as a base hook → overlay wins
                ("api_hook".to_string(), gate()),
            ]),
            &["api_hook".to_string(), "base_hook".to_string()],
        );
        deploy.global_hooks.push("base_hook".to_string());
        merge_into(&mut deploy, doc);
        assert!(deploy.hooks.contains_key("api_hook"));
        assert!(deploy.hooks.contains_key("base_hook"));
        // global_hooks unioned, no duplicate of base_hook.
        assert_eq!(
            deploy
                .global_hooks
                .iter()
                .filter(|g| *g == "base_hook")
                .count(),
            1,
            "global union does not duplicate"
        );
        assert!(deploy.global_hooks.iter().any(|g| g == "api_hook"));
    }

    /// TOMBSTONE: a hook the API deleted (recorded in `deleted`) is removed from the effective config at
    /// boot even if it was defined in base config.yaml — so an API deletion survives a restart.
    #[test]
    fn merge_into_applies_tombstones() {
        let mut deploy: DeployCfg =
            serde_json::from_value(serde_json::json!({"providers": {}, "models": {}})).unwrap();
        deploy.hooks.insert("base_hook".to_string(), gate());
        deploy.global_hooks.push("base_hook".to_string());
        let doc = OverlayDoc {
            hooks: HashMap::new(),
            global_hooks: Vec::new(),
            deleted: vec!["base_hook".to_string()],
        };
        merge_into(&mut deploy, doc);
        assert!(
            !deploy.hooks.contains_key("base_hook"),
            "a tombstoned base hook is removed from the effective config"
        );
        assert!(!deploy.global_hooks.iter().any(|g| g == "base_hook"));
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
        let mut deploy: DeployCfg =
            serde_json::from_value(serde_json::json!({"providers": {}, "models": {}})).unwrap();
        merge_into(&mut deploy, doc);
        assert!(
            deploy.hooks.contains_key("x"),
            "rollback is durable across restart"
        );
        let _ = std::fs::remove_file(&path);
    }
}
