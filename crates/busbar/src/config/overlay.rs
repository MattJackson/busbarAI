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

use super::{
    AdvancedCfg, DeployCfg, GroupCfg, HealthDefaultsCfg, HookCfg, LimitsCfg, MetricsCfg,
    ObservabilityCfg, RateEntryCfg, RootCfg, RoutingCfg, SecurityCfg, StoreCfg, TlsCfg,
};

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
        OverlayReadState::Loaded(doc) => Some(*doc),
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

/// The `root` overlay section (1.5.0 full-config coverage): the API-settable SINGLE-VALUE config
/// sections that are NOT name-keyed maps (so they carry no tombstones — a field is either PRESENT in
/// the overlay, and WINS over base `config.yaml`, or ABSENT, and base stands). It mirrors the
/// uncovered `DeployCfg` surface: the process-level binds (`listen`/`tls`/`admin_listen`/`admin_tls`/
/// `admin_insecure`), the cost inputs (`rate_card`/`per_request_fee`), the durable `store`, the
/// `security` SSRF controls, and the operational-limit blocks (`limits`/`observability`/`advanced`/
/// `metrics`/`health`/`routing`). Every field is `Option`: a `PUT /config/settings` overwrites only
/// the fields it names (a partial edit), and the merge (`apply_to_deploy`) splices exactly those onto
/// the resolved base `DeployCfg` BEFORE `resolve` — so the limits projection + admin-mTLS boot-guard
/// re-run over the merged shape exactly as for a hand-written config. `deny_unknown_fields` so a
/// typo'd key is a loud reject, never a silent no-op.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RootSettings {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) listen: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) tls: Option<TlsCfg>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) admin_listen: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) admin_tls: Option<TlsCfg>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) admin_insecure: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) rate_card: Option<BTreeMap<String, RateEntryCfg>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) per_request_fee: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) store: Option<StoreCfg>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) security: Option<SecurityCfg>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) limits: Option<LimitsCfg>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) observability: Option<ObservabilityCfg>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) advanced: Option<AdvancedCfg>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) metrics: Option<MetricsCfg>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) health: Option<HealthDefaultsCfg>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) routing: Option<RoutingCfg>,
}

impl RootSettings {
    /// Whether NO root override is set (every field `None`) — drives the section-empty predicate and
    /// the idempotent-reset short-circuit. Checked field-by-field (not via `PartialEq`) so the nested
    /// config structs need no `PartialEq` derive.
    pub(crate) fn is_empty(&self) -> bool {
        self.listen.is_none()
            && self.tls.is_none()
            && self.admin_listen.is_none()
            && self.admin_tls.is_none()
            && self.admin_insecure.is_none()
            && self.rate_card.is_none()
            && self.per_request_fee.is_none()
            && self.store.is_none()
            && self.security.is_none()
            && self.limits.is_none()
            && self.observability.is_none()
            && self.advanced.is_none()
            && self.metrics.is_none()
            && self.health.is_none()
            && self.routing.is_none()
    }

    /// Splice the present overrides onto a base `DeployCfg`, IN PLACE. Applied BEFORE `resolve` so the
    /// limits projection + the exposed-admin-mTLS boot-guard re-derive over the merged shape exactly
    /// as for a hand-written config. Only `Some` fields overwrite; a `None` field leaves base config
    /// untouched. `admin_insecure`/`per_request_fee` are non-optional on `DeployCfg`, so an unset
    /// overlay override simply preserves the base value.
    pub(crate) fn apply_to_deploy(&self, deploy: &mut DeployCfg) {
        if let Some(v) = &self.listen {
            deploy.listen = v.clone();
        }
        if self.tls.is_some() {
            deploy.tls = self.tls.clone();
        }
        if let Some(v) = &self.admin_listen {
            deploy.admin_listen = v.clone();
        }
        if self.admin_tls.is_some() {
            deploy.admin_tls = self.admin_tls.clone();
        }
        if let Some(v) = self.admin_insecure {
            deploy.admin_insecure = v;
        }
        if self.rate_card.is_some() {
            deploy.rate_card = self.rate_card.clone();
        }
        if let Some(v) = self.per_request_fee {
            deploy.per_request_fee = v;
        }
        if self.store.is_some() {
            deploy.store = self.store.clone();
        }
        if self.security.is_some() {
            deploy.security = self.security.clone();
        }
        if let Some(v) = &self.limits {
            deploy.limits = v.clone();
        }
        if self.observability.is_some() {
            deploy.observability = self.observability.clone();
        }
        if let Some(v) = &self.advanced {
            deploy.advanced = v.clone();
        }
        if let Some(v) = &self.metrics {
            deploy.metrics = v.clone();
        }
        if let Some(v) = &self.health {
            deploy.health = v.clone();
        }
        if let Some(v) = &self.routing {
            deploy.routing = v.clone();
        }
    }
}

/// Persist the `root` overlay section (1.5.0 full-config coverage), IF persistence is enabled. Same
/// read-modify-WRITE durability contract as `persist`/`persist_groups`: the hooks + groups sections
/// (and their tombstones) are carried forward verbatim, and an unreadable overlay is REFUSED (never
/// clobbered). `None` path is a no-op. `settings` is the full desired root state (the merge of the
/// prior overlay root + this request's fields is computed by the caller, so a `PUT /config/settings`
/// passes the already-merged desired state here — this fn just stores it).
pub(crate) fn persist_root(path: Option<&Path>, settings: &RootSettings) {
    if let Some(p) = path {
        let Some(mut doc) = load_for_rmw(p) else {
            return;
        };
        doc.root = if settings.is_empty() {
            None
        } else {
            Some(settings.clone())
        };
        doc.version = OVERLAY_VERSION;
        if let Err(e) = write(p, &doc) {
            tracing::warn!(error = %e, path = %p.display(), "failed to persist config overlay (root)");
        }
    }
}

/// One MUTABLE overlay SECTION — the unit a per-section reset (`DELETE /api/v1/admin/overlay/{section}`)
/// discards. Each section is an independent `base + overlay` layer with its own entries + tombstones;
/// clearing one reverts exactly that slice of the effective config to base `config.yaml` while the
/// other section's overlay mutations survive untouched.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum OverlaySection {
    Hooks,
    Groups,
    /// The single-value config sections (`RootSettings`) — the 1.5.0 full-config coverage slice.
    Root,
}

impl OverlaySection {
    /// Parse a URL path segment into a section, or `None` for an unknown name (the caller 400s). The
    /// ONE place the valid section names live, so the route + the doc + the tests share one source.
    pub(crate) fn parse(s: &str) -> Option<Self> {
        match s {
            "hooks" => Some(OverlaySection::Hooks),
            "groups" => Some(OverlaySection::Groups),
            "root" => Some(OverlaySection::Root),
            _ => None,
        }
    }

    /// The section's wire/label name (the path segment).
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            OverlaySection::Hooks => "hooks",
            OverlaySection::Groups => "groups",
            OverlaySection::Root => "root",
        }
    }
}

/// Clear ONE section's entries + tombstones from the persisted overlay, IF persistence is enabled —
/// the durable half of a per-section reset (`DELETE /api/v1/admin/overlay/{section}`). Read-modify-write
/// so the OTHER section (its API-applied entries and tombstones) is carried forward verbatim: a
/// `groups` reset must not resurrect an API-deleted hook, and vice-versa. Same durability (not
/// correctness) contract as `persist`/`persist_groups`: the live config already reverted, so a write
/// failure is logged, never fatal. `None` path is a no-op; an unreadable overlay is REFUSED (clearing
/// it would silently drop the other section's tombstones).
pub(crate) fn clear_section(path: Option<&Path>, section: OverlaySection) {
    if let Some(p) = path {
        let Some(mut doc) = load_for_rmw(p) else {
            return;
        };
        doc.clear_section(section);
        doc.version = OVERLAY_VERSION;
        if let Err(e) = write(p, &doc) {
            tracing::warn!(
                error = %e, path = %p.display(), section = section.as_str(),
                "failed to persist config overlay (section reset)"
            );
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
    /// The `root` section (1.5.0 full-config coverage): API-set single-value config overrides
    /// (`listen`/`tls`/`rate_card`/`store`/`security`/`limits`/…). `None` = no root override (base
    /// `config.yaml` stands). Applied at the `DeployCfg` level BEFORE `resolve` — see
    /// `RootSettings::apply_to_deploy`. No tombstones: a single-value field is present-or-absent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) root: Option<RootSettings>,
}

impl OverlayDoc {
    /// Wipe ONE section's entries + tombstones in place (the pure core of a per-section reset). The
    /// remaining section is untouched, so merging this doc onto a freshly-resolved base config reverts
    /// exactly the cleared section to `config.yaml` truth while the other section's overlay stays live.
    pub(crate) fn clear_section(&mut self, section: OverlaySection) {
        match section {
            OverlaySection::Hooks => {
                self.hooks.clear();
                self.global_hooks.clear();
                self.deleted.clear();
            }
            OverlaySection::Groups => {
                self.groups.clear();
                self.deleted_groups.clear();
            }
            OverlaySection::Root => {
                self.root = None;
            }
        }
    }

    /// Whether a section carries NO overlay state (no API-applied entries AND no tombstones) — so a
    /// reset of it is a clean no-op (the effective config already equals base for that section). Drives
    /// the idempotent-success short-circuit: resetting an untouched section changes nothing and must
    /// not bump the config version or re-run the boot pipeline.
    pub(crate) fn section_is_empty(&self, section: OverlaySection) -> bool {
        match section {
            OverlaySection::Hooks => {
                self.hooks.is_empty() && self.global_hooks.is_empty() && self.deleted.is_empty()
            }
            OverlaySection::Groups => self.groups.is_empty() && self.deleted_groups.is_empty(),
            OverlaySection::Root => self.root.as_ref().is_none_or(RootSettings::is_empty),
        }
    }
}

/// Read the overlay at `path`, or `None` if it is absent, unreadable, or malformed. Fail-soft: a
/// corrupt overlay must NEVER brick boot — busbar starts on base config alone and the operator can
/// re-apply. Unlike the old silent-soft read, a present-but-corrupt overlay is now logged LOUD at
/// boot: silently starting on base config alone drops every API-applied hook AND group with no signal,
/// which is exactly the failure that hides overlay corruption.
pub(crate) fn read(path: &Path) -> Option<OverlayDoc> {
    match read_state(path) {
        OverlayReadState::Absent => None,
        OverlayReadState::Loaded(doc) => Some(*doc),
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
    // Boxed: `OverlayDoc` grew a large `root` section (1.5.0 full-config coverage), so an inline
    // variant would make the whole enum ~1 KiB regardless of the `Absent`/`Unreadable` common case
    // (clippy `large_enum_variant`). The box keeps the enum pointer-sized.
    Loaded(Box<OverlayDoc>),
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

/// Apply the overlay's `root` section (the single-value config overrides) to a base `DeployCfg`
/// BEFORE `resolve` — the pre-resolve half of the boot-merge. The hooks + groups sections merge
/// POST-resolve (`merge_into`, the runtime registry is synthesized in `resolve`); the root section is
/// DeployCfg-level input, so the limits projection + the exposed-admin-mTLS boot-guard re-run over
/// the merged shape. A no-op when the overlay carries no root override. Kept a free fn (not folded
/// into `merge_into`) precisely because it operates on a DIFFERENT input (DeployCfg, not RootCfg) at
/// a DIFFERENT pipeline stage.
pub(crate) fn apply_root_to_deploy(deploy: &mut DeployCfg, doc: &OverlayDoc) {
    if let Some(root) = &doc.root {
        root.apply_to_deploy(deploy);
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
            "kind": "gate", "plugin": "test-hook", "prompt": "rw", "global": true
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

    /// `OverlaySection::parse` is the ONE valid-name gate: `groups`/`hooks` round-trip, everything
    /// else is `None` (the reset endpoint 400s on it).
    #[test]
    fn overlay_section_parse_round_trips_and_rejects() {
        assert_eq!(
            OverlaySection::parse("groups"),
            Some(OverlaySection::Groups)
        );
        assert_eq!(OverlaySection::parse("hooks"), Some(OverlaySection::Hooks));
        assert_eq!(OverlaySection::parse("root"), Some(OverlaySection::Root));
        assert_eq!(OverlaySection::Groups.as_str(), "groups");
        assert_eq!(OverlaySection::Hooks.as_str(), "hooks");
        assert_eq!(OverlaySection::Root.as_str(), "root");
        for bad in ["", "Groups", "hook", "auth", "plugins", "groups/", "Root"] {
            assert!(
                OverlaySection::parse(bad).is_none(),
                "`{bad}` is not a section"
            );
        }
    }

    /// `clear_section(Groups)` wipes the groups entries + tombstones and leaves the hooks section
    /// (and its tombstones) untouched — the per-section reset invariant.
    #[test]
    fn clear_section_wipes_one_section_only() {
        let mut doc = OverlayDoc {
            hooks: HashMap::from([("h".to_string(), gate())]),
            global_hooks: vec!["h".to_string()],
            deleted: vec!["gonehook".to_string()],
            groups: BTreeMap::from([("user:alice".to_string(), group_with_budget())]),
            deleted_groups: vec!["gonegroup".to_string()],
            ..Default::default()
        };
        doc.clear_section(OverlaySection::Groups);
        assert!(doc.groups.is_empty(), "groups entries cleared");
        assert!(doc.deleted_groups.is_empty(), "group tombstones cleared");
        assert!(doc.hooks.contains_key("h"), "hooks section preserved");
        assert_eq!(
            doc.global_hooks,
            vec!["h".to_string()],
            "global wiring preserved"
        );
        assert_eq!(
            doc.deleted,
            vec!["gonehook".to_string()],
            "hook tombstones preserved"
        );
        // And the symmetric case.
        doc.clear_section(OverlaySection::Hooks);
        assert!(doc.hooks.is_empty() && doc.global_hooks.is_empty() && doc.deleted.is_empty());
    }

    /// `section_is_empty` is true only when a section carries neither entries nor tombstones — the
    /// idempotent-no-op predicate the reset handler short-circuits on.
    #[test]
    fn section_is_empty_tracks_entries_and_tombstones() {
        let empty = OverlayDoc::default();
        assert!(empty.section_is_empty(OverlaySection::Groups));
        assert!(empty.section_is_empty(OverlaySection::Hooks));
        // A lone tombstone (no live entry) still counts as non-empty (a base deletion to revert).
        let tombstoned = OverlayDoc {
            deleted_groups: vec!["x".to_string()],
            deleted: vec!["y".to_string()],
            ..Default::default()
        };
        assert!(!tombstoned.section_is_empty(OverlaySection::Groups));
        assert!(!tombstoned.section_is_empty(OverlaySection::Hooks));
    }

    /// The DURABLE half of a reset: `clear_section` on disk wipes one section + preserves the other,
    /// exactly like the read-modify-write persist paths. Guards "reset drops the sibling section".
    #[test]
    fn clear_section_persist_preserves_sibling() {
        let dir = std::env::temp_dir();
        let path = dir.join(format!("busbar-ovl-clearsect-{}.json", std::process::id()));
        write(
            &path,
            &OverlayDoc {
                hooks: HashMap::from([("keepme".to_string(), gate())]),
                deleted: vec!["keephook_tomb".to_string()],
                groups: BTreeMap::from([("user:zap".to_string(), group_with_budget())]),
                deleted_groups: vec!["zap_tomb".to_string()],
                ..Default::default()
            },
        )
        .unwrap();
        clear_section(Some(&path), OverlaySection::Groups);
        let doc = read(&path).expect("read back");
        assert!(
            doc.groups.is_empty() && doc.deleted_groups.is_empty(),
            "groups reset on disk"
        );
        assert!(
            doc.hooks.contains_key("keepme"),
            "hooks entries survive the groups reset"
        );
        assert_eq!(
            doc.deleted,
            vec!["keephook_tomb".to_string()],
            "hook tombstones survive"
        );
        assert_eq!(doc.version, OVERLAY_VERSION, "schema version stamped");
        let _ = std::fs::remove_file(&path);
    }

    /// A section reset must REFUSE to overwrite a present-but-corrupt overlay (clearing it would drop
    /// the sibling section's tombstones), mirroring the persist paths' fail-closed posture.
    #[test]
    fn clear_section_refuses_to_overwrite_corrupt_overlay() {
        let dir = std::env::temp_dir();
        let path = dir.join(format!(
            "busbar-ovl-clearcorrupt-{}.json",
            std::process::id()
        ));
        let corrupt = b"{ not valid json hiding tombstones";
        std::fs::write(&path, corrupt).unwrap();
        clear_section(Some(&path), OverlaySection::Groups);
        let raw = std::fs::read(&path).expect("still present");
        assert_eq!(
            raw, corrupt,
            "a corrupt overlay is preserved verbatim, never clobbered"
        );
        let _ = std::fs::remove_file(&path);
    }

    // ── ROOT section (1.5.0 full-config coverage) ─────────────────────────────────────────────

    /// A minimal base `DeployCfg` (all uncovered sections at their defaults) to apply root overrides
    /// onto. Uses the real YAML parse path so the defaults match production exactly.
    fn minimal_deploy() -> DeployCfg {
        serde_yaml::from_str("providers: {}\nmodels: {}\n").expect("minimal deploy parses")
    }

    /// A `RootSettings` naming a couple of overrides, parsed from JSON exactly as the API body would.
    fn sample_root() -> RootSettings {
        serde_json::from_value(serde_json::json!({
            "listen": "0.0.0.0:9000",
            "per_request_fee": 7,
            "rate_card": { "m0": { "input_utok": 1.5, "output_utok": 2.0 } },
            "limits": { "max_inbound_concurrent": 512 }
        }))
        .expect("root settings parse")
    }

    /// `apply_to_deploy` overwrites ONLY the named fields; unset fields keep base values.
    #[test]
    fn root_apply_overwrites_only_named_fields() {
        let mut deploy = minimal_deploy();
        let base_admin_listen = deploy.admin_listen.clone();
        sample_root().apply_to_deploy(&mut deploy);
        assert_eq!(deploy.listen, "0.0.0.0:9000", "listen overridden");
        assert_eq!(deploy.per_request_fee, 7, "fee overridden");
        assert_eq!(
            deploy.limits.max_inbound_concurrent, 512,
            "a limits field overridden"
        );
        assert!(
            deploy
                .rate_card
                .as_ref()
                .is_some_and(|rc| rc.contains_key("m0")),
            "rate_card overridden"
        );
        assert_eq!(
            deploy.admin_listen, base_admin_listen,
            "an unset field keeps its base value"
        );
    }

    /// `is_empty` / `section_is_empty(Root)` track whether any override is set.
    #[test]
    fn root_is_empty_tracks_overrides() {
        assert!(RootSettings::default().is_empty());
        assert!(OverlayDoc::default().section_is_empty(OverlaySection::Root));
        let doc = OverlayDoc {
            root: Some(sample_root()),
            ..Default::default()
        };
        assert!(!doc.section_is_empty(OverlaySection::Root));
        // A root override does not make hooks/groups non-empty (independent sections).
        assert!(doc.section_is_empty(OverlaySection::Hooks));
        assert!(doc.section_is_empty(OverlaySection::Groups));
    }

    /// `persist_root` round-trips the root section AND preserves the hooks + groups sections; storing
    /// an empty `RootSettings` clears the section back to `None`.
    #[test]
    fn persist_root_round_trips_and_preserves_siblings() {
        let dir = std::env::temp_dir();
        let path = dir.join(format!("busbar-ovl-root-{}.json", std::process::id()));
        write(
            &path,
            &OverlayDoc {
                hooks: HashMap::from([("keepme".to_string(), gate())]),
                groups: BTreeMap::from([("user:z".to_string(), group_with_budget())]),
                deleted_groups: vec!["oldteam".to_string()],
                ..Default::default()
            },
        )
        .unwrap();
        persist_root(Some(&path), &sample_root());
        let doc = read(&path).expect("read back");
        assert!(
            doc.root
                .as_ref()
                .is_some_and(|r| r.per_request_fee == Some(7)),
            "root section written"
        );
        assert!(doc.hooks.contains_key("keepme"), "hooks preserved");
        assert!(doc.groups.contains_key("user:z"), "groups preserved");
        assert_eq!(
            doc.deleted_groups,
            vec!["oldteam".to_string()],
            "group tombstones preserved"
        );
        // Storing an empty root clears the section.
        persist_root(Some(&path), &RootSettings::default());
        let doc = read(&path).expect("read back after clear");
        assert!(doc.root.is_none(), "empty root clears the section");
        assert!(doc.hooks.contains_key("keepme"), "hooks still preserved");
        let _ = std::fs::remove_file(&path);
    }

    /// `clear_section(Root)` wipes only the root override; the hooks/groups sections survive. And the
    /// on-disk `clear_section` refuses a corrupt overlay (fail-closed, like the sibling sections).
    #[test]
    fn clear_root_section_only() {
        let mut doc = OverlayDoc {
            hooks: HashMap::from([("h".to_string(), gate())]),
            root: Some(sample_root()),
            ..Default::default()
        };
        doc.clear_section(OverlaySection::Root);
        assert!(doc.root.is_none(), "root cleared");
        assert!(doc.hooks.contains_key("h"), "hooks preserved");
    }

    /// `apply_root_to_deploy` is a no-op when the overlay has no root override, and applies it when
    /// present — the pre-resolve boot-merge half.
    #[test]
    fn apply_root_to_deploy_noop_and_active() {
        let mut deploy = minimal_deploy();
        apply_root_to_deploy(&mut deploy, &OverlayDoc::default());
        assert_eq!(
            deploy.per_request_fee, 0,
            "no root override → base unchanged"
        );
        let doc = OverlayDoc {
            root: Some(sample_root()),
            ..Default::default()
        };
        apply_root_to_deploy(&mut deploy, &doc);
        assert_eq!(deploy.per_request_fee, 7, "root override applied");
    }

    /// An unknown key in a root-settings body is a loud reject (`deny_unknown_fields`), never a silent
    /// no-op — the same fail-closed posture as the DeployCfg surface.
    #[test]
    fn root_settings_rejects_unknown_field() {
        let r: Result<RootSettings, _> =
            serde_json::from_value(serde_json::json!({ "lissten": "0.0.0.0:9000" }));
        assert!(r.is_err(), "a typo'd root field is rejected");
    }
}
