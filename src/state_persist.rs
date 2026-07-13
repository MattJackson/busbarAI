// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! HEALTH-STATE PERSISTENCE (D3): restart forgets nothing.
//!
//! Busbar's learned reliability state — circuit breakers, cooldown deadlines, latency EWMAs,
//! hard-down latches — plus the admin audit log and the config version history are snapshotted to
//! ONE state file (~every 30s and on graceful shutdown) and restored at boot. Combined with the
//! stable-lane-identity keying (D1), a restart — including an UPGRADE — costs sub-second downtime
//! and zero amnesia, which is what makes "fix the config and restart" the recovery path (D3: no
//! break-glass endpoints exist).
//!
//! The file is a single JSON document written temp-then-atomic-rename (never a torn read), owned
//! by busbar, fail-soft in every direction: unreadable/corrupt/stale at boot ⇒ start fresh with a
//! loud log; unwritable at runtime ⇒ persistence disables itself with a loud log. It contains NO
//! secrets (health metrics, audit metadata, hook definitions).
//!
//! Path resolution: `BUSBAR_STATE_FILE=/path` overrides; empty string disables; unset defaults to
//! `busbar-state.json` next to config.yaml (and disables, loudly, when there is no config path —
//! ephemeral/test mode).

use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

/// One persisted process state: everything a restart would otherwise forget.
#[derive(Serialize, Deserialize)]
pub(crate) struct PersistedState {
    /// Unix seconds when this snapshot was written (staleness gate at restore).
    pub(crate) written_at: u64,
    /// Per-lane health, keyed by stable identity (D1).
    pub(crate) health: Vec<crate::store::LaneHealthSnapshot>,
    /// The admin audit ring (hash chain intact — restored verbatim, resumed after max seq).
    pub(crate) audit: Vec<crate::admin::audit::AuditEntry>,
    /// The config version history, WITH snapshots (rollback works across restarts).
    pub(crate) versions: Vec<crate::admin::versions::PersistedVersion>,
}

/// Snapshots older than this are dropped whole at restore: a week-old picture of provider health
/// is noise, and every cooldown/window inside it long expired. (Fresh restarts — the actual use
/// case — are seconds old.)
const MAX_SNAPSHOT_AGE_SECS: u64 = 7 * 24 * 3600;

/// Resolve the state-file path: env override / explicit disable / default-next-to-config.
pub(crate) fn resolve_path(config_path: Option<&Path>) -> Option<PathBuf> {
    match std::env::var("BUSBAR_STATE_FILE") {
        Ok(v) if v.is_empty() => None, // explicit opt-out
        Ok(v) => Some(PathBuf::from(v)),
        Err(_) => config_path.map(|p| p.with_file_name("busbar-state.json")),
    }
}

/// Write the snapshot atomically (temp + rename). Errors are RETURNED (the caller logs once and
/// may disable the loop) — persistence must never take busbar down.
pub(crate) fn write(path: &Path, state: &PersistedState) -> Result<(), String> {
    let bytes = serde_json::to_vec(state).map_err(|e| format!("serialize state: {e}"))?;
    let tmp = path.with_extension("json.tmp");
    std::fs::write(&tmp, &bytes).map_err(|e| format!("write {}: {e}", tmp.display()))?;
    std::fs::rename(&tmp, path).map_err(|e| format!("rename to {}: {e}", path.display()))?;
    Ok(())
}

/// Read + staleness-gate a snapshot. `None` = no file / unreadable / corrupt / too old — every
/// case logs and boots fresh (fail-soft; a bad state file can never brick startup).
pub(crate) fn read(path: &Path, now: u64) -> Option<PersistedState> {
    let bytes = match std::fs::read(path) {
        Ok(b) => b,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return None,
        Err(e) => {
            tracing::warn!(path = %path.display(), error = %e, "state file unreadable; booting fresh");
            return None;
        }
    };
    let state: PersistedState = match serde_json::from_slice(&bytes) {
        Ok(s) => s,
        Err(e) => {
            tracing::warn!(path = %path.display(), error = %e, "state file corrupt; booting fresh");
            return None;
        }
    };
    if now.saturating_sub(state.written_at) > MAX_SNAPSHOT_AGE_SECS {
        tracing::warn!(
            path = %path.display(),
            age_secs = now.saturating_sub(state.written_at),
            "state file too old; booting fresh"
        );
        return None;
    }
    Some(state)
}

/// Capture the current process state from a live `App`.
pub(crate) fn capture(app: &crate::state::App) -> PersistedState {
    PersistedState {
        written_at: crate::store::now(),
        health: app.store.export_health(),
        audit: crate::admin::audit::AUDIT.export(),
        versions: app.versions.export(),
    }
}

/// The periodic snapshotter: every ~30s capture + write. Spawned by main after boot; reads the
/// CURRENT app through the handle so it follows config swaps. Self-disables (loudly, once) if the
/// path stops being writable.
pub(crate) fn spawn_snapshotter(handle: std::sync::Arc<crate::state::AppHandle>, path: PathBuf) {
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(std::time::Duration::from_secs(30));
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        // The first tick fires immediately: an early snapshot exists even for short-lived runs.
        loop {
            tick.tick().await;
            let app = handle.load();
            if let Err(e) = write(&path, &capture(&app)) {
                tracing::warn!(path = %path.display(), error = %e,
                    "state snapshot failed; persistence disabled for this run");
                return;
            }
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    /// write → read round-trips; staleness gate drops old snapshots; corrupt files boot fresh.
    #[test]
    fn roundtrip_staleness_and_corruption() {
        let dir = std::env::temp_dir().join(format!("busbar-persist-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("busbar-state.json");

        let state = PersistedState {
            written_at: 1_000_000,
            health: vec![],
            audit: vec![],
            versions: vec![],
        };
        write(&path, &state).expect("write");
        let got = read(&path, 1_000_100).expect("fresh snapshot restores");
        assert_eq!(got.written_at, 1_000_000);

        // Too old: dropped whole.
        assert!(
            read(&path, 1_000_000 + MAX_SNAPSHOT_AGE_SECS + 1).is_none(),
            "stale snapshot must boot fresh"
        );

        // Corrupt: fail-soft.
        std::fs::write(&path, b"{not json").unwrap();
        assert!(read(&path, 1_000_100).is_none(), "corrupt file boots fresh");

        // Missing: silent None.
        std::fs::remove_file(&path).unwrap();
        assert!(read(&path, 1_000_100).is_none());
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The full D3 restart cycle at module level: capture a live app's state (tripped lane +
    /// audit + versions), write, read back, restore into a FRESH app — the trip, the audit chain,
    /// and the version history all survive.
    #[test]
    fn capture_write_read_restore_cycle() {
        let dir = std::env::temp_dir().join(format!("busbar-cycle-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("busbar-state.json");

        let app_a = crate::test_support::TestApp::new()
            .lane(crate::test_support::LaneSpec::new(
                "m0",
                crate::proto::Protocol::anthropic(),
                "http://127.0.0.1:1/",
            ))
            .pool("p", &[(0, 1)])
            .build();
        app_a.store.record_hard_down(0, "down before restart");
        app_a.versions.record(
            7,
            "admin",
            "hook.register hook:x",
            &app_a.hook_registry,
            &[],
        );
        write(&path, &capture(&app_a)).expect("snapshot");

        // "Reboot": a fresh app with the same lane identity restores the snapshot.
        let app_b = crate::test_support::TestApp::new()
            .lane(crate::test_support::LaneSpec::new(
                "m0",
                crate::proto::Protocol::anthropic(),
                "http://127.0.0.1:1/",
            ))
            .pool("p", &[(0, 1)])
            .build();
        let persisted = read(&path, crate::store::now()).expect("readable + fresh");
        app_b.store.restore_health(&persisted.health);
        app_b.versions.load(persisted.versions);
        // (The AUDIT global is deliberately NOT loaded here — process-global, and tests share it.)

        let restored = &app_b.store.export_health()[0];
        assert_eq!(restored.dead_reason, "down before restart");
        assert!(
            app_b.versions.get(7).is_some(),
            "version history survives the restart"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Path resolution: env override wins, empty disables, default rides next to config.yaml.
    #[test]
    fn path_resolution_rules() {
        // (env manipulation avoided — parallel-test hazard; the unset-env branches are pure.)
        let cfg = std::path::Path::new("/etc/busbar/config.yaml");
        if std::env::var("BUSBAR_STATE_FILE").is_err() {
            assert_eq!(
                resolve_path(Some(cfg)),
                Some(std::path::PathBuf::from("/etc/busbar/busbar-state.json"))
            );
            assert_eq!(resolve_path(None), None, "no config path = disabled");
        }
    }
}
