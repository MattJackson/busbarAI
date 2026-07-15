// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Config VERSION HISTORY — every successful config-plane mutation records the resulting
//! hook-surface snapshot, so an operator can list versions, inspect any one, diff two, and ROLL
//! BACK (design-admin-api-v1 §2.2).
//!
//! This is the in-memory MVP: a bounded ring held on `App` behind an `Arc` (the Arc is SHARED
//! across config-apply snapshots — `App::clone` clones the Arc, not the ring — so history survives
//! every swap); the durable store is an additive follow-up behind the same record/read seam. The
//! SNAPSHOT is deliberately the RESTRICT-SCOPE config surface (the hook registry + global wiring):
//! lanes/pools/auth changes desync the lane-indexed live store (the store↔lane-index constraint),
//! so v1 versioning covers exactly what v1 apply can mutate.

use serde::Serialize;
use std::collections::HashMap;

/// One recorded config version: the metadata the versions LIST shows, plus the full hook-surface
/// snapshot rollback restores. Never contains a secret (hook definitions are operator config —
/// transports, grants, deadlines).
#[derive(Clone, Serialize)]
pub(crate) struct ConfigVersion {
    /// The `App.config_version` this snapshot corresponds to (monotonic per process).
    pub(crate) version: u64,
    /// Unix seconds when the mutation committed.
    pub(crate) ts: u64,
    /// The acting principal (audit attribution, same handle as the audit log).
    pub(crate) principal: String,
    /// Human summary of the mutation that produced this version (e.g. `hook.register hook:x`).
    pub(crate) summary: String,
    /// The hook registry at this version (the rollback payload).
    #[serde(skip)]
    pub(crate) hook_registry: HashMap<String, crate::config::HookCfg>,
    /// The global wiring at this version.
    #[serde(skip)]
    pub(crate) global_hooks: Vec<String>,
}

/// Bounded version history (`max_config_versions` — the spec default 100): FIFO prune of the
/// oldest; a rollback to a pruned version is a clear error, never a guess.
const MAX_VERSIONS: usize = 100;

pub(crate) struct VersionLog {
    entries: std::sync::Mutex<std::collections::VecDeque<ConfigVersion>>,
}

impl VersionLog {
    pub(crate) fn new() -> Self {
        Self {
            entries: std::sync::Mutex::new(std::collections::VecDeque::new()),
        }
    }

    /// Record the snapshot a successful mutation produced. Never fails (poisoned lock recovered —
    /// version history must not take down a mutation that already committed).
    pub(crate) fn record(
        &self,
        version: u64,
        principal: &str,
        summary: &str,
        hook_registry: &HashMap<String, crate::config::HookCfg>,
        global_hooks: &[String],
    ) {
        let mut q = self.entries.lock().unwrap_or_else(|e| e.into_inner());
        // Idempotence guard: re-recording the same version (e.g. a retried handler) replaces
        // rather than duplicates, keeping the ring strictly monotonic.
        q.retain(|v| v.version != version);
        while q.len() >= MAX_VERSIONS {
            q.pop_front();
        }
        q.push_back(ConfigVersion {
            version,
            ts: crate::store::now(),
            principal: principal.to_string(),
            summary: summary.to_string(),
            hook_registry: hook_registry.clone(),
            global_hooks: global_hooks.to_vec(),
        });
    }

    /// A page of version metadata, most-recent-first (the LIST projection — snapshots omitted): skip
    /// `offset`, then take `limit`. The transport fetches `limit + 1` to detect a further page for the
    /// cursor envelope (design-admin-api-v1 §0.4).
    pub(crate) fn list(&self, offset: usize, limit: usize) -> Vec<ConfigVersion> {
        let q = self.entries.lock().unwrap_or_else(|e| e.into_inner());
        q.iter().rev().skip(offset).take(limit).cloned().collect()
    }

    /// One full version (with its snapshot), if retained.
    pub(crate) fn get(&self, version: u64) -> Option<ConfigVersion> {
        let q = self.entries.lock().unwrap_or_else(|e| e.into_inner());
        q.iter().find(|v| v.version == version).cloned()
    }
}

/// The PERSISTED form of a version — unlike the API list view (which `serde(skip)`s the
/// snapshots), persistence must carry them: they are what rollback restores after a restart.
#[derive(Clone, serde::Serialize, serde::Deserialize)]
pub(crate) struct PersistedVersion {
    pub(crate) version: u64,
    pub(crate) ts: u64,
    pub(crate) principal: String,
    pub(crate) summary: String,
    pub(crate) hook_registry: HashMap<String, crate::config::HookCfg>,
    pub(crate) global_hooks: Vec<String>,
}

impl VersionLog {
    /// Export the retained history, oldest first, WITH snapshots (D3 persistence input).
    pub(crate) fn export(&self) -> Vec<PersistedVersion> {
        let q = self.entries.lock().unwrap_or_else(|e| e.into_inner());
        q.iter()
            .map(|v| PersistedVersion {
                version: v.version,
                ts: v.ts,
                principal: v.principal.clone(),
                summary: v.summary.clone(),
                hook_registry: v.hook_registry.clone(),
                global_hooks: v.global_hooks.clone(),
            })
            .collect()
    }

    /// Seed the history from a persisted snapshot (boot restore), replacing current contents.
    pub(crate) fn load(&self, versions: Vec<PersistedVersion>) {
        let mut q = self.entries.lock().unwrap_or_else(|e| e.into_inner());
        q.clear();
        for v in versions {
            q.push_back(ConfigVersion {
                version: v.version,
                ts: v.ts,
                principal: v.principal,
                summary: v.summary,
                hook_registry: v.hook_registry,
                global_hooks: v.global_hooks,
            });
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn reg(names: &[&str]) -> HashMap<String, crate::config::HookCfg> {
        names
            .iter()
            .map(|n| {
                (
                    n.to_string(),
                    serde_yaml::from_str::<crate::config::HookCfg>(&format!(
                        "kind: tap\nsocket: /run/busbar/{n}.sock\n"
                    ))
                    .expect("hook parses"),
                )
            })
            .collect()
    }

    /// record → list (newest first, metadata) → get (full snapshot); re-record replaces; the ring
    /// is bounded FIFO.
    #[test]
    fn record_list_get_and_bound() {
        let log = VersionLog::new();
        log.record(1, "admin", "hook.register hook:a", &reg(&["a"]), &[]);
        log.record(2, "admin", "hook.register hook:b", &reg(&["a", "b"]), &[]);
        let listed = log.list(0, 10);
        assert_eq!(listed.len(), 2);
        assert_eq!(listed[0].version, 2, "newest first");
        assert_eq!(listed[0].principal, "admin");
        let v1 = log.get(1).expect("v1 retained");
        assert_eq!(v1.hook_registry.len(), 1);
        assert!(log.get(99).is_none(), "unknown version is None");

        // Re-record replaces (no duplicate versions).
        log.record(2, "admin", "hook.register hook:b2", &reg(&["b"]), &[]);
        assert_eq!(log.list(0, 10).len(), 2);
        assert_eq!(log.get(2).unwrap().summary, "hook.register hook:b2");

        // Bounded: MAX_VERSIONS + overflow prunes the oldest.
        for v in 3..(MAX_VERSIONS as u64 + 5) {
            log.record(v, "admin", "s", &reg(&[]), &[]);
        }
        let all = log.list(0, usize::MAX);
        assert_eq!(all.len(), MAX_VERSIONS);
        assert!(log.get(1).is_none(), "oldest pruned");
    }
}
