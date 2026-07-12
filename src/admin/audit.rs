// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The admin AUDIT log — every admin MUTATION is recorded, success AND failure (design-admin-api-v1
//! §6.7), so a credential probing the surface or an operator asking "who changed what" leaves a trail.
//!
//! This is the in-memory MVP: a bounded ring of entries behind a process-global. Audit is process-wide
//! state (NOT config-derived), so it lives as a global rather than on the swappable `App` snapshot —
//! it survives a config apply naturally. The DURABLE + hash-chained store (SQLite now, SIEM via a
//! `kind: tap` later) is an additive follow-up behind an `AuditStore` trait; the record/read shape here
//! is the stable seam it will implement.

use serde::Serialize;

/// One admin audit record. `outcome` is a stable token tooling can branch on.
#[derive(Debug, Clone, Serialize)]
pub(crate) struct AuditEntry {
    /// Monotonic sequence number (1-based), unique within a process lifetime.
    pub(crate) seq: u64,
    /// Unix seconds when the mutation was attempted.
    pub(crate) ts: u64,
    /// The action, `noun.verb` (e.g. `hook.register`, `hook.delete`).
    pub(crate) action: String,
    /// The resource acted on (e.g. `hook:compress`). Never a secret.
    pub(crate) resource: String,
    /// Stable outcome token: `applied` (mutation committed) | `rejected` (validation/conflict, nothing
    /// changed).
    pub(crate) outcome: &'static str,
}

/// Outcome tokens (kept small + stable).
pub(crate) const OUTCOME_APPLIED: &str = "applied";
pub(crate) const OUTCOME_REJECTED: &str = "rejected";

const MAX_AUDIT_ENTRIES: usize = 1000;

/// The in-memory audit ring. `record` is append-only + bounded (FIFO prune of the oldest); `list`
/// returns most-recent-first. Interior-mutable so it can be a shared global.
pub(crate) struct AuditLog {
    entries: std::sync::Mutex<std::collections::VecDeque<AuditEntry>>,
    seq: std::sync::atomic::AtomicU64,
}

impl AuditLog {
    const fn new() -> Self {
        Self {
            entries: std::sync::Mutex::new(std::collections::VecDeque::new()),
            seq: std::sync::atomic::AtomicU64::new(1),
        }
    }

    /// Record one mutation attempt. Never fails (a poisoned lock is recovered — losing the audit log
    /// to a panic would be worse than proceeding). Bounded: prunes the oldest past the cap.
    pub(crate) fn record(&self, action: &str, resource: &str, outcome: &'static str) {
        let seq = self.seq.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let entry = AuditEntry {
            seq,
            ts: crate::store::now(),
            action: action.to_string(),
            resource: resource.to_string(),
            outcome,
        };
        let mut q = self.entries.lock().unwrap_or_else(|e| e.into_inner());
        while q.len() >= MAX_AUDIT_ENTRIES {
            q.pop_front();
        }
        q.push_back(entry);
    }

    /// The most-recent `limit` entries, newest first.
    pub(crate) fn list(&self, limit: usize) -> Vec<AuditEntry> {
        let q = self.entries.lock().unwrap_or_else(|e| e.into_inner());
        q.iter().rev().take(limit).cloned().collect()
    }
}

/// The process-wide admin audit log. Const-constructed, so no lazy init needed.
pub(crate) static AUDIT: AuditLog = AuditLog::new();

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn record_and_list_newest_first() {
        let log = AuditLog::new();
        log.record("hook.register", "hook:a", OUTCOME_APPLIED);
        log.record("hook.delete", "hook:a", OUTCOME_APPLIED);
        let entries = log.list(10);
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].action, "hook.delete", "newest first");
        assert!(entries[0].seq > entries[1].seq, "monotonic seq");
    }
}
