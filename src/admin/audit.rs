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

/// One admin audit record. `outcome` is a stable token tooling can branch on. The record is
/// HASH-CHAINED for tamper-EVIDENCE (§6.7): `hash = sha256(prev_hash | seq | ts | action | resource |
/// outcome)`, and `prev_hash` is the preceding entry's `hash`. Recomputing the chain detects any
/// altered/reordered/deleted entry (detection, not prevention — a compromised host can still rewrite
/// the whole chain; prevention is shipping the log off-box to a SIEM).
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
    /// WHO — the authenticated principal id that attempted the mutation (`admin` for the operator
    /// token; a virtual-key id or an external module's principal id otherwise; `anonymous` for the
    /// explicit open admin posture). Attribution, never a credential.
    pub(crate) principal: String,
    /// The preceding entry's `hash` (empty for the first entry of the process, or the oldest retained
    /// entry whose predecessor was pruned).
    pub(crate) prev_hash: String,
    /// `sha256(prev_hash | seq | ts | action | resource | outcome)` — the tamper-evidence digest.
    pub(crate) hash: String,
}

impl AuditEntry {
    /// Recompute this entry's digest from its fields — the verification primitive.
    fn compute_hash(&self) -> String {
        let canonical = format!(
            "{}|{}|{}|{}|{}|{}|{}",
            self.prev_hash,
            self.seq,
            self.ts,
            self.action,
            self.resource,
            self.outcome,
            self.principal
        );
        crate::sigv4::sha256_hex(canonical.as_bytes())
    }
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
    /// Record one mutation attempt WITH principal attribution (§6.7: every mutation, success AND
    /// failure, attributed to WHO attempted it).
    pub(crate) fn record_by(
        &self,
        action: &str,
        resource: &str,
        outcome: &'static str,
        principal: &str,
    ) {
        let seq = self.seq.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let mut q = self.entries.lock().unwrap_or_else(|e| e.into_inner());
        // Chain to the most recent entry (the back), before any prune.
        let prev_hash = q.back().map(|e| e.hash.clone()).unwrap_or_default();
        let mut entry = AuditEntry {
            seq,
            ts: crate::store::now(),
            action: action.to_string(),
            resource: resource.to_string(),
            outcome,
            principal: principal.to_string(),
            prev_hash,
            hash: String::new(),
        };
        entry.hash = entry.compute_hash();
        while q.len() >= MAX_AUDIT_ENTRIES {
            q.pop_front();
        }
        q.push_back(entry);
    }

    /// Verify the tamper-evidence chain over the RETAINED entries: every entry's `hash` recomputes
    /// from its fields, and each entry links to its predecessor (`prev_hash == predecessor.hash`). The
    /// oldest retained entry's `prev_hash` may point to a pruned digest, so its link is not checked —
    /// only its self-digest. Returns `true` if intact. Used by the tamper test; a live tamper-alert
    /// endpoint is a follow-up.
    #[cfg(test)]
    pub(crate) fn verify(&self) -> bool {
        let q = self.entries.lock().unwrap_or_else(|e| e.into_inner());
        let mut prev: Option<&str> = None;
        for e in q.iter() {
            if e.hash != e.compute_hash() {
                return false;
            }
            if let Some(p) = prev {
                if e.prev_hash != p {
                    return false;
                }
            }
            prev = Some(&e.hash);
        }
        true
    }

    /// The most-recent `limit` entries, newest first, optionally filtered by exact `action` and/or
    /// `resource` (design-admin-api-v1 §2.5). `None` filters match everything.
    pub(crate) fn list_filtered(
        &self,
        limit: usize,
        action: Option<&str>,
        resource: Option<&str>,
    ) -> Vec<AuditEntry> {
        let q = self.entries.lock().unwrap_or_else(|e| e.into_inner());
        q.iter()
            .rev()
            .filter(|e| action.is_none_or(|a| e.action == a))
            .filter(|e| resource.is_none_or(|r| e.resource == r))
            .take(limit)
            .cloned()
            .collect()
    }

    /// The most-recent `limit` entries, newest first (unfiltered).
    #[cfg(test)]
    pub(crate) fn list(&self, limit: usize) -> Vec<AuditEntry> {
        self.list_filtered(limit, None, None)
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
        log.record_by("hook.register", "hook:a", OUTCOME_APPLIED, "admin");
        log.record_by("hook.delete", "hook:a", OUTCOME_APPLIED, "admin");
        let entries = log.list(10);
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].action, "hook.delete", "newest first");
        assert!(entries[0].seq > entries[1].seq, "monotonic seq");
    }

    #[test]
    fn hash_chain_links_and_verifies() {
        let log = AuditLog::new();
        log.record_by("hook.register", "hook:a", OUTCOME_APPLIED, "admin");
        log.record_by("hook.register", "hook:b", OUTCOME_REJECTED, "admin");
        log.record_by("hook.delete", "hook:a", OUTCOME_APPLIED, "admin");
        assert!(log.verify(), "an untouched chain verifies");

        // Each entry (oldest→newest) links to its predecessor's hash.
        let q = log.entries.lock().unwrap();
        assert_eq!(q[0].prev_hash, "", "first entry has no predecessor");
        assert_eq!(q[1].prev_hash, q[0].hash);
        assert_eq!(q[2].prev_hash, q[1].hash);
        drop(q);

        // Tamper: mutate a recorded field in place → verification fails.
        {
            let mut q = log.entries.lock().unwrap();
            q[1].resource = "hook:evil".to_string();
        }
        assert!(!log.verify(), "a tampered entry breaks the chain");
    }
}
