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
/// outcome | principal)`, and `prev_hash` is the preceding entry's `hash`. Recomputing the chain detects any
/// altered/reordered/deleted entry (detection, not prevention — a compromised host can still rewrite
/// the whole chain; prevention is shipping the log off-box to a SIEM).
#[derive(Debug, Clone, Serialize, serde::Deserialize)]
#[cfg_attr(feature = "openapi-schema", derive(schemars::JsonSchema))]
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
    pub(crate) outcome: String,
    /// WHO — the authenticated principal id that attempted the mutation (`admin` for the operator
    /// token; a virtual-key id or an external module's principal id otherwise; `anonymous` for the
    /// explicit open admin posture). Attribution, never a credential.
    pub(crate) principal: String,
    /// The preceding entry's `hash` (empty for the first entry of the process, or the oldest retained
    /// entry whose predecessor was pruned).
    pub(crate) prev_hash: String,
    /// `sha256(prev_hash | seq | ts | action | resource | outcome | principal)` — the tamper-evidence digest.
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

/// Convert an in-memory [`AuditEntry`] to the store-seam [`busbar_api::AuditRecord`] (same fields).
/// The store persists records verbatim — the hash chain is computed here, in the engine.
fn to_record(e: &AuditEntry) -> busbar_api::AuditRecord {
    busbar_api::AuditRecord {
        seq: e.seq,
        ts: e.ts,
        action: e.action.clone(),
        resource: e.resource.clone(),
        outcome: e.outcome.clone(),
        principal: e.principal.clone(),
        prev_hash: e.prev_hash.clone(),
        hash: e.hash.clone(),
    }
}

/// Convert a store-seam [`busbar_api::AuditRecord`] back to an in-memory [`AuditEntry`].
fn from_record(r: busbar_api::AuditRecord) -> AuditEntry {
    AuditEntry {
        seq: r.seq,
        ts: r.ts,
        action: r.action,
        resource: r.resource,
        outcome: r.outcome,
        principal: r.principal,
        prev_hash: r.prev_hash,
        hash: r.hash,
    }
}

/// The in-memory audit ring. `record` is append-only + bounded (FIFO prune of the oldest — a hot
/// cache of the recent tail); `list` returns most-recent-first. When a DURABLE store sink is attached
/// (governance.store: sqlite/postgres/redis), each appended entry is ALSO write-through-persisted to
/// the store, which keeps the FULL history (never pruned) — so the ring's size bound bounds RAM, not
/// history, and a hard crash loses ~0 entries instead of up to a snapshot interval. With the RAM
/// default (`store: memory`) no sink is attached and the log stays ephemeral, exactly as before.
/// Interior-mutable so it can be a shared global.
pub(crate) struct AuditLog {
    entries: std::sync::Mutex<std::collections::VecDeque<AuditEntry>>,
    seq: std::sync::atomic::AtomicU64,
    /// The durable sink, attached once at boot when a durable store is configured. Best-effort: a
    /// write-through failure logs a warning but NEVER fails the admin mutation (the RAM ring still
    /// holds the entry; the periodic state snapshot is a second safety net). `None` = ephemeral.
    sink: std::sync::Mutex<Option<std::sync::Arc<dyn busbar_api::Store>>>,
}

impl AuditLog {
    const fn new() -> Self {
        Self {
            entries: std::sync::Mutex::new(std::collections::VecDeque::new()),
            seq: std::sync::atomic::AtomicU64::new(1),
            sink: std::sync::Mutex::new(None),
        }
    }

    /// Attach the durable store sink (boot only). The last set wins. Passing a store whose
    /// `list_audit`/`append_audit` are the trait defaults (no durable audit — the memory store or an
    /// old plugin) is harmless: write-throughs no-op and restore reads nothing.
    pub(crate) fn set_sink(&self, store: std::sync::Arc<dyn busbar_api::Store>) {
        *self.sink.lock().unwrap_or_else(|e| e.into_inner()) = Some(store);
    }

    /// Restore the ring FROM the durable store at boot (the store is the source of truth when one is
    /// configured): load every persisted record, verify the hash chain, seed the ring (bounded to the
    /// most recent `MAX_AUDIT_ENTRIES` for the hot read path), and resume the sequence after the
    /// highest restored seq. Returns `Ok(count)` restored (0 = nothing to restore / no durable audit),
    /// or `Err` if the chain fails verification (a tamper signal — the caller logs it and falls back to
    /// the file snapshot).
    pub(crate) fn restore_from_store(
        &self,
        store: &dyn busbar_api::Store,
    ) -> Result<usize, String> {
        let records = store
            .list_audit()
            .map_err(|e| format!("audit restore read failed: {}", e.0))?;
        if records.is_empty() {
            return Ok(0);
        }
        let entries: Vec<AuditEntry> = records.into_iter().map(from_record).collect();
        // Verify the full restored chain BEFORE trusting it (tamper-evidence across restart): every
        // entry's digest recomputes, and each links to its predecessor. The first restored entry's
        // predecessor may pre-date what we hold, so only its self-digest is checked.
        let mut prev: Option<&str> = None;
        for e in &entries {
            if e.hash != e.compute_hash() {
                return Err(format!(
                    "restored audit entry seq {} fails its digest",
                    e.seq
                ));
            }
            if let Some(p) = prev {
                if e.prev_hash != p {
                    return Err(format!(
                        "restored audit chain breaks at seq {} (prev_hash mismatch)",
                        e.seq
                    ));
                }
            }
            prev = Some(&e.hash);
        }
        let total = entries.len();
        let max_seq = entries.iter().map(|e| e.seq).max().unwrap_or(0);
        // Seed the ring with the most-recent MAX_AUDIT_ENTRIES (the durable store keeps the rest).
        let tail_start = total.saturating_sub(MAX_AUDIT_ENTRIES);
        let mut q = self.entries.lock().unwrap_or_else(|e| e.into_inner());
        q.clear();
        q.extend(entries.into_iter().skip(tail_start));
        self.seq
            .store(max_seq + 1, std::sync::atomic::Ordering::Relaxed);
        Ok(total)
    }

    /// Record one mutation attempt. Never fails (a poisoned lock is recovered — losing the audit log
    /// to a panic would be worse than proceeding). Bounded RAM ring: prunes the oldest past the cap
    /// (the durable sink, when present, keeps the pruned tail). WITH principal attribution (§6.7:
    /// every mutation, success AND failure, attributed to WHO attempted it).
    pub(crate) fn record_by(
        &self,
        action: &str,
        resource: &str,
        outcome: &'static str,
        principal: &str,
    ) {
        // Allocate `seq` INSIDE the entries lock so it matches insertion order: fetching it before
        // the lock let two concurrent recorders interleave (thread B takes the lock with the higher
        // seq and pushes first, thread A pushes its lower seq behind it), producing out-of-order
        // seq numbers in the ring. Under the lock, Relaxed is sufficient (the mutex is the ordering
        // point).
        let record = {
            let mut q = self.entries.lock().unwrap_or_else(|e| e.into_inner());
            let seq = self.seq.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            // Chain to the most recent entry (the back), before any prune.
            let prev_hash = q.back().map(|e| e.hash.clone()).unwrap_or_default();
            let mut entry = AuditEntry {
                seq,
                ts: crate::store::now(),
                action: action.to_string(),
                resource: resource.to_string(),
                outcome: outcome.to_string(),
                principal: principal.to_string(),
                prev_hash,
                hash: String::new(),
            };
            entry.hash = entry.compute_hash();
            while q.len() >= MAX_AUDIT_ENTRIES {
                q.pop_front();
            }
            // Snapshot the store-seam record while the seq/chain are fixed, for the write-through
            // below (done OUTSIDE the entries lock so a slow store never blocks other recorders).
            let record = to_record(&entry);
            q.push_back(entry);
            record
        };
        // Write-through to the durable sink (best-effort): the store keeps the FULL history so a hard
        // crash loses ~0 entries and pruning the RAM ring never loses durable history. A failure is
        // logged once and swallowed — an audit-store hiccup must NEVER fail the admin mutation it
        // records (the RAM ring already holds it, and the periodic snapshot is a second net). No sink
        // (memory default) ⇒ no-op, ephemeral as before.
        let sink = self.sink.lock().unwrap_or_else(|e| e.into_inner()).clone();
        if let Some(store) = sink {
            if let Err(e) = store.append_audit(&record) {
                tracing::warn!(
                    seq = record.seq,
                    action = %record.action,
                    error = %e.0,
                    "durable audit write-through failed (entry retained in the in-memory ring + state snapshot)"
                );
            }
        }
    }

    /// Export the retained ring, oldest first — the persistence snapshotter's input (D3).
    pub(crate) fn export(&self) -> Vec<AuditEntry> {
        let q = self.entries.lock().unwrap_or_else(|e| e.into_inner());
        q.iter().cloned().collect()
    }

    /// Seed the ring from a persisted snapshot (boot restore). Replaces the current contents and
    /// resumes the sequence AFTER the highest restored seq, so post-restart entries chain onto the
    /// restored history without seq reuse.
    pub(crate) fn load(&self, entries: Vec<AuditEntry>) {
        let mut q = self.entries.lock().unwrap_or_else(|e| e.into_inner());
        let max_seq = entries.iter().map(|e| e.seq).max().unwrap_or(0);
        q.clear();
        q.extend(entries);
        self.seq
            .store(max_seq + 1, std::sync::atomic::Ordering::Relaxed);
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

    /// A page of entries newest-first, optionally filtered by exact `action` and/or `resource`
    /// (design-admin-api-v1 §2.5): skip `offset`, then take `limit`. `None` filters match everything.
    /// The transport fetches `limit + 1` to detect whether a further page exists (the cursor envelope).
    pub(crate) fn list_filtered(
        &self,
        offset: usize,
        limit: usize,
        action: Option<&str>,
        resource: Option<&str>,
    ) -> Vec<AuditEntry> {
        let q = self.entries.lock().unwrap_or_else(|e| e.into_inner());
        q.iter()
            .rev()
            .filter(|e| action.is_none_or(|a| e.action == a))
            .filter(|e| resource.is_none_or(|r| e.resource == r))
            .skip(offset)
            .take(limit)
            .cloned()
            .collect()
    }

    /// The most-recent `limit` entries, newest first (unfiltered).
    #[cfg(test)]
    pub(crate) fn list(&self, limit: usize) -> Vec<AuditEntry> {
        self.list_filtered(0, limit, None, None)
    }
}

/// The process-wide admin audit log. Const-constructed, so no lazy init needed.
pub(crate) static AUDIT: AuditLog = AuditLog::new();

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn export_load_roundtrip_resumes_chain() {
        let log = AuditLog::new();
        log.record_by("hook.register", "hook:a", OUTCOME_APPLIED, "admin");
        log.record_by("hook.delete", "hook:a", OUTCOME_REJECTED, "admin");
        let exported = log.export();
        assert_eq!(exported.len(), 2);

        // Restore into a fresh log (a fresh boot): chain intact, sequence resumes AFTER max seq.
        let restored = AuditLog::new();
        restored.load(exported);
        assert!(restored.verify(), "restored chain must verify");
        restored.record_by("hook.register", "hook:b", OUTCOME_APPLIED, "admin");
        let all = restored.list(10);
        assert_eq!(all.len(), 3);
        assert!(
            all[0].seq > all[1].seq,
            "post-restore entries continue the sequence"
        );
        assert!(
            restored.verify(),
            "chain still verifies across the restore boundary"
        );
    }

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

    // ── durable audit through the configured Store (#17) ─────────────────────────────────────────

    use busbar_api::Store;
    use std::sync::Arc;

    /// WRITE-THROUGH + RESTORE across a simulated restart, over the REAL SQLite store. A first process
    /// records N mutations with the store attached as the sink (each write-through persisted); a fresh
    /// process (fresh `AuditLog`, SAME store) restores from it — the chain verifies, the entries are
    /// intact, and the sequence resumes after the max restored seq. This is the durable roundtrip.
    #[test]
    fn durable_write_through_and_restore_roundtrip() {
        let store: Arc<dyn Store> =
            Arc::new(busbar_store_sqlite::SqliteStore::open_in_memory().unwrap());

        // Process 1: record through the sink.
        let log1 = AuditLog::new();
        log1.set_sink(store.clone());
        log1.record_by("hook.register", "hook:a", OUTCOME_APPLIED, "admin");
        log1.record_by("plugin.install", "plugin:x", OUTCOME_APPLIED, "admin");
        log1.record_by("hook.delete", "hook:a", OUTCOME_REJECTED, "admin");

        // The store durably holds all three, in order, with the chain intact.
        let persisted = store.list_audit().unwrap();
        assert_eq!(persisted.len(), 3);
        assert_eq!(persisted[0].seq, 1);
        assert_eq!(persisted[2].action, "hook.delete");

        // Process 2 (a "restart"): a fresh log restores FROM the store.
        let log2 = AuditLog::new();
        let n = log2
            .restore_from_store(store.as_ref())
            .expect("restore + chain verify");
        assert_eq!(n, 3, "all three durable entries restored");
        assert!(log2.verify(), "restored chain verifies across the restart");

        // Sequence resumes AFTER the max restored seq: a new entry chains onto the restored tail.
        log2.set_sink(store.clone());
        log2.record_by("hook.register", "hook:b", OUTCOME_APPLIED, "admin");
        let all = log2.list(10);
        assert_eq!(all[0].action, "hook.register");
        assert!(all[0].seq > 3, "post-restore seq continues (> 3)");
        assert!(
            log2.verify(),
            "chain still verifies after the post-restore append"
        );
        // And the store now has 4 (the write-through of the post-restore entry landed).
        assert_eq!(store.list_audit().unwrap().len(), 4);
    }

    /// The RAM ring is bounded to `MAX_AUDIT_ENTRIES`, but a durable store keeps the FULL history — so
    /// recording more than the cap prunes the RAM ring WITHOUT losing durable history (the #17 fix:
    /// the size bound bounds RAM, not history). Restoring seeds the ring with the recent tail while the
    /// store retains everything.
    #[test]
    fn durable_store_keeps_history_beyond_the_ram_cap() {
        let store: Arc<dyn Store> =
            Arc::new(busbar_store_sqlite::SqliteStore::open_in_memory().unwrap());
        let log = AuditLog::new();
        log.set_sink(store.clone());
        let total = MAX_AUDIT_ENTRIES + 25;
        for i in 0..total {
            log.record_by(
                "hook.register",
                &format!("hook:{i}"),
                OUTCOME_APPLIED,
                "admin",
            );
        }
        // The RAM ring is capped…
        assert_eq!(
            log.list(usize::MAX).len(),
            MAX_AUDIT_ENTRIES,
            "the RAM ring stays bounded"
        );
        // …but the durable store kept EVERY entry (no history lost to the ring's prune).
        let persisted = store.list_audit().unwrap();
        assert_eq!(
            persisted.len(),
            total,
            "durable store keeps the full history"
        );
        assert_eq!(
            persisted[0].seq, 1,
            "the oldest entry survives in the store"
        );
        assert_eq!(persisted.last().unwrap().seq as usize, total);

        // A restart restores the recent tail into the ring and resumes the sequence past the max.
        let log2 = AuditLog::new();
        let n = log2.restore_from_store(store.as_ref()).expect("restore");
        assert_eq!(n, total, "restore reports the full durable count");
        assert_eq!(
            log2.list(usize::MAX).len(),
            MAX_AUDIT_ENTRIES,
            "the restored ring is bounded to the recent tail"
        );
        assert!(log2.verify(), "the restored tail's chain verifies");
    }

    /// A memory store (the RAM default — trait-default `append_audit`/`list_audit`) makes durable
    /// audit a no-op: nothing persists and a restore reads nothing, so the log stays ephemeral exactly
    /// as before. This proves the default posture is unchanged.
    #[test]
    fn memory_store_keeps_audit_ephemeral() {
        let store: Arc<dyn Store> = Arc::new(busbar_store_memory::MemoryStore::new());
        let log = AuditLog::new();
        log.set_sink(store.clone());
        log.record_by("hook.register", "hook:a", OUTCOME_APPLIED, "admin");
        // The memory store's default append_audit is a no-op and list_audit is empty.
        assert!(
            store.list_audit().unwrap().is_empty(),
            "memory store persists no audit"
        );
        let log2 = AuditLog::new();
        assert_eq!(
            log2.restore_from_store(store.as_ref()).unwrap(),
            0,
            "nothing to restore from an ephemeral store"
        );
    }

    /// A TAMPERED durable record is rejected on restore (tamper-evidence survives the restart): if a
    /// stored entry's field is altered without recomputing the chain, `restore_from_store` returns an
    /// error rather than silently loading a broken chain.
    #[test]
    fn restore_rejects_a_tampered_durable_chain() {
        let store: Arc<dyn Store> =
            Arc::new(busbar_store_sqlite::SqliteStore::open_in_memory().unwrap());
        let log = AuditLog::new();
        log.set_sink(store.clone());
        log.record_by("hook.register", "hook:a", OUTCOME_APPLIED, "admin");
        log.record_by("hook.delete", "hook:a", OUTCOME_APPLIED, "admin");

        // Tamper: re-write seq 1's resource in the store WITHOUT fixing its hash (append_audit upserts
        // on seq, so this overwrites the stored record in place).
        let mut rec = store
            .list_audit()
            .unwrap()
            .into_iter()
            .find(|r| r.seq == 1)
            .unwrap();
        rec.resource = "hook:evil".to_string();
        store.append_audit(&rec).unwrap();

        let fresh = AuditLog::new();
        assert!(
            fresh.restore_from_store(store.as_ref()).is_err(),
            "a tampered durable record must fail chain verification on restore"
        );
    }
}
