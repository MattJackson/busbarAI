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
    /// The highest CONTIGUOUS seq known to be durably persisted (0 = none yet). The write-through
    /// backfills from `durable_high + 1` up to each new entry's seq, so a TRANSIENT `append_audit`
    /// failure that previously left a permanent gap now heals: the next successful write-through
    /// catches up the skipped seq(s) from the RAM ring, keeping the durable hash chain CONTIGUOUS
    /// (which the strict `restore_from_store` linkage check requires). Serialized by `durable_lock`.
    durable_high: std::sync::atomic::AtomicU64,
    /// Serializes the write-through (backfill + append) so two concurrent recorders cannot interleave
    /// their catch-up writes and re-introduce a gap or write a seq out of order to the store.
    durable_lock: std::sync::Mutex<()>,
}

impl AuditLog {
    const fn new() -> Self {
        Self {
            entries: std::sync::Mutex::new(std::collections::VecDeque::new()),
            seq: std::sync::atomic::AtomicU64::new(1),
            sink: std::sync::Mutex::new(None),
            durable_high: std::sync::atomic::AtomicU64::new(0),
            durable_lock: std::sync::Mutex::new(()),
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
        // BOUNDED read (audit issue): the durable log is never pruned and can dwarf the RAM ring; over
        // the plugin ABI the full list can exceed the response cap or OOM. Restore only the most-recent
        // `MAX_AUDIT_ENTRIES` - exactly what the ring keeps - so the read is bounded regardless of how
        // large the durable history grew. The tail is the NEWEST records, so its max seq IS the durable
        // max (the seq floor below stays correct), and tamper-evidence is verified over the loaded tail
        // (internal linkage + the tail head's self-digest). `list_audit_tail` bounds at the source for a
        // durable backend and falls back to `list_audit` + truncation for an older plugin.
        let records = store
            .list_audit_tail(MAX_AUDIT_ENTRIES as u64)
            .map_err(|e| format!("audit restore read failed: {}", e.0))?;
        if records.is_empty() {
            return Ok(0);
        }
        let entries: Vec<AuditEntry> = records.into_iter().map(from_record).collect();
        // FLOOR the sequence to the store's max BEFORE verification, so even a chain-verification
        // failure (where the caller falls back to a possibly-stale file snapshot) can never leave
        // the counter rewound below what the store already holds. The durable write-through is
        // keyed on `seq`, so a rewound counter would silently OVERWRITE existing durable history on
        // the next mutation; flooring here makes new entries always append past the durable max.
        let durable_max = entries.iter().map(|e| e.seq).max().unwrap_or(0);
        self.seq
            .fetch_max(durable_max + 1, std::sync::atomic::Ordering::Relaxed);
        // Seed the durable-catch-up watermark: the store already holds a contiguous chain through
        // `durable_max`, so the write-through backfill starts appending at `durable_max + 1`.
        self.durable_high
            .fetch_max(durable_max, std::sync::atomic::Ordering::Relaxed);
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
        // Seed the ring with the most-recent MAX_AUDIT_ENTRIES (the durable store keeps the rest).
        // The sequence was already floored past the durable max above.
        let tail_start = total.saturating_sub(MAX_AUDIT_ENTRIES);
        let mut q = self.entries.lock().unwrap_or_else(|e| e.into_inner());
        q.clear();
        q.extend(entries.into_iter().skip(tail_start));
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
        // logged and swallowed - an audit-store hiccup must NEVER fail the admin mutation it records
        // (the RAM ring already holds it, and the periodic snapshot is a second net). No sink (memory
        // default) ⇒ no-op, ephemeral as before.
        let sink = self.sink.lock().unwrap_or_else(|e| e.into_inner()).clone();
        if let Some(store) = sink {
            self.durable_write_through(store.as_ref(), record.seq);
        }
    }

    /// RESILIENT durable write-through with GAP BACKFILL (audit chain-corruption fix). A TRANSIENT
    /// `append_audit` failure used to be swallowed while the mutation still succeeded, leaving a
    /// PERMANENT hole in the durable chain (seq N missing, N+1 present with `prev_hash` pointing at N):
    /// on restart the strict contiguous linkage check in [`restore_from_store`] hits the gap, rejects
    /// the whole durable chain, and the boot falls back to the stale file snapshot - silently
    /// discarding all durable audit history. This never self-heals.
    ///
    /// Instead of writing only `new_seq`, catch up the durable chain from `durable_high + 1` up TO AND
    /// INCLUDING `new_seq`, pulling each entry from the authoritative RAM ring. So a write that failed
    /// on seq N (leaving `durable_high = N-1`) is retried on the NEXT successful mutation: it appends N
    /// (from the ring) then N+1, keeping the durable chain CONTIGUOUS. Serialized by `durable_lock` so
    /// concurrent recorders can't interleave their catch-up writes. Best-effort throughout: any append
    /// error stops the catch-up, logs, and leaves `durable_high` where it is so the next mutation
    /// retries from the same point (the mutation itself never fails). If the gap is older than the ring
    /// bound (many consecutive failures), the un-recoverable seq(s) simply stay missing - the ring is
    /// the only in-process source - but a single transient hiccup can no longer corrupt the chain.
    fn durable_write_through(&self, store: &dyn busbar_api::Store, new_seq: u64) {
        let _serial = self.durable_lock.lock().unwrap_or_else(|e| e.into_inner());
        let start = self.durable_high.load(std::sync::atomic::Ordering::Relaxed) + 1;
        for seq in start..=new_seq {
            // Source the record for `seq` from the RAM ring (the authoritative in-process copy).
            let record = {
                let q = self.entries.lock().unwrap_or_else(|e| e.into_inner());
                q.iter().find(|e| e.seq == seq).map(to_record)
            };
            let Some(record) = record else {
                // `seq` has already been pruned from the ring (a gap older than the ring bound); it
                // cannot be backfilled in-process. Skip it and keep going so newer entries still land;
                // do NOT advance `durable_high` past a hole we couldn't fill.
                tracing::warn!(
                    seq,
                    "durable audit backfill: seq no longer in the RAM ring; cannot catch up this entry"
                );
                continue;
            };
            if let Err(e) = store.append_audit(&record) {
                tracing::warn!(
                    seq,
                    action = %record.action,
                    error = %e.0,
                    "durable audit write-through failed (entry retained in the in-memory ring + state \
                     snapshot; will backfill on the next successful write-through)"
                );
                // Stop the catch-up here; `durable_high` stays put so the next mutation retries from
                // this seq, keeping the durable chain contiguous once the store recovers.
                return;
            }
            self.durable_high
                .fetch_max(seq, std::sync::atomic::Ordering::Relaxed);
        }
    }

    /// Export the retained ring, oldest first — the persistence snapshotter's input (D3).
    pub(crate) fn export(&self) -> Vec<AuditEntry> {
        let q = self.entries.lock().unwrap_or_else(|e| e.into_inner());
        q.iter().cloned().collect()
    }

    /// Seed the ring from a persisted snapshot (boot restore). Replaces the current contents and
    /// resumes the sequence AFTER the highest restored seq, so post-restart entries chain onto the
    /// restored history without seq reuse. FLOOR semantics (fetch_max, never store): a file
    /// snapshot can lag the durable store, and the durable write-through is keyed on `seq` — a
    /// blind store here would rewind the counter below the store's max and the next mutation would
    /// silently OVERWRITE durable history. The snapshot only ever RAISES the counter.
    pub(crate) fn load(&self, entries: Vec<AuditEntry>) {
        let mut q = self.entries.lock().unwrap_or_else(|e| e.into_inner());
        let max_seq = entries.iter().map(|e| e.seq).max().unwrap_or(0);
        q.clear();
        q.extend(entries);
        self.seq
            .fetch_max(max_seq + 1, std::sync::atomic::Ordering::Relaxed);
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

    /// A REWOUND sequence counter must never clobber durable history. The durable write-through is
    /// keyed on `seq` (idempotent-replay upsert in the store), so if a boot path seeds the counter
    /// from a STALE file snapshot (fewer entries than the store holds — e.g. after a failed
    /// durable restore), the next mutation would reuse a durable seq and silently overwrite that
    /// entry. Both hydration paths floor instead: `restore_from_store` floors past the durable max
    /// even when chain verification fails, and `load` only ever raises the counter.
    #[test]
    fn rewound_seq_cannot_overwrite_durable_history() {
        let store: Arc<dyn Store> =
            Arc::new(busbar_store_sqlite::SqliteStore::open_in_memory().unwrap());

        // Process 1: three durable entries (seq 1..=3).
        let log1 = AuditLog::new();
        log1.set_sink(store.clone());
        log1.record_by("hook.register", "hook:a", OUTCOME_APPLIED, "admin");
        log1.record_by("hook.register", "hook:b", OUTCOME_APPLIED, "admin");
        log1.record_by("hook.delete", "hook:a", OUTCOME_APPLIED, "admin");
        assert_eq!(store.list_audit().unwrap().len(), 3);

        // Tamper the durable chain so the restart's durable restore FAILS and the boot path falls
        // back to a stale file snapshot holding only seq 1 (the rewind scenario).
        {
            let mut tampered = store.list_audit().unwrap();
            tampered[1].resource = "hook:evil".to_string();
            store.append_audit(&tampered[1]).unwrap();
        }
        let stale_snapshot: Vec<AuditEntry> = store
            .list_audit()
            .unwrap()
            .into_iter()
            .take(1)
            .map(from_record)
            .collect();

        // Process 2 (the restart): sink attached, durable restore fails on the broken chain, and
        // the stale snapshot is loaded — exactly the boot fallback ordering in main.rs.
        let log2 = AuditLog::new();
        log2.set_sink(store.clone());
        assert!(
            log2.restore_from_store(store.as_ref()).is_err(),
            "the tampered chain must fail verification"
        );
        log2.load(stale_snapshot);

        // The next mutation must APPEND past the durable max (seq 4), not reuse seq 2 and clobber
        // the existing durable entry.
        log2.record_by("hook.register", "hook:c", OUTCOME_APPLIED, "admin");
        let persisted = store.list_audit().unwrap();
        assert_eq!(persisted.len(), 4, "durable history grew; nothing replaced");
        assert_eq!(
            persisted.last().unwrap().seq,
            4,
            "the new entry appended past the durable max"
        );
        assert_eq!(
            persisted[2].action, "hook.delete",
            "the pre-existing seq-3 entry is untouched"
        );
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

        // A restart restores the recent BOUNDED tail into the ring and resumes the sequence past the
        // max. The restore read is bounded to the ring cap (audit bounded-read fix), so it reports the
        // count it LOADED - the tail - not the full (possibly huge) durable history.
        let log2 = AuditLog::new();
        let n = log2.restore_from_store(store.as_ref()).expect("restore");
        assert_eq!(
            n, MAX_AUDIT_ENTRIES,
            "restore loads (and reports) only the bounded tail"
        );
        assert_eq!(
            log2.list(usize::MAX).len(),
            MAX_AUDIT_ENTRIES,
            "the restored ring is bounded to the recent tail"
        );
        assert!(log2.verify(), "the restored tail's chain verifies");
        // The durable store still holds the FULL history - only the RESTORE READ is bounded.
        assert_eq!(
            store.list_audit().unwrap().len(),
            total,
            "the durable store keeps the full history; only the boot read is bounded"
        );
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

    // ── transient-failure durability + bounded restore ───────────────────────────────────────────

    /// A `Store` decorator over a real SQLite store that FAILS `append_audit` for a configured set of
    /// seqs (simulating a TRANSIENT durable-write hiccup), then behaves normally once those seqs are
    /// cleared. All reads delegate to the inner store. Used to prove the write-through backfill heals a
    /// gap rather than leaving the durable chain permanently corrupt.
    struct FlakyAuditStore {
        inner: busbar_store_sqlite::SqliteStore,
        fail_seqs: std::sync::Mutex<std::collections::HashSet<u64>>,
    }

    impl Store for FlakyAuditStore {
        fn put_key(&self, key: &busbar_api::VirtualKey) -> busbar_api::StoreResult<()> {
            self.inner.put_key(key)
        }
        fn get_key(&self, id: &str) -> busbar_api::StoreResult<Option<busbar_api::VirtualKey>> {
            self.inner.get_key(id)
        }
        fn list_keys(&self) -> busbar_api::StoreResult<Vec<busbar_api::VirtualKey>> {
            self.inner.list_keys()
        }
        fn delete_key(&self, id: &str) -> busbar_api::StoreResult<()> {
            self.inner.delete_key(id)
        }
        fn get_usage(
            &self,
            bucket_id: &str,
            window_start: u64,
        ) -> busbar_api::StoreResult<busbar_api::UsageLedger> {
            self.inner.get_usage(bucket_id, window_start)
        }
        fn put_usage(
            &self,
            bucket_id: &str,
            window_start: u64,
            ledger: &busbar_api::UsageLedger,
        ) -> busbar_api::StoreResult<()> {
            self.inner.put_usage(bucket_id, window_start, ledger)
        }
        fn add_metering(&self, delta: &busbar_api::MeteringDelta) -> busbar_api::StoreResult<()> {
            self.inner.add_metering(delta)
        }
        fn list_metering(
            &self,
            bucket: u64,
        ) -> busbar_api::StoreResult<Vec<busbar_api::MeteringRow>> {
            self.inner.list_metering(bucket)
        }
        fn append_audit(&self, entry: &busbar_api::AuditRecord) -> busbar_api::StoreResult<()> {
            if self.fail_seqs.lock().unwrap().contains(&entry.seq) {
                return Err(busbar_api::StoreError(format!(
                    "injected transient append_audit failure for seq {}",
                    entry.seq
                )));
            }
            self.inner.append_audit(entry)
        }
        fn list_audit(&self) -> busbar_api::StoreResult<Vec<busbar_api::AuditRecord>> {
            self.inner.list_audit()
        }
        fn list_audit_tail(
            &self,
            limit: u64,
        ) -> busbar_api::StoreResult<Vec<busbar_api::AuditRecord>> {
            self.inner.list_audit_tail(limit)
        }
    }

    /// AUDIT CHAIN-CORRUPTION FIX: a TRANSIENT `append_audit` failure must not permanently corrupt the
    /// durable chain. We fail the write-through for seq 2, so the old behavior left a permanent hole
    /// (1, _, 3, …) that fails the strict restore linkage check and discards ALL durable history. With
    /// the backfill, the next successful write-through (seq 3) catches seq 2 up from the RAM ring, so
    /// the durable chain is CONTIGUOUS and restores intact.
    #[test]
    fn transient_append_failure_is_backfilled_and_chain_survives_restart() {
        let store = std::sync::Arc::new(FlakyAuditStore {
            inner: busbar_store_sqlite::SqliteStore::open_in_memory().unwrap(),
            fail_seqs: std::sync::Mutex::new([2u64].into_iter().collect()),
        });
        let log = AuditLog::new();
        log.set_sink(store.clone());

        log.record_by("hook.register", "hook:a", OUTCOME_APPLIED, "admin"); // seq 1 -> durable
        log.record_by("hook.register", "hook:b", OUTCOME_APPLIED, "admin"); // seq 2 -> FAILS (gap)

        // After the injected failure, the store is missing seq 2 (the transient hiccup).
        let after_fail = store.list_audit().unwrap();
        assert_eq!(
            after_fail.iter().map(|r| r.seq).collect::<Vec<_>>(),
            vec![1],
            "seq 2's write-through failed, so only seq 1 is durable so far"
        );

        // Clear the fault (the store recovered), then record seq 3: its write-through BACKFILLS seq 2
        // from the RAM ring before appending seq 3, healing the gap.
        store.fail_seqs.lock().unwrap().clear();
        log.record_by("hook.delete", "hook:a", OUTCOME_APPLIED, "admin"); // seq 3 -> backfills 2, then 3

        let healed = store.list_audit().unwrap();
        assert_eq!(
            healed.iter().map(|r| r.seq).collect::<Vec<_>>(),
            vec![1, 2, 3],
            "the transient gap is backfilled; the durable chain is contiguous again"
        );

        // A restart restores the healed durable chain intact (no permanent loss, chain verifies).
        let store_ro: std::sync::Arc<dyn Store> = store.clone();
        let log2 = AuditLog::new();
        let n = log2
            .restore_from_store(store_ro.as_ref())
            .expect("the backfilled chain restores without a linkage break");
        assert_eq!(n, 3, "all three entries restored (nothing discarded)");
        assert!(log2.verify(), "the restored chain verifies");
    }

    /// BOUNDED RESTORE READ: with a durable history far larger than the RAM ring, `restore_from_store`
    /// must read only the bounded tail (`list_audit_tail`), never materialize the whole log. We record
    /// more than `MAX_AUDIT_ENTRIES`, then restore and assert the ring holds exactly the cap and the
    /// restored tail verifies - proving the read is bounded (the SQLite `LIMIT` tail query backs it).
    #[test]
    fn restore_read_is_bounded_to_the_ring() {
        let store: Arc<dyn Store> =
            Arc::new(busbar_store_sqlite::SqliteStore::open_in_memory().unwrap());
        let log = AuditLog::new();
        log.set_sink(store.clone());
        let total = MAX_AUDIT_ENTRIES + 50;
        for i in 0..total {
            log.record_by(
                "hook.register",
                &format!("hook:{i}"),
                OUTCOME_APPLIED,
                "admin",
            );
        }

        // The bounded tail read returns exactly the ring bound, oldest-first, chained to the head.
        let tail = store.list_audit_tail(MAX_AUDIT_ENTRIES as u64).unwrap();
        assert_eq!(
            tail.len(),
            MAX_AUDIT_ENTRIES,
            "the source-bounded read caps the tail"
        );
        assert_eq!(
            tail.last().unwrap().seq as usize,
            total,
            "the tail ends at the newest durable seq"
        );

        let log2 = AuditLog::new();
        let n = log2
            .restore_from_store(store.as_ref())
            .expect("bounded restore");
        assert_eq!(
            n, MAX_AUDIT_ENTRIES,
            "restore loads only the bounded tail, not the full history"
        );
        assert_eq!(
            log2.list(usize::MAX).len(),
            MAX_AUDIT_ENTRIES,
            "the restored ring is bounded"
        );
        assert!(log2.verify(), "the restored bounded tail's chain verifies");
    }
}
