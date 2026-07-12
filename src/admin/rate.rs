// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Per-principal ADMIN MUTATION rate limits (design-admin-api-v1 §6.6) — separate from the data
//! plane's per-key RPM. Config-plane mutations (apply/rollback) are capped at 10/min and the other
//! mutation classes (hook CRUD, key CRUD) at 60/min, per principal, in fixed one-minute windows.
//! FAILED attempts count too (anti-enumeration: probing 404s spends the same budget as mutating),
//! which is why enforcement lives in the auth middleware — before any handler runs. Limit events
//! are audited.

use std::collections::HashMap;

/// The mutation classes with distinct budgets. `Config` = apply/rollback (the blast-radius class);
/// `Crud` = everything else that mutates (hooks, keys).
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum MutationClass {
    Config,
    Crud,
}

impl MutationClass {
    /// The per-minute budget for this class (spec defaults; a config knob is an additive follow-up).
    fn limit(self) -> u32 {
        match self {
            MutationClass::Config => 10,
            MutationClass::Crud => 60,
        }
    }

    /// Audit-facing label.
    pub(crate) fn label(self) -> &'static str {
        match self {
            MutationClass::Config => "config",
            MutationClass::Crud => "crud",
        }
    }
}

/// Fixed-window counters keyed by (principal, class). Held on `App` behind an `Arc` (shared across
/// config-apply snapshots — rate state survives every swap); bounded by construction: entries are
/// per-principal-per-class and a sweep on every check drops past-window entries, so a churn of
/// principals cannot grow the map unboundedly.
/// One window entry: (window start, attempts spent in it).
type Window = (u64, u32);

pub(crate) struct MutationLimiter {
    windows: std::sync::Mutex<Option<HashMap<(String, MutationClass), Window>>>,
}

impl MutationLimiter {
    pub(crate) fn new() -> Self {
        Self {
            windows: std::sync::Mutex::new(None),
        }
    }

    /// Spend one attempt from `principal`'s budget for `class` at time `now` (unix seconds).
    /// Returns `false` when the budget for the current window is exhausted (the caller responds
    /// 429 and audits). Never panics (poisoned lock recovered).
    pub(crate) fn check(&self, principal: &str, class: MutationClass, now: u64) -> bool {
        let window = now - (now % 60);
        let mut guard = self.windows.lock().unwrap_or_else(|e| e.into_inner());
        let map = guard.get_or_insert_with(HashMap::new);
        // Opportunistic sweep: drop every entry from a PAST window (each principal-class re-inserts
        // on its next attempt), keeping the map proportional to currently-active principals.
        map.retain(|_, (w, _)| *w == window);
        let entry = map
            .entry((principal.to_string(), class))
            .or_insert((window, 0));
        if entry.1 >= class.limit() {
            return false;
        }
        entry.1 += 1;
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The budget is per (principal, class) within a fixed window; a new window refills; one
    /// principal exhausting a class neither affects another principal nor its own other class.
    #[test]
    fn windows_are_per_principal_per_class_and_refill() {
        let l = MutationLimiter::new();
        let t = 1_000_000; // window-aligned enough (fixed windows key on now - now%60)
        for _ in 0..10 {
            assert!(l.check("a", MutationClass::Config, t));
        }
        assert!(
            !l.check("a", MutationClass::Config, t),
            "11th config mutation in the window is limited"
        );
        assert!(
            l.check("a", MutationClass::Crud, t),
            "the other class has its own budget"
        );
        assert!(
            l.check("b", MutationClass::Config, t),
            "another principal has its own budget"
        );
        assert!(
            l.check("a", MutationClass::Config, t + 60),
            "a new window refills"
        );
    }
}
