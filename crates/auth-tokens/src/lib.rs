// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The built-in `tokens` auth PLUGIN.
//!
//! A default-included, compile-removable implementation of the engine's `AuthModule` contract
//! (`busbar-api`). It is architecturally IDENTICAL to any external auth plugin (SAML / AD / OIDC,
//! developed in the private repo): same trait, same trichotomy, same registration. The engine core
//! contains NO token-specific logic — `grep token` in the engine's `src/` finds nothing; all of it
//! lives here. Yank it from the binary with `--no-default-features` (compliance-by-compilation).

use busbar_api::{sha256_hex, AuthModule, AuthOutcome, Principal};

/// The built-in `tokens` auth module: a static allowlist of client tokens, matched in constant time
/// against the presented candidate. Owns the SHA-256 digests (64-hex-char) of each configured token,
/// pre-computed once at construction so `authenticate` folds over FIXED-LENGTH digests instead of
/// re-hashing the allowlist per call. The security property is unchanged from the pre-plugin fold:
/// the candidate is hashed exactly once, ALL N comparisons run unconditionally (bitwise-OR, no
/// short-circuit), and every compare is over equal-length (64-hex-char) strings.
pub struct TokensModule {
    hashed_tokens: Vec<String>,
}

impl TokensModule {
    /// Pre-hash the allowlist once. `sha256_hex` is the same digest facility used for virtual keys.
    ///
    /// DUPLICATE tokens are DE-DUPLICATED here (first occurrence wins), which is a CORRECTNESS
    /// requirement, not just tidiness. The principal id minted on a match is the matched allowlist
    /// position, accumulated in `authenticate` by bitwise-OR of the 1-based indices of ALL matching
    /// entries. If the SAME token appeared twice (say positions 1 and 2) BOTH would match a presented
    /// candidate and the OR-fold would yield `1 | 2 == 3` — a PHANTOM principal id belonging to
    /// neither entry (and, worse, colliding with a legitimately-distinct token at position 3). That
    /// cross-principal misattribution would then flow into the audit log, hooks, and governance keying.
    /// Collapsing to distinct digests guarantees AT MOST ONE entry can match, so the OR-fold is always
    /// an unambiguous single position. `dedup` after a stable sort would reorder ids; instead we keep
    /// first-seen order (and thus stable 1-based ids across restarts) with a seen-set filter.
    pub fn new(tokens: &[String]) -> Self {
        let mut seen = std::collections::HashSet::new();
        let hashed_tokens = tokens
            .iter()
            .map(|t| sha256_hex(t.as_bytes()))
            .filter(|h| seen.insert(h.clone()))
            .collect();
        Self { hashed_tokens }
    }
}

impl AuthModule for TokensModule {
    fn name(&self) -> &'static str {
        "tokens"
    }

    fn authenticate(&self, candidate: Option<&str>) -> AuthOutcome {
        // No usable credential presented -> Pass (defer). An empty candidate is treated as absent.
        let Some(token) = candidate.filter(|t| !t.is_empty()) else {
            return AuthOutcome::Pass;
        };
        // Hash the candidate once, then constant-time-fold against EVERY allowed digest with
        // bitwise-OR (NOT `.any()`, which would short-circuit and leak the matched token's position
        // as a list-level timing oracle). `black_box` keeps the optimizer from reintroducing an
        // early exit. Byte-for-byte the pre-plugin fold from `AuthMiddleware::validate_token`.
        let candidate_hash = sha256_hex(token.as_bytes());
        // `matched` doubles as the found flag AND the 1-based matched position, accumulated with
        // bitwise-OR so every iteration does identical work (no early exit, no position-dependent
        // branch — the matched index is derived arithmetically, preserving the timing stance).
        let matched =
            self.hashed_tokens
                .iter()
                .enumerate()
                .fold(0usize, |acc, (i, allowed_hash)| {
                    acc | ((i + 1)
                        * usize::from(busbar_api::constant_time_eq(&candidate_hash, allowed_hash)))
                });
        if std::hint::black_box(matched) != 0 {
            // The principal id is the allowlist POSITION (`tokens:<n>`, 1-based) — stable across
            // restarts for a stable config, and never derived from the secret's bytes.
            AuthOutcome::Identify(Principal::from_id(format!("tokens:{matched}")))
        } else {
            AuthOutcome::Reject
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn id_of(outcome: AuthOutcome) -> String {
        match outcome {
            AuthOutcome::Identify(p) => p.id,
            other => panic!("expected Identify, got {other:?}"),
        }
    }

    /// A single distinct token mints the 1-based position as its principal id.
    #[test]
    fn single_token_mints_position_one() {
        let m = TokensModule::new(&["alpha".to_string()]);
        assert_eq!(id_of(m.authenticate(Some("alpha"))), "tokens:1");
    }

    /// Distinct tokens each mint their own stable, first-seen 1-based position.
    #[test]
    fn distinct_tokens_mint_their_own_positions() {
        let m = TokensModule::new(&[
            "alpha".to_string(),
            "bravo".to_string(),
            "charlie".to_string(),
        ]);
        assert_eq!(id_of(m.authenticate(Some("alpha"))), "tokens:1");
        assert_eq!(id_of(m.authenticate(Some("bravo"))), "tokens:2");
        assert_eq!(id_of(m.authenticate(Some("charlie"))), "tokens:3");
    }

    /// REGRESSION (P1): a DUPLICATE token must never mint a phantom principal id. Before the dedup
    /// fix, a token duplicated at positions 1 and 2 matched BOTH, and the OR-fold produced
    /// `1 | 2 == 3` — a `tokens:3` principal belonging to neither entry and colliding with a
    /// distinct token legitimately at position 3. After the fix the duplicate collapses to a single
    /// entry, so the presented token mints exactly `tokens:1` and the distinct third token keeps
    /// `tokens:2` (its post-dedup position), with no phantom `tokens:3` ever reachable.
    #[test]
    fn duplicate_token_does_not_mint_phantom_principal() {
        let m = TokensModule::new(&[
            "dup".to_string(),
            "dup".to_string(),
            "distinct".to_string(),
        ]);
        // The duplicated token mints its FIRST position only — never the OR-collision `tokens:3`.
        assert_eq!(id_of(m.authenticate(Some("dup"))), "tokens:1");
        // The distinct token that followed two identical entries lands at post-dedup position 2,
        // NOT the phantom `tokens:3` the pre-fix OR-fold would have made reachable.
        assert_eq!(id_of(m.authenticate(Some("distinct"))), "tokens:2");
    }

    /// An unmatched candidate is Rejected; an absent/empty candidate Passes (defers).
    #[test]
    fn unmatched_rejects_absent_passes() {
        let m = TokensModule::new(&["alpha".to_string()]);
        assert!(matches!(m.authenticate(Some("nope")), AuthOutcome::Reject));
        assert!(matches!(m.authenticate(Some("")), AuthOutcome::Pass));
        assert!(matches!(m.authenticate(None), AuthOutcome::Pass));
    }
}
