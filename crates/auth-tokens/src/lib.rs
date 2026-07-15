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
    pub fn new(tokens: &[String]) -> Self {
        Self {
            hashed_tokens: tokens.iter().map(|t| sha256_hex(t.as_bytes())).collect(),
        }
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
