// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The built-in `tokens` auth PLUGIN.
//!
//! A default-included, compile-removable implementation of the engine's `AuthModule` contract
//! (`crate::auth`). It is architecturally IDENTICAL to any external auth plugin (SAML / AD / OIDC,
//! developed in the private repo): same trait, same trichotomy, same registration. The engine core
//! contains NO token-specific logic — `grep token src/*.rs` in the engine finds nothing; all of it
//! lives here. Yank it from the binary with `--no-default-features` (compliance-by-compilation).

use crate::auth::{AuthMiddleware, AuthModule, AuthOutcome};

/// The built-in `tokens` auth module: a static allowlist of client tokens, matched in constant time
/// against the presented candidate. Owns the SHA-256 digests (64-hex-char) of each configured token,
/// pre-computed once at construction so `authenticate` folds over FIXED-LENGTH digests instead of
/// re-hashing the allowlist per call. The security property is unchanged from the pre-plugin fold:
/// the candidate is hashed exactly once, ALL N comparisons run unconditionally (bitwise-OR, no
/// short-circuit), and every compare is over equal-length (64-hex-char) strings.
pub(crate) struct TokensModule {
    hashed_tokens: Vec<String>,
}

impl TokensModule {
    /// Pre-hash the allowlist once. `sha256_hex` is the same digest facility used for virtual keys.
    pub(crate) fn new(tokens: &[String]) -> Self {
        Self {
            hashed_tokens: tokens
                .iter()
                .map(|t| crate::sigv4::sha256_hex(t.as_bytes()))
                .collect(),
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
        let candidate_hash = crate::sigv4::sha256_hex(token.as_bytes());
        let found = self.hashed_tokens.iter().fold(0u8, |acc, allowed_hash| {
            acc | u8::from(AuthMiddleware::constant_time_eq(
                &candidate_hash,
                allowed_hash,
            ))
        });
        if std::hint::black_box(found) != 0 {
            AuthOutcome::Identify
        } else {
            AuthOutcome::Reject
        }
    }
}
