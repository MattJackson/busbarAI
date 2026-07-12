// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The built-in `admin-tokens` ADMIN auth PLUGIN.
//!
//! A default-included, compile-removable module for the `admin_auth:` chain (the parallel chain
//! gating `/admin/v1/*`): the single operator admin token, presented as `Authorization: Bearer` or
//! `X-Admin-Token`. Architecturally a peer of any external admin module (AD/OIDC — private repo);
//! this one is credential-compare only, so it takes the pre-computed token hash and the extracted
//! carriers rather than the `AuthModule` single-candidate shape (an admin credential legitimately
//! arrives on two carriers, and the constant-time both-carriers fold must live INSIDE the module —
//! selecting a carrier before the compare would reintroduce the timing observable the fold kills).

use crate::auth::{AuthMiddleware, AuthOutcome, Principal};

/// The fixed principal id the operator admin token identifies as. The built-in operator credential
/// carries FULL admin scope by definition (it is the root credential the deployment was born with);
/// group-mapped external principals get their scope from `group_map:` instead.
pub(crate) const ADMIN_TOKENS_PRINCIPAL_ID: &str = "admin";

/// Judge the presented admin credential carriers against the configured admin token hash
/// (SHA-256 hex, pre-computed at `GovState` construction).
///
/// Timing stance (unchanged from the pre-plugin inline check): BOTH carrier comparisons run
/// UNCONDITIONALLY and fold with bitwise-OR — a request presenting both a Bearer and an
/// `X-Admin-Token` never skips the second compare, so "Bearer matched" and "Bearer missed, header
/// matched" are indistinguishable. Both candidates are SHA-256-hashed before the constant-time
/// compare, so candidate length leaks nothing. A missing carrier contributes 0.
///
/// `None` hash (no admin token configured) ⇒ `Pass` — this module has nothing to judge; a chain
/// that ends all-`Pass` is denied (fail-closed), preserving "admin API disabled without a token".
pub(crate) fn authenticate_admin_tokens(
    configured_hash: Option<&str>,
    bearer: Option<&str>,
    header: Option<&str>,
) -> AuthOutcome {
    let Some(configured_hash) = configured_hash else {
        return AuthOutcome::Pass;
    };
    if bearer.is_none() && header.is_none() {
        // No credential presented for this module — defer (the chain's all-Pass denies).
        return AuthOutcome::Pass;
    }
    let bearer_match = u8::from(
        bearer
            .map(|b| {
                AuthMiddleware::constant_time_eq(
                    &crate::sigv4::sha256_hex(b.as_bytes()),
                    configured_hash,
                )
            })
            .unwrap_or(false),
    );
    let header_match = u8::from(
        header
            .map(|h| {
                AuthMiddleware::constant_time_eq(
                    &crate::sigv4::sha256_hex(h.as_bytes()),
                    configured_hash,
                )
            })
            .unwrap_or(false),
    );
    if std::hint::black_box(bearer_match | header_match) != 0 {
        AuthOutcome::Identify(Principal::from_id(ADMIN_TOKENS_PRINCIPAL_ID))
    } else {
        AuthOutcome::Reject
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hash(s: &str) -> String {
        crate::sigv4::sha256_hex(s.as_bytes())
    }

    #[test]
    fn no_configured_token_passes() {
        assert_eq!(
            authenticate_admin_tokens(None, Some("x"), None),
            AuthOutcome::Pass
        );
    }

    #[test]
    fn no_credential_passes() {
        let h = hash("secret");
        assert_eq!(
            authenticate_admin_tokens(Some(&h), None, None),
            AuthOutcome::Pass
        );
    }

    #[test]
    fn either_carrier_identifies() {
        let h = hash("secret");
        for (b, hd) in [
            (Some("secret"), None),
            (None, Some("secret")),
            (Some("secret"), Some("wrong")),
            (Some("wrong"), Some("secret")),
        ] {
            match authenticate_admin_tokens(Some(&h), b, hd) {
                AuthOutcome::Identify(p) => assert_eq!(p.id, ADMIN_TOKENS_PRINCIPAL_ID),
                other => panic!("expected Identify, got {other:?} for ({b:?},{hd:?})"),
            }
        }
    }

    #[test]
    fn wrong_credential_rejects() {
        let h = hash("secret");
        assert_eq!(
            authenticate_admin_tokens(Some(&h), Some("nope"), None),
            AuthOutcome::Reject
        );
        assert_eq!(
            authenticate_admin_tokens(Some(&h), None, Some("nope")),
            AuthOutcome::Reject
        );
    }
}
