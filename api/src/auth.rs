// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The AUTH contract: one module, one verdict.

use sha2::{Digest, Sha256};

/// The authenticated PRINCIPAL — who the caller IS, established at the auth stage and keyed to by
/// everything downstream (governance, audit attribution, the hook `send_user` projection, admin
/// scopes). IDENTITY ONLY: a module returns who; policy (allowed pools, budgets, admin scope) is
/// resolved by busbar from config (`group_map:`), never asserted by the module (design-hooks-v2
/// §2.3). NEVER carries the credential itself.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Principal {
    /// Stable identity handle (required): the virtual-key id for governance keys, a stable
    /// module-scoped handle otherwise (e.g. `tokens:2`, an AD UPN).
    pub id: String,
    /// Display name, if the module knows one.
    pub name: Option<String>,
    /// Group memberships (external modules). Mapped to governance via config `group_map:`;
    /// intersected with the module's `allowed_groups:` cap before mapping. Empty = no groups.
    pub groups: Vec<String>,
    /// Module-suggested cache TTL for this identification, seconds (clamped by the engine's hard
    /// cap when the credential cache lands). `None` = engine default.
    pub ttl_secs: Option<u64>,
}

impl Principal {
    /// A principal with only a stable id — the common built-in-module shape.
    pub fn from_id(id: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            name: None,
            groups: Vec::new(),
            ttl_secs: None,
        }
    }
}

/// The verdict of one auth module. The PAM-style trichotomy the 1.3 auth-plugin layer is built on
/// (design-hooks-v2 §2): `Identify` = this module authenticated the caller and this is WHO —
/// carries the [`Principal`]; `Reject` = a credential was presented but is invalid (fail-closed,
/// stop the chain); `Pass` = "not mine" — no usable credential for this module, defer to the next
/// module / the mode default.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthOutcome {
    Identify(Principal),
    Reject,
    Pass,
}

/// One authentication module — a swappable implementation of the fixed `auth` engine stage. The
/// built-in `tokens` module implements it (the `auth/tokens/` crate); SAML/AD/OIDC modules
/// implement the same trait in the private repo. Extraction of the credential carriers (Bearer /
/// x-api-key / x-goog-api-key) stays in the engine's middleware, so a module never re-parses
/// headers — it receives the already-extracted candidate and returns a verdict.
pub trait AuthModule: Send + Sync {
    /// Stable module name for config references, metrics, and audit (e.g. `"tokens"`).
    fn name(&self) -> &'static str;
    /// Judge the presented candidate credential. Constant-time and side-effect-free.
    fn authenticate(&self, candidate: Option<&str>) -> AuthOutcome;
    /// Whether the engine may CACHE this module's verdicts (the credential cache). Default
    /// `false`: an in-process module is microseconds and caching its verdicts would only widen
    /// the revocation window. A module that does real I/O per call (a directory lookup over a
    /// socket) overrides to `true`.
    fn cacheable(&self) -> bool {
        false
    }
}

/// Constant-time string comparison to avoid leaking how much of a token matches via timing.
/// `#[inline(never)]` + `black_box` keep the optimizer from turning the accumulation loop into
/// an early-exit branch (which would reintroduce a timing signal). The length check is a
/// deliberate fast-path: token *length* is not treated as secret.
#[inline(never)]
pub fn constant_time_eq(a: &str, b: &str) -> bool {
    let a_bytes = a.as_bytes();
    let b_bytes = b.as_bytes();

    if a_bytes.len() != b_bytes.len() {
        return false;
    }

    // XOR all bytes and OR the results together. If any bit differs, result > 0.
    let mut result: u8 = 0;
    for (x, y) in a_bytes.iter().zip(b_bytes.iter()) {
        result |= x ^ y;
    }

    std::hint::black_box(result) == 0
}

/// Lowercase hex SHA-256 of `data` — THE digest facility credentials are compared under (a module
/// hashes both sides before [`constant_time_eq`], so candidate length leaks nothing).
pub fn sha256_hex(data: &[u8]) -> String {
    hex::encode(Sha256::digest(data))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn constant_time_eq_basics() {
        assert!(constant_time_eq("secret", "secret"));
        assert!(!constant_time_eq("short", "longer"));
        assert!(!constant_time_eq("secret1", "secret2"));
    }

    #[test]
    fn sha256_hex_is_lowercase_64() {
        let h = sha256_hex(b"busbar");
        assert_eq!(h.len(), 64);
        assert_eq!(h, h.to_lowercase());
    }
}
