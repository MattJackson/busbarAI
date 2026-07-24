// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The **auth** payload schema (kind = [`crate::kind::AUTH`]) that rides the kind-neutral `call`.
//!
//! ## Identity-only — STRUCTURAL, not merely conventional
//!
//! An auth plugin asserts WHO the caller is, NEVER what they may do. The only data-carrying success
//! payload it can produce is [`Identity`] — `sub` + `groups` + `name` + `ttl_secs` — and NOTHING in
//! its transitive type graph has a slot for pools, scope, permissions, roles-as-policy, or a policy
//! decision. `#[serde(deny_unknown_fields)]` makes a rogue plugin's extra keys a REJECT, not a
//! silently-ignored field, so the identity-only guarantee is structural. The engine resolves
//! `groups → role_bindings → policy` AFTER, from [`Identity`] alone (design-hooks-v2 §2.3). A plugin
//! CANNOT serialize an authorization decision — the type it must produce has no place to put one.
//!
//! `Identity.groups` is the frozen WIRE name for the caller's asserted memberships; it maps to the
//! engine's [`busbar_api::Principal::roles`] (the field the auth chain consumes and resolves through
//! `auth.role_bindings`). The wire name stays `groups` (the operator-facing membership vocabulary).
//!
//! ## What crosses the boundary
//!
//! IN: the already-extracted OPAQUE candidate credential (the bearer token the engine's middleware
//! pulled off the request) via [`AuthRequest::Authenticate`]. The plugin never sees raw headers, the
//! path, or the peer. OUT: an [`AuthResponse`] — `Identity` (this is WHO), `Reject` (a credential was
//! presented and is invalid — fail-closed, stop the chain), or `Pass` ("not mine", defer to the next
//! chain module). `Reject`/`Pass` are control-flow, not policy; the ONLY shape carrying data OUT is
//! the identity-only [`Identity`].

use busbar_api::{AuthOutcome, Principal};
use serde::{Deserialize, Serialize};

/// The identity-only success payload an auth plugin returns: WHO the caller is, and nothing about
/// what they may do. `#[serde(deny_unknown_fields)]` rejects any extra key a plugin tries to smuggle
/// (a policy/scope field), so the identity-only guarantee is structural. Converts to/from the
/// engine's [`busbar_api::Principal`] (the seam the auth chain consumes; `groups` ↔ `roles`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Identity {
    /// Stable subject handle (required): a module-scoped identity (e.g. an OIDC subject / UPN).
    pub sub: String,
    /// Asserted group/role memberships. Mapped to policy via the operator's `auth.role_bindings:`
    /// AFTER the plugin returns — the plugin asserts membership, never the grant. Empty = none.
    #[serde(default)]
    pub groups: Vec<String>,
    /// Display name, if the plugin knows one.
    #[serde(default)]
    pub name: Option<String>,
    /// Plugin-suggested cache TTL for this identification, seconds (clamped by the engine's hard cap).
    /// `None` = engine default.
    #[serde(default)]
    pub ttl_secs: Option<u64>,
}

impl From<Principal> for Identity {
    fn from(p: Principal) -> Self {
        Identity {
            sub: p.id,
            groups: p.roles,
            name: p.name,
            ttl_secs: p.ttl_secs,
        }
    }
}

impl From<Identity> for Principal {
    fn from(i: Identity) -> Self {
        Principal {
            id: i.sub,
            name: i.name,
            roles: i.groups,
            ttl_secs: i.ttl_secs,
        }
    }
}

/// An auth operation, serialized as the `call` request payload. Mirrors the `busbar_api::AuthModule`
/// trait; the variant is the op-code.
#[derive(Debug, Serialize, Deserialize)]
pub enum AuthRequest {
    /// `name()` — the module's stable name (config/metrics/audit identifier). Resolved once at load.
    Name,
    /// `cacheable()` — whether the engine may cache this module's verdicts.
    Cacheable,
    /// `authenticate(candidate)` — judge the OPAQUE already-extracted candidate credential. An empty
    /// string means no usable credential was presented on any carrier the engine supports.
    Authenticate { credential: String },
}

/// The success payload for an auth `call`. Module-level FAILURES (e.g. an unreachable JWKS endpoint)
/// ride `STATUS_ERR` with a UTF-8 message, NOT here. The ONLY data-carrying success shape is
/// [`AuthResponse::Identity`] — the identity-only [`Identity`]. `Reject`/`Pass` are the fail-closed
/// and defer control-flow verdicts (a denied credential is NOT an error; it is a successful call).
#[derive(Debug, Serialize, Deserialize)]
pub enum AuthResponse {
    /// `name()` — the module's stable name.
    Name(String),
    /// `cacheable()` — whether verdicts may be cached.
    Cacheable(bool),
    /// `authenticate()` identified the caller — the ONLY shape carrying identity data out.
    Identity(Identity),
    /// `authenticate()` rejects: a credential was presented and is invalid (fail-closed, stop chain).
    Reject,
    /// `authenticate()` defers: not this module's credential shape — try the next chain module.
    Pass,
}

impl AuthResponse {
    /// Build the `authenticate` response from an engine [`AuthOutcome`]. The identity-only `Identify`
    /// projects to [`AuthResponse::Identity`]; the control-flow verdicts map straight across.
    pub fn from_outcome(outcome: AuthOutcome) -> Self {
        match outcome {
            AuthOutcome::Identify(p) => AuthResponse::Identity(p.into()),
            AuthOutcome::Reject => AuthResponse::Reject,
            AuthOutcome::Pass => AuthResponse::Pass,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_identity() -> Identity {
        Identity {
            sub: "oidc:alice@contoso.com".into(),
            groups: vec!["engineering".into(), "sre".into()],
            name: Some("Alice".into()),
            ttl_secs: Some(300),
        }
    }

    #[test]
    fn request_response_json_roundtrip() {
        let reqs = vec![
            AuthRequest::Name,
            AuthRequest::Cacheable,
            AuthRequest::Authenticate {
                credential: String::new(),
            },
            AuthRequest::Authenticate {
                credential: "ey.jwt.token".into(),
            },
        ];
        for r in reqs {
            let j = serde_json::to_vec(&r).unwrap();
            let back: AuthRequest = serde_json::from_slice(&j).unwrap();
            assert_eq!(serde_json::to_vec(&back).unwrap(), j);
        }

        let resp = AuthResponse::Identity(sample_identity());
        let j = serde_json::to_vec(&resp).unwrap();
        match serde_json::from_slice::<AuthResponse>(&j).unwrap() {
            AuthResponse::Identity(i) => assert_eq!(i, sample_identity()),
            other => panic!("wrong variant: {other:?}"),
        }
    }

    /// The identity-only guarantee is STRUCTURAL: an extra field (a smuggled policy/scope) is
    /// REJECTED by `deny_unknown_fields`, never ignored.
    #[test]
    fn identity_rejects_unknown_fields() {
        let rogue = r#"{"sub":"x","groups":[],"name":null,"ttl_secs":null,"admin_scope":"full"}"#;
        assert!(
            serde_json::from_str::<Identity>(rogue).is_err(),
            "a plugin smuggling a policy field must be rejected, not silently accepted"
        );
    }

    /// Identity <-> Principal is lossless (the seam the auth chain consumes; groups ↔ roles).
    #[test]
    fn identity_principal_roundtrip() {
        let id = sample_identity();
        let p: Principal = id.clone().into();
        assert_eq!(p.id, id.sub);
        assert_eq!(p.roles, id.groups);
        let back: Identity = p.into();
        assert_eq!(back, id);
    }

    #[test]
    fn from_outcome_maps_verdicts() {
        let mut p = Principal::from_id("oidc:bob");
        p.roles = vec!["g".into()];
        match AuthResponse::from_outcome(AuthOutcome::Identify(p)) {
            AuthResponse::Identity(i) => assert_eq!(i.sub, "oidc:bob"),
            other => panic!("{other:?}"),
        }
        assert!(matches!(
            AuthResponse::from_outcome(AuthOutcome::Reject),
            AuthResponse::Reject
        ));
        assert!(matches!(
            AuthResponse::from_outcome(AuthOutcome::Pass),
            AuthResponse::Pass
        ));
    }
}
