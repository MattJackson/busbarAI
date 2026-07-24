// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The AUTH seam of the kind-neutral loader: [`DynAuth`], a [`busbar_api::AuthModule`] backed by a
//! dynamically-loaded plugin whose kind was bound to `auth` at load. Its verdict carries only an
//! identity-only [`busbar_plugin_abi::auth::Identity`] (→ [`busbar_api::Principal`]); a misbehaving
//! plugin is FAIL-CLOSED (rejected, never admitted).

use crate::{stage, wire_up_raw, RawPlugin};
use busbar_api::{AuthModule, AuthOutcome, Principal};
use busbar_plugin_abi::{
    auth::{AuthRequest, AuthResponse},
    kind as abi_kind,
};

/// An `AuthModule` loaded from a dynamic library over the kind-neutral ABI. The module's stable
/// `name()` and `cacheable()` are resolved ONCE at load (the C ABI can't return a `&'static str`, so
/// the loaded name is leaked to `'static` — a bounded, one-per-plugin leak of a non-secret id).
pub struct DynAuth {
    raw: RawPlugin,
    name: &'static str,
    cacheable: bool,
}

impl AuthModule for DynAuth {
    fn name(&self) -> &'static str {
        self.name
    }

    fn authenticate(&self, candidate: Option<&str>) -> AuthOutcome {
        let req = AuthRequest::Authenticate {
            credential: candidate.unwrap_or("").to_string(),
        };
        match self.raw.transport_call::<AuthRequest, AuthResponse>(&req) {
            Ok(AuthResponse::Identity(id)) => AuthOutcome::Identify(Principal::from(id)),
            Ok(AuthResponse::Reject) => AuthOutcome::Reject,
            Ok(AuthResponse::Pass) => AuthOutcome::Pass,
            // A wrong-variant response, or a transport/module error, is FAIL-CLOSED: a misbehaving
            // plugin must never admit a caller. `Reject` (not `Pass`) — a credential may have been
            // presented; with no candidate the middleware's all-Pass path denies anyway, so Reject
            // never admits on error either way.
            Ok(other) => {
                tracing::warn!(
                    module = self.name,
                    "auth plugin returned an unexpected response variant ({other:?}); rejecting"
                );
                AuthOutcome::Reject
            }
            Err(e) => {
                tracing::warn!(module = self.name, error = %e, "auth plugin call failed; rejecting");
                AuthOutcome::Reject
            }
        }
    }

    fn cacheable(&self) -> bool {
        self.cacheable
    }
}

impl std::fmt::Debug for DynAuth {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DynAuth")
            .field("name", &self.name)
            .field("path", &self.raw.path)
            .finish()
    }
}

/// Load an AUTH module from EXACTLY the verified library `bytes` (TOCTOU-safe). Enforces the frozen
/// contract (transport, kind==`auth` && kind==manifest), then resolves the module's `name()` /
/// `cacheable()` ONCE. `manifest_kind` is the trust-verified signed-manifest `kind`.
pub fn load_auth_from_bytes(
    bytes: &[u8],
    cfg_json: &str,
    display: &str,
    manifest_kind: &str,
) -> Result<Box<dyn AuthModule>, String> {
    let (lib, staged) = stage::load_library_from_bytes(bytes, display)?;
    let raw = wire_up_raw(
        lib,
        cfg_json,
        display.to_string(),
        abi_kind::AUTH,
        manifest_kind,
        Some(staged),
    )?;

    let name = match raw.transport_call::<AuthRequest, AuthResponse>(&AuthRequest::Name) {
        Ok(AuthResponse::Name(n)) => n,
        Ok(other) => {
            return Err(format!(
                "auth plugin '{}' returned {other:?} for Name (expected Name)",
                raw.path
            ))
        }
        Err(e) => return Err(format!("auth plugin '{}' Name query failed: {e}", raw.path)),
    };
    let cacheable = match raw.transport_call::<AuthRequest, AuthResponse>(&AuthRequest::Cacheable) {
        Ok(AuthResponse::Cacheable(c)) => c,
        Ok(other) => {
            return Err(format!(
                "auth plugin '{}' returned {other:?} for Cacheable (expected Cacheable)",
                raw.path
            ))
        }
        Err(e) => {
            return Err(format!(
                "auth plugin '{}' Cacheable query failed: {e}",
                raw.path
            ))
        }
    };
    // Leak the name to 'static: `AuthModule::name` is `&'static str`, and a loaded module lives for
    // the process (or until the chain is rebuilt); a bounded one-per-plugin leak of a non-secret id.
    let name: &'static str = Box::leak(name.into_boxed_str());
    Ok(Box::new(DynAuth {
        raw,
        name,
        cacheable,
    }))
}
