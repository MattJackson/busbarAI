// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! A **hermetic static-token `kind: auth` plugin** — a `cdylib` exporting the auth C ABI, used only
//! as TEST support for the full-chain auth-plugin seam tests (the engine's `AuthMiddleware` loading a
//! real signed `kind: auth` tarball over the loader). It does NO network and NO crypto: a single
//! configured token maps to a single configured identity + roles, so a valid token yields a
//! `Principal` (→ role_bindings policy) and anything else `Pass`es. This is deliberately trivial — the
//! point under test is the ENGINE seam (resolve → load → box → run_chain → identity→policy), not an
//! IdP. Production IdP logic lives in `busbar-auth-oidc(-plugin)`.
//!
//! Config JSON (the chain entry's `settings:` map, passed verbatim by the engine):
//! ```json
//! { "token": "sekret", "id": "alice", "roles": ["platform"] }
//! ```

use busbar_api::{constant_time_eq, AuthModule, AuthOutcome, Principal};
use serde::Deserialize;

/// The plugin's opaque config: the one accepted token and the identity it grants.
#[derive(Deserialize)]
struct StaticConfig {
    /// The single credential this module accepts.
    token: String,
    /// The stable principal id the accepted token identifies as.
    id: String,
    /// The roles asserted for that principal (mapped to policy via `role_bindings.<module>`).
    #[serde(default)]
    roles: Vec<String>,
}

/// A static-token identity module: the configured `token` → `Identify(id, roles)`; anything else
/// (including no credential) → `Pass` (defer to the next module). Never `Reject`s, so a chain of
/// `[static-auth, keys]` can still fall through to the built-in verifier — the fail-closed all-`Pass`
/// deny lives in the engine, not here.
struct StaticModule {
    token: String,
    id: String,
    roles: Vec<String>,
}

impl AuthModule for StaticModule {
    fn name(&self) -> &'static str {
        // The RUNTIME module identity — what `role_bindings.<module>` and `auth.modules.<module>`
        // caps key off. Deliberately fixed (not the config alias) to prove the engine keys policy off
        // `module.name()`, not the config chain name.
        "static-auth"
    }

    fn authenticate(&self, candidate: Option<&str>) -> AuthOutcome {
        match candidate {
            Some(cred) if constant_time_eq(cred, &self.token) => {
                let mut p = Principal::from_id(self.id.clone());
                p.roles = self.roles.clone();
                AuthOutcome::Identify(p)
            }
            _ => AuthOutcome::Pass,
        }
    }
}

/// Construct the module from the engine-passed JSON config. Fail-closed: an empty/invalid config is a
/// load error (surfaced by `open_auth` → boot/apply abort).
fn open(cfg: &str) -> Result<Box<dyn AuthModule>, String> {
    if cfg.trim().is_empty() {
        return Err("static-auth plugin requires config (token, id); none provided".to_string());
    }
    let c: StaticConfig =
        serde_json::from_str(cfg).map_err(|e| format!("invalid static-auth plugin config: {e}"))?;
    if c.token.is_empty() || c.id.is_empty() {
        return Err("static-auth plugin config needs a non-empty `token` and `id`".to_string());
    }
    Ok(Box::new(StaticModule {
        token: c.token,
        id: c.id,
        roles: c.roles,
    }))
}

busbar_plugin_sdk::export_auth_plugin!(open);
