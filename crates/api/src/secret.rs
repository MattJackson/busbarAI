// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The SECRET-MODULE contract (`kind: secret` plugins). A secret module turns a config secret
//! reference's opaque `settings` into the secret BYTES: the built-in `env` module reads an
//! environment variable (settings.key), the built-in `file` module reads a file (settings.path),
//! and a third-party module (vault, a cloud secret manager, a database) implements the same trait
//! behind the plugin trust pipeline. The engine sees only `dyn SecretModule` - never the
//! implementation - and treats every failure as FAIL-CLOSED (an unresolvable secret refuses boot,
//! never resolves empty).

/// The result type every [`SecretModule`] call returns.
pub type SecretResult<T> = Result<T, SecretError>;

/// A secret-resolution failure, carried as a human-readable message. The message must NEVER carry
/// secret material - name the source (variable name, path, module) and the failure, not the value.
#[derive(Debug)]
pub struct SecretError(pub String);

impl std::fmt::Display for SecretError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "secret error: {}", self.0)
    }
}
impl std::error::Error for SecretError {}

impl From<String> for SecretError {
    fn from(s: String) -> Self {
        SecretError(s)
    }
}
impl From<&str> for SecretError {
    fn from(s: &str) -> Self {
        SecretError(s.to_string())
    }
}

/// One secret module - a resolver from a secret reference's `settings` map to the secret bytes.
/// Stateless per call: one module instance serves EVERY reference naming it, each carrying its own
/// `settings` (the `{ module: vault, settings: { path: kv/x } }` shape), so `resolve` takes the
/// settings per call rather than at construction. Off every hot path (secrets resolve at boot /
/// first use), so a plain synchronous call is the whole contract.
pub trait SecretModule: Send + Sync + 'static {
    /// Resolve one reference's settings to the secret bytes. FAIL-CLOSED: an unknown setting, a
    /// missing source, or an EMPTY value is an error, never `Ok(vec![])` - the engine additionally
    /// rejects an empty success defensively.
    fn resolve(
        &self,
        settings: &serde_json::Map<String, serde_json::Value>,
    ) -> SecretResult<Vec<u8>>;
}
