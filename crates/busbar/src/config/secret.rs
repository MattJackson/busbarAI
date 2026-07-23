// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The SECRET REFERENCE type (CLEAN-CONFIG rule C2): every secret/external value in the config is
//! `{ module: <secret-module>, settings: {…} }` — a reference to a SECRET MODULE (`kind: secret`
//! plugin), never the secret itself. The built-in modules are `env` (settings.key names an
//! environment variable) and `file` (settings.path names a file whose contents are the secret);
//! third-party modules (vault, cloud secret managers, …) load through the plugin system.
//!
//! Two ergonomic SUGAR spellings desugar to the built-ins so the common cases stay one-liners:
//!
//! ```yaml
//! api_key: { env: ANTHROPIC_API_KEY }          # ⇒ { module: env,  settings: { key: ANTHROPIC_API_KEY } }
//! cert:    { file: /run/secrets/tls-cert.pem } # ⇒ { module: file, settings: { path: /run/secrets/tls-cert.pem } }
//! ```
//!
//! A `SecretRef` holds NO secret material — only the module name and its opaque settings — so it is
//! safe to derive `Debug`/`Clone` on it and on every struct embedding it. Resolution (turning the
//! ref into bytes) happens at boot/first-use through the secret-resolver seam and is FAIL-CLOSED:
//! an unknown module or a failed resolution is a hard error, never an empty secret.

use std::fmt;

use serde::de::{self, Deserializer, MapAccess, Visitor};
use serde::Deserialize;

/// The built-in `env` secret module name (settings: `{ key: <ENV_VAR> }`).
pub(crate) const SECRET_MODULE_ENV: &str = "env";
/// The built-in `file` secret module name (settings: `{ path: <FILE> }`).
pub(crate) const SECRET_MODULE_FILE: &str = "file";
/// The `env` module's settings key naming the environment variable.
pub(crate) const SECRET_ENV_SETTING_KEY: &str = "key";
/// The `file` module's settings key naming the file path.
pub(crate) const SECRET_FILE_SETTING_PATH: &str = "path";

/// A reference to a secret, resolved through a secret MODULE. See the module docs for the accepted
/// YAML spellings. `settings` is the module's own (opaque) config — busbar passes it through
/// verbatim and never interprets it beyond the built-ins.
#[derive(Debug, Clone, PartialEq, serde::Serialize)]
pub(crate) struct SecretRef {
    /// The secret module resolving this reference (`env` / `file` built-ins, or a `kind: secret`
    /// plugin's name/alias).
    pub(crate) module: String,
    /// The module's own settings (opaque to busbar; the built-ins read `key` / `path`).
    pub(crate) settings: serde_json::Map<String, serde_json::Value>,
}

impl SecretRef {
    /// A `{ module: env, settings: { key } }` reference (the canonical form of the `{ env: … }` sugar).
    pub(crate) fn env(var: impl Into<String>) -> Self {
        let mut settings = serde_json::Map::new();
        settings.insert(
            SECRET_ENV_SETTING_KEY.to_string(),
            serde_json::Value::String(var.into()),
        );
        Self {
            module: SECRET_MODULE_ENV.to_string(),
            settings,
        }
    }

    /// A `{ module: file, settings: { path } }` reference (the canonical form of the `{ file: … }` sugar).
    pub(crate) fn file(path: impl Into<String>) -> Self {
        let mut settings = serde_json::Map::new();
        settings.insert(
            SECRET_FILE_SETTING_PATH.to_string(),
            serde_json::Value::String(path.into()),
        );
        Self {
            module: SECRET_MODULE_FILE.to_string(),
            settings,
        }
    }

    /// The `env` module's variable name, when this ref uses the built-in `env` module.
    pub(crate) fn env_var(&self) -> Option<&str> {
        if self.module == SECRET_MODULE_ENV {
            self.settings
                .get(SECRET_ENV_SETTING_KEY)
                .and_then(|v| v.as_str())
        } else {
            None
        }
    }

    /// The `file` module's path, when this ref uses the built-in `file` module.
    pub(crate) fn file_path(&self) -> Option<&str> {
        if self.module == SECRET_MODULE_FILE {
            self.settings
                .get(SECRET_FILE_SETTING_PATH)
                .and_then(|v| v.as_str())
        } else {
            None
        }
    }

    /// A short display form for error messages: `env:VAR`, `file:/path`, or `module '<name>'`.
    pub(crate) fn describe(&self) -> String {
        if let Some(var) = self.env_var() {
            format!("env:{var}")
        } else if let Some(path) = self.file_path() {
            format!("file:{path}")
        } else {
            format!("secret module '{}'", self.module)
        }
    }
}

impl<'de> Deserialize<'de> for SecretRef {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct RefVisitor;

        impl<'de> Visitor<'de> for RefVisitor {
            type Value = SecretRef;

            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(
                    "a secret reference map: { module: <secret-module>, settings: {…} }, \
                     { env: <VAR> }, or { file: <path> }",
                )
            }

            // A bare string here is almost always a LITERAL SECRET pasted inline (the exact
            // mistake this type exists to prevent). Reject it with a message that NEVER echoes
            // the value - serde's default invalid-type error would print the string verbatim
            // into boot logs.
            fn visit_str<E>(self, _v: &str) -> Result<SecretRef, E>
            where
                E: de::Error,
            {
                Err(E::custom(
                    "a secret value must be a REFERENCE, never an inline literal (the value is \
                     not echoed): use { env: <VAR> }, { file: <path> }, or \
                     { module: <secret-module>, settings: {…} }",
                ))
            }

            fn visit_map<A>(self, mut map: A) -> Result<SecretRef, A::Error>
            where
                A: MapAccess<'de>,
            {
                let mut module: Option<String> = None;
                let mut settings: Option<serde_json::Map<String, serde_json::Value>> = None;
                let mut sugar: Option<(&'static str, String)> = None;

                while let Some(key) = map.next_key::<String>()? {
                    match key.as_str() {
                        "module" => {
                            if module.is_some() {
                                return Err(de::Error::duplicate_field("module"));
                            }
                            module = Some(map.next_value()?);
                        }
                        "settings" => {
                            if settings.is_some() {
                                return Err(de::Error::duplicate_field("settings"));
                            }
                            settings = Some(map.next_value()?);
                        }
                        "env" => {
                            if sugar.is_some() {
                                return Err(de::Error::custom(
                                    "a secret reference takes exactly one of `env:` / `file:`",
                                ));
                            }
                            sugar = Some((SECRET_MODULE_ENV, map.next_value()?));
                        }
                        "file" => {
                            if sugar.is_some() {
                                return Err(de::Error::custom(
                                    "a secret reference takes exactly one of `env:` / `file:`",
                                ));
                            }
                            sugar = Some((SECRET_MODULE_FILE, map.next_value()?));
                        }
                        other => {
                            return Err(de::Error::unknown_field(
                                other,
                                &["module", "settings", "env", "file"],
                            ));
                        }
                    }
                }

                match (module, sugar) {
                    (Some(_), Some(_)) => Err(de::Error::custom(
                        "a secret reference is either `{ module: …, settings: … }` or the \
                         `{ env: … }` / `{ file: … }` sugar, not both",
                    )),
                    (Some(module), None) => {
                        if module.trim().is_empty() {
                            return Err(de::Error::custom(
                                "a secret reference `module:` must be non-empty",
                            ));
                        }
                        Ok(SecretRef {
                            module,
                            settings: settings.unwrap_or_default(),
                        })
                    }
                    (None, Some((kind, value))) => {
                        if settings.is_some() {
                            return Err(de::Error::custom(
                                "the `{ env: … }` / `{ file: … }` sugar takes no `settings:` \
                                 (use the canonical `{ module: …, settings: … }` form instead)",
                            ));
                        }
                        if value.trim().is_empty() {
                            return Err(de::Error::custom(format!(
                                "a `{{ {kind}: … }}` secret reference must name a non-empty value"
                            )));
                        }
                        Ok(match kind {
                            SECRET_MODULE_ENV => SecretRef::env(value),
                            _ => SecretRef::file(value),
                        })
                    }
                    (None, None) => Err(de::Error::custom(
                        "a secret reference needs `module:` (with optional `settings:`) or the \
                         `{ env: <VAR> }` / `{ file: <path> }` sugar",
                    )),
                }
            }
        }

        deserializer.deserialize_any(RefVisitor)
    }
}

/// The engine-facing SECRET RESOLVER seam (P2): the engine holds a `SecretResolver` and asks it to
/// turn a [`SecretRef`] into bytes, never touching a secret module's implementation. The built-in
/// `env` / `file` modules resolve inline (no plugin needed, so a zero-plugin deployment still has
/// secrets); any OTHER module name is delegated to a `kind: secret` plugin loaded through the
/// normal trust pipeline. FAIL-CLOSED at every branch: an unknown module or a resolution failure
/// is a hard error, never an empty secret.
///
/// The plugin lookup is a boxed closure so `config`/`tls` stay free of a `plugin-loader`
/// dependency (the engine wires the registry in at `build_app`); `None` = no plugin subsystem, so
/// only the built-ins resolve.
pub(crate) struct SecretResolver {
    /// Resolve one non-built-in reference through a loaded `kind: secret` plugin: given the module
    /// name + its settings JSON, return the secret bytes (or a fail-closed error). `None` when no
    /// plugin registry is available (built-ins only).
    plugin: Option<PluginResolveFn>,
}

/// The boxed closure a [`SecretResolver`] delegates a non-built-in module to: `(module, settings
/// JSON) -> secret bytes` (fail-closed on error). Boxed so `config` stays free of a `plugin-loader`
/// dependency (the engine wires the registry in at `build_app`).
pub(crate) type PluginResolveFn = Box<dyn Fn(&str, &str) -> Result<Vec<u8>, String> + Send + Sync>;

impl SecretResolver {
    /// A built-ins-only resolver (no plugin subsystem): `env` / `file` resolve, everything else is
    /// fail-closed. The zero-plugin resolver used by tests and any path with no registry.
    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn builtins_only() -> Self {
        Self { plugin: None }
    }

    /// A resolver whose non-built-in modules resolve through `plugin` (a `kind: secret` plugin
    /// loader). Built-ins still short-circuit to the inline `env` / `file` path.
    pub(crate) fn with_plugin(plugin: PluginResolveFn) -> Self {
        Self {
            plugin: Some(plugin),
        }
    }

    /// Resolve a reference to raw bytes. `env` / `file` are built in; any other module delegates to
    /// the plugin resolver (fail-closed if none is wired or it fails).
    pub(crate) fn resolve(&self, secret: &SecretRef) -> Result<Vec<u8>, String> {
        match secret.module.as_str() {
            SECRET_MODULE_ENV | SECRET_MODULE_FILE => resolve_builtin(secret),
            module => match &self.plugin {
                Some(f) => {
                    let settings = serde_json::Value::Object(secret.settings.clone()).to_string();
                    let bytes = f(module, &settings).map_err(|e| {
                        format!(
                            "secret module '{module}' (a kind: secret plugin) failed to resolve \
                             {}: {e}",
                            secret.describe()
                        )
                    })?;
                    if bytes.is_empty() {
                        return Err(format!(
                            "secret module '{module}' resolved {} to an EMPTY value; a secret must \
                             be non-empty (fail-closed)",
                            secret.describe()
                        ));
                    }
                    Ok(bytes)
                }
                None => Err(format!(
                    "secret module '{module}' is not a built-in (`env` / `file`) and the plugin \
                     subsystem is not enabled, so no secret plugin can resolve {}; a secret that \
                     cannot resolve is a hard error (fail-closed)",
                    secret.describe()
                )),
            },
        }
    }

    /// Resolve to a UTF-8 STRING (trailing newline trimmed; fail-closed on non-UTF-8 or empty).
    /// The string-secret convenience twin of [`Self::resolve`], mirroring [`resolve_builtin_string`].
    pub(crate) fn resolve_string(&self, secret: &SecretRef) -> Result<String, String> {
        let bytes = self.resolve(secret)?;
        let s = String::from_utf8(bytes).map_err(|_| {
            format!(
                "secret {} resolved to non-UTF-8 bytes where a text secret is required",
                secret.describe()
            )
        })?;
        let trimmed = s.trim_end_matches(['\r', '\n']);
        if trimmed.is_empty() {
            return Err(format!(
                "secret {} resolved to an empty value after trimming trailing newlines \
                 (fail-closed)",
                secret.describe()
            ));
        }
        Ok(trimmed.to_string())
    }
}

/// P1-internal BUILT-IN resolution of a secret reference to its raw bytes: `env` reads the
/// environment variable; `file` reads the file. Any other module name is FAIL-CLOSED here — the
/// full secret-plugin resolver (third-party `kind: secret` modules through the plugin trust
/// pipeline) is layered on top of this by [`SecretResolver`], which falls back to these built-ins
/// by these exact names.
pub(crate) fn resolve_builtin(secret: &SecretRef) -> Result<Vec<u8>, String> {
    if let Some(var) = self_env_var_checked(secret)? {
        return match std::env::var(&var) {
            Ok(v) if !v.is_empty() => Ok(v.into_bytes()),
            Ok(_) => Err(format!(
                "secret env:{var} resolved to an EMPTY value; a secret must be non-empty \
                 (fail-closed)"
            )),
            Err(_) => Err(format!(
                "secret env:{var} cannot resolve: environment variable '{var}' is unset"
            )),
        };
    }
    if let Some(path) = self_file_path_checked(secret)? {
        return match std::fs::read(&path) {
            Ok(bytes) if !bytes.is_empty() => Ok(bytes),
            Ok(_) => Err(format!(
                "secret file:{path} resolved to an EMPTY file; a secret must be non-empty \
                 (fail-closed)"
            )),
            Err(e) => Err(format!("secret file:{path} cannot resolve: {e}")),
        };
    }
    Err(format!(
        "secret module '{}' is not a built-in (`env` / `file`) and no secret plugin provides it; \
         a secret that cannot resolve is a hard error (fail-closed)",
        secret.module
    ))
}

/// The `env` module's variable name, validating the settings shape (a malformed built-in ref must
/// fail loudly, not fall through to "unknown module").
fn self_env_var_checked(secret: &SecretRef) -> Result<Option<String>, String> {
    if secret.module != SECRET_MODULE_ENV {
        return Ok(None);
    }
    match secret.env_var() {
        Some(v) if !v.trim().is_empty() => Ok(Some(v.to_string())),
        _ => Err(
            "secret module 'env' requires settings.key naming the environment variable \
             (e.g. `{ env: MY_VAR }` or `{ module: env, settings: { key: MY_VAR } }`)"
                .to_string(),
        ),
    }
}

/// The `file` module's path, validating the settings shape.
fn self_file_path_checked(secret: &SecretRef) -> Result<Option<String>, String> {
    if secret.module != SECRET_MODULE_FILE {
        return Ok(None);
    }
    match secret.file_path() {
        Some(p) if !p.trim().is_empty() => Ok(Some(p.to_string())),
        _ => Err(
            "secret module 'file' requires settings.path naming the file \
             (e.g. `{ file: /run/secrets/x }` or `{ module: file, settings: { path: /run/secrets/x } }`)"
                .to_string(),
        ),
    }
}

/// Resolve a secret reference to a UTF-8 STRING (trailing newline trimmed — the universal
/// file-delivered-secret convention). Fail-closed on non-UTF-8.
pub(crate) fn resolve_builtin_string(secret: &SecretRef) -> Result<String, String> {
    let bytes = resolve_builtin(secret)?;
    let s = String::from_utf8(bytes).map_err(|_| {
        format!(
            "secret {} resolved to non-UTF-8 bytes where a text secret is required",
            secret.describe()
        )
    })?;
    let trimmed = s.trim_end_matches(['\r', '\n']);
    if trimmed.is_empty() {
        return Err(format!(
            "secret {} resolved to an empty value after trimming trailing newlines (fail-closed)",
            secret.describe()
        ));
    }
    Ok(trimmed.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The env built-in resolves a set variable, trims trailing newlines in the string form, and
    /// fails closed on unset / empty values.
    #[test]
    fn env_module_resolves_and_fails_closed() {
        let var = format!("BUSBAR_SECRET_TEST_{}", std::process::id());
        std::env::set_var(&var, "s3cret\n");
        let r = SecretRef::env(&var);
        assert_eq!(resolve_builtin(&r).unwrap(), b"s3cret\n");
        assert_eq!(resolve_builtin_string(&r).unwrap(), "s3cret");
        std::env::remove_var(&var);
        let err = resolve_builtin(&r).unwrap_err();
        assert!(err.contains("unset"), "unset env is fail-closed: {err}");
        std::env::set_var(&var, "");
        let err = resolve_builtin(&r).unwrap_err();
        assert!(err.contains("EMPTY"), "empty env is fail-closed: {err}");
        std::env::remove_var(&var);
    }

    /// The file built-in resolves file bytes and fails closed on a missing or empty file.
    #[test]
    fn file_module_resolves_and_fails_closed() {
        let path = std::env::temp_dir().join(format!("busbar-secret-{}.txt", std::process::id()));
        std::fs::write(&path, b"file-secret\n").unwrap();
        let r = SecretRef::file(path.to_string_lossy().into_owned());
        assert_eq!(resolve_builtin(&r).unwrap(), b"file-secret\n");
        assert_eq!(resolve_builtin_string(&r).unwrap(), "file-secret");
        std::fs::write(&path, b"").unwrap();
        let err = resolve_builtin(&r).unwrap_err();
        assert!(err.contains("EMPTY"), "empty file is fail-closed: {err}");
        let _ = std::fs::remove_file(&path);
        let err = resolve_builtin(&r).unwrap_err();
        assert!(err.contains("cannot resolve"), "missing file fails: {err}");
    }

    /// An unknown secret module is FAIL-CLOSED at the built-in resolver (the plugin-backed
    /// resolver layers on top; anything it cannot resolve lands here and refuses).
    #[test]
    fn unknown_module_fails_closed() {
        let r = SecretRef {
            module: "vault".to_string(),
            settings: serde_json::Map::new(),
        };
        let err = resolve_builtin(&r).unwrap_err();
        assert!(
            err.contains("fail-closed") && err.contains("vault"),
            "unknown module refuses: {err}"
        );
    }

    /// Malformed built-in refs (env without key, file without path) error precisely, never fall
    /// through to "unknown module".
    #[test]
    fn malformed_builtin_refs_error_precisely() {
        let r = SecretRef {
            module: SECRET_MODULE_ENV.to_string(),
            settings: serde_json::Map::new(),
        };
        assert!(resolve_builtin(&r).unwrap_err().contains("settings.key"));
        let r = SecretRef {
            module: SECRET_MODULE_FILE.to_string(),
            settings: serde_json::Map::new(),
        };
        assert!(resolve_builtin(&r).unwrap_err().contains("settings.path"));
    }

    /// Deserialize: the `{env}` / `{file}` sugar desugars to the canonical module + settings; the
    /// canonical form parses; mixed / unknown / empty forms are rejected.
    #[test]
    fn deserialize_accepts_canonical_and_sugar_rejects_malformed() {
        let r: SecretRef = serde_yaml::from_str("{ env: MY_VAR }").unwrap();
        assert_eq!(r, SecretRef::env("MY_VAR"));
        assert_eq!(r.env_var(), Some("MY_VAR"));
        let r: SecretRef = serde_yaml::from_str("{ file: /run/secrets/x }").unwrap();
        assert_eq!(r, SecretRef::file("/run/secrets/x"));
        assert_eq!(r.file_path(), Some("/run/secrets/x"));
        let r: SecretRef =
            serde_yaml::from_str("{ module: vault, settings: { path: kv/data/x } }").unwrap();
        assert_eq!(r.module, "vault");
        assert_eq!(
            r.settings.get("path").and_then(|v| v.as_str()),
            Some("kv/data/x")
        );

        for bad in [
            "{ env: A, file: B }",
            "{ module: vault, env: A }",
            "{ env: A, settings: {} }",
            "{ unknown_key: A }",
            "{}",
            "{ env: \"\" }",
            "{ module: \"\" }",
            "plain-string",
        ] {
            assert!(
                serde_yaml::from_str::<SecretRef>(bad).is_err(),
                "must reject: {bad}"
            );
        }
    }
}

#[cfg(test)]
mod resolver_tests {
    use super::*;

    /// The resolver's built-in arm resolves env/file inline WITHOUT any plugin.
    #[test]
    fn resolver_builtins_resolve_without_plugin() {
        let r = SecretResolver::builtins_only();
        let var = format!("BUSBAR_RESOLVER_TEST_{}", std::process::id());
        std::env::set_var(&var, "abc\n");
        assert_eq!(r.resolve(&SecretRef::env(&var)).unwrap(), b"abc\n");
        assert_eq!(r.resolve_string(&SecretRef::env(&var)).unwrap(), "abc");
        std::env::remove_var(&var);
    }

    /// A non-built-in module with NO plugin subsystem is FAIL-CLOSED, naming the module.
    #[test]
    fn resolver_unknown_module_without_plugin_fails_closed() {
        let r = SecretResolver::builtins_only();
        let s = SecretRef {
            module: "vault".to_string(),
            settings: serde_json::Map::new(),
        };
        let err = r.resolve(&s).unwrap_err();
        assert!(
            err.contains("vault") && err.contains("fail-closed"),
            "unknown module with no plugin refuses: {err}"
        );
    }

    /// A non-built-in module DELEGATES to the plugin resolver; a plugin error and an empty result
    /// are both fail-closed.
    #[test]
    fn resolver_delegates_to_plugin_and_fails_closed_on_empty_or_error() {
        // Plugin that returns bytes for `vault` and errors for anything else.
        let r = SecretResolver::with_plugin(Box::new(|module: &str, settings: &str| {
            if module == "vault" {
                let v: serde_json::Value = serde_json::from_str(settings).unwrap();
                match v.get("path").and_then(|p| p.as_str()) {
                    Some("kv/ok") => Ok(b"plugin-secret".to_vec()),
                    Some("kv/empty") => Ok(Vec::new()),
                    _ => Err("no such path".to_string()),
                }
            } else {
                Err("unknown module".to_string())
            }
        }));
        let mk = |path: &str| {
            let mut settings = serde_json::Map::new();
            settings.insert(
                "path".to_string(),
                serde_json::Value::String(path.to_string()),
            );
            SecretRef {
                module: "vault".to_string(),
                settings,
            }
        };
        assert_eq!(r.resolve(&mk("kv/ok")).unwrap(), b"plugin-secret");
        // Empty plugin result is rejected (fail-closed), never an empty secret.
        assert!(r.resolve(&mk("kv/empty")).unwrap_err().contains("EMPTY"));
        // Plugin error is surfaced fail-closed.
        assert!(r
            .resolve(&mk("kv/missing"))
            .unwrap_err()
            .contains("failed to resolve"));
        // Built-ins still short-circuit past the plugin.
        let var = format!("BUSBAR_RESOLVER_PLUGIN_TEST_{}", std::process::id());
        std::env::set_var(&var, "envval");
        assert_eq!(r.resolve_string(&SecretRef::env(&var)).unwrap(), "envval");
        std::env::remove_var(&var);
    }
}
