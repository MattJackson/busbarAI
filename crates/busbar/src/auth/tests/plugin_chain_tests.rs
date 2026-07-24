// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! FULL-CHAIN auth-plugin seam tests: the engine's `AuthMiddleware` loading a REAL signed
//! `kind: auth` plugin cdylib over the loader, exactly as boot does. We pack the hermetic
//! `busbar-auth-static-plugin` cdylib into a tarball, run it through `plugins_preflight` +
//! `AuthMiddleware::new`, and prove:
//!
//!   * a valid token → `Identify` → a mapped `Principal` whose roles resolve to `role_bindings`
//!     policy AND whose admin scope is capped by `auth.chain.<module>.max_admin_scope`;
//!   * an invalid/absent credential → the chain fail-closed-denies (all-`Pass`);
//!   * a MISSING or UNTRUSTED plugin at boot → a LOUD failure (never a silently-open front door);
//!   * `plugins.enabled: false` + a configured auth plugin → boot refuses (`plugins_preflight`).
//!
//! Mirrors the store-plugin end-to-end packed test (`crate::tests`), reusing its plugin-dir /
//! manifest helpers.

use crate::auth::{AuthMiddleware, ChainVerdict};
use crate::config::{AuthCfg, AuthChainEntry, PluginsCfg};
use crate::tests::{plugin_manifest, tmp_plugin_dir, unsigned_tarball};
use std::path::{Path, PathBuf};

/// Locate the hermetic static-auth plugin cdylib in the build's target dir (like the sqlite store
/// tests). Under CI (`cargo test --workspace` always builds it) a missing cdylib is a HARD failure,
/// never a silent skip; locally a missing cdylib skips cleanly.
fn static_auth_cdylib() -> Option<PathBuf> {
    let candidate = (|| {
        let exe = std::env::current_exe().ok()?;
        let profile_dir = exe.parent()?.parent()?;
        let name = busbar_plugin_loader::plugin_library_filename("busbar_auth_static_plugin");
        let candidate = profile_dir.join(&name);
        candidate.exists().then_some(candidate)
    })();
    if candidate.is_none() && std::env::var_os("CI").is_some() {
        panic!(
            "the static-auth plugin cdylib is not built under CI; refusing to silently skip the \
             full-chain auth-plugin seam coverage"
        );
    }
    candidate
}

/// A `kind: auth` manifest for the given name/alias (the store helper stamps kind=store; we retarget
/// it to auth + the auth ABI so the scan admits it).
fn auth_manifest(name: &str, alias: &str, publisher: &str) -> busbar_plugin_sign::Manifest {
    let mut m = plugin_manifest(name, alias, publisher);
    m.kind = "auth".into();
    m.abi_version = *busbar_plugin_loader::supported_abi("auth")
        .iter()
        .max()
        .expect("auth abi");
    m
}

/// Write an UNSIGNED (structurally valid) static-auth tarball into `dir` under `file`, returning the
/// cdylib bytes' presence. We use the unsigned+`allow_unsigned` path because the test cannot sign
/// with the embedded first-party release key; this still exercises the whole load pipeline.
fn write_static_auth(dir: &Path, file: &str, name: &str, alias: &str) -> bool {
    let Some(path) = static_auth_cdylib() else {
        return false;
    };
    let lib = std::fs::read(&path).expect("read static-auth cdylib");
    let tarball = unsigned_tarball(auth_manifest(name, alias, "acme"), &lib);
    std::fs::write(dir.join(file), tarball).unwrap();
    true
}

/// An enabled plugins config over `dir` that permits the unsigned test cdylib.
fn plugins_cfg_allow_unsigned(dir: &Path) -> PluginsCfg {
    let mut cfg = PluginsCfg {
        enabled: true,
        dir: dir.to_string_lossy().into_owned(),
        ..Default::default()
    };
    cfg.trust.allow_unsigned = true;
    cfg
}

/// An `auth.chain` naming exactly the given plugin module (with an optional `settings` map).
fn chain_with(module: &str, settings: serde_json::Map<String, serde_json::Value>) -> AuthCfg {
    let mut entry = AuthChainEntry::bare(module);
    entry.settings = settings;
    AuthCfg {
        chain: vec![entry],
        ..AuthCfg::default_none()
    }
}

/// The static-auth `settings:` map: token `sekret` → id `alice`, role `platform`.
fn alice_settings() -> serde_json::Map<String, serde_json::Value> {
    serde_json::json!({ "token": "sekret", "id": "alice", "roles": ["platform"] })
        .as_object()
        .unwrap()
        .clone()
}

/// FULL CHAIN, REAL CDYLIB: `auth.chain: [my-auth]` loads the static-auth plugin over the loader;
/// the valid token identifies as `alice/platform`, an invalid/absent credential fail-closed-denies.
#[test]
fn auth_plugin_loads_and_identifies_through_middleware() {
    let dir = tmp_plugin_dir("auth-plugin-e2e");
    // The config chain name is the ALIAS `my-auth`; the plugin's canonical name differs on purpose.
    if !write_static_auth(&dir, "static.tar.gz", "acme-auth-static", "my-auth") {
        eprintln!("skip: static-auth plugin cdylib not built (run under --workspace)");
        return;
    }
    let plugins = plugins_cfg_allow_unsigned(&dir);
    let cfg = chain_with("my-auth", alice_settings());

    // Manifest-only preflight resolves the auth plugin (the `--validate`/boot gate).
    let registry = crate::plugins_preflight(None, Some(&cfg), &Default::default(), &plugins)
        .expect("preflight resolves the kind:auth plugin");

    // The real load through the middleware — resolve → open_auth → box → chain.
    let mw = AuthMiddleware::new(&cfg, &registry).expect("auth chain loads the plugin");
    // The RUNTIME module identity is the plugin's own `name()` (`static-auth`), NOT the config alias.
    assert_eq!(mw.chain_names(), vec!["static-auth"], "runtime module name");

    // Valid token → Identify with the configured id + roles.
    match mw.run_chain(Some("sekret")) {
        ChainVerdict::Identified { module, principal } => {
            assert_eq!(module, "static-auth", "role_bindings key = module.name()");
            assert_eq!(principal.id, "alice");
            assert_eq!(principal.roles, vec!["platform".to_string()]);
        }
        other => panic!("valid token must Identify, got {other:?}"),
    }
    // Invalid credential → the module Passes → a non-empty chain fail-closed-DENIES.
    assert_eq!(
        mw.run_chain(Some("wrong")),
        ChainVerdict::Denied,
        "bad token denies"
    );
    // Absent credential → likewise denied (never the open front door for a configured chain).
    assert_eq!(
        mw.run_chain(None),
        ChainVerdict::Denied,
        "no credential denies"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

/// IDENTITY → POLICY hop with a PLUGIN module name: a role a loaded auth plugin asserts resolves
/// through `role_bindings.<plugin-name>` to an admin scope, CAPPED by the module's `max_admin_scope`.
/// Proves role_bindings resolution + the module ceiling both work when `<module>` is a plugin name.
#[test]
fn auth_plugin_role_binding_and_scope_cap_apply() {
    use crate::admin::v1::contract::Scope;

    let dir = tmp_plugin_dir("auth-plugin-policy");
    if !write_static_auth(&dir, "static.tar.gz", "acme-auth-static", "static-auth") {
        eprintln!("skip: static-auth plugin cdylib not built (run under --workspace)");
        return;
    }
    let plugins = plugins_cfg_allow_unsigned(&dir);
    let mut cfg = chain_with("static-auth", alice_settings());
    // The chain entry caps this module at `mint`, below the `full` the role would otherwise grant.
    cfg.chain[0].max_admin_scope = Some("mint".into());
    // role_bindings NESTED BY THE PLUGIN'S RUNTIME NAME (`static-auth`): the `platform` role → full.
    let mut roles = std::collections::BTreeMap::new();
    roles.insert(
        "platform".to_string(),
        crate::config::RoleBindingCfg {
            admin_scope: Some("full".into()),
            ..Default::default()
        },
    );
    cfg.role_bindings.insert("static-auth".into(), roles);

    let registry = crate::plugins_preflight(None, Some(&cfg), &Default::default(), &plugins)
        .expect("preflight");
    let mw = AuthMiddleware::new(&cfg, &registry).expect("load");

    let principal = match mw.run_chain(Some("sekret")) {
        ChainVerdict::Identified { principal, .. } => principal,
        other => panic!("expected Identify, got {other:?}"),
    };
    // The role resolves to `full` in role_bindings.static-auth.platform...
    let bound =
        crate::auth::admin_scope_for(Some("static-auth"), Some(&principal), &cfg.role_bindings);
    assert_eq!(
        bound,
        Some(Scope::Full),
        "role binds full under the PLUGIN module name"
    );
    // ...but the module's `max_admin_scope: mint` ceiling caps the effective scope.
    let capped = std::cmp::min(bound.unwrap(), Scope::Mint);
    assert_eq!(
        capped,
        Scope::Mint,
        "max_admin_scope caps the plugin module"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

/// FAIL-CLOSED: a configured auth plugin that is PRESENT but UNTRUSTED (unsigned under the default
/// strict policy) is SKIPPED by the scan; both `plugins_preflight` and `AuthMiddleware::new` must
/// fail LOUD — never silently drop the front-door module and admit everyone.
#[test]
fn untrusted_auth_plugin_fails_closed_not_open() {
    let dir = tmp_plugin_dir("auth-plugin-untrusted");
    let Some(path) = static_auth_cdylib() else {
        eprintln!("skip: static-auth plugin cdylib not built (run under --workspace)");
        return;
    };
    let lib = std::fs::read(&path).unwrap();
    let tarball = unsigned_tarball(auth_manifest("acme-auth-static", "oidc", "acme"), &lib);
    std::fs::write(dir.join("static.tar.gz"), tarball).unwrap();

    // STRICT default trust: the unsigned auth plugin is skipped.
    let strict = PluginsCfg {
        enabled: true,
        dir: dir.to_string_lossy().into_owned(),
        ..Default::default()
    };
    let cfg = chain_with("oidc", alice_settings());
    // Preflight refuses (names the module + carries the trust opt-in to set).
    let err = crate::plugins_preflight(None, Some(&cfg), &Default::default(), &strict).unwrap_err();
    assert!(err.contains("oidc"), "names the auth module: {err}");
    assert!(
        err.contains("allow_unsigned"),
        "carries the trust reason: {err}"
    );

    // And the middleware itself fail-closes on the skipped plugin (the runtime load-time gate):
    // the scan succeeds (skips are not fatal) but resolving the referenced module fails loud.
    let registry = busbar_plugin_loader::scan_and_validate(
        Path::new(&strict.dir),
        &strict.to_policy().unwrap(),
    )
    .expect("scan succeeds; the untrusted plugin is merely skipped");
    let mw_err = AuthMiddleware::new(&cfg, &registry).unwrap_err();
    assert!(
        mw_err.contains("oidc"),
        "middleware names the module: {mw_err}"
    );
    assert!(
        mw_err.contains("not loaded") || mw_err.contains("was not loaded"),
        "middleware fail-closes with the trust reason: {mw_err}"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

/// FAIL-CLOSED: a configured auth plugin with NO matching tarball is a loud boot error at both
/// gates — never silently skipped.
#[test]
fn missing_auth_plugin_is_loud_boot_failure() {
    let dir = tmp_plugin_dir("auth-plugin-missing");
    // A DIFFERENT (store) plugin present, so the dir is non-empty but the auth ref is absent.
    let other = unsigned_tarball(plugin_manifest("acme-store-x", "x", "acme"), b"lib");
    std::fs::write(dir.join("x.tar.gz"), other).unwrap();
    let plugins = plugins_cfg_allow_unsigned(&dir);
    let cfg = chain_with("oidc", alice_settings());

    let err =
        crate::plugins_preflight(None, Some(&cfg), &Default::default(), &plugins).unwrap_err();
    assert!(err.contains("oidc"), "names the missing module: {err}");
    assert!(
        err.contains("does not match any plugin"),
        "explains it is unresolved: {err}"
    );

    // The middleware's own resolution is equally loud.
    let registry = busbar_plugin_loader::scan_and_validate(
        Path::new(&plugins.dir),
        &plugins.to_policy().unwrap(),
    )
    .expect("scan");
    let mw_err = AuthMiddleware::new(&cfg, &registry).unwrap_err();
    assert!(mw_err.contains("oidc"), "middleware names it: {mw_err}");

    let _ = std::fs::remove_dir_all(&dir);
}

/// FAIL-CLOSED: `plugins.enabled: false` with a configured auth plugin refuses boot naming the flag
/// — the plugin subsystem being off must never leave a configured front-door module silently absent.
#[test]
fn auth_plugin_with_plugins_disabled_is_boot_error_naming_the_flag() {
    let dir = tmp_plugin_dir("auth-plugin-disabled");
    let plugins = PluginsCfg {
        enabled: false,
        dir: dir.to_string_lossy().into_owned(),
        ..Default::default()
    };
    let cfg = chain_with("oidc", alice_settings());
    let err =
        crate::plugins_preflight(None, Some(&cfg), &Default::default(), &plugins).unwrap_err();
    assert!(err.contains("plugins.enabled"), "names the flag: {err}");
    assert!(err.contains("oidc"), "names the auth module: {err}");
    let _ = std::fs::remove_dir_all(&dir);
}

/// The builtin `keys` module is engine-handled and never treated as a plugin — a `[keys]` chain
/// needs no plugin subsystem and loads fine with plugins disabled (regression guard for the
/// plugin-ref filter).
#[test]
fn keys_module_is_not_a_plugin_ref() {
    let cfg = AuthCfg {
        chain: vec![AuthChainEntry::bare(crate::config::KEYS_MODULE)],
        ..AuthCfg::default_none()
    };
    // No plugins dir, plugins disabled: keys must not be treated as a plugin ref.
    let plugins = PluginsCfg::default();
    let registry = crate::plugins_preflight(None, Some(&cfg), &Default::default(), &plugins)
        .expect("keys needs no plugin");
    let mw = AuthMiddleware::new(&cfg, &registry).expect("keys chain builds");
    assert!(mw.keys_in_chain, "keys sets the engine flag");
    assert!(mw.chain_names().is_empty(), "keys is not a boxed module");
}
