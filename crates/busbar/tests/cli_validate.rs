// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! END-TO-END CLI regression tests for `busbar --validate` and `busbar --list-plugins`, driving the
//! REAL binary (`CARGO_BIN_EXE_busbar`) against generated config + plugin-tarball fixtures. These
//! pin the three hard 1.5.0 acceptance properties at the outermost surface:
//!
//! 1. FAIL-CLOSED: a bad config.yaml or ANY bad/conflicting plugin manifest exits 1 with a loud,
//!    named error (never a partial success).
//! 2. `--validate` validates EVERYTHING (config + every plugin manifest + store resolution) with
//!    zero side effects and matches boot behavior (it runs the same shared preflight).
//! 3. `--list-plugins` is a MANIFEST-ONLY inventory: correct per-plugin status, and it must
//!    succeed (exit 0) even over a directory of untrusted/invalid artifacts, proving nothing is
//!    loaded from listing.
//!
//! Each test gets an isolated temp workspace (its own config/providers/plugins), so no test shares
//! or mutates process-global state.

use std::path::{Path, PathBuf};
use std::process::Command;

/// A fresh, isolated fixture directory.
fn fixture_dir(tag: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!(
        "busbar-cli-validate-{}-{tag}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(d.join("plugins")).unwrap();
    d
}

/// A minimal VALID providers.yaml + config.yaml pair. `extra` is appended verbatim to config.yaml
/// (the governance/plugins blocks under test).
fn write_configs(dir: &Path, extra: &str) {
    std::fs::write(
        dir.join("providers.yaml"),
        r#"mock:
  protocol: anthropic
  base_url: "http://127.0.0.1:9"
  api_key_env: MOCK_KEY
"#,
    )
    .unwrap();
    std::fs::write(
        dir.join("config.yaml"),
        format!(
            r#"listen: "127.0.0.1:0"
providers:
  mock:
    api_key_env: MOCK_KEY
models:
  test-model:
    provider: mock
{extra}"#
        ),
    )
    .unwrap();
}

/// Run the real busbar binary with the fixture's config env; returns (exit_code, stdout, stderr).
fn run_busbar(dir: &Path, args: &[&str]) -> (i32, String, String) {
    let out = Command::new(env!("CARGO_BIN_EXE_busbar"))
        .args(args)
        .env("BUSBAR_CONFIG", dir.join("config.yaml"))
        .env("BUSBAR_PROVIDERS", dir.join("providers.yaml"))
        .output()
        .expect("run busbar");
    (
        out.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

/// An UNSIGNED (structurally valid) plugin tarball written into the fixture's plugins dir.
fn write_tarball(dir: &Path, file: &str, name: &str, alias: &str, lib: &[u8]) {
    let m = busbar_plugin_sign::Manifest {
        name: name.into(),
        alias: alias.into(),
        kind: "store".into(),
        version: "1.5.0".into(),
        publisher: "acme".into(),
        abi_version: 1,
        sha256: busbar_plugin_sign::sha256_hex(lib),
        signature: String::new(),
        description: String::new(),
        homepage: String::new(),
        license: String::new(),
    };
    let bytes = busbar_plugin_loader::tarball::package(&m, "lib.so", lib).unwrap();
    std::fs::write(dir.join("plugins").join(file), bytes).unwrap();
}

/// The plugins block pointing at this fixture's dir (yaml-escaped path).
fn plugins_block(dir: &Path, enabled: bool, allow_unsigned: bool) -> String {
    format!(
        "plugins:\n  enabled: {enabled}\n  dir: \"{}\"\n  trust:\n    allow_unsigned: {allow_unsigned}\n",
        dir.join("plugins").display()
    )
}

/// Baseline: a valid config with no plugins block validates clean (exit 0) and reports plugins
/// disabled.
#[test]
fn validate_ok_on_valid_config_without_plugins() {
    let dir = fixture_dir("ok");
    write_configs(&dir, "");
    let (code, stdout, stderr) = run_busbar(&dir, &["--validate"]);
    assert_eq!(code, 0, "stdout={stdout} stderr={stderr}");
    assert!(stdout.contains("ok: config valid"), "got {stdout}");
    assert!(stdout.contains("plugins:   disabled"), "got {stdout}");
    let _ = std::fs::remove_dir_all(&dir);
}

/// FAIL-CLOSED on a BAD config.yaml: an unknown key exits 1 with the offending key named.
#[test]
fn validate_fails_on_unknown_config_key() {
    let dir = fixture_dir("badkey");
    write_configs(&dir, "goovernance:\n  admin_token: x\n");
    let (code, _stdout, stderr) = run_busbar(&dir, &["--validate"]);
    assert_eq!(code, 1);
    assert!(
        stderr.contains("goovernance"),
        "names the bad key: {stderr}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// FAIL-CLOSED (hard requirement 1+2): `governance.store: redis` with plugins disabled exits 1
/// naming `plugins.enabled` — the exact same refusal boot performs.
#[test]
fn validate_fails_when_store_plugin_referenced_but_plugins_disabled() {
    let dir = fixture_dir("disabled");
    write_configs(&dir, "governance:\n  store: redis\n");
    let (code, _stdout, stderr) = run_busbar(&dir, &["--validate"]);
    assert_eq!(code, 1);
    assert!(
        stderr.contains("plugins.enabled"),
        "names the flag: {stderr}"
    );
    assert!(stderr.contains("redis"), "names the store: {stderr}");
    let _ = std::fs::remove_dir_all(&dir);
}

/// FAIL-CLOSED: ANY invalid tarball in an enabled plugins dir fails --validate naming the file,
/// even when no plugin is referenced by the config.
#[test]
fn validate_fails_on_invalid_tarball_in_enabled_dir() {
    let dir = fixture_dir("invalid");
    std::fs::write(dir.join("plugins/junk.tar.gz"), b"not a tarball").unwrap();
    write_configs(&dir, &plugins_block(&dir, true, false));
    let (code, _stdout, stderr) = run_busbar(&dir, &["--validate"]);
    assert_eq!(code, 1);
    assert!(stderr.contains("junk.tar.gz"), "names the file: {stderr}");
    assert!(stderr.contains("plugin validation failed"), "got {stderr}");
    let _ = std::fs::remove_dir_all(&dir);
}

/// FAIL-CLOSED: a sha256-mismatched (tampered) manifest fails --validate with the integrity reason.
#[test]
fn validate_fails_on_sha_mismatch() {
    let dir = fixture_dir("sha");
    let m = busbar_plugin_sign::Manifest {
        name: "acme-store-x".into(),
        alias: "x".into(),
        kind: "store".into(),
        version: "1.5.0".into(),
        publisher: "acme".into(),
        abi_version: 1,
        sha256: busbar_plugin_sign::sha256_hex(b"OTHER bytes"),
        signature: String::new(),
        description: String::new(),
        homepage: String::new(),
        license: String::new(),
    };
    let bytes = busbar_plugin_loader::tarball::package(&m, "lib.so", b"real bytes").unwrap();
    std::fs::write(dir.join("plugins/x.tar.gz"), bytes).unwrap();
    write_configs(&dir, &plugins_block(&dir, true, false));
    let (code, _stdout, stderr) = run_busbar(&dir, &["--validate"]);
    assert_eq!(code, 1);
    assert!(
        stderr.contains("integrity"),
        "names the sha mismatch: {stderr}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// FAIL-CLOSED: referencing an UNSIGNED plugin store under the strict default posture exits 1
/// naming the opt-in flag; with allow_unsigned it validates clean and the summary reports the
/// validated plugin — proving --validate exercises the trust gate exactly as boot does.
#[test]
fn validate_trust_gate_matches_boot() {
    let dir = fixture_dir("trust");
    write_tarball(
        &dir,
        "sqlite.tar.gz",
        "busbar-store-sqlite",
        "sqlite",
        b"lib",
    );
    write_configs(
        &dir,
        &format!(
            "{}governance:\n  store: sqlite\n",
            plugins_block(&dir, true, false)
        ),
    );
    let (code, _stdout, stderr) = run_busbar(&dir, &["--validate"]);
    assert_eq!(code, 1);
    assert!(
        stderr.contains("allow_unsigned"),
        "names the opt-in: {stderr}"
    );

    // Same fixture with the opt-in: clean.
    write_configs(
        &dir,
        &format!(
            "{}governance:\n  store: sqlite\n",
            plugins_block(&dir, true, true)
        ),
    );
    let (code, stdout, stderr) = run_busbar(&dir, &["--validate"]);
    assert_eq!(code, 0, "stderr={stderr}");
    assert!(stdout.contains("1 validated"), "got {stdout}");
    let _ = std::fs::remove_dir_all(&dir);
}

/// FAIL-CLOSED (conflict): two plugins claiming the same alias fail --validate naming BOTH.
#[test]
fn validate_fails_on_alias_conflict_naming_both() {
    let dir = fixture_dir("conflict");
    write_tarball(&dir, "a.tar.gz", "busbar-store-redis", "redis", b"a");
    write_tarball(&dir, "b.tar.gz", "acme-store-redis", "redis", b"b");
    write_configs(&dir, &plugins_block(&dir, true, true));
    let (code, _stdout, stderr) = run_busbar(&dir, &["--validate"]);
    assert_eq!(code, 1);
    assert!(
        stderr.contains("busbar-store-redis") && stderr.contains("acme-store-redis"),
        "names both: {stderr}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// `--list-plugins` prints a manifest-only inventory with the correct status per row — and exits 0
/// even over untrusted + invalid artifacts (nothing is loaded from listing).
#[test]
fn list_plugins_reports_statuses_without_loading() {
    let dir = fixture_dir("list");
    write_tarball(&dir, "good.tar.gz", "busbar-store-sqlite", "sqlite", b"g");
    write_tarball(&dir, "third.tar.gz", "acme-store-dynamo", "dynamo", b"t");
    std::fs::write(dir.join("plugins/junk.tar.gz"), b"garbage").unwrap();
    // allow_unsigned so the sqlite one is loadable; the store selects it.
    write_configs(
        &dir,
        &format!(
            "{}governance:\n  store: sqlite\n",
            plugins_block(&dir, true, true)
        ),
    );
    let (code, stdout, _stderr) = run_busbar(&dir, &["--list-plugins"]);
    assert_eq!(code, 0, "list-plugins is informational: {stdout}");
    assert!(
        stdout.contains("LOADS (governance.store: sqlite)"),
        "the selected store row: {stdout}"
    );
    assert!(stdout.contains("busbar-store-sqlite"), "{stdout}");
    assert!(stdout.contains("acme-store-dynamo"), "{stdout}");
    assert!(stdout.contains("ready"), "{stdout}");
    assert!(stdout.contains("INVALID"), "the junk row: {stdout}");
    let _ = std::fs::remove_dir_all(&dir);
}
