// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Tests for the 1.4.x -> 1.5.0 config migrator + the loud fail-closed 1.x detector (P9).

use super::*;

/// A representative 1.4.x config exercising every deterministic transform at once.
const LEGACY_14X: &str = r#"
listen: "0.0.0.0:8080"
auth:
  chain: ["oidc"]
  group_map:
    growth-eng:
      allowed_pools: [fast]
      group: growth
    platform:
      allowed_pools: []
      admin_scope: full
    capped:
      rpm_limit: 60
      tpm_limit: 100000
      max_budget_cents: 5000
      budget_period: monthly
governance:
  enabled: true
  store: postgres
  db_path: "postgres://host/db"
  admin_token: "${BUSBAR_ADMIN_TOKEN}"
  price_per_request_cents: 2
  rate_sweep_interval: 128
  usage_flush_interval_ms: 50
  rate_card:
    claude: { input_utok: 3.0, output_utok: 15.0 }
  budget_groups:
    acme: { max_budget_cents: 1000000, budget_period: monthly }
    growth: { max_budget_cents: 200000, budget_period: daily, parent: acme }
providers:
  anthropic:
    api_key_env: ANTHROPIC_KEY
models:
  claude: { provider: anthropic }
pools:
  fast:
    members:
      - { target: claude, weight: 1, cost_per_mtok: 4 }
    hooks: [cheapest, pii-screen]
    breaker:
      base_cooldown_secs: 15
      trip: { mode: error_rate, window_s: 30, n: 3 }
    failover: { deadline_secs: 120, cap: 3 }
hooks:
  pii-screen:
    kind: gate
    socket: /run/pii.sock
    timeout_ms: 2
    on_error: reject
  audit-tap:
    kind: tap
    webhook: "https://sidecar.internal/audit"
    global: true
observability:
  otlp_endpoint: "http://otel:4318/v1/traces"
"#;

/// Every 1.x structural marker is DETECTED and NAMED; a clean 1.5.0 document yields none.
#[test]
fn legacy_markers_detected_and_named() {
    let doc: serde_yaml::Value = serde_yaml::from_str(LEGACY_14X).unwrap();
    let markers = detect_legacy_markers(&doc);
    let joined = markers.join("\n");
    for expect in [
        "`governance:`",
        "`auth.group_map:`",
        "top-level `hooks:`",
        "api_key_env",
        "target:",
    ] {
        assert!(
            joined.contains(expect),
            "marker '{expect}' missing from: {joined}"
        );
    }
    let err = legacy_config_error(&markers);
    assert!(
        err.contains("busbar --migrate-config"),
        "the refusal must point at the migrator: {err}"
    );
    assert!(
        err.contains("1.x"),
        "the refusal must name the version family: {err}"
    );

    // A clean 1.5.0 shape (the canonical example) has NO markers.
    let clean = std::fs::read_to_string(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../examples/clean-config-1.5.0.yaml"),
    )
    .expect("the canonical example exists");
    let doc: serde_yaml::Value = serde_yaml::from_str(&clean).unwrap();
    assert!(
        detect_legacy_markers(&doc).is_empty(),
        "the canonical 1.5.0 example must not trip the 1.x detector"
    );
}

/// `auth.mode:` alone (the oldest marker) trips the detector too.
#[test]
fn auth_mode_marker_detected() {
    let doc: serde_yaml::Value =
        serde_yaml::from_str("auth:\n  mode: token\nproviders: {}\nmodels: {}\n").unwrap();
    let markers = detect_legacy_markers(&doc);
    assert!(
        markers.iter().any(|m| m.contains("`auth.mode:`")),
        "{markers:?}"
    );
}

/// The migrated output covers every deterministic transform, parses as YAML, and its VALUE TREE
/// deserializes into the 1.5.0 `DeployCfg` (boot-parses) - the round-trip that makes the
/// migration path real.
#[test]
fn migrate_14x_round_trips_into_deploy_cfg() {
    let out = migrate_config(LEGACY_14X).expect("migrates");
    let doc: serde_yaml::Value = serde_yaml::from_str(&out.yaml).expect("output is valid YAML");
    let root = doc.as_mapping().unwrap();
    let get = |path: &[&str]| -> serde_yaml::Value {
        let mut cur = serde_yaml::Value::Mapping(root.clone());
        for k in path {
            cur = cur
                .as_mapping()
                .and_then(|m| m.get(serde_yaml::Value::from(*k)).cloned())
                .unwrap_or_else(|| panic!("path {path:?} missing at '{k}'"));
        }
        cur
    };

    // governance dissolved.
    assert!(root.get(serde_yaml::Value::from("governance")).is_none());
    assert_eq!(get(&["store", "module"]).as_str(), Some("postgres"));
    assert_eq!(
        get(&["store", "settings", "url"]).as_str(),
        Some("postgres://host/db")
    );
    assert_eq!(get(&["per_request_fee"]).as_u64(), Some(2));
    assert_eq!(
        get(&["advanced", "rate_sweep_interval"]).as_u64(),
        Some(128)
    );
    assert_eq!(
        get(&["rate_card", "claude", "input_utok"]).as_f64(),
        Some(3.0)
    );
    // budget_groups -> groups with C8 window nouns (daily -> day, monthly -> month).
    let growth_limits = get(&["groups", "growth", "limits"]);
    let growth_limit = &growth_limits.as_sequence().unwrap()[0];
    assert_eq!(
        growth_limit
            .as_mapping()
            .unwrap()
            .get(serde_yaml::Value::from("per"))
            .and_then(|v| v.as_str()),
        Some("day")
    );
    assert_eq!(get(&["groups", "growth", "parent"]).as_str(), Some("acme"));
    // admin_token ${VAR} -> admin-tokens secret ref.
    let admin_auth = get(&["auth", "admin_auth"]);
    let entry = &admin_auth.as_sequence().unwrap()[0];
    let token_env = entry
        .as_mapping()
        .unwrap()
        .get(serde_yaml::Value::from("admin-tokens"))
        .and_then(|v| v.as_mapping())
        .and_then(|m| m.get(serde_yaml::Value::from("token")))
        .and_then(|v| v.as_mapping())
        .and_then(|m| m.get(serde_yaml::Value::from("env")))
        .and_then(|v| v.as_str());
    assert_eq!(token_env, Some("BUSBAR_ADMIN_TOKEN"));
    // group_map -> role_bindings nested under the ONE external chain module.
    assert_eq!(
        get(&["auth", "role_bindings", "oidc", "growth-eng", "group"]).as_str(),
        Some("growth")
    );
    // Inline caps became a generated group bound to the role.
    assert_eq!(
        get(&["auth", "role_bindings", "oidc", "capped", "group"]).as_str(),
        Some("migrated-capped")
    );
    let ml = get(&["groups", "migrated-capped", "limits"]);
    let limits = ml.as_sequence().unwrap();
    assert_eq!(limits.len(), 3, "rpm + tpm + budget -> three limits");
    // api_key_env -> secret ref.
    assert_eq!(
        get(&["providers", "anthropic", "api_key", "env"]).as_str(),
        Some("ANTHROPIC_KEY")
    );
    // target -> model; cost off members; alias renames.
    let members = get(&["pools", "fast", "members"]);
    let member = members.as_sequence().unwrap()[0].as_mapping().unwrap();
    assert_eq!(
        member
            .get(serde_yaml::Value::from("model"))
            .and_then(|v| v.as_str()),
        Some("claude")
    );
    assert!(member.get(serde_yaml::Value::from("target")).is_none());
    assert!(member
        .get(serde_yaml::Value::from("cost_per_mtok"))
        .is_none());
    assert_eq!(
        get(&["pools", "fast", "breaker", "trip", "window_secs"]).as_u64(),
        Some(30)
    );
    assert_eq!(
        get(&["pools", "fast", "breaker", "trip", "consecutive_n"]).as_u64(),
        Some(3)
    );
    assert_eq!(
        get(&["pools", "fast", "failover", "timeout_secs"]).as_u64(),
        Some(120)
    );
    assert_eq!(
        get(&["pools", "fast", "failover", "max_hops"]).as_u64(),
        Some(3)
    );
    // hooks block dissolved: the pool ref inlined, the global tap moved to global_hooks.
    assert!(root.get(serde_yaml::Value::from("hooks")).is_none());
    let pool_hooks = get(&["pools", "fast", "hooks"]);
    let pool_hooks = pool_hooks.as_sequence().unwrap();
    assert_eq!(
        pool_hooks[0].as_str(),
        Some("cheapest"),
        "strategies stay bare"
    );
    let inlined = pool_hooks[1].as_mapping().unwrap();
    assert_eq!(
        inlined
            .get(serde_yaml::Value::from("module"))
            .and_then(|v| v.as_str()),
        Some("socket")
    );
    assert_eq!(
        inlined
            .get(serde_yaml::Value::from("settings"))
            .and_then(|v| v.as_mapping())
            .and_then(|m| m.get(serde_yaml::Value::from("path")))
            .and_then(|v| v.as_str()),
        Some("/run/pii.sock")
    );
    let ghooks = get(&["global_hooks"]);
    let g0 = ghooks.as_sequence().unwrap()[0].as_mapping().unwrap();
    assert_eq!(
        g0.get(serde_yaml::Value::from("module"))
            .and_then(|v| v.as_str()),
        Some("webhook")
    );
    // otlp_endpoint -> otlp_url.
    assert_eq!(
        get(&["observability", "otlp_url"]).as_str(),
        Some("http://otel:4318/v1/traces")
    );

    // The LOUD [] warning fired for the platform role's semantic flip, exactly once.
    assert_eq!(
        out.warnings
            .iter()
            .filter(|w| w.contains("allowed_pools: []") && w.contains("platform"))
            .count(),
        1,
        "warnings: {:?}",
        out.warnings
    );
    // The output document itself carries the warning as a comment.
    assert!(out.yaml.contains("# WARNING(migrate):"));

    // ROUND-TRIP: the migrated document deserializes into the 1.5.0 DeployCfg (boot-parses) and
    // trips NO legacy marker.
    assert!(detect_legacy_markers(&doc).is_empty());
    let deploy: Result<crate::config::DeployCfg, _> = serde_yaml::from_str(&out.yaml);
    assert!(
        deploy.is_ok(),
        "migrated config must boot-parse: {:?}",
        deploy.err().map(|e| e.to_string())
    );
}

/// `price_per_1k_tokens_cents` synthesizes a flagged rate_card entry per model (N cents/1k =
/// 10N micro-units/token on every tier).
#[test]
fn migrate_price_per_1k_synthesizes_rate_card() {
    let raw = r#"
governance:
  price_per_1k_tokens_cents: 5
providers: {}
models:
  m1: { provider: p }
  m2: { provider: p }
pools: {}
"#;
    let out = migrate_config(raw).expect("migrates");
    let doc: serde_yaml::Value = serde_yaml::from_str(&out.yaml).unwrap();
    let card = doc
        .as_mapping()
        .unwrap()
        .get(serde_yaml::Value::from("rate_card"))
        .and_then(|v| v.as_mapping())
        .expect("rate_card synthesized");
    for m in ["m1", "m2"] {
        let entry = card
            .get(serde_yaml::Value::from(m))
            .and_then(|v| v.as_mapping())
            .unwrap();
        assert_eq!(
            entry
                .get(serde_yaml::Value::from("input_utok"))
                .and_then(|v| v.as_f64()),
            Some(50.0),
            "5 cents/1k = 50 micro-units/token"
        );
    }
    assert!(
        out.todos.iter().any(|t| t.contains("rate_card")),
        "the uniform synthesis is flagged for review"
    );
}

/// REGRESSION: a pool `policy:` migrates to `hooks: [<strategy>, ...]` even when the config has
/// NO top-level `hooks:` registry block (the block-processing pass returns early in that case).
#[test]
fn migrate_pool_policy_without_hooks_block() {
    let raw = r#"
providers: {}
models: {}
pools:
  fast:
    members: [ { target: claude, weight: 1 } ]
    policy: cheapest
"#;
    let out = migrate_config(raw).expect("migrates");
    let doc: serde_yaml::Value = serde_yaml::from_str(&out.yaml).unwrap();
    let hooks = doc
        .as_mapping()
        .and_then(|m| m.get(serde_yaml::Value::from("pools")))
        .and_then(|v| v.as_mapping())
        .and_then(|m| m.get(serde_yaml::Value::from("fast")))
        .and_then(|v| v.as_mapping())
        .and_then(|m| m.get(serde_yaml::Value::from("hooks")))
        .and_then(|v| v.as_sequence())
        .expect("policy became a hooks list");
    assert_eq!(hooks[0].as_str(), Some("cheapest"));
    // The migrated document boot-parses (no leftover `policy:` unknown-field).
    assert!(
        serde_yaml::from_str::<crate::config::DeployCfg>(&out.yaml).is_ok(),
        "policy-only pool must migrate to a bootable config"
    );
}

/// `auth.mode` mapping: passthrough -> upstream_credentials; token -> keys chain + a re-mint TODO.
#[test]
fn migrate_auth_mode_arms() {
    let out = migrate_config("auth:\n  mode: passthrough\nproviders: {}\nmodels: {}\npools: {}\n")
        .unwrap();
    assert!(out.yaml.contains("upstream_credentials: passthrough"));

    let out =
        migrate_config("auth:\n  mode: token\nproviders: {}\nmodels: {}\npools: {}\n").unwrap();
    assert!(out.yaml.contains("- keys"));
    assert!(
        out.todos.iter().any(|t| t.contains("signed key")),
        "static-token removal must surface the key re-mint TODO: {:?}",
        out.todos
    );
}

/// A group_map with an AMBIGUOUS module home (no external chain module) gets the placeholder +
/// TODO, never a silent guess.
#[test]
fn migrate_group_map_without_module_flags_placeholder() {
    let raw = r#"
auth:
  group_map:
    r1: { allowed_pools: [fast] }
providers: {}
models: {}
pools: {}
"#;
    let out = migrate_config(raw).unwrap();
    assert!(out.yaml.contains("<module>"));
    assert!(out
        .todos
        .iter()
        .any(|t| t.contains("replace the '<module>' placeholder")));
}
