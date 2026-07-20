use super::*;

// 1.4.0 audit (config-compat): a 1.3.0 config using the removed `auth.mode:` key must fail with an
// actionable migration hint, not just serde's bare "unknown field `mode`". Verify the hint is appended
// for the mode error and that unrelated errors pass through verbatim; plus an end-to-end parse.
#[test]
fn augment_config_error_adds_auth_mode_migration_hint() {
    let augmented =
        crate::config::augment_config_error("unknown field `mode`, expected one of `chain`");
    assert!(
        augmented.contains("auth.mode:"),
        "hint names the removed key: {augmented}"
    );
    assert!(
        augmented.contains("auth.chain:"),
        "hint points to the new key: {augmented}"
    );
    assert!(
        augmented.contains("upstream_credentials"),
        "hint covers the passthrough migration: {augmented}"
    );
    // Unrelated errors are returned unchanged.
    assert_eq!(
        crate::config::augment_config_error("some other yaml error"),
        "some other yaml error"
    );
    // End-to-end: a legacy `auth.mode:` config surfaces the hint through the parse path.
    let legacy = "providers: {}\nauth:\n  mode: none\n";
    let err = serde_yaml::from_str::<crate::config::DeployCfg>(legacy)
        .map_err(crate::config::augment_config_error)
        .expect_err("legacy auth.mode must fail to parse");
    assert!(
        err.contains("auth.chain:"),
        "end-to-end error carries the hint: {err}"
    );
}

/// The hook config types are round-trippable (Deserialize + Serialize) — the foundation for the
/// config-overlay persistence that will let a runtime-registered hook survive a restart. A
/// `HookCfg` deserialized from JSON re-serializes + re-parses to an identical shape, exercising the
/// snake_case enums (kind/prompt/user) + the transport + the ordering/stage fields.
#[test]
fn hook_cfg_round_trips_for_overlay_persistence() {
    let src = serde_json::json!({
        "kind": "gate",
        "webhook": "http://127.0.0.1:8900/",
        "prompt": "rw",
        "user": "ro",
        "priority": 7,
        "on_error": "reject",
        "global": true,
        "timeout_ms": 25
    });
    let cfg: HookCfg = serde_json::from_value(src).expect("HookCfg deserializes");
    // Serialize -> re-deserialize -> re-serialize: the two JSON forms must be identical (stable).
    let once = serde_json::to_value(&cfg).expect("HookCfg serializes");
    let cfg2: HookCfg = serde_json::from_value(once.clone()).expect("re-deserializes");
    let twice = serde_json::to_value(&cfg2).expect("re-serializes");
    assert_eq!(once, twice, "HookCfg round-trips stably");
    // Spot-check the snake_case enum projection survives.
    assert_eq!(once["kind"], "gate");
    assert_eq!(once["prompt"], "rw");
    assert_eq!(once["user"], "ro");
    assert_eq!(once["on_error"], "reject");
}

/// Serializes tests that touch the *shared* `BUSBAR_CLIENT_TOKEN` env var. Env vars are
/// process-global, and `cargo test` runs tests in parallel by default, so two tests that
/// `set_var`/`remove_var` the same name race: one can wipe the value mid-flight of the other,
/// causing a spurious "unset variable" interpolation failure. Renaming is not viable because the
/// shipped `config.yaml` hard-references `${BUSBAR_CLIENT_TOKEN}`; instead, every test that
/// drives that var must hold this lock for the whole set/interpolate/remove sequence.
///
/// Per-test vars use unique `BUSBAR_T_*` names and so do not need this guard.
static CLIENT_TOKEN_ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// 1.0.0 MIGRATION: the legacy single-token `token:` key was REMOVED. `AuthCfg` is now
/// `#[serde(deny_unknown_fields)]`, so a config still setting `token:` is REJECTED AT PARSE with
/// serde's "unknown field `token`, expected one of `mode`, `client_tokens`" — a hard, clear
/// migration error, never a silent credential drop. (Previously the key deserialized into a
/// tombstone field and was caught later at validate time; that mechanism was removed.)
#[test]
fn test_legacy_token_key_is_rejected_at_parse() {
    let yaml = "mode: token\ntoken: \"sk-bb-legacy\"\nclient_tokens: []";
    let err = serde_yaml::from_str::<AuthCfg>(yaml)
        .expect_err("legacy `token:` must be rejected at parse, not deserialize");
    let msg = err.to_string();
    assert!(
        msg.contains("unknown field") && msg.contains("token"),
        "expected serde's unknown-field error naming `token`; got: {msg}"
    );
    // The rejected secret value is NEVER echoed back in the parse error.
    assert!(
        !msg.contains("sk-bb-legacy"),
        "the parse error must not leak the configured token value; got: {msg}"
    );
}

/// 1.0.0 KEY RENAMES — back-compat: every renamed key still loads from its OLD spelling via a
/// serde alias, and the new spelling loads too. Pins the alias surface so a future field rename
/// can't silently drop the alias (which would break a deployed pre-1.0 config on upgrade).
#[test]
fn test_renamed_keys_accept_old_and_new_spellings() {
    // breaker trip: window_s → window_secs, n → consecutive_n
    let old: BreakerTripConfig =
        serde_yaml::from_str("mode: consecutive\nwindow_s: 42\nn: 7").expect("old trip keys");
    assert_eq!(old.window_secs, 42);
    assert_eq!(old.consecutive_n, 7);
    let new: BreakerTripConfig =
        serde_yaml::from_str("mode: consecutive\nwindow_secs: 42\nconsecutive_n: 7")
            .expect("new trip keys");
    assert_eq!(new.window_secs, 42);
    assert_eq!(new.consecutive_n, 7);

    // failover: deadline_secs → timeout_secs, cap → max_hops
    let old: FailoverCfg =
        serde_yaml::from_str("deadline_secs: 30\ncap: 5").expect("old failover keys");
    assert_eq!(old.timeout_secs, 30);
    assert_eq!(old.max_hops, 5);
    let new: FailoverCfg =
        serde_yaml::from_str("timeout_secs: 30\nmax_hops: 5").expect("new failover keys");
    assert_eq!(new.timeout_secs, 30);
    assert_eq!(new.max_hops, 5);
}

/// A minimal config without a `pools:` section parses fine — pools are optional (direct
/// model routing). Only providers + models are required.
#[test]
fn test_config_without_pools_parses() {
    let yaml = r#"
listen: "0.0.0.0:8080"
providers:
  anthropic:
    api_key_env: ANTHROPIC_KEY
models:
  claude:
    provider: anthropic
    max_concurrent: 10
"#;
    let deploy: DeployCfg = serde_yaml::from_str(yaml).expect("config without pools must parse");
    assert!(deploy.pools.is_empty());
    assert!(deploy.models.contains_key("claude"));
}

/// A provider's `path` override flows from the catalog (and a deployment override wins) into
/// the resolved ProviderCfg — the knob that fixes version-in-base-url providers.
#[test]
fn test_provider_path_override_resolves() {
    let mut defs = HashMap::new();
    defs.insert(
        "zai-payg".to_string(),
        ProviderDef {
            protocol: "openai".to_string(),
            base_url: "https://api.z.ai/api/paas/v4".to_string(),
            error_map: HashMap::new(),
            health: None,
            path: Some("/chat/completions".to_string()),
            path_base: None,
            token_url: None,
            scope: None,
            auth: None,
            allow_metadata_hosts: Vec::new(),
        },
    );
    let mut providers = HashMap::new();
    providers.insert(
        "zai-payg".to_string(),
        ProviderDeploy {
            api_key_env: "ZAI_KEY".to_string(),
            protocol: None,
            base_url: None,
            error_map: None,
            path: None, // inherit the catalog override
            path_base: None,
            token_url: None,
            scope: None,
            auth: None,
            // Deployment-side health (the block config.yaml documents under a provider).
            health: Some(HealthCfg {
                mode: HealthMode::Dead,
                interval_secs: Some(5),
                timeout_secs: None,
            }),
            _legacy_api_key: None,
            allow_metadata_hosts: None,
        },
    );
    let deploy = DeployCfg {
        listen: DEFAULT_LISTEN_ADDR.into(),
        tls: None,
        admin_listen: DEFAULT_ADMIN_LISTEN_ADDR.into(),
        admin_tls: None,
        admin_insecure: false,
        auth: None,
        providers,
        models: HashMap::new(),
        pools: HashMap::new(),
        hooks: HashMap::new(),
        admin_auth: vec!["admin-tokens".to_string()],
        group_map: HashMap::new(),
        global_hooks: Vec::new(),
        observability: None,
        governance: None,
        security: None,
        limits: LimitsCfg::default(),
        metrics: MetricsCfg::default(),
        health: HealthDefaultsCfg::default(),
        routing: RoutingCfg::default(),
    };
    let cfg = resolve(&deploy, &defs).expect("resolve");
    assert_eq!(
        cfg.providers["zai-payg"].path.as_deref(),
        Some("/chat/completions"),
        "catalog path override must resolve into ProviderCfg"
    );
    // Deployment-side health must survive resolve (regression: it was silently dropped).
    assert_eq!(
        cfg.providers["zai-payg"].health.as_ref().map(|h| h.mode),
        Some(HealthMode::Dead),
        "config.yaml provider health must resolve into ProviderCfg"
    );
}

#[test]
fn bind_is_loopback_classification() {
    // Loopback binds — safe for a token-only admin plane.
    assert!(bind_is_loopback("127.0.0.1:8081"));
    assert!(bind_is_loopback("localhost:8081"));
    assert!(bind_is_loopback("LocalHost:8081")); // case-insensitive
    assert!(bind_is_loopback("[::1]:8081")); // IPv6 loopback with brackets
    assert!(bind_is_loopback("127.0.0.1")); // no :port
    assert!(bind_is_loopback("127.0.0.2:80")); // whole 127/8 is loopback
                                               // Exposed binds — the boot-guard must treat these as network-reachable.
    assert!(!bind_is_loopback("0.0.0.0:8081"));
    assert!(!bind_is_loopback("10.0.0.5:8081"));
    assert!(!bind_is_loopback("[::]:8081")); // IPv6 unspecified
    assert!(!bind_is_loopback("admin.internal:8081")); // hostname → fail closed (exposed)
}

/// The admin-plane boot-guard: a network-exposed `admin_listen` refuses to boot without mTLS,
/// unless deliberately waived. Loopback binds and mTLS-equipped exposed binds resolve cleanly.
#[test]
fn admin_plane_boot_guard() {
    fn build(
        admin_listen: &str,
        client_ca: Option<&str>,
        admin_insecure: bool,
    ) -> Result<RootCfg, Vec<String>> {
        let mut defs = HashMap::new();
        defs.insert(
            "p".to_string(),
            ProviderDef {
                protocol: "openai".to_string(),
                base_url: "https://api.example.com/v1".to_string(),
                error_map: HashMap::new(),
                health: None,
                path: None,
                path_base: None,
                token_url: None,
                scope: None,
                auth: None,
                allow_metadata_hosts: Vec::new(),
            },
        );
        let mut providers = HashMap::new();
        providers.insert(
            "p".to_string(),
            ProviderDeploy {
                api_key_env: "P_KEY".to_string(),
                protocol: None,
                base_url: None,
                error_map: None,
                path: None,
                path_base: None,
                token_url: None,
                scope: None,
                auth: None,
                health: None,
                _legacy_api_key: None,
                allow_metadata_hosts: None,
            },
        );
        let deploy = DeployCfg {
            listen: DEFAULT_LISTEN_ADDR.into(),
            tls: None,
            admin_listen: admin_listen.to_string(),
            admin_tls: client_ca.map(|ca| TlsCfg {
                cert_file: "cert.pem".into(),
                key_file: "key.pem".into(),
                client_ca_file: Some(ca.to_string()),
            }),
            admin_insecure,
            auth: None,
            providers,
            models: HashMap::new(),
            pools: HashMap::new(),
            hooks: HashMap::new(),
            admin_auth: vec!["admin-tokens".to_string()],
            group_map: HashMap::new(),
            global_hooks: Vec::new(),
            observability: None,
            governance: None,
            security: None,
            limits: LimitsCfg::default(),
            metrics: MetricsCfg::default(),
            health: HealthDefaultsCfg::default(),
            routing: RoutingCfg::default(),
        };
        resolve(&deploy, &defs)
    }

    // DEFAULT: the zero-config admin listener is loopback, so it boots with no mTLS.
    assert!(
        build(DEFAULT_ADMIN_LISTEN_ADDR, None, false).is_ok(),
        "the default loopback admin_listen must resolve"
    );
    // Loopback admin plane is safe without mTLS (unreachable off-host).
    assert!(build("127.0.0.1:8081", None, false).is_ok());
    assert!(build("[::1]:8081", None, false).is_ok());
    assert!(build("localhost:8081", None, false).is_ok());
    // EXPOSED admin plane without mTLS and without waiver → REFUSE TO BOOT.
    let err = build("0.0.0.0:8081", None, false)
        .expect_err("exposed admin without mTLS must refuse to boot");
    let joined = err.join("\n");
    assert!(joined.contains("admin_listen"), "guard message: {joined}");
    assert!(joined.contains("mTLS"), "guard message: {joined}");
    // Exposed admin WITH client-cert mTLS → allowed.
    assert!(build("0.0.0.0:8081", Some("client-ca.pem"), false).is_ok());
    // Exposed admin with an explicit insecure waiver → allowed (operator's deliberate choice).
    assert!(build("0.0.0.0:8081", None, true).is_ok());
}

/// The shipped example config.yaml must parse and resolve cleanly against providers.yaml
/// (every referenced provider/model exists; the example stays a working starting point).
#[test]
fn test_shipped_example_config_resolves() {
    // Hold the shared-env lock across the whole set/interpolate/remove sequence so a sibling test
    // that also drives BUSBAR_CLIENT_TOKEN cannot wipe it mid-flight (recover on poison: a panic
    // in another holder must not block this test).
    let _env_guard = CLIENT_TOKEN_ENV_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    // The example references env-var placeholders via `${...}` interpolation, which scans the
    // whole file — including commented blocks. ONLY the active (uncommented) `auth.client_tokens`
    // entry uses the brace form, so only BUSBAR_CLIENT_TOKEN must be set. The commented
    // governance `admin_token` deliberately uses the no-brace `$BUSBAR_ADMIN_TOKEN` form, which
    // interpolate_env does NOT expand, so booting the default config must NOT require
    // BUSBAR_ADMIN_TOKEN to be set (regression: the brace form forced a mandatory boot failure
    // even with governance disabled). We intentionally do NOT set BUSBAR_ADMIN_TOKEN here.
    std::env::set_var("BUSBAR_CLIENT_TOKEN", "example-token");
    std::env::remove_var("BUSBAR_ADMIN_TOKEN");
    let providers_raw =
        std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/../../providers.yaml"))
            .unwrap();
    let defs: HashMap<String, ProviderDef> =
        serde_yaml::from_str(&providers_raw).expect("parse providers.yaml");

    let config_raw =
        std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/../../config.yaml")).unwrap();
    let expanded = interpolate_env(&config_raw).expect("expand ${ENV} in example config.yaml");
    let deploy: DeployCfg = serde_yaml::from_str(&expanded).expect("parse example config.yaml");

    let cfg = resolve(&deploy, &defs).expect("example config.yaml must resolve");
    // Spot-check the progressively-complex pools all wired up.
    assert!(cfg.pools.contains_key("smart"));
    assert!(cfg.pools.contains_key("overflow"));
    assert!(cfg.models.contains_key("claude-sonnet"));

    // Env vars are process-global and tests run in parallel; clean up so this test cannot
    // leave BUSBAR_CLIENT_TOKEN set for the rest of the run (which could mask an "unset
    // variable" assertion in another test).
    std::env::remove_var("BUSBAR_CLIENT_TOKEN");
}

/// Regression (#23): booting the shipped default config.yaml must NOT require BUSBAR_ADMIN_TOKEN
/// to be set. `interpolate_env` expands `${...}` anywhere in the raw text — including comments —
/// so a commented `admin_token: "${BUSBAR_ADMIN_TOKEN}"` example would make an unset
/// BUSBAR_ADMIN_TOKEN a MANDATORY boot failure even when governance is disabled. The commented
/// example uses the no-brace `$BUSBAR_ADMIN_TOKEN` form, which interpolate_env leaves verbatim.
/// This test interpolates the default config with BUSBAR_ADMIN_TOKEN guaranteed-unset and asserts
/// success; it fails against the old `${...}` comment (unset-variable boot error).
#[test]
fn test_default_config_boots_without_admin_token_env() {
    // Serialize with the sibling that shares BUSBAR_CLIENT_TOKEN (see CLIENT_TOKEN_ENV_LOCK).
    let _env_guard = CLIENT_TOKEN_ENV_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    std::env::set_var("BUSBAR_CLIENT_TOKEN", "example-token");
    std::env::remove_var("BUSBAR_ADMIN_TOKEN");

    let config_raw =
        std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/../../config.yaml")).unwrap();

    // No active OR commented `${...}` token in the shipped config may reference an admin token:
    // the only legitimate brace-form interpolation is the active client-tokens entry.
    assert!(
        !config_raw.contains("${BUSBAR_ADMIN_TOKEN}"),
        "the commented admin_token example must use the no-brace $BUSBAR_ADMIN_TOKEN form so it \
             does not force a mandatory boot failure on unset BUSBAR_ADMIN_TOKEN"
    );

    let expanded = interpolate_env(&config_raw)
        .expect("default config.yaml must interpolate with BUSBAR_ADMIN_TOKEN unset");
    // The no-brace form is passed through verbatim (interpolate_env only expands `${...}`).
    assert!(
        expanded.contains("$BUSBAR_ADMIN_TOKEN"),
        "the no-brace admin_token example must survive interpolation untouched"
    );

    std::env::remove_var("BUSBAR_CLIENT_TOKEN");
}

/// Regression (#20): the two integration tests above share the process-global
/// `BUSBAR_CLIENT_TOKEN` env var with a set → interpolate → remove sequence. Under the default
/// parallel test runner, an unguarded sibling could `remove_var` between this test's `set_var`
/// and `interpolate_env`, making interpolation fail with an "unset variable" error. This test
/// reproduces that race deterministically by hammering the exact sequence from many threads, and
/// asserts that holding `CLIENT_TOKEN_ENV_LOCK` across the whole sequence keeps every
/// interpolation succeeding. Run against the old (unguarded) sequence it flakes/fails; with the
/// guard it is stable.
#[test]
fn test_client_token_env_lock_serializes_set_interpolate_remove() {
    const THREADS: usize = 8;
    const ITERS: usize = 200;
    let failures = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let mut handles = Vec::with_capacity(THREADS);
    for _ in 0..THREADS {
        let failures = std::sync::Arc::clone(&failures);
        handles.push(std::thread::spawn(move || {
            for _ in 0..ITERS {
                // The guard makes set/interpolate/remove atomic w.r.t. other lock holders.
                let _g = CLIENT_TOKEN_ENV_LOCK
                    .lock()
                    .unwrap_or_else(|p| p.into_inner());
                std::env::set_var("BUSBAR_CLIENT_TOKEN", "race-token");
                let r = interpolate_env("tok: \"${BUSBAR_CLIENT_TOKEN}\"");
                if r.as_deref() != Ok("tok: \"race-token\"") {
                    failures.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                }
                std::env::remove_var("BUSBAR_CLIENT_TOKEN");
            }
        }));
    }
    for h in handles {
        h.join().expect("interpolation thread must not panic");
    }
    assert_eq!(
        failures.load(std::sync::atomic::Ordering::Relaxed),
        0,
        "guarded set/interpolate/remove of BUSBAR_CLIENT_TOKEN must never observe an unset var"
    );
}

/// The `hooks: [...]` list parses each native strategy name as the base; absent defaults to
/// weighted with base NOT named (so the `default:` hook can replace it at resolution).
#[test]
fn test_pool_policy_strategies_parse() {
    for (name, expected) in [
        ("cheapest", PoolPolicy::Cheapest),
        ("fastest", PoolPolicy::Fastest),
        ("least_busy", PoolPolicy::LeastBusy),
        ("usage", PoolPolicy::Usage),
        ("weighted", PoolPolicy::Weighted),
    ] {
        let yaml = format!("hooks: [{name}]\nmembers: []\n");
        let pool: PoolCfg = serde_yaml::from_str(&yaml).expect("strategy name must parse");
        assert_eq!(pool.policy, expected, "{name} must parse to its strategy");
        assert!(pool.gates.is_empty());
        assert!(pool.base_named, "a named strategy names the base");
    }
    // Absent hooks: defaults to the zero-cost weighted strategy; base NOT named ⇒ inherits default:
    let absent: PoolCfg = serde_yaml::from_str("members: []\n").expect("absent parses");
    assert_eq!(absent.policy, PoolPolicy::Weighted);
    assert!(absent.gates.is_empty());
    assert!(!absent.base_named, "an absent hooks: did not name the base");
}

/// RETIRED transitional keys: the `policy:`/`hook:` pool pair each fail with a migration error
/// pointing at the `hooks: [...]` list.
#[test]
fn test_pool_policy_and_hook_keys_retired() {
    let e = serde_yaml::from_str::<PoolCfg>("policy: cheapest\nmembers: []\n")
        .expect_err("policy: must be a retirement error");
    assert!(
        e.to_string().contains("retired") && e.to_string().contains("hooks: [cheapest]"),
        "policy: must point at the hooks list — got: {e}"
    );
    let e = serde_yaml::from_str::<PoolCfg>("hook: smart-router\nmembers: []\n")
        .expect_err("hook: must be a retirement error");
    assert!(
        e.to_string().contains("retired") && e.to_string().contains("hooks: [my-gate]"),
        "hook: must point at the hooks list — got: {e}"
    );
    // The block form of the retired key errors the same way (IgnoredAny swallows any shape).
    let e = serde_yaml::from_str::<PoolCfg>("members: []\npolicy:\n  socket: /s\n")
        .expect_err("policy block must be a retirement error");
    assert!(e.to_string().contains("retired"), "{e}");
}

/// The unified `hooks: [...]` pool form desugars into the internal (base policy, gate) rep: an
/// ordering-strategy name sets the base ranking, any other name is a gate reference.
#[test]
fn test_pool_hooks_list_desugars() {
    // strategy + gate ⇒ base explicitly named
    let pool: PoolCfg = serde_yaml::from_str("hooks: [cheapest, smart-router]\nmembers: []\n")
        .expect("hooks list must parse");
    assert_eq!(pool.policy, PoolPolicy::Cheapest);
    assert_eq!(pool.gates, ["smart-router"]);
    assert!(pool.base_named, "a named strategy sets base_named");

    // gate only ⇒ base stays default (weighted placeholder); base NOT named ⇒ inherits default:
    let g: PoolCfg =
        serde_yaml::from_str("hooks: [pii-guard]\nmembers: []\n").expect("gate-only list parses");
    assert_eq!(g.policy, PoolPolicy::Weighted);
    assert_eq!(g.gates, ["pii-guard"]);
    assert!(
        !g.base_named,
        "a gate-only pool did not name its base ordering"
    );

    // strategy only ⇒ base set, no gate, base named
    let s: PoolCfg =
        serde_yaml::from_str("hooks: [fastest]\nmembers: []\n").expect("strategy-only parses");
    assert_eq!(s.policy, PoolPolicy::Fastest);
    assert!(s.gates.is_empty());
    assert!(s.base_named);
}

/// A `hooks:` list may name SEVERAL gates — they fire concurrently in the phase-2 reconcile.
/// List order is preserved (the chain tie-break within equal `priority`).
#[test]
fn test_pool_hooks_list_accepts_multiple_gates() {
    let pool: PoolCfg =
        serde_yaml::from_str("hooks: [cheapest, pii-guard, compliance]\nmembers: []\n")
            .expect("multi-gate list must parse");
    assert_eq!(pool.policy, PoolPolicy::Cheapest);
    assert_eq!(pool.gates, ["pii-guard", "compliance"]);
    assert!(pool.base_named);
}

/// The retired keys error even alongside a valid `hooks:` list (the retirement check fires
/// before desugar — no silent half-migration).
#[test]
fn test_pool_hooks_and_legacy_pair_conflict() {
    let e = serde_yaml::from_str::<PoolCfg>("hooks: [cheapest]\npolicy: fastest\nmembers: []\n")
        .expect_err("a retired key alongside hooks: must error");
    assert!(e.to_string().contains("retired"), "{e}");
}

/// Two ordering strategies in one `hooks:` list is an error (a pool has one base ordering).
#[test]
fn test_pool_hooks_two_strategies_error() {
    let e = serde_yaml::from_str::<PoolCfg>("hooks: [cheapest, fastest]\nmembers: []\n")
        .expect_err("two strategies must error");
    assert!(
        e.to_string().contains("more than one ordering strategy"),
        "{e}"
    );
}

/// Any `policy:` value — known strategy or not — is the same retirement error (the key is gone).
#[test]
fn test_pool_policy_unknown_value_errors() {
    let err = serde_yaml::from_str::<PoolCfg>("policy: bogus\nmembers: []\n")
        .expect_err("the retired policy: key must be a parse error");
    assert!(err.to_string().contains("retired"), "{err}");
}

/// CLEAN-BREAK migration errors: the removed `route:` pool key names its replacement per value —
/// every arm points at the `hooks: [...]` pool list.
#[test]
fn test_legacy_keys_are_migration_errors() {
    // route: <native> -> hooks: [<name>]
    let e = serde_yaml::from_str::<PoolCfg>("route: cheapest\nmembers: []\n")
        .expect_err("route: <native> must error");
    assert!(
        e.to_string().contains("hooks: [cheapest]"),
        "route:<native> must point at the hooks list — got: {e}"
    );
    // route: socket|webhook -> hooks: registry + pool hooks: [name]
    let e = serde_yaml::from_str::<PoolCfg>("route: socket\nmembers: []\n")
        .expect_err("route: socket must error");
    assert!(
        e.to_string().contains("hooks: [my-hook]"),
        "route: socket must point at the hooks registry + list — got: {e}"
    );
    // route: script -> gate under hooks:
    let e = serde_yaml::from_str::<PoolCfg>("route: script\nmembers: []\n")
        .expect_err("route: script must error");
    assert!(
        e.to_string().contains("removed in 1.3"),
        "route: script must name the removal — got: {e}"
    );
}

/// A hook's `prompt:` / `user:` grants parse the trust ladder; absent defaults to `no`.
#[test]
fn test_hook_access_grants_parse() {
    let hook: HookCfg = serde_yaml::from_str("kind: gate\nsocket: /s\nprompt: rw\nuser: ro\n")
        .expect("grants must parse");
    assert_eq!(hook.prompt, PromptAccess::Rw);
    assert!(hook.prompt.sends_prompt() && hook.prompt.can_rewrite());
    assert_eq!(hook.user, UserAccess::Ro);
    assert!(hook.user.sends_user());

    let bare: HookCfg =
        serde_yaml::from_str("kind: tap\nsocket: /s\n").expect("bare hook must parse");
    assert_eq!(bare.prompt, PromptAccess::No, "prompt defaults to no");
    assert_eq!(bare.user, UserAccess::No, "user defaults to no");
    assert!(!bare.prompt.sends_prompt());
}

/// The shipped providers.yaml catalog must parse, name only known protocols, and use HTTPS.
#[test]
fn test_shipped_providers_catalog_valid() {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../../providers.yaml");
    let raw = std::fs::read_to_string(path).expect("read providers.yaml");
    let defs: HashMap<String, ProviderDef> =
        serde_yaml::from_str(&raw).expect("parse providers.yaml");
    assert!(defs.len() >= 10, "catalog should be non-trivial");
    let registry = crate::proto::ProtocolRegistry::with_builtins();
    for (name, def) in &defs {
        assert!(
            registry.get(&def.protocol).is_some(),
            "provider '{name}' names unknown protocol '{}'",
            def.protocol
        );
        assert!(
            def.base_url.starts_with("https://"),
            "provider '{name}' base_url must be https"
        );
    }
}

// NOTE: env vars are process-global; tests run in parallel. Use UNIQUE per-test var
// names so they cannot race each other (the old shared HOST/USER raced + USER even
// collided with the real shell var). Do not reintroduce shared names.
#[test]
fn test_interpolate_env_simple() {
    let input = "https://${BUSBAR_T_SIMPLE_HOST}/api";
    std::env::set_var("BUSBAR_T_SIMPLE_HOST", "example.com");
    let result = interpolate_env(input).unwrap();
    assert_eq!(result, "https://example.com/api");
    std::env::remove_var("BUSBAR_T_SIMPLE_HOST");
}

#[test]
fn test_interpolate_env_multiple() {
    let input =
            "${BUSBAR_T_MULTI_PROTO}://${BUSBAR_T_MULTI_USER}@${BUSBAR_T_MULTI_HOST}:${BUSBAR_T_MULTI_PORT}/";
    std::env::set_var("BUSBAR_T_MULTI_PROTO", "https");
    std::env::set_var("BUSBAR_T_MULTI_USER", "admin");
    std::env::set_var("BUSBAR_T_MULTI_HOST", "localhost");
    std::env::set_var("BUSBAR_T_MULTI_PORT", "8080");
    let result = interpolate_env(input).unwrap();
    assert_eq!(result, "https://admin@localhost:8080/");
    std::env::remove_var("BUSBAR_T_MULTI_PROTO");
    std::env::remove_var("BUSBAR_T_MULTI_USER");
    std::env::remove_var("BUSBAR_T_MULTI_HOST");
    std::env::remove_var("BUSBAR_T_MULTI_PORT");
}

#[test]
fn test_interpolate_env_unset_fails() {
    let input = "https://${UNSET_VAR}/api";
    let result = interpolate_env(input);
    assert!(result.is_err());
    assert_eq!(result.unwrap_err(), "unset environment variable: UNSET_VAR");
}

#[test]
fn test_interpolate_env_empty_var() {
    let input = "${}";
    let result = interpolate_env(input);
    assert!(result.is_err());
    assert_eq!(result.unwrap_err(), "empty variable name in ${}");
}

/// `--validate` leniency: in Lenient mode an unset `${VAR}` substitutes a placeholder (its own name)
/// and is recorded (deduped) instead of erroring; Strict still errors. Uses names guaranteed unset.
#[test]
fn test_interpolate_env_lenient_collects_unset() {
    use crate::config::{interpolate_env_with, EnvSubst};
    let input =
        "a: \"${BB_LENIENT_UNSET_A}\"\nb: \"${BB_LENIENT_UNSET_A}\"\nc: \"${BB_LENIENT_UNSET_B}\"";
    let mut unset = Vec::new();
    let out = interpolate_env_with(input, EnvSubst::Lenient, &mut unset).unwrap();
    assert!(out.contains("\"BB_LENIENT_UNSET_A\""));
    assert!(out.contains("\"BB_LENIENT_UNSET_B\""));
    assert_eq!(unset, vec!["BB_LENIENT_UNSET_A", "BB_LENIENT_UNSET_B"]);
    let mut sink = Vec::new();
    assert!(interpolate_env_with(input, EnvSubst::Strict, &mut sink).is_err());
    assert!(sink.is_empty());
}

#[test]
fn test_interpolate_env_no_vars() {
    let input = "plain-text-no-vars";
    let result = interpolate_env(input).unwrap();
    assert_eq!(result, "plain-text-no-vars");
}

/// Regression (YAML-structure injection): an env value containing a NEWLINE (the structural
/// break that closes a quoted YAML scalar) must be rejected, not spliced into the raw config
/// text. The exploit shape from the finding — a value that ends a quoted `client_tokens` entry
/// and injects an extra list item — must fail loudly at interpolation time. Uses a unique
/// per-test var name (process-global env, parallel tests).
#[test]
fn test_interpolate_env_rejects_newline_yaml_injection() {
    // The double-quote/newline breakout payload the finding calls out for client_tokens.
    std::env::set_var("BUSBAR_T_INJECT_NL", "real-tok\"\n    - \"injected-tok");
    let input = "client_tokens:\n    - \"${BUSBAR_T_INJECT_NL}\"";
    let result = interpolate_env(input);
    std::env::remove_var("BUSBAR_T_INJECT_NL");
    assert!(
        result.is_err(),
        "an env value with a newline must be rejected to prevent YAML injection"
    );
    let err = result.unwrap_err();
    assert!(
        err.contains("control character") && err.contains("BUSBAR_T_INJECT_NL"),
        "error must name the offending variable and the control-character reason, got: {err}"
    );
}

/// A bare carriage return is also a YAML line break and must be rejected on the same grounds.
#[test]
fn test_interpolate_env_rejects_carriage_return() {
    std::env::set_var("BUSBAR_T_INJECT_CR", "tok\r- injected");
    let result = interpolate_env("x: \"${BUSBAR_T_INJECT_CR}\"");
    std::env::remove_var("BUSBAR_T_INJECT_CR");
    assert!(
        result.is_err(),
        "an env value with a carriage return must be rejected"
    );
}

/// The guard must NOT over-reject: ordinary token / URL values (including ones with `:`, `/`,
/// `@`, `.`, `-`, and even an embedded double-quote or `#`, which are harmless without a line
/// break) interpolate cleanly. This keeps real opaque API keys working.
#[test]
fn test_interpolate_env_allows_ordinary_values_with_punctuation() {
    std::env::set_var("BUSBAR_T_OK_TOK", "sk-bb-aB3#9/x.y@z:1234567890abcdef");
    let result = interpolate_env("token: \"${BUSBAR_T_OK_TOK}\"").unwrap();
    std::env::remove_var("BUSBAR_T_OK_TOK");
    assert_eq!(result, "token: \"sk-bb-aB3#9/x.y@z:1234567890abcdef\"");
}

/// End-to-end: an env value carrying a newline-based injection must NOT smuggle an extra
/// `client_tokens` entry into the parsed config. The interpolation rejects it before serde ever
/// sees the malformed YAML, so the allowlist cannot be silently widened via a compromised env
/// var.
#[test]
fn test_env_injection_cannot_widen_client_tokens_allowlist() {
    std::env::set_var(
        "BUSBAR_T_ALLOWLIST_INJECT",
        "legit\"\n    - \"smuggled-admin-token",
    );
    let yaml = "auth:\n  mode: token\n  client_tokens:\n    - \"${BUSBAR_T_ALLOWLIST_INJECT}\"";
    let result = interpolate_env(yaml);
    std::env::remove_var("BUSBAR_T_ALLOWLIST_INJECT");
    assert!(
        result.is_err(),
        "newline injection into client_tokens must be rejected at interpolation, not parsed"
    );
}

/// An unclosed `${FOO` (missing `}`) must fail loudly with an "unclosed" error rather than be
/// treated as `${FOO}` — regardless of whether FOO is set in the environment. Uses a unique
/// per-test var name (process-global env, parallel tests) and a guaranteed-unset name.
#[test]
fn test_interpolate_env_unclosed_brace_fails() {
    // Unset variable, missing brace: must report "unclosed", NOT "unset environment variable".
    let result = interpolate_env("prefix-${BUSBAR_T_UNCLOSED_UNSET");
    assert!(result.is_err(), "unclosed token must error");
    let err = result.unwrap_err();
    assert!(
        err.contains("unclosed"),
        "error must mention 'unclosed', got: {err}"
    );
    assert!(
        !err.contains("unset environment variable"),
        "must not misreport as an unset-variable error, got: {err}"
    );

    // Set variable, missing brace: must STILL error (not silently interpolate the value).
    std::env::set_var("BUSBAR_T_UNCLOSED_SET", "leaked-value");
    let result2 = interpolate_env("https://${BUSBAR_T_UNCLOSED_SET/api");
    std::env::remove_var("BUSBAR_T_UNCLOSED_SET");
    assert!(
        result2.is_err(),
        "unclosed token must error even when the var is set"
    );
    let err2 = result2.unwrap_err();
    assert!(
        err2.contains("unclosed"),
        "error must mention 'unclosed', got: {err2}"
    );
}

// Two-file (providers.yaml + config.yaml) resolution tests

#[test]
fn test_resolve_provider_from_def() {
    // DeployCfg referencing z.ai + providers.yaml def -> resolved ProviderCfg has protocol/base_url/error_map from def
    let mut defs = HashMap::new();
    let mut error_map = HashMap::new();
    error_map.insert("1113".to_string(), "billing".to_string());
    error_map.insert("1302".to_string(), "rate_limit".to_string());

    defs.insert(
        "z.ai".to_string(),
        ProviderDef {
            protocol: DEFAULT_PROTOCOL.to_string(),
            base_url: "https://api.z.ai/api/anthropic".to_string(),
            error_map,
            health: None,
            path: None,
            path_base: None,
            token_url: None,
            scope: None,
            auth: None,
            allow_metadata_hosts: Vec::new(),
        },
    );

    let mut providers = HashMap::new();
    providers.insert(
        "z.ai".to_string(),
        ProviderDeploy {
            api_key_env: "ZAI_KEY".to_string(),
            protocol: None,
            base_url: None,
            error_map: None,
            path: None,
            path_base: None,
            token_url: None,
            scope: None,
            auth: None,
            health: None,
            _legacy_api_key: None,
            allow_metadata_hosts: None,
        },
    );

    let deploy = DeployCfg {
        listen: DEFAULT_LISTEN_ADDR.into(),
        tls: None,
        admin_listen: DEFAULT_ADMIN_LISTEN_ADDR.into(),
        admin_tls: None,
        admin_insecure: false,
        auth: None,
        providers,
        models: HashMap::new(),
        pools: HashMap::new(),
        hooks: HashMap::new(),
        admin_auth: vec!["admin-tokens".to_string()],
        group_map: HashMap::new(),
        global_hooks: Vec::new(),
        observability: None,
        governance: None,
        security: None,
        limits: LimitsCfg::default(),
        metrics: MetricsCfg::default(),
        health: HealthDefaultsCfg::default(),
        routing: RoutingCfg::default(),
    };

    let result = resolve(&deploy, &defs).expect("resolve should succeed");

    let provider_cfg = result
        .providers
        .get("z.ai")
        .expect("z.ai should be in resolved providers");
    assert_eq!(provider_cfg.protocol, DEFAULT_PROTOCOL);
    assert_eq!(provider_cfg.base_url, "https://api.z.ai/api/anthropic");
    assert_eq!(provider_cfg.api_key_env, "ZAI_KEY");
    assert_eq!(
        provider_cfg.error_map.get("1113"),
        Some(&"billing".to_string())
    );
    assert_eq!(
        provider_cfg.error_map.get("1302"),
        Some(&"rate_limit".to_string())
    );
}

/// A legacy inline `api_key:` under a provider in config.yaml must parse onto
/// `ProviderDeploy._legacy_api_key` (so resolve can warn on it) rather than being silently
/// dropped by serde, and must NOT leak into the resolved ProviderCfg (keys come only from env).
#[test]
fn test_inline_api_key_parsed_and_ignored() {
    let yaml = r#"
listen: "0.0.0.0:8080"
providers:
  myprov:
    api_key_env: MYPROV_KEY
    api_key: "sk-inline-should-be-ignored"
models: {}
"#;
    let deploy: DeployCfg =
        serde_yaml::from_str(yaml).expect("config with inline api_key must parse");
    let dep = deploy.providers.get("myprov").expect("myprov present");
    assert_eq!(
        dep._legacy_api_key.as_deref(),
        Some("sk-inline-should-be-ignored"),
        "inline api_key must be captured on ProviderDeploy, not silently dropped"
    );

    // resolve() discards it (and warns); the resolved ProviderCfg never carries the inline key.
    let mut defs = HashMap::new();
    defs.insert(
        "myprov".to_string(),
        ProviderDef {
            protocol: DEFAULT_PROTOCOL.to_string(),
            base_url: "https://api.example.com".to_string(),
            error_map: HashMap::new(),
            health: None,
            path: None,
            path_base: None,
            token_url: None,
            scope: None,
            auth: None,
            allow_metadata_hosts: Vec::new(),
        },
    );
    let cfg = resolve(&deploy, &defs).expect("resolve");
    assert_eq!(
        cfg.providers["myprov"]._legacy_api_key, None,
        "inline api_key must never reach the resolved ProviderCfg"
    );
    assert_eq!(cfg.providers["myprov"].api_key_env, "MYPROV_KEY");
}

// Admin-token behavior — requires the compile-removable `admin-tokens` module.
#[cfg(feature = "auth-admin-tokens")]
#[test]
fn test_resolve_accepts_enabled_governance_with_admin_token() {
    let defs = HashMap::new();
    let deploy = DeployCfg {
        listen: DEFAULT_LISTEN_ADDR.into(),
        tls: None,
        admin_listen: DEFAULT_ADMIN_LISTEN_ADDR.into(),
        admin_tls: None,
        admin_insecure: false,
        auth: None,
        providers: HashMap::new(),
        models: HashMap::new(),
        pools: HashMap::new(),
        hooks: HashMap::new(),
        admin_auth: vec!["admin-tokens".to_string()],
        group_map: HashMap::new(),
        global_hooks: Vec::new(),
        observability: None,
        governance: Some(GovernanceCfg {
            store: crate::config::GovernanceStore::Memory,
            db_path: DEFAULT_GOVERNANCE_DB.to_string(),
            price_per_request_cents: 1,
            price_per_1k_tokens_cents: 0,
            admin_token: Some("operator-secret".to_string()),
            sqlite_busy_timeout_ms: crate::config::DEFAULT_SQLITE_BUSY_TIMEOUT_MS,
            rate_sweep_interval: crate::config::DEFAULT_RATE_SWEEP_INTERVAL,
            usage_flush_interval_ms: crate::config::DEFAULT_USAGE_FLUSH_INTERVAL_MS,
        }),
        security: None,
        limits: LimitsCfg::default(),
        metrics: MetricsCfg::default(),
        health: HealthDefaultsCfg::default(),
        routing: RoutingCfg::default(),
    };
    assert!(
        resolve(&deploy, &defs).is_ok(),
        "enabled governance WITH an admin_token must resolve"
    );
}

#[test]
fn test_resolve_unknown_provider_error() {
    // config.yaml references nope not in providers.yaml -> resolve returns error naming nope
    let defs = HashMap::new();

    let mut providers = HashMap::new();
    providers.insert(
        "nope".to_string(),
        ProviderDeploy {
            api_key_env: "NOPE_KEY".to_string(),
            protocol: None,
            base_url: None,
            error_map: None,
            path: None,
            path_base: None,
            token_url: None,
            scope: None,
            auth: None,
            health: None,
            _legacy_api_key: None,
            allow_metadata_hosts: None,
        },
    );

    let deploy = DeployCfg {
        listen: DEFAULT_LISTEN_ADDR.into(),
        tls: None,
        admin_listen: DEFAULT_ADMIN_LISTEN_ADDR.into(),
        admin_tls: None,
        admin_insecure: false,
        auth: None,
        providers,
        models: HashMap::new(),
        pools: HashMap::new(),
        hooks: HashMap::new(),
        admin_auth: vec!["admin-tokens".to_string()],
        group_map: HashMap::new(),
        global_hooks: Vec::new(),
        observability: None,
        governance: None,
        security: None,
        limits: LimitsCfg::default(),
        metrics: MetricsCfg::default(),
        health: HealthDefaultsCfg::default(),
        routing: RoutingCfg::default(),
    };

    let result = resolve(&deploy, &defs);
    assert!(result.is_err());
    let errs = result.unwrap_err();
    assert_eq!(errs.len(), 1);
    assert!(errs[0].contains("nope"));
    assert!(errs[0].contains("not found in providers.yaml"));
}

#[test]
fn test_resolve_override_wins() {
    // config.yaml provider with a base_url override wins over the def
    let mut defs = HashMap::new();
    let error_map = HashMap::new();

    defs.insert(
        "custom".to_string(),
        ProviderDef {
            protocol: DEFAULT_PROTOCOL.to_string(),
            base_url: "https://default.example.com".to_string(),
            error_map,
            health: None,
            path: None,
            path_base: None,
            token_url: None,
            scope: None,
            auth: None,
            allow_metadata_hosts: Vec::new(),
        },
    );

    let mut providers = HashMap::new();
    let mut override_error_map = HashMap::new();
    override_error_map.insert("9999".to_string(), "client_error".to_string());

    providers.insert(
        "custom".to_string(),
        ProviderDeploy {
            api_key_env: "CUSTOM_KEY".to_string(),
            protocol: Some("openai".to_string()), // Override protocol
            base_url: Some("https://override.example.com".to_string()), // Override base_url
            error_map: Some(override_error_map),  // Override error_map
            path: None,
            path_base: None,
            token_url: None,
            scope: None,
            auth: None,
            health: None,
            _legacy_api_key: None,
            allow_metadata_hosts: None,
        },
    );

    let deploy = DeployCfg {
        listen: DEFAULT_LISTEN_ADDR.into(),
        tls: None,
        admin_listen: DEFAULT_ADMIN_LISTEN_ADDR.into(),
        admin_tls: None,
        admin_insecure: false,
        auth: None,
        providers,
        models: HashMap::new(),
        pools: HashMap::new(),
        hooks: HashMap::new(),
        admin_auth: vec!["admin-tokens".to_string()],
        group_map: HashMap::new(),
        global_hooks: Vec::new(),
        observability: None,
        governance: None,
        security: None,
        limits: LimitsCfg::default(),
        metrics: MetricsCfg::default(),
        health: HealthDefaultsCfg::default(),
        routing: RoutingCfg::default(),
    };

    let result = resolve(&deploy, &defs).expect("resolve should succeed");

    let provider_cfg = result
        .providers
        .get("custom")
        .expect("custom should be in resolved providers");
    assert_eq!(
        provider_cfg.protocol, "openai",
        "protocol override should win"
    );
    assert_eq!(
        provider_cfg.base_url, "https://override.example.com",
        "base_url override should win"
    );
    assert_eq!(provider_cfg.api_key_env, "CUSTOM_KEY");
    assert_eq!(
        provider_cfg.error_map.get("9999"),
        Some(&"client_error".to_string())
    );
}

#[test]
fn test_resolve_empty_error_map_allowed_in_def() {
    // A def can have empty error_map; validation will catch it later if required
    let mut defs = HashMap::new();
    defs.insert(
        "minimal".to_string(),
        ProviderDef {
            protocol: DEFAULT_PROTOCOL.to_string(),
            base_url: "https://api.example.com".to_string(),
            error_map: HashMap::new(), // Empty but valid for resolution
            health: None,
            path: None,
            path_base: None,
            token_url: None,
            scope: None,
            auth: None,
            allow_metadata_hosts: Vec::new(),
        },
    );

    let mut providers = HashMap::new();
    providers.insert(
        "minimal".to_string(),
        ProviderDeploy {
            api_key_env: "MINIMAL_KEY".to_string(),
            protocol: None,
            base_url: None,
            error_map: None,
            path: None,
            path_base: None,
            token_url: None,
            scope: None,
            auth: None,
            health: None,
            _legacy_api_key: None,
            allow_metadata_hosts: None,
        },
    );

    let deploy = DeployCfg {
        listen: DEFAULT_LISTEN_ADDR.into(),
        tls: None,
        admin_listen: DEFAULT_ADMIN_LISTEN_ADDR.into(),
        admin_tls: None,
        admin_insecure: false,
        auth: None,
        providers,
        models: HashMap::new(),
        pools: HashMap::new(),
        hooks: HashMap::new(),
        admin_auth: vec!["admin-tokens".to_string()],
        group_map: HashMap::new(),
        global_hooks: Vec::new(),
        observability: None,
        governance: None,
        security: None,
        limits: LimitsCfg::default(),
        metrics: MetricsCfg::default(),
        health: HealthDefaultsCfg::default(),
        routing: RoutingCfg::default(),
    };

    let result = resolve(&deploy, &defs).expect("resolve should succeed");
    let provider_cfg = result
        .providers
        .get("minimal")
        .expect("minimal should exist");
    assert!(provider_cfg.error_map.is_empty());
}

// OnExhausted mode parsing tests
#[test]
fn test_on_exhausted_parse_status_503_variants() {
    // Test all Status503 variants
    assert_eq!(
        OnExhausted::parse("reject").unwrap(),
        OnExhausted::Status503
    );
    assert_eq!(OnExhausted::parse("503").unwrap(), OnExhausted::Status503);
    assert_eq!(
        OnExhausted::parse("status_503").unwrap(),
        OnExhausted::Status503
    );
    assert_eq!(
        OnExhausted::parse("status503").unwrap(),
        OnExhausted::Status503
    );
}

#[test]
fn test_on_exhausted_parse_least_bad_variants() {
    // Test all LeastBad variants
    assert_eq!(
        OnExhausted::parse("least_bad").unwrap(),
        OnExhausted::LeastBad
    );
    assert_eq!(
        OnExhausted::parse("least-bad").unwrap(),
        OnExhausted::LeastBad
    );
    assert_eq!(
        OnExhausted::parse("leastbad").unwrap(),
        OnExhausted::LeastBad
    );
}

#[test]
fn test_on_exhausted_parse_fallback_pool() {
    // Test FallbackPool with colon syntax
    let result = OnExhausted::parse("fallback_pool:drain").unwrap();
    assert_eq!(result, OnExhausted::FallbackPool("drain".to_string()));

    let result2 = OnExhausted::parse("fallback_pool:backup").unwrap();
    assert_eq!(result2, OnExhausted::FallbackPool("backup".to_string()));
}

#[test]
fn test_on_exhausted_parse_unknown_action() {
    // Test that unknown actions produce clear error messages (exhaustive match)
    let result = OnExhausted::parse("invalid_mode");
    assert!(result.is_err());
    let err_msg = result.unwrap_err();
    assert!(err_msg.contains("unknown on_exhausted action"));
    assert!(err_msg.contains("invalid_mode"));

    let result2 = OnExhausted::parse("fallback");
    assert!(result2.is_err());
    let err_msg2 = result2.unwrap_err();
    assert!(err_msg2.contains("'fallback' is not a valid on_exhausted action"));
}

#[test]
fn test_on_exhausted_parse_empty_fallback_pool_name() {
    // Test that empty fallback pool name produces error
    let result = OnExhausted::parse("fallback_pool:");
    assert!(result.is_err());
    let err_msg = result.unwrap_err();
    assert!(err_msg.contains("fallback_pool requires a non-empty pool name"));
}

#[test]
fn breaker_cfg_default_matches_serde_default_fns() {
    // `BreakerCfg::default()` (used when a pool omits the whole `breaker:` block) and the
    // `#[serde(default = ...)]` fns (used when individual fields are omitted) must agree on the
    // cooldown literals; otherwise the same pool would get different cooldowns depending on
    // whether the block is present. `Default` now delegates to these fns, so this guards against
    // the two ever drifting again.
    let d = BreakerCfg::default();
    assert_eq!(
        d.base_cooldown_secs,
        default_cooldown(),
        "base_cooldown_secs default diverged from default_cooldown()"
    );
    assert_eq!(
        d.max_cooldown_secs,
        default_max_cooldown(),
        "max_cooldown_secs default diverged from default_max_cooldown()"
    );
}

/// REGRESSION: every config struct that carries a secret must REDACT it
/// in `Debug`, not print it in plaintext. A derived `Debug` for AuthCfg,
/// GovernanceCfg, ProviderCfg, and ProviderDeploy would leak the literal token/api_key the moment
/// the struct — or any struct that embeds it (RootCfg/DeployCfg) — is debug-logged. Against the
/// old derived impls these assertions FAIL (the secret appears); they pass once the manual
/// redacting impls are in place. The secret values are deliberately distinctive so a substring
/// search is decisive.
#[test]
fn test_debug_redacts_all_config_secrets() {
    // AuthCfg: client_tokens (the 1.0.0 `token` field was removed — setting it is now a parse
    // error, so it can no longer reach `Debug`).
    let auth = AuthCfg {
        chain: vec!["tokens".to_string()],
        upstream_credentials: crate::auth::UpstreamCreds::Own,
        client_tokens: vec![
            "SECRET-client-token-aaa".to_string(),
            "SECRET-client-token-bbb".to_string(),
        ],
        modules: std::collections::HashMap::new(),
    };
    let dbg = format!("{auth:?}");
    assert!(
        !dbg.contains("SECRET-client-token-aaa") && !dbg.contains("SECRET-client-token-bbb"),
        "AuthCfg Debug leaked a client token: {dbg}"
    );
    assert!(
        dbg.contains("2 configured"),
        "AuthCfg Debug should report the allowlist COUNT: {dbg}"
    );

    // GovernanceCfg: admin_token.
    let gov = GovernanceCfg {
        store: crate::config::GovernanceStore::Memory,
        db_path: "x.db".to_string(),
        price_per_request_cents: 1,
        price_per_1k_tokens_cents: 0,
        admin_token: Some("SECRET-admin-bearer-token-qqq".to_string()),
        sqlite_busy_timeout_ms: crate::config::DEFAULT_SQLITE_BUSY_TIMEOUT_MS,
        rate_sweep_interval: crate::config::DEFAULT_RATE_SWEEP_INTERVAL,
        usage_flush_interval_ms: crate::config::DEFAULT_USAGE_FLUSH_INTERVAL_MS,
    };
    let dbg = format!("{gov:?}");
    assert!(
        !dbg.contains("SECRET-admin-bearer-token-qqq"),
        "GovernanceCfg Debug leaked admin_token: {dbg}"
    );
    assert!(
        dbg.contains("<redacted; present>"),
        "GovernanceCfg Debug should mark admin_token present-but-redacted: {dbg}"
    );

    // ProviderCfg: inline _legacy_api_key.
    let prov = ProviderCfg {
        protocol: DEFAULT_PROTOCOL.to_string(),
        base_url: "https://example".to_string(),
        api_key_env: "PROV_KEY".to_string(),
        health: None,
        error_map: HashMap::new(),
        path: None,
        path_base: None,
        token_url: None,
        scope: None,
        auth: None,
        allow_metadata_hosts: Vec::new(),
        _legacy_api_key: Some("SECRET-inline-provider-key-www".to_string()),
    };
    let dbg = format!("{prov:?}");
    assert!(
        !dbg.contains("SECRET-inline-provider-key-www"),
        "ProviderCfg Debug leaked the inline api_key: {dbg}"
    );
    assert!(
        dbg.contains("PROV_KEY"),
        "ProviderCfg Debug should still show the api_key_env NAME (not a secret): {dbg}"
    );

    // ProviderDeploy: inline _legacy_api_key.
    let deploy = ProviderDeploy {
        api_key_env: "DEPLOY_KEY".to_string(),
        _legacy_api_key: Some("SECRET-inline-deploy-key-zzz".to_string()),
        ..ProviderDeploy::default()
    };
    let dbg = format!("{deploy:?}");
    assert!(
        !dbg.contains("SECRET-inline-deploy-key-zzz"),
        "ProviderDeploy Debug leaked the inline api_key: {dbg}"
    );
    assert!(
        dbg.contains("DEPLOY_KEY"),
        "ProviderDeploy Debug should still show the api_key_env NAME (not a secret): {dbg}"
    );
}

/// REGRESSION: the redaction must hold TRANSITIVELY — a derived `Debug`
/// on an embedding struct (DeployCfg) delegates to each field's `Debug`, so the redacting impls
/// above are what protect the whole-config dump an operator is most likely to log. This builds a
/// DeployCfg containing every secret and asserts none survive its Debug output.
#[test]
fn test_debug_redacts_secrets_transitively_through_deploycfg() {
    let mut providers = HashMap::new();
    providers.insert(
        "myprov".to_string(),
        ProviderDeploy {
            api_key_env: "DEPLOY_KEY".to_string(),
            _legacy_api_key: Some("SECRET-embedded-deploy-key".to_string()),
            ..ProviderDeploy::default()
        },
    );
    let deploy = DeployCfg {
        listen: "127.0.0.1:8080".to_string(),
        tls: None,
        admin_listen: DEFAULT_ADMIN_LISTEN_ADDR.into(),
        admin_tls: None,
        admin_insecure: false,
        auth: Some(AuthCfg {
            chain: vec!["tokens".to_string()],
            upstream_credentials: crate::auth::UpstreamCreds::Own,
            client_tokens: vec!["SECRET-embedded-client-token".to_string()],
            modules: std::collections::HashMap::new(),
        }),
        providers,
        models: HashMap::new(),
        pools: HashMap::new(),
        hooks: HashMap::new(),
        admin_auth: vec!["admin-tokens".to_string()],
        group_map: HashMap::new(),
        global_hooks: Vec::new(),
        observability: None,
        governance: Some(GovernanceCfg {
            store: crate::config::GovernanceStore::Memory,
            db_path: "x.db".to_string(),
            price_per_request_cents: 1,
            price_per_1k_tokens_cents: 0,
            admin_token: Some("SECRET-embedded-admin-token".to_string()),
            sqlite_busy_timeout_ms: crate::config::DEFAULT_SQLITE_BUSY_TIMEOUT_MS,
            rate_sweep_interval: crate::config::DEFAULT_RATE_SWEEP_INTERVAL,
            usage_flush_interval_ms: crate::config::DEFAULT_USAGE_FLUSH_INTERVAL_MS,
        }),
        security: None,
        limits: LimitsCfg::default(),
        metrics: MetricsCfg::default(),
        health: HealthDefaultsCfg::default(),
        routing: RoutingCfg::default(),
    };
    let dbg = format!("{deploy:?}");
    for secret in [
        "SECRET-embedded-deploy-key",
        "SECRET-embedded-client-token",
        "SECRET-embedded-admin-token",
    ] {
        assert!(
            !dbg.contains(secret),
            "DeployCfg Debug leaked a nested secret ({secret}): {dbg}"
        );
    }
}

// ── operational limits ("NEVER CODED CAPS") ──────────────────────────────────────────────────

/// A config that OMITS the whole `limits:` block (and every other limit section) must resolve to
/// the HISTORICAL hardcoded defaults — the common case, and the guarantee that nothing changes
/// for existing deployments. Asserts every resolved limit equals its `DEFAULT_*` const.
#[test]
fn test_limits_absent_block_yields_historical_defaults() {
    let yaml = r#"
listen: "0.0.0.0:8080"
providers:
  anthropic:
    api_key_env: ANTHROPIC_KEY
models:
  claude:
    provider: anthropic
    max_concurrent: 10
"#;
    let deploy: DeployCfg =
        serde_yaml::from_str(yaml).expect("config without a limits block must parse");
    let l = LimitsResolved::from_sections(
        &deploy.limits,
        &deploy.observability.clone().unwrap_or_default(),
        &deploy.governance.clone().unwrap_or_default(),
        &deploy.metrics,
        &deploy.health,
        &deploy.routing,
    );
    assert_eq!(
        l.upstream_request_timeout_secs,
        DEFAULT_UPSTREAM_REQUEST_TIMEOUT_SECS
    );
    assert_eq!(l.request_body_max_bytes, DEFAULT_REQUEST_BODY_MAX_BYTES);
    assert_eq!(l.pool_max_idle_per_host, DEFAULT_POOL_MAX_IDLE_PER_HOST);
    assert_eq!(l.max_inbound_concurrent, DEFAULT_MAX_INBOUND_CONCURRENT);
    assert_eq!(
        l.max_inbound_concurrent, 0,
        "default must be the unlimited no-op"
    );
    assert_eq!(l.hard_down_cooldown_secs, DEFAULT_HARD_DOWN_COOLDOWN_SECS);
    assert_eq!(
        l.upstream_error_body_max_bytes,
        DEFAULT_UPSTREAM_ERROR_BODY_MAX_BYTES
    );
    assert_eq!(
        l.tls_handshake_timeout_secs,
        DEFAULT_TLS_HANDSHAKE_TIMEOUT_SECS
    );
    assert_eq!(
        l.max_honored_retry_after_secs,
        DEFAULT_MAX_HONORED_RETRY_AFTER_SECS
    );
    assert_eq!(l.default_max_tokens, DEFAULT_DEFAULT_MAX_TOKENS);
    assert_eq!(l.default_max_tokens, crate::proto::DEFAULT_MAX_TOKENS);
    assert_eq!(
        l.max_inflight_webhook_deliveries,
        DEFAULT_MAX_INFLIGHT_WEBHOOK_DELIVERIES
    );
    assert_eq!(
        l.webhook_delivery_timeout_secs,
        DEFAULT_WEBHOOK_DELIVERY_TIMEOUT_SECS
    );
    assert_eq!(l.key_gauge_limit, DEFAULT_KEY_GAUGE_LIMIT);
    assert_eq!(l.sqlite_busy_timeout_ms, DEFAULT_SQLITE_BUSY_TIMEOUT_MS);
    assert_eq!(l.rate_sweep_interval, DEFAULT_RATE_SWEEP_INTERVAL);
    assert_eq!(l.default_probe_interval_secs, DEFAULT_PROBE_INTERVAL_SECS);
    assert_eq!(l.default_probe_timeout_secs, DEFAULT_PROBE_TIMEOUT_SECS);
    assert_eq!(l.default_policy_timeout_ms, DEFAULT_POLICY_TIMEOUT_MS);
}

/// `LimitsResolved::default()` (the omitted-everything path) must equal the per-field defaults —
/// the two ways of getting "today's behavior" cannot drift.
#[test]
fn test_limits_resolved_default_matches_from_sections_defaults() {
    let a = LimitsResolved::default();
    let b = LimitsResolved::from_sections(
        &LimitsCfg::default(),
        &ObservabilityCfg::default(),
        &GovernanceCfg::default(),
        &MetricsCfg::default(),
        &HealthDefaultsCfg::default(),
        &RoutingCfg::default(),
    );
    assert_eq!(a.request_body_max_bytes, b.request_body_max_bytes);
    assert_eq!(
        a.upstream_request_timeout_secs,
        b.upstream_request_timeout_secs
    );
    assert_eq!(a.sqlite_busy_timeout_ms, b.sqlite_busy_timeout_ms);
    assert_eq!(a.default_policy_timeout_ms, b.default_policy_timeout_ms);
    assert_eq!(a.key_gauge_limit, b.key_gauge_limit);
}

/// A SET limit value (across several sections) OVERRIDES the default; an unset SIBLING field in
/// the same block still defaults. Exercises the per-field `#[serde(default = "...")]` wiring.
#[test]
fn test_limits_set_value_overrides_default() {
    let yaml = r#"
listen: "0.0.0.0:8080"
providers:
  anthropic:
    api_key_env: ANTHROPIC_KEY
models:
  claude:
    provider: anthropic
    max_concurrent: 10
limits:
  upstream_request_timeout_secs: 42
  max_inbound_concurrent: 256
  request_body_max_bytes: 1048576
metrics:
  key_gauge_limit: 9
governance:
  sqlite_busy_timeout_ms: 1234
health:
  default_probe_interval_secs: 7
routing:
  default_policy_timeout_ms: 99
"#;
    let deploy: DeployCfg = serde_yaml::from_str(yaml).expect("limits override must parse");
    let l = LimitsResolved::from_sections(
        &deploy.limits,
        &deploy.observability.clone().unwrap_or_default(),
        &deploy.governance.clone().unwrap_or_default(),
        &deploy.metrics,
        &deploy.health,
        &deploy.routing,
    );
    assert_eq!(l.upstream_request_timeout_secs, 42);
    assert_eq!(l.max_inbound_concurrent, 256);
    assert_eq!(l.request_body_max_bytes, 1_048_576);
    assert_eq!(l.key_gauge_limit, 9);
    assert_eq!(l.sqlite_busy_timeout_ms, 1234);
    assert_eq!(l.default_probe_interval_secs, 7);
    assert_eq!(l.default_policy_timeout_ms, 99);
    // Unset SIBLING fields still default (pool_max_idle in the same `limits:` block, probe
    // TIMEOUT in the same `health:` block):
    assert_eq!(l.pool_max_idle_per_host, DEFAULT_POOL_MAX_IDLE_PER_HOST);
    assert_eq!(l.default_probe_timeout_secs, DEFAULT_PROBE_TIMEOUT_SECS);
    assert_eq!(l.hard_down_cooldown_secs, DEFAULT_HARD_DOWN_COOLDOWN_SECS);
}

/// The body-size COUPLING: `limits.request_body_max_bytes` is the SINGLE knob; the resolved value
/// the inbound `DefaultBodyLimit` uses IS the same value the egress translate-body cap reads
/// (`crate::limits::translate_body_max_bytes` returns `request_body_max_bytes`). So an accepted
/// request is always buffer-translatable on egress.
#[test]
fn test_request_body_size_couples_ingress_and_translate() {
    let d = LimitsResolved::default();
    assert_eq!(d.request_body_max_bytes, DEFAULT_REQUEST_BODY_MAX_BYTES);

    let yaml = r#"
listen: "0.0.0.0:8080"
providers:
  anthropic:
    api_key_env: ANTHROPIC_KEY
models:
  claude:
    provider: anthropic
    max_concurrent: 10
limits:
  request_body_max_bytes: 5242880
"#;
    let deploy: DeployCfg = serde_yaml::from_str(yaml).expect("parse");
    let l = LimitsResolved::from_sections(
        &deploy.limits,
        &ObservabilityCfg::default(),
        &GovernanceCfg::default(),
        &MetricsCfg::default(),
        &HealthDefaultsCfg::default(),
        &RoutingCfg::default(),
    );
    assert_eq!(l.request_body_max_bytes, 5 * 1024 * 1024);
}
