use super::*;

use crate::config;

fn make_root_cfg(
    providers: HashMap<String, config::ProviderCfg>,
    models: HashMap<String, config::ModelCfg>,
    pools: HashMap<String, config::PoolCfg>,
) -> RootCfg {
    config::RootCfg {
        listen: crate::config::DEFAULT_LISTEN_ADDR.into(),
        tls: None,
        admin_listen: crate::config::DEFAULT_ADMIN_LISTEN_ADDR.to_string(),
        admin_tls: None,
        auth: None,
        providers,
        models,
        pools,
        hooks: HashMap::new(),
        admin_auth: vec!["admin-tokens".to_string()],
        group_map: HashMap::new(),
        global_hooks: Vec::new(),
        blocked_metadata_hosts: Vec::new(),
        allow_metadata_hosts: Vec::new(),
        allow_all_metadata: false,
        limits: config::LimitsResolved::default(),
    }
}

/// Like [`make_root_cfg`] but with operator-supplied `security.blocked_metadata_hosts` entries.
fn make_root_cfg_with_blocked(
    providers: HashMap<String, config::ProviderCfg>,
    blocked_metadata_hosts: Vec<String>,
) -> RootCfg {
    let mut cfg = make_root_cfg(providers, HashMap::new(), HashMap::new());
    cfg.blocked_metadata_hosts = blocked_metadata_hosts;
    cfg
}

fn make_provider(protocol: &str, base_url: &str, api_key_env: &str) -> config::ProviderCfg {
    // Provide a minimal valid error_map to satisfy validation
    let mut error_map = std::collections::HashMap::new();
    error_map.insert("400".to_string(), "client_error".to_string());

    config::ProviderCfg {
        protocol: protocol.into(),
        base_url: base_url.into(),
        api_key_env: api_key_env.into(),
        health: None,
        error_map,
        path: None,
        path_base: None,
        token_url: None,
        scope: None,
        auth: None,
        _legacy_api_key: None,
        allow_metadata_hosts: Vec::new(),
    }
}

fn make_model(provider: &str, max_concurrent: usize) -> config::ModelCfg {
    // Existing callers pass a concrete cap; wrap it as `Some` now that the field is optional
    // (None = unbounded). The omitted-cap case is covered by `make_model_unbounded`.
    let mut m = make_model_unbounded(provider);
    m.max_concurrent = Some(max_concurrent);
    m
}

/// A model config with `max_concurrent` OMITTED (None = unbounded), exercising the opt-in-limiter
/// default that mirrors `max_requests: -1`.
fn make_model_unbounded(provider: &str) -> config::ModelCfg {
    config::ModelCfg {
        reasoning: None,
        prompt_caching: None,
        max_requests: -1,
        provider: provider.into(),
        max_concurrent: None,
        default_max_tokens: None,
        upstream_model: None,
        attempt_timeout_ms: None,
    }
}

fn make_pool(members: Vec<config::PoolMember>) -> config::PoolCfg {
    config::PoolCfg {
        members,
        breaker: None,
        failover: None,
        on_exhausted: None,
        affinity: None,
        policy: config::PoolPolicy::default(),
        gates: Vec::new(),
        base_named: false,
    }
}

fn make_member(target: &str) -> config::PoolMember {
    config::PoolMember {
        reasoning: None,
        target: target.into(),
        weight: 1,
        attempt_timeout_ms: None,
        context_max: None,
        tier: None,
        cost_per_mtok: None,
        tags: Vec::new(),
    }
}

#[test]
fn test_provider_auth_style_is_a_closed_enum() {
    // The per-provider auth-style override is a `ProviderAuth` enum, so an unrecognized spelling
    // is rejected at DESERIALIZE time (no hand-check in validate()). The two accepted wire strings
    // ('bearer' / 'api-key') are unchanged from the pre-enum `Option<String>` field.
    assert_eq!(
        serde_yaml::from_str::<config::ProviderAuth>("bearer").unwrap(),
        config::ProviderAuth::Bearer
    );
    assert_eq!(
        serde_yaml::from_str::<config::ProviderAuth>("api-key").unwrap(),
        config::ProviderAuth::ApiKey
    );
    assert!(
        serde_yaml::from_str::<config::ProviderAuth>("oauth2").is_err(),
        "'oauth2' is not a recognized provider auth style and must fail to deserialize"
    );
}

#[test]
fn test_validate_rejects_bad_protocol() {
    // An unknown `protocol` must be COLLECTED by validate() (alongside any other config error),
    // not escape to a lone `die()` at lane construction in main.rs. Mirrors
    // test_validate_rejects_bad_auth_style.
    let mut providers = HashMap::new();
    let bad = make_provider("nope", "https://api.example.com", "API_KEY");
    providers.insert("bad".to_string(), bad);
    // A provider on a real protocol must NOT trigger this error.
    let ok = make_provider("anthropic", "https://api.anthropic.com", "ANTHROPIC_KEY");
    providers.insert("good".to_string(), ok);

    let cfg = make_root_cfg(providers, HashMap::new(), HashMap::new());
    let errs = validate(&cfg).expect_err("unknown protocol must fail validation");
    assert!(
        errs.iter()
            .any(|e| e.contains("unknown protocol 'nope'") && e.contains("'bad'")),
        "expected an unknown-protocol error naming provider 'bad' and 'nope'; got: {errs:?}"
    );
    // The error must enumerate the allowed set so the operator can self-correct.
    let msg = errs
        .iter()
        .find(|e| e.contains("unknown protocol 'nope'"))
        .unwrap_or_else(|| panic!("expected unknown-protocol error; got: {errs:?}"));
    for proto in crate::proto::KNOWN_PROTOCOLS {
        assert!(
            msg.contains(proto),
            "allowed-set list must include '{proto}'; got: {msg}"
        );
    }
    // A real protocol ('anthropic') must not be flagged as unknown.
    assert!(
        !errs
            .iter()
            .any(|e| e.contains("unknown protocol 'anthropic'")),
        "'anthropic' is a valid protocol and must not error; got: {errs:?}"
    );
}

#[test]
fn test_error_map_invalid_class_message_lists_full_valid_set() {
    // The invalid-StatusClass diagnostic must enumerate EVERY class that
    // breaker::status_class_from_str accepts; `context_length` was historically
    // omitted from the message even though it is a valid mapping target, so an
    // operator who saw the error could not learn it was an allowed value.
    let mut providers = HashMap::new();
    let mut p = make_provider("anthropic", "https://api.example.com", "API_KEY");
    // Replace the minimal valid map with one bad entry to force the diagnostic.
    p.error_map.clear();
    p.error_map
        .insert("429".to_string(), "not_a_class".to_string());
    providers.insert("bad".to_string(), p);

    let cfg = make_root_cfg(providers, HashMap::new(), HashMap::new());
    let errs = validate(&cfg).expect_err("invalid StatusClass must fail validation");

    let msg = errs
        .iter()
        .find(|e| e.contains("invalid StatusClass 'not_a_class'"))
        .unwrap_or_else(|| panic!("expected invalid-StatusClass error; got: {errs:?}"));
    assert!(
            msg.contains("context_length"),
            "valid-values list must include 'context_length' (it is accepted by status_class_from_str); got: {msg}"
        );

    // Guard against drift in the other direction: every class the breaker accepts
    // must appear in the message's valid-values list.
    for class in [
        "rate_limit",
        "overloaded",
        "server_error",
        "timeout",
        "network",
        "auth",
        "billing",
        "client_error",
        "context_length",
    ] {
        assert!(
            crate::config::status_class_from_str(class).is_some(),
            "test invariant: '{class}' should be a real StatusClass"
        );
        assert!(
            msg.contains(class),
            "valid-values list must include '{class}'; got: {msg}"
        );
    }
}

#[test]
fn test_error_map_context_length_is_a_valid_class() {
    // `context_length` must be accepted as an error_map target without producing
    // an invalid-StatusClass error (it is a real breaker StatusClass).
    let mut providers = HashMap::new();
    let mut p = make_provider("anthropic", "https://api.example.com", "API_KEY");
    p.error_map.clear();
    p.error_map
        .insert("400".to_string(), "context_length".to_string());
    providers.insert("ctx".to_string(), p);

    let cfg = make_root_cfg(providers, HashMap::new(), HashMap::new());
    let result = validate(&cfg);
    if let Err(errs) = result {
        assert!(
            !errs.iter().any(|e| e.contains("invalid StatusClass")),
            "'context_length' is a valid StatusClass and must not error; got: {errs:?}"
        );
    }
}

#[test]
fn test_validate_rejects_zero_default_max_tokens() {
    let mut providers = HashMap::new();
    providers.insert(
        "myprovider".to_string(),
        make_provider("anthropic", "https://api.example.com", "API_KEY"),
    );
    let mut models = HashMap::new();
    let mut m = make_model("myprovider", 10);
    m.default_max_tokens = Some(0);
    models.insert("mymodel".to_string(), m);
    // A positive value (and the unset None default) must NOT error.
    let mut ok = make_model("myprovider", 10);
    ok.default_max_tokens = Some(4096);
    models.insert("okmodel".to_string(), ok);

    let cfg = make_root_cfg(providers, models, HashMap::new());
    let errs = validate(&cfg).expect_err("default_max_tokens: 0 must fail validation");
    assert!(
        errs.iter()
            .any(|e| e.contains("mymodel") && e.contains("default_max_tokens: 0")),
        "expected a default_max_tokens:0 error for 'mymodel'; got: {errs:?}"
    );
    assert!(
        !errs.iter().any(|e| e.contains("okmodel")),
        "a positive default_max_tokens must not error; got: {errs:?}"
    );
}

#[test]
fn test_validate_rejects_empty_upstream_model() {
    let mut providers = HashMap::new();
    providers.insert(
        "myprovider".to_string(),
        make_provider("anthropic", "https://api.example.com", "API_KEY"),
    );
    let mut models = HashMap::new();
    // Whitespace-only override → empty wire model id → must error.
    let mut bad = make_model("myprovider", 10);
    bad.upstream_model = Some("   ".to_string());
    models.insert("badmodel".to_string(), bad);
    // A real override (and the unset None default) must NOT error.
    let mut ok = make_model("myprovider", 10);
    ok.upstream_model = Some("anthropic.claude-3-5-sonnet-20241022-v2:0".to_string());
    models.insert("okmodel".to_string(), ok);

    let cfg = make_root_cfg(providers, models, HashMap::new());
    let errs = validate(&cfg).expect_err("empty upstream_model must fail validation");
    assert!(
        errs.iter()
            .any(|e| e.contains("badmodel") && e.contains("upstream_model")),
        "expected an empty-upstream_model error for 'badmodel'; got: {errs:?}"
    );
    assert!(
        !errs.iter().any(|e| e.contains("okmodel")),
        "a non-empty upstream_model must not error; got: {errs:?}"
    );
}

#[test]
fn test_validate_rejects_pool_name_equals_provider_name() {
    let mut providers = HashMap::new();
    // Add minimal error_map to avoid extra validation error
    let mut pm_error_map = std::collections::HashMap::new();
    pm_error_map.insert("400".to_string(), "client_error".to_string());

    providers.insert(
        "myprovider".to_string(),
        config::ProviderCfg {
            protocol: "anthropic".into(),
            base_url: "https://api.example.com".into(),
            api_key_env: "API_KEY".into(),
            health: None,
            error_map: pm_error_map,
            path: None,
            path_base: None,
            token_url: None,
            scope: None,
            auth: None,
            _legacy_api_key: None,
            allow_metadata_hosts: Vec::new(),
        },
    );

    let mut models = HashMap::new();
    models.insert("mymodel".to_string(), make_model("myprovider", 10));

    let mut pools = HashMap::new();
    pools.insert(
        "myprovider".to_string(), // Same name as provider!
        make_pool(vec![make_member("mymodel")]),
    );

    let cfg = make_root_cfg(providers, models, pools);
    let result = validate(&cfg);

    assert!(result.is_err());
    let errs = result.unwrap_err();
    assert_eq!(errs.len(), 1);
    assert!(errs[0].contains("myprovider"));
    assert!(errs[0].contains("pool name") && errs[0].contains("conflicts with provider name"));
}

#[test]
fn test_validate_rejects_unknown_member_ref() {
    let mut providers = HashMap::new();
    // Add minimal error_map to avoid extra validation error
    let mut mp_error_map = std::collections::HashMap::new();
    mp_error_map.insert("400".to_string(), "client_error".to_string());

    providers.insert(
        "myprovider".to_string(),
        config::ProviderCfg {
            protocol: "anthropic".into(),
            base_url: "https://api.example.com".into(),
            api_key_env: "API_KEY".into(),
            health: None,
            error_map: mp_error_map,
            path: None,
            path_base: None,
            token_url: None,
            scope: None,
            auth: None,
            _legacy_api_key: None,
            allow_metadata_hosts: Vec::new(),
        },
    );

    let models = HashMap::new();

    let mut pools = HashMap::new();
    pools.insert(
        "mypoool".to_string(),
        make_pool(vec![make_member("unknownmodel")]), // References non-existent model
    );

    let cfg = make_root_cfg(providers, models, pools);
    let result = validate(&cfg);

    assert!(result.is_err());
    let errs = result.unwrap_err();
    assert_eq!(errs.len(), 1);
    assert!(errs[0].contains("unknownmodel"));
    assert!(errs[0].contains("references unknown model"));
}

#[test]
fn test_validate_token_url_ssrf_and_scheme() {
    // token_url carries the client secret in the POST body, so it must clear BOTH the https
    // requirement (case-INSENSITIVELY) and the SSRF/metadata denylist — same as base_url. (audit H1.)
    let build = |token_url: &str| -> Vec<String> {
        let mut error_map = std::collections::HashMap::new();
        error_map.insert("400".to_string(), "client_error".to_string());
        let mut providers = HashMap::new();
        providers.insert(
            "entra".to_string(),
            config::ProviderCfg {
                protocol: "openai".into(),
                base_url: "https://myres.openai.azure.com".into(),
                api_key_env: "API_KEY".into(),
                health: None,
                error_map,
                path: None,
                path_base: None,
                token_url: Some(token_url.to_string()),
                scope: Some("api://x/.default".into()),
                auth: Some(config::ProviderAuth::OAuthClientCredentials),
                _legacy_api_key: None,
                allow_metadata_hosts: Vec::new(),
            },
        );
        let mut models = HashMap::new();
        models.insert("m".to_string(), make_model("entra", 10));
        let mut pools = HashMap::new();
        pools.insert("p".to_string(), make_pool(vec![make_member("m")]));
        let cfg = make_root_cfg(providers, models, pools);
        validate(&cfg).err().unwrap_or_default()
    };

    // A legitimate Entra token endpoint validates clean.
    assert!(
        build("https://login.microsoftonline.com/TENANT/oauth2/v2.0/token").is_empty(),
        "a valid https token_url must pass"
    );
    // Case-insensitive scheme: uppercase HTTPS must NOT trip the scheme guard.
    let up = build("HTTPS://login.microsoftonline.com/t/token");
    assert!(
        !up.iter()
            .any(|e| e.contains("token_url") && e.contains("must use")),
        "uppercase HTTPS token_url must not trip the scheme guard; got: {up:?}"
    );
    // Public http:// is rejected (cleartext secret) — and uppercase HTTP:// cannot bypass it.
    for scheme in ["http", "HTTP"] {
        let errs = build(&format!("{scheme}://token.example.com/oauth"));
        assert!(
            errs.iter()
                .any(|e| e.contains("token_url") && e.contains("https")),
            "{scheme}:// public token_url must be rejected; got: {errs:?}"
        );
    }
    // SSRF: an https token_url pointed at cloud metadata is blocked (would leak the client secret).
    for host in ["169.254.169.254", "metadata.google.internal"] {
        let errs = build(&format!("https://{host}/token"));
        assert!(
            errs.iter()
                .any(|e| e.contains("token_url") && e.contains("metadata")),
            "token_url at {host} must be SSRF-blocked; got: {errs:?}"
        );
    }
    // Whitespace-only token_url is treated as absent (trimmed), not a valid endpoint.
    let ws = build("   ");
    assert!(
        ws.iter().any(|e| e.contains("token_url")),
        "whitespace-only token_url must be rejected as missing; got: {ws:?}"
    );
}

#[test]
fn test_validate_conflicting_context_max_across_pools() {
    // A model maps to one lane, so a DIFFERING context_max across pools must be a validate() error —
    // not only a boot-time `die`. Else a clean --validate would still crash at real boot. (audit M7.)
    let build = |ca: Option<usize>, cb: Option<usize>| -> Vec<String> {
        let mut error_map = std::collections::HashMap::new();
        error_map.insert("400".to_string(), "client_error".to_string());
        let mut providers = HashMap::new();
        providers.insert(
            "p".to_string(),
            config::ProviderCfg {
                protocol: "openai".into(),
                base_url: "https://api.example.com".into(),
                api_key_env: "API_KEY".into(),
                health: None,
                error_map,
                path: None,
                path_base: None,
                token_url: None,
                scope: None,
                auth: None,
                _legacy_api_key: None,
                allow_metadata_hosts: Vec::new(),
            },
        );
        let mut models = HashMap::new();
        models.insert("m".to_string(), make_model("p", 10));
        let mut a = make_member("m");
        a.context_max = ca;
        let mut b = make_member("m");
        b.context_max = cb;
        let mut pools = HashMap::new();
        pools.insert("poolA".to_string(), make_pool(vec![a]));
        pools.insert("poolB".to_string(), make_pool(vec![b]));
        validate(&make_root_cfg(providers, models, pools))
            .err()
            .unwrap_or_default()
    };
    assert!(
        build(Some(128000), Some(200000))
            .iter()
            .any(|e| e.contains("conflicting context_max")),
        "differing context_max across pools must be a validate() error"
    );
    assert!(
        !build(Some(128000), Some(128000))
            .iter()
            .any(|e| e.contains("conflicting context_max")),
        "identical context_max must not conflict"
    );
    assert!(
        !build(Some(128000), None)
            .iter()
            .any(|e| e.contains("conflicting context_max")),
        "None must not conflict with an explicit value"
    );
}

#[test]
fn test_validate_collects_all_errors() {
    let mut providers = HashMap::new();
    // Add minimal error_map to avoid extra validation error
    let mut cm_error_map = std::collections::HashMap::new();
    cm_error_map.insert("400".to_string(), "client_error".to_string());

    providers.insert(
        "conflict_provider".to_string(),
        config::ProviderCfg {
            protocol: "anthropic".into(),
            base_url: "https://api.example.com".into(),
            api_key_env: "API_KEY".into(),
            health: None,
            error_map: cm_error_map,
            path: None,
            path_base: None,
            token_url: None,
            scope: None,
            auth: None,
            _legacy_api_key: None,
            allow_metadata_hosts: Vec::new(),
        },
    );

    let mut models = HashMap::new();
    models.insert("model1".to_string(), make_model("conflict_provider", 10));

    let mut pools = HashMap::new();
    // Pool with same name as provider
    pools.insert(
        "conflict_provider".to_string(),
        make_pool(vec![make_member("model1")]),
    );
    // Pool with unknown member
    pools.insert(
        "otherpool".to_string(),
        make_pool(vec![make_member("nonexistent_model")]),
    );

    let cfg = make_root_cfg(providers, models, pools);
    let result = validate(&cfg);

    assert!(result.is_err());
    let errs = result.unwrap_err();

    // Should collect BOTH errors (pool-name conflict + unknown member)
    assert_eq!(errs.len(), 2);

    let err_text = errs.join(" | ");
    assert!(err_text.contains("conflict_provider"));
    assert!(err_text.contains("nonexistent_model"));
}

#[test]
fn test_validate_heterogeneous_pool_is_ok() {
    let mut providers = HashMap::new();
    // Two different protocols with minimal error_maps
    let mut anthropic_error_map = std::collections::HashMap::new();
    anthropic_error_map.insert("400".to_string(), "client_error".to_string());

    let mut openai_error_map = std::collections::HashMap::new();
    openai_error_map.insert("400".to_string(), "client_error".to_string());

    providers.insert(
        "anthropic_provider".to_string(),
        config::ProviderCfg {
            protocol: "anthropic".into(),
            base_url: "https://api.anthropic.com".into(),
            api_key_env: "ANTHROPIC_KEY".into(),
            health: None,
            error_map: anthropic_error_map,
            path: None,
            path_base: None,
            token_url: None,
            scope: None,
            auth: None,
            _legacy_api_key: None,
            allow_metadata_hosts: Vec::new(),
        },
    );
    providers.insert(
        "openai_provider".to_string(),
        config::ProviderCfg {
            protocol: "openai".into(),
            base_url: "https://api.openai.com".into(),
            api_key_env: "OPENAI_KEY".into(),
            health: None,
            error_map: openai_error_map,
            path: None,
            path_base: None,
            token_url: None,
            scope: None,
            auth: None,
            _legacy_api_key: None,
            allow_metadata_hosts: Vec::new(),
        },
    );

    let mut models = HashMap::new();
    models.insert(
        "anthropic_model".to_string(),
        make_model("anthropic_provider", 10),
    );
    models.insert(
        "openai_model".to_string(),
        make_model("openai_provider", 10),
    );

    let mut pools = HashMap::new();
    // Pool with members from different protocols (heterogeneous)
    pools.insert(
        "mixedpool".to_string(),
        make_pool(vec![
            make_member("anthropic_model"),
            make_member("openai_model"),
        ]),
    );

    let cfg = make_root_cfg(providers, models, pools);
    let result = validate(&cfg);

    // Should return Ok (heterogeneous pool is a warning, not an error)
    assert!(result.is_ok());
}

#[test]
fn test_validate_valid_config_succeeds() {
    let mut providers = HashMap::new();
    // Add minimal error_map to avoid validation errors
    let mut pm_error_map = std::collections::HashMap::new();
    pm_error_map.insert("400".to_string(), "client_error".to_string());

    providers.insert(
        "myprovider".to_string(),
        config::ProviderCfg {
            protocol: "anthropic".into(),
            base_url: "https://api.example.com".into(),
            api_key_env: "API_KEY".into(),
            health: None,
            error_map: pm_error_map,
            path: None,
            path_base: None,
            token_url: None,
            scope: None,
            auth: None,
            _legacy_api_key: None,
            allow_metadata_hosts: Vec::new(),
        },
    );

    let mut models = HashMap::new();
    models.insert("mymodel".to_string(), make_model("myprovider", 10));

    let mut pools = HashMap::new();
    pools.insert(
        "mypool".to_string(), // Distinct from provider name
        make_pool(vec![make_member("mymodel")]),
    );

    let cfg = make_root_cfg(providers, models, pools);
    let result = validate(&cfg);

    assert!(result.is_ok());
}

#[test]
fn test_validate_model_without_provider_error() {
    // No providers defined - should error on orphan model reference
    let providers = HashMap::new();

    let mut models = HashMap::new();
    models.insert(
        "orphan_model".to_string(),
        make_model("nonexistent_provider", 10),
    );

    let pools = HashMap::new();

    let cfg = make_root_cfg(providers, models, pools);
    let result = validate(&cfg);

    assert!(result.is_err());
    let errs = result.unwrap_err();
    // Should have exactly 1 error (orphan model), no error_map errors since providers is empty
    assert_eq!(errs.len(), 1);
    assert!(errs[0].contains("orphan_model"));
    assert!(errs[0].contains("references unknown provider"));
}

fn make_auth(mode: &str, client_tokens: Vec<&str>) -> config::AuthCfg {
    // Map the legacy mode string onto the 1.3 chain/upstream shape: token -> chain [tokens];
    // none -> empty chain; passthrough -> empty chain + upstream passthrough.
    let (chain, upstream): (Vec<String>, crate::auth::UpstreamCreds) = match mode {
        "token" => (vec!["tokens".to_string()], crate::auth::UpstreamCreds::Own),
        "none" => (vec![], crate::auth::UpstreamCreds::Own),
        "passthrough" => (vec![], crate::auth::UpstreamCreds::Passthrough),
        other => panic!("invalid auth mode in test: {other}"),
    };
    config::AuthCfg {
        chain,
        upstream_credentials: upstream,
        client_tokens: client_tokens.into_iter().map(|s| s.to_string()).collect(),
        modules: std::collections::HashMap::new(),
    }
}

fn make_breaker(
    base_cooldown_secs: u64,
    max_cooldown_secs: u64,
    trip: Option<config::BreakerTripConfig>,
) -> config::BreakerCfg {
    config::BreakerCfg {
        base_cooldown_secs,
        max_cooldown_secs,
        trip,
    }
}

fn make_trip(
    mode: config::BreakerTripMode,
    window_secs: u64,
    threshold: f64,
    min_requests: usize,
    consecutive_n: u32,
) -> config::BreakerTripConfig {
    config::BreakerTripConfig {
        mode,
        window_secs,
        threshold,
        min_requests,
        consecutive_n,
    }
}

// A minimal valid single-provider/single-model/single-pool config, returned as its three maps
// so individual tests can mutate one field and re-assemble via `make_root_cfg`.
fn valid_maps() -> (
    HashMap<String, config::ProviderCfg>,
    HashMap<String, config::ModelCfg>,
    HashMap<String, config::PoolCfg>,
) {
    let mut providers = HashMap::new();
    providers.insert(
        "myprovider".to_string(),
        make_provider("anthropic", "https://api.example.com", "API_KEY"),
    );
    let mut models = HashMap::new();
    models.insert("mymodel".to_string(), make_model("myprovider", 10));
    let mut pools = HashMap::new();
    pools.insert(
        "mypool".to_string(),
        make_pool(vec![make_member("mymodel")]),
    );
    (providers, models, pools)
}

#[test]
fn test_validate_rejects_non_https_base_url() {
    // A PUBLIC host over plaintext http leaks the key on the wire → rejected with the https rule.
    for (bad, fragment) in [
        ("http://api.example.com", "must use https for a public host"),
        // A non-http(s) scheme (file://) or an empty url is not a valid upstream scheme at all.
        ("file:///etc/shadow", "must use http or https"),
        ("", "must use http or https"),
    ] {
        let mut providers = HashMap::new();
        providers.insert("p".to_string(), make_provider("anthropic", bad, "API_KEY"));
        let cfg = make_root_cfg(providers, HashMap::new(), HashMap::new());
        let errs = validate(&cfg)
            .unwrap_err_or_default(format!("non-https base_url '{bad}' must fail validation"));
        assert!(
            errs.iter().any(|e| e.contains(fragment) && e.contains('p')),
            "expected a scheme error ('{fragment}') for '{bad}'; got: {errs:?}"
        );
    }
    // An http:// IMDS literal passes the scheme rule (link-local ⇒ private/loopback) but is then
    // rejected by the metadata denylist.
    let mut providers = HashMap::new();
    providers.insert(
        "p".to_string(),
        make_provider(
            "anthropic",
            "http://169.254.169.254/latest/meta-data/",
            "API_KEY",
        ),
    );
    let cfg = make_root_cfg(providers, HashMap::new(), HashMap::new());
    let errs =
        validate(&cfg).unwrap_err_or_default("http IMDS base_url must fail validation".into());
    assert!(
        errs.iter()
            .any(|e| e.contains("blocked cloud-metadata host") && e.contains("169.254.169.254")),
        "expected a metadata-host error for the http IMDS literal; got: {errs:?}"
    );
}

#[test]
fn test_validate_accepts_https_base_url() {
    let mut providers = HashMap::new();
    providers.insert(
        "p".to_string(),
        make_provider("anthropic", "https://api.example.com", "API_KEY"),
    );
    let cfg = make_root_cfg(providers, HashMap::new(), HashMap::new());
    assert!(validate(&cfg).is_ok(), "an https base_url must validate");
}

#[test]
fn test_validate_rejects_zero_max_concurrent() {
    let mut providers = HashMap::new();
    providers.insert(
        "myprovider".to_string(),
        make_provider("anthropic", "https://api.example.com", "API_KEY"),
    );
    let mut models = HashMap::new();
    models.insert("zeromodel".to_string(), make_model("myprovider", 0));
    // A positive max_concurrent must NOT error.
    models.insert("okmodel".to_string(), make_model("myprovider", 1));

    let cfg = make_root_cfg(providers, models, HashMap::new());
    let errs = validate(&cfg).expect_err("max_concurrent: 0 must fail validation");
    assert!(
        errs.iter()
            .any(|e| e.contains("zeromodel") && e.contains("max_concurrent: 0")),
        "expected a max_concurrent:0 error for 'zeromodel'; got: {errs:?}"
    );
    assert!(
        !errs.iter().any(|e| e.contains("okmodel")),
        "a positive max_concurrent must not error; got: {errs:?}"
    );
}

/// `max_concurrent` OMITTED (None = unbounded) must VALIDATE cleanly — it is an opt-in limiter, not
/// a required field. Only an explicit `Some(0)` is rejected; absence carries no requirement, exactly
/// like `max_requests: -1`.
#[test]
fn test_validate_accepts_omitted_max_concurrent() {
    let mut providers = HashMap::new();
    providers.insert(
        "myprovider".to_string(),
        make_provider("anthropic", "https://api.example.com", "API_KEY"),
    );
    let mut models = HashMap::new();
    models.insert(
        "unbounded".to_string(),
        make_model_unbounded("myprovider"), // max_concurrent: None
    );

    let cfg = make_root_cfg(providers, models, HashMap::new());
    validate(&cfg)
        .expect("a model omitting max_concurrent must validate (unbounded is the default)");
}

/// A minimal model config that OMITS max_concurrent must DESERIALIZE — proving the field is no
/// longer mandatory at the serde layer (the config-load foot-gun this fix removes).
#[test]
fn test_minimal_model_config_without_max_concurrent_deserializes() {
    // Only `provider` is required; every other ModelCfg field (max_requests, max_concurrent, …)
    // defaults. Before the fix this failed with "missing field `max_concurrent`".
    let m: config::ModelCfg = serde_yaml::from_str("provider: myprovider\n")
        .expect("a model config with only `provider` must load (max_concurrent is optional)");
    assert_eq!(m.provider, "myprovider");
    assert_eq!(
        m.max_concurrent, None,
        "an omitted max_concurrent must be None (unbounded)"
    );
    assert_eq!(
        m.max_requests, -1,
        "an omitted max_requests must default to -1 (unlimited)"
    );
}

#[test]
fn test_validate_rejects_bad_reasoning_effort_budgets() {
    let base = || {
        let mut providers = HashMap::new();
        providers.insert(
            "p".to_string(),
            make_provider("anthropic", "https://api.example.com", "K"),
        );
        let mut models = HashMap::new();
        models.insert("m".to_string(), make_model("p", 10));
        make_root_cfg(providers, models, HashMap::new())
    };
    // zero entry -> rejected
    let mut cfg = base();
    cfg.limits.reasoning_effort_budgets = crate::config::ReasoningEffortBudgets {
        minimal: 0,
        low: 4096,
        medium: 8192,
        high: 16384,
    };
    let errs = validate(&cfg).expect_err("zero budget must fail");
    assert!(errs
        .iter()
        .any(|e| e.contains("reasoning_effort_budgets") && e.contains("> 0")));
    // non-ascending -> rejected
    let mut cfg2 = base();
    cfg2.limits.reasoning_effort_budgets = crate::config::ReasoningEffortBudgets {
        minimal: 4096,
        low: 1024,
        medium: 8192,
        high: 16384,
    };
    let errs2 = validate(&cfg2).expect_err("non-ascending must fail");
    assert!(errs2
        .iter()
        .any(|e| e.contains("reasoning_effort_budgets") && e.contains("ascending")));
}

#[test]
fn test_validate_rejects_zero_attempt_timeout_ms() {
    // attempt_timeout_ms: 0 races a zero-duration timer against req.send() — every attempt
    // "times out" before the connection is tried, permanently poisoning the lane. Must fail
    // loud at boot at BOTH levels (model default and pool-member override); omitted (None)
    // and positive values must not error.
    let mut providers = HashMap::new();
    providers.insert(
        "myprovider".to_string(),
        make_provider("anthropic", "https://api.example.com", "API_KEY"),
    );
    let mut models = HashMap::new();
    let mut zero = make_model("myprovider", 10);
    zero.attempt_timeout_ms = Some(0);
    models.insert("zerocap".to_string(), zero);
    let mut positive = make_model("myprovider", 10);
    positive.attempt_timeout_ms = Some(5000);
    models.insert("okcap".to_string(), positive);
    models.insert("nocap".to_string(), make_model("myprovider", 10)); // None

    // Pool with one zero-override member and one positive-override member.
    let mut zero_member = make_member("okcap");
    zero_member.attempt_timeout_ms = Some(0);
    let mut ok_member = make_member("nocap");
    ok_member.attempt_timeout_ms = Some(200);
    let mut pools = HashMap::new();
    pools.insert(
        "mypool".to_string(),
        make_pool(vec![zero_member, ok_member]),
    );

    let cfg = make_root_cfg(providers, models, pools);
    let errs = validate(&cfg).expect_err("attempt_timeout_ms: 0 must fail validation");
    assert!(
        errs.iter()
            .any(|e| e.contains("zerocap") && e.contains("attempt_timeout_ms: 0")),
        "expected a model-level attempt_timeout_ms:0 error for 'zerocap'; got: {errs:?}"
    );
    assert!(
            errs.iter().any(|e| e.contains("mypool")
                && e.contains("okcap")
                && e.contains("attempt_timeout_ms: 0")),
            "expected a member-level attempt_timeout_ms:0 error for pool 'mypool' member 'okcap'; got: {errs:?}"
        );
    assert!(
        !errs
            .iter()
            .any(|e| e.contains("attempt_timeout_ms") && e.contains("nocap")),
        "None / positive attempt_timeout_ms must not error; got: {errs:?}"
    );
}

#[test]
fn test_validate_rejects_zero_max_requests() {
    // Twin of the max_concurrent:0 foot-gun on the lifetime-budget axis: max_requests:0 yields
    // limited=true, budget=0, which store::usable() rejects forever — must fail loud at boot.
    let mut providers = HashMap::new();
    providers.insert(
        "myprovider".to_string(),
        make_provider("anthropic", "https://api.example.com", "API_KEY"),
    );
    let mut models = HashMap::new();
    let mut zero = make_model("myprovider", 10);
    zero.max_requests = 0;
    models.insert("zeroreq".to_string(), zero);
    // -1 (unlimited, the default) and a positive cap must NOT error.
    models.insert("unlimited".to_string(), make_model("myprovider", 10)); // max_requests = -1
    let mut positive = make_model("myprovider", 10);
    positive.max_requests = 100;
    models.insert("capped".to_string(), positive);

    let cfg = make_root_cfg(providers, models, HashMap::new());
    let errs = validate(&cfg).expect_err("max_requests: 0 must fail validation");
    assert!(
        errs.iter()
            .any(|e| e.contains("zeroreq") && e.contains("max_requests: 0")),
        "expected a max_requests:0 error for 'zeroreq'; got: {errs:?}"
    );
    // Exactly one error, naming only the zero-budget model — the -1 and positive lanes are clean.
    assert_eq!(
        errs.len(),
        1,
        "only the zero lane must error; got: {errs:?}"
    );
    assert!(
        !errs
            .iter()
            .any(|e| e.contains("'unlimited'") || e.contains("'capped'")),
        "a -1 (unlimited) or positive max_requests must not error; got: {errs:?}"
    );
}

#[test]
fn test_localhost_is_allowed_by_default() {
    // Under the metadata-denylist model, `localhost` is a legitimate LOCAL-MODEL upstream and is
    // ALLOWED with NO flag — it is not a metadata endpoint. Both the bare name and the
    // trailing-dot FQDN form, case-insensitively, are NOT flagged by the SSRF guard.
    for ok in [
        "https://localhost/",
        "https://localhost:11434/",
        "https://LOCALHOST/v1",
        "https://localhost./",
        "https://localhost.:443/api",
        "http://localhost:11434/", // plaintext to loopback is fine
    ] {
        assert!(
            ssrf_blocked_host(ok, &[], false, &[]).is_none(),
            "expected '{ok}' to be allowed (localhost is a local-model target, not metadata)"
        );
    }
    // A full validate() pass must ACCEPT an https localhost base_url with no flag.
    let mut providers = HashMap::new();
    providers.insert(
        "p".to_string(),
        make_provider("anthropic", "https://localhost:11434/", "API_KEY"),
    );
    let cfg = make_root_cfg(providers, HashMap::new(), HashMap::new());
    assert!(
        validate(&cfg).is_ok(),
        "a localhost base_url must validate with no flag; got: {:?}",
        validate(&cfg)
    );
}

#[test]
fn test_validate_rejects_pool_name_equals_model_name() {
    let (providers, models, _) = valid_maps();
    let mut pools = HashMap::new();
    // Pool named identically to the model would shadow it on the `named` route.
    pools.insert(
        "mymodel".to_string(),
        make_pool(vec![make_member("mymodel")]),
    );
    let cfg = make_root_cfg(providers, models, pools);
    let errs = validate(&cfg).expect_err("pool name == model name must fail validation");
    assert!(
        errs.iter()
            .any(|e| e.contains("conflicts with model name") && e.contains("mymodel")),
        "expected a pool/model name-collision error; got: {errs:?}"
    );
}

#[test]
fn test_validate_rejects_pool_named_admin() {
    // A pool named `admin` is reached at `/api/v1/admin/messages`, which the auth middleware
    // intercepts as the operator admin surface — making the pool unreachable to clients and
    // (in governance mode) bypassing per-pool enforcement. Must fail loud at boot.
    let (providers, models, _) = valid_maps();
    let mut pools = HashMap::new();
    pools.insert("admin".to_string(), make_pool(vec![make_member("mymodel")]));
    let cfg = make_root_cfg(providers, models, pools);
    let errs = validate(&cfg).expect_err("a pool named 'admin' must fail validation");
    assert!(
        errs.iter()
            .any(|e| e.contains("pool name 'admin' is reserved")),
        "expected a reserved-admin-name error for the pool; got: {errs:?}"
    );
}

#[test]
fn test_validate_rejects_provider_named_admin() {
    // A provider named `admin` is reachable via the adhoc route `/admin/<model>/v1/messages`,
    // which the auth middleware likewise intercepts as the admin surface. Reject symmetrically.
    let mut providers = HashMap::new();
    providers.insert(
        "admin".to_string(),
        make_provider("anthropic", "https://api.example.com", "API_KEY"),
    );
    let cfg = make_root_cfg(providers, HashMap::new(), HashMap::new());
    let errs = validate(&cfg).expect_err("a provider named 'admin' must fail validation");
    assert!(
        errs.iter()
            .any(|e| e.contains("provider name 'admin' is reserved")),
        "expected a reserved-admin-name error for the provider; got: {errs:?}"
    );
}

#[test]
fn test_validate_rejects_model_named_admin() {
    // Regression: a MODEL named `admin` is reached at `/api/v1/admin/messages`,
    // which the auth middleware intercepts as the operator admin surface — unreachable to clients
    // and (in governance mode) a per-model `allowed_pools` bypass via the GovCtx::default() admin
    // branch. The model loop previously skipped the reserved-name check the pool/provider loops
    // run. Must fail loud at boot, symmetric with the pool and provider cases.
    let (mut providers, mut models, pools) = valid_maps();
    providers
        .entry("myprovider".to_string())
        .or_insert_with(|| make_provider("anthropic", "https://api.example.com", "API_KEY"));
    models.insert("admin".to_string(), make_model("myprovider", 10));
    let cfg = make_root_cfg(providers, models, pools);
    let errs = validate(&cfg).expect_err("a model named 'admin' must fail validation");
    assert!(
        errs.iter()
            .any(|e| e.contains("model name 'admin' is reserved")),
        "expected a reserved-admin-name error for the model; got: {errs:?}"
    );
}

#[test]
fn test_validate_allows_admin_prefixed_but_boundary_safe_names() {
    // The reserved check mirrors the auth middleware's PATH-BOUNDARY-SAFE `is_admin` test: only
    // the exact `admin` segment collides. `adminx` / `administrative` / `admin-pool` are normal
    // routes (proven by test_admin_prefix_is_boundary_safe in auth.rs) and must NOT be rejected.
    for name in ["adminx", "administrative", "admin-pool", "admin_portal"] {
        assert!(
            !reserved_admin_name(name),
            "'{name}' is a boundary-safe name and must not be treated as reserved"
        );
    }
    assert!(reserved_admin_name("admin"), "'admin' must be reserved");

    // A full validate() pass with an `adminx` pool must succeed (no reserved-name error).
    let (providers, models, _) = valid_maps();
    let mut pools = HashMap::new();
    pools.insert(
        "adminx".to_string(),
        make_pool(vec![make_member("mymodel")]),
    );
    let cfg = make_root_cfg(providers, models, pools);
    assert!(
        validate(&cfg).is_ok(),
        "an 'adminx' pool is boundary-safe and must validate"
    );
}

#[test]
fn test_validate_rejects_bad_breaker_params() {
    // (description, breaker, substring expected in the error)
    let cases: Vec<(&str, config::BreakerCfg, &str)> = vec![
        (
            "min_requests 0",
            make_breaker(
                15,
                120,
                Some(make_trip(config::BreakerTripMode::ErrorRate, 30, 0.5, 0, 3)),
            ),
            "trip.min_requests must be >= 1",
        ),
        (
            "window_s 0",
            make_breaker(
                15,
                120,
                Some(make_trip(config::BreakerTripMode::ErrorRate, 0, 0.5, 5, 3)),
            ),
            "trip.window_secs must be >= 1",
        ),
        (
            "threshold > 1.0",
            make_breaker(
                15,
                120,
                Some(make_trip(config::BreakerTripMode::ErrorRate, 30, 1.5, 5, 3)),
            ),
            "trip.threshold must be in (0.0, 1.0]",
        ),
        (
            "threshold 0.0",
            make_breaker(
                15,
                120,
                Some(make_trip(config::BreakerTripMode::ErrorRate, 30, 0.0, 5, 3)),
            ),
            "trip.threshold must be in (0.0, 1.0]",
        ),
        (
            "consecutive n 0",
            make_breaker(
                15,
                120,
                Some(make_trip(
                    config::BreakerTripMode::Consecutive,
                    30,
                    0.5,
                    5,
                    0,
                )),
            ),
            "trip.consecutive_n must be >= 1",
        ),
        (
            "max_cooldown < base_cooldown",
            make_breaker(
                100,
                50,
                Some(make_trip(config::BreakerTripMode::ErrorRate, 30, 0.5, 5, 3)),
            ),
            "max_cooldown_secs",
        ),
        (
            // Regression (MED #9): a zero base cooldown yields a degenerate breaker that re-admits
            // a tripped backend immediately — must fail loud, mirroring the trip.* zero-floor guards.
            "base_cooldown 0",
            make_breaker(
                0,
                120,
                Some(make_trip(config::BreakerTripMode::ErrorRate, 30, 0.5, 5, 3)),
            ),
            "base_cooldown_secs must be >= 1",
        ),
        (
            // Regression (MED #9): the max-cooldown twin of the above.
            "max_cooldown 0",
            make_breaker(
                0,
                0,
                Some(make_trip(config::BreakerTripMode::ErrorRate, 30, 0.5, 5, 3)),
            ),
            "max_cooldown_secs must be >= 1",
        ),
    ];

    for (desc, breaker, expected) in cases {
        let (providers, models, _) = valid_maps();
        let mut pools = HashMap::new();
        let mut pool = make_pool(vec![make_member("mymodel")]);
        pool.breaker = Some(breaker);
        pools.insert("mypool".to_string(), pool);
        let cfg = make_root_cfg(providers, models, pools);
        let errs = validate(&cfg)
            .unwrap_err_or_default(format!("breaker case '{desc}' must fail validation"));
        assert!(
            errs.iter().any(|e| e.contains(expected)),
            "case '{desc}': expected error containing '{expected}'; got: {errs:?}"
        );
    }
}

#[test]
fn test_validate_accepts_good_breaker_params() {
    let (providers, models, _) = valid_maps();
    let mut pools = HashMap::new();
    let mut pool = make_pool(vec![make_member("mymodel")]);
    pool.breaker = Some(make_breaker(
        15,
        120,
        Some(make_trip(
            config::BreakerTripMode::ErrorRate,
            30,
            1.0, // boundary: rate-cap value is valid
            1,   // boundary: minimum floor
            3,
        )),
    ));
    pools.insert("mypool".to_string(), pool);
    let cfg = make_root_cfg(providers, models, pools);
    assert!(
        validate(&cfg).is_ok(),
        "a well-formed breaker config must validate"
    );
}

#[test]
fn test_validate_rejects_zero_cooldown_breaker() {
    // Regression (MED #9): a breaker with base_cooldown_secs == 0 or max_cooldown_secs == 0
    // passes the inversion check (0 <= 0) yet is degenerate — when it trips open it re-admits the
    // failing backend immediately because the cooldown window is zero seconds, defeating the
    // back-off the breaker exists to provide. This is the cooldown-axis twin of the trip.* zero-
    // floor guards and must fail loud at boot. The breaker has NO `trip` block here, proving the
    // cooldown floor is enforced independently of trip validation.
    for (base, max, expected) in [
        (0u64, 120u64, "base_cooldown_secs must be >= 1"),
        (15, 0, "max_cooldown_secs must be >= 1"),
        (0, 0, "base_cooldown_secs must be >= 1"),
    ] {
        let (providers, models, _) = valid_maps();
        let mut pools = HashMap::new();
        let mut pool = make_pool(vec![make_member("mymodel")]);
        pool.breaker = Some(make_breaker(base, max, None));
        pools.insert("mypool".to_string(), pool);
        let cfg = make_root_cfg(providers, models, pools);
        let errs = validate(&cfg).unwrap_err_or_default(format!(
            "breaker base={base} max={max} must fail validation"
        ));
        assert!(
            errs.iter()
                .any(|e| e.contains(expected) && e.contains("mypool")),
            "base={base} max={max}: expected error containing '{expected}'; got: {errs:?}"
        );
    }

    // The boundary (both fields == 1) is the minimum well-formed breaker and must validate.
    let (providers, models, _) = valid_maps();
    let mut pools = HashMap::new();
    let mut pool = make_pool(vec![make_member("mymodel")]);
    pool.breaker = Some(make_breaker(1, 1, None));
    pools.insert("mypool".to_string(), pool);
    let cfg = make_root_cfg(providers, models, pools);
    assert!(
        validate(&cfg).is_ok(),
        "a breaker with base==max==1 is the minimum well-formed config and must validate"
    );
}

#[test]
fn test_validate_rejects_zero_failover_deadline() {
    // Twin of the breaker window_s:0 / max_concurrent:0 foot-guns on the failover-budget axis:
    // RequestCtx::new(0) sets deadline == start, so the failover loop's first (primary) deadline
    // check rejects with a 503 before the primary attempt runs — the pool serves ZERO requests
    // with no boot diagnostic. Must fail loud at startup.
    let (providers, models, _) = valid_maps();
    let mut pools = HashMap::new();
    let mut pool = make_pool(vec![make_member("mymodel")]);
    pool.failover = Some(config::FailoverCfg {
        timeout_secs: 0,
        exclusions: None,
        max_hops: 3,
    });
    pools.insert("mypool".to_string(), pool);
    let cfg = make_root_cfg(providers, models, pools);
    let errs = validate(&cfg).expect_err("failover.timeout_secs: 0 must fail validation");
    assert!(
        errs.iter()
            .any(|e| e.contains("failover.timeout_secs must be >= 1") && e.contains("mypool")),
        "expected a zero-failover-deadline error for 'mypool'; got: {errs:?}"
    );
}

#[test]
fn test_validate_accepts_positive_failover_deadline_and_zero_cap() {
    // A positive deadline validates. cap == 0 is deliberately BENIGN (the `0..=cap` loop still
    // runs the primary once), so it must NOT be rejected.
    let (providers, models, _) = valid_maps();
    let mut pools = HashMap::new();
    let mut pool = make_pool(vec![make_member("mymodel")]);
    pool.failover = Some(config::FailoverCfg {
        timeout_secs: 30,
        exclusions: None,
        max_hops: 0,
    });
    pools.insert("mypool".to_string(), pool);
    let cfg = make_root_cfg(providers, models, pools);
    assert!(
        validate(&cfg).is_ok(),
        "a positive failover.timeout_secs with max_hops:0 must validate"
    );
}

#[test]
fn test_validate_rejects_unknown_failover_exclusion() {
    // Regression (MEDIUM, re-audit): a `failover.exclusions` entry is a member model name benched
    // from the pool's candidate set at runtime; the runtime matches it against member targets. A
    // misspelled / stale entry resolves to nothing and silently fails to bench the intended
    // member, so it must fail loud at boot (mirroring the dangling-fallback-pool rule).
    let (providers, models, _) = valid_maps();
    let mut pools = HashMap::new();
    let mut pool = make_pool(vec![make_member("mymodel")]);
    pool.failover = Some(config::FailoverCfg {
        timeout_secs: 30,
        exclusions: Some(vec!["mymodell".to_string()]), // typo: pool member is `mymodel`
        max_hops: 3,
    });
    pools.insert("mypool".to_string(), pool);
    let cfg = make_root_cfg(providers, models, pools);
    let errs = validate(&cfg).expect_err("an unknown failover exclusion must fail validation");
    assert!(
        errs.iter()
            .any(|e| e.contains("failover.exclusions references 'mymodell'")
                && e.contains("not a member of the pool")),
        "expected an unknown-exclusion error naming 'mymodell'; got: {errs:?}"
    );
}

#[test]
fn test_validate_rejects_bad_module_scope_and_group_map_scope() {
    // Both scope-token rules: a typo'd `auth.modules.<m>.max_admin_scope` and a typo'd
    // `group_map.<g>.admin_scope` each fail loud at boot, naming the offender.
    let (providers, models, pools) = valid_maps();
    let mut cfg = make_root_cfg(providers, models, pools);
    let mut auth = config::AuthCfg::default_none();
    auth.modules.insert(
        "corp-ad".to_string(),
        config::AuthModuleCfg {
            allowed_groups: Some(vec!["llm-users".to_string()]),
            max_admin_scope: Some("superuser".to_string()), // typo
        },
    );
    cfg.auth = Some(auth);
    cfg.group_map.insert(
        "viewers".to_string(),
        config::GroupMapEntry {
            admin_scope: Some("readonly".to_string()), // typo (it's read-only)
            ..Default::default()
        },
    );
    let errs = validate(&cfg).expect_err("typo'd scope tokens must fail validation");
    assert!(
        errs.iter()
            .any(|e| e.contains("auth.modules 'corp-ad'") && e.contains("superuser")),
        "expected the max_admin_scope error; got: {errs:?}"
    );
    assert!(
        errs.iter()
            .any(|e| e.contains("group_map 'viewers'") && e.contains("readonly")),
        "expected the group_map scope error; got: {errs:?}"
    );
}

#[test]
fn test_validate_accepts_known_failover_exclusion() {
    // An exclusion that names a real member of the pool is the supported case and must validate.
    let (mut providers, mut models, _) = valid_maps();
    providers
        .entry("myprovider".to_string())
        .or_insert_with(|| make_provider("anthropic", "https://api.example.com", "API_KEY"));
    models
        .entry("secondmodel".to_string())
        .or_insert_with(|| make_model("myprovider", 10));
    let mut pools = HashMap::new();
    let mut pool = make_pool(vec![make_member("mymodel"), make_member("secondmodel")]);
    pool.failover = Some(config::FailoverCfg {
        timeout_secs: 30,
        exclusions: Some(vec!["secondmodel".to_string()]), // a real member — benched on purpose
        max_hops: 3,
    });
    pools.insert("mypool".to_string(), pool);
    let cfg = make_root_cfg(providers, models, pools);
    assert!(
        validate(&cfg).is_ok(),
        "a failover exclusion naming a real pool member must validate"
    );
}

// Admin-token behavior — requires the compile-removable `admin-tokens` module.
#[cfg(feature = "auth-admin-tokens")]
#[test]
fn test_validate_governance_rejects_whitespace_only_admin_token() {
    // Regression (LOW #21): a WHITESPACE-ONLY admin_token (" ", "\t", "\n") passes a bare
    // is_empty() guard but is a degenerate, functionally-unusable secret — `${BUSBAR_ADMIN_TOKEN}`
    // expanding to all blanks silently locks the /admin API exactly as an unset token does. The
    // boot diagnostic must fire for the whitespace case too, not just truly-empty. Against the
    // old `t.is_empty()` guard these would PASS validation (bug); the `t.trim().is_empty()` fix
    // rejects them.
    for blank in [" ", "   ", "\t", "\n", " \t\n "] {
        let gov = config::GovernanceCfg {
            store: crate::config::GovernanceStore::Memory,
            db_path: "busbar-governance.db".to_string(),
            price_per_request_cents: 1,
            price_per_1k_tokens_cents: 0,
            admin_token: Some(blank.to_string()),
            sqlite_busy_timeout_ms: crate::config::DEFAULT_SQLITE_BUSY_TIMEOUT_MS,
            plugins_dir: "plugins".to_string(),
            trust: Default::default(),
            rate_sweep_interval: crate::config::DEFAULT_RATE_SWEEP_INTERVAL,
            usage_flush_interval_ms: crate::config::DEFAULT_USAGE_FLUSH_INTERVAL_MS,
        };
        let errs = validate_governance(&gov, None).unwrap_err_or_default(format!(
            "a whitespace-only admin_token {blank:?} must fail validation"
        ));
        assert!(
            errs.iter().any(|e| e.contains("governance.admin_token")
                && e.contains("/admin management API is unreachable")),
            "expected an admin-token lockout error for blank token {blank:?}; got: {errs:?}"
        );
    }

    // A token with surrounding whitespace but a real non-blank core is usable and must NOT error
    // (we only reject ALL-blank, not trim the stored secret).
    let gov = config::GovernanceCfg {
        store: crate::config::GovernanceStore::Memory,
        db_path: "busbar-governance.db".to_string(),
        price_per_request_cents: 1,
        price_per_1k_tokens_cents: 0,
        admin_token: Some("  real-secret  ".to_string()),
        sqlite_busy_timeout_ms: crate::config::DEFAULT_SQLITE_BUSY_TIMEOUT_MS,
        plugins_dir: "plugins".to_string(),
        trust: Default::default(),
        rate_sweep_interval: crate::config::DEFAULT_RATE_SWEEP_INTERVAL,
        usage_flush_interval_ms: crate::config::DEFAULT_USAGE_FLUSH_INTERVAL_MS,
    };
    assert!(
        validate_governance(&gov, None).is_ok(),
        "an admin_token with a non-blank core must validate (we do not reject surrounding space)"
    );
}

/// FEATURELESS counterpart: a configured admin token in a binary WITHOUT the `admin-tokens`
/// module is a loud boot error (a silently-disabled admin API is a lockout, never acceptable).
#[cfg(not(feature = "auth-admin-tokens"))]
#[test]
fn test_validate_governance_rejects_admin_token_without_module() {
    let gov = crate::config::GovernanceCfg {
        store: crate::config::GovernanceStore::Memory,
        admin_token: Some("tok".to_string()),
        ..Default::default()
    };
    let errs = validate_governance(&gov, None).expect_err("must be a boot error");
    assert!(
        errs.iter().any(|e| e.contains("auth-admin-tokens")),
        "{errs:?}"
    );
}

// Admin-token behavior — requires the compile-removable `admin-tokens` module.
#[cfg(feature = "auth-admin-tokens")]
#[test]
fn test_validate_governance_ok_when_enabled_with_admin_token() {
    let gov = config::GovernanceCfg {
        store: crate::config::GovernanceStore::Memory,
        db_path: "busbar-governance.db".to_string(),
        price_per_request_cents: 1,
        price_per_1k_tokens_cents: 0,
        admin_token: Some("an-operator-secret".to_string()),
        sqlite_busy_timeout_ms: crate::config::DEFAULT_SQLITE_BUSY_TIMEOUT_MS,
        plugins_dir: "plugins".to_string(),
        trust: Default::default(),
        rate_sweep_interval: crate::config::DEFAULT_RATE_SWEEP_INTERVAL,
        usage_flush_interval_ms: crate::config::DEFAULT_USAGE_FLUSH_INTERVAL_MS,
    };
    assert!(
        validate_governance(&gov, None).is_ok(),
        "enabled governance WITH an admin_token must validate"
    );
}

#[test]
fn test_validate_governance_rejects_zero_rate_sweep_interval() {
    // `rate_sweep_interval: 0` is rejected fail-loud rather than silently disabling the rate-map
    // eviction sweep (which would ride on the non-obvious `u32::is_multiple_of(0) == false`).
    let gov = config::GovernanceCfg {
        store: crate::config::GovernanceStore::Memory,
        db_path: "busbar-governance.db".to_string(),
        price_per_request_cents: 1,
        price_per_1k_tokens_cents: 0,
        admin_token: Some("an-operator-secret".to_string()),
        sqlite_busy_timeout_ms: crate::config::DEFAULT_SQLITE_BUSY_TIMEOUT_MS,
        plugins_dir: "plugins".to_string(),
        trust: Default::default(),
        rate_sweep_interval: 0,
        usage_flush_interval_ms: crate::config::DEFAULT_USAGE_FLUSH_INTERVAL_MS,
    };
    let err = validate_governance(&gov, None)
        .expect_err("rate_sweep_interval: 0 must be rejected at validation");
    assert!(
        err.iter().any(|e| e.contains("rate_sweep_interval")),
        "the error must name the offending key, got: {err:?}"
    );
}

#[test]
fn test_validate_governance_disabled_carries_no_requirement() {
    // A disabled governance block (the admin surface is inert) must not require an admin_token.
    let gov = config::GovernanceCfg {
        store: crate::config::GovernanceStore::Memory,
        db_path: "busbar-governance.db".to_string(),
        price_per_request_cents: 1,
        price_per_1k_tokens_cents: 0,
        admin_token: None,
        sqlite_busy_timeout_ms: crate::config::DEFAULT_SQLITE_BUSY_TIMEOUT_MS,
        plugins_dir: "plugins".to_string(),
        trust: Default::default(),
        rate_sweep_interval: crate::config::DEFAULT_RATE_SWEEP_INTERVAL,
        usage_flush_interval_ms: crate::config::DEFAULT_USAGE_FLUSH_INTERVAL_MS,
    };
    assert!(
        validate_governance(&gov, None).is_ok(),
        "disabled governance carries no admin_token requirement"
    );
}

fn auth_cfg(mode: &str) -> config::AuthCfg {
    let (chain, upstream): (Vec<String>, crate::auth::UpstreamCreds) = match mode {
        "token" => (vec!["tokens".to_string()], crate::auth::UpstreamCreds::Own),
        "none" => (vec![], crate::auth::UpstreamCreds::Own),
        "passthrough" => (vec![], crate::auth::UpstreamCreds::Passthrough),
        other => panic!("invalid auth mode in test: {other}"),
    };
    config::AuthCfg {
        chain,
        upstream_credentials: upstream,
        client_tokens: vec![],
        modules: std::collections::HashMap::new(),
    }
}

#[test]
fn test_validate_governance_rejects_passthrough_combination() {
    // Regression: governance.enabled + upstream_credentials: passthrough is self-contradictory.
    // Governance supersedes passthrough (every request must resolve to an enabled virtual key),
    // so an operator who believes they are in passthrough silently rejects every caller lacking
    // a virtual key — a behaviour inversion that must fail loud at boot, not pass to a runtime
    // warning.
    {
        let mode = "passthrough";
        let gov = config::GovernanceCfg {
            store: crate::config::GovernanceStore::Memory,
            db_path: "busbar-governance.db".to_string(),
            price_per_request_cents: 1,
            price_per_1k_tokens_cents: 0,
            admin_token: Some("an-operator-secret".to_string()),
            sqlite_busy_timeout_ms: crate::config::DEFAULT_SQLITE_BUSY_TIMEOUT_MS,
            plugins_dir: "plugins".to_string(),
            trust: Default::default(),
            rate_sweep_interval: crate::config::DEFAULT_RATE_SWEEP_INTERVAL,
            usage_flush_interval_ms: crate::config::DEFAULT_USAGE_FLUSH_INTERVAL_MS,
        };
        let errs = validate_governance(&gov, Some(&auth_cfg(mode)))
            .expect_err("governance + passthrough must be rejected at boot");
        assert!(
            errs.iter().any(
                |e| e.contains("upstream_credentials: passthrough") && e.contains("governance")
            ),
            "expected a governance+passthrough rejection for mode {mode:?}; got: {errs:?}"
        );
    }
}

// Admin-token behavior — requires the compile-removable `admin-tokens` module.
#[cfg(feature = "auth-admin-tokens")]
#[test]
fn test_validate_governance_allows_token_and_none_modes() {
    // governance + auth.mode=token (or none) is the supported pairing and must NOT be rejected
    // on the passthrough ground.
    for mode in ["token", "none"] {
        let gov = config::GovernanceCfg {
            store: crate::config::GovernanceStore::Memory,
            db_path: "busbar-governance.db".to_string(),
            price_per_request_cents: 1,
            price_per_1k_tokens_cents: 0,
            admin_token: Some("an-operator-secret".to_string()),
            sqlite_busy_timeout_ms: crate::config::DEFAULT_SQLITE_BUSY_TIMEOUT_MS,
            plugins_dir: "plugins".to_string(),
            trust: Default::default(),
            rate_sweep_interval: crate::config::DEFAULT_RATE_SWEEP_INTERVAL,
            usage_flush_interval_ms: crate::config::DEFAULT_USAGE_FLUSH_INTERVAL_MS,
        };
        assert!(
            validate_governance(&gov, Some(&auth_cfg(mode))).is_ok(),
            "governance + auth.mode={mode} must validate"
        );
    }
}

#[test]
fn test_validate_governance_passthrough_ignored_when_disabled() {
    // A DISABLED governance block carries no requirement, so even auth.mode=passthrough is fine
    // (governance is inert — passthrough semantics apply unchanged).
    let gov = config::GovernanceCfg {
        store: crate::config::GovernanceStore::Memory,
        db_path: "busbar-governance.db".to_string(),
        price_per_request_cents: 1,
        price_per_1k_tokens_cents: 0,
        admin_token: None,
        sqlite_busy_timeout_ms: crate::config::DEFAULT_SQLITE_BUSY_TIMEOUT_MS,
        plugins_dir: "plugins".to_string(),
        trust: Default::default(),
        rate_sweep_interval: crate::config::DEFAULT_RATE_SWEEP_INTERVAL,
        usage_flush_interval_ms: crate::config::DEFAULT_USAGE_FLUSH_INTERVAL_MS,
    };
    assert!(
        validate_governance(&gov, Some(&auth_cfg("passthrough"))).is_ok(),
        "disabled governance + passthrough must validate (governance inert)"
    );
}

#[test]
fn test_validate_rejects_token_mode_with_no_tokens() {
    let (providers, models, pools) = valid_maps();
    let mut cfg = make_root_cfg(providers, models, pools);
    cfg.auth = Some(make_auth("token", vec![]));
    let errs = validate(&cfg).expect_err("token mode with no tokens must fail validation");
    assert!(
        errs.iter()
            .any(|e| e.contains("the tokens module requires at least one client token")),
        "expected a token-mode lockout error; got: {errs:?}"
    );
}

#[cfg(feature = "auth-tokens")]
#[test]
fn test_validate_token_mode_with_tokens_ok() {
    // The allowlist form satisfies the requirement (the legacy single-token form was removed in
    // 1.0.0; see `test_legacy_token_is_rejected_at_parse`).
    let (providers, models, pools) = valid_maps();
    let mut cfg = make_root_cfg(providers, models, pools);
    cfg.auth = Some(make_auth("token", vec!["secret"]));
    assert!(
        validate(&cfg).is_ok(),
        "token mode with at least one client token must validate"
    );
}

#[test]
fn test_legacy_token_is_rejected_at_parse() {
    // 1.0.0 MIGRATION: the legacy single-token `token:` field was REMOVED. `AuthCfg` is now
    // `#[serde(deny_unknown_fields)]`, so a full config that still sets `auth.token` is REJECTED
    // AT PARSE (the config-LOAD entry point) with serde's "unknown field `token`" — never a
    // silent credential drop and never a deferred validate-time check. This is the load-level
    // companion to `config::tests::test_legacy_token_key_is_rejected_at_parse`.
    let yaml = r#"
listen: "0.0.0.0:8080"
auth:
  mode: token
  token: "stale-legacy-secret"
  client_tokens: ["real-secret"]
providers:
  anthropic:
    api_key_env: ANTHROPIC_KEY
models:
  claude:
    provider: anthropic
    max_concurrent: 10
"#;
    let err = serde_yaml::from_str::<crate::config::DeployCfg>(yaml)
        .expect_err("a config setting the removed `token` field must fail to parse");
    let msg = err.to_string();
    assert!(
        msg.contains("unknown field") && msg.contains("token"),
        "expected serde's unknown-field error naming `token` at parse; got: {msg}"
    );
    // The rejected secret value is NEVER echoed back in the parse error.
    assert!(
        !msg.contains("stale-legacy-secret"),
        "the parse error must not leak the configured token value; got: {msg}"
    );
}

/// A `tracing::Layer` that records the messages of WARN-level events it sees, so a test can
/// assert a particular `tracing::warn!` fired (mirrors the helper in `config.rs`). The structured
/// fields (`provider`, `api_key_env`) are recorded into the message-or-field buffer.
#[derive(Clone, Default)]
struct WarnCapture(std::sync::Arc<std::sync::Mutex<Vec<String>>>);

impl<S: tracing::Subscriber> tracing_subscriber::Layer<S> for WarnCapture {
    fn on_event(
        &self,
        event: &tracing::Event<'_>,
        _ctx: tracing_subscriber::layer::Context<'_, S>,
    ) {
        if *event.metadata().level() != tracing::Level::WARN {
            return;
        }
        struct Vis(String);
        impl tracing::field::Visit for Vis {
            fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
                // Append every field's debug rendering so both the `message` and the structured
                // `provider`/`api_key_env` fields are searchable by the assertion.
                self.0.push_str(&format!(" {}={value:?}", field.name()));
            }
        }
        let mut vis = Vis(String::new());
        event.record(&mut vis);
        if let Ok(mut msgs) = self.0.lock() {
            msgs.push(vis.0);
        }
    }
}

#[test]
fn test_validate_passthrough_warns_on_nonempty_configured_key() {
    // Regression (LOW #10): in passthrough mode the proxy engine selects the upstream key as
    // `caller_token.unwrap_or("")` (NOT `lane.api_key` — that was hardened per LOW #15), so under
    // passthrough the configured `api_key` is NEVER forwarded: it is inert dead config. Its presence
    // means the operator likely wanted static-key gating (`upstream_credentials: own`) but wired
    // passthrough. validate() must emit a prominent boot WARNING for any provider whose `api_key_env`
    // resolves to a NON-EMPTY value while auth.mode=passthrough. A legit Bedrock-ingress passthrough
    // provider authenticates per-request via SigV4 and resolves an EMPTY key, so it must NOT warn —
    // that is the second half of this test.
    use tracing_subscriber::layer::SubscriberExt as _;

    // Unique env-var names so parallel tests cannot clobber the values we set/read here.
    let leak_env = "BUSBAR_T_R22_PASSTHROUGH_LEAK_KEY";
    let bedrock_env = "BUSBAR_T_R22_PASSTHROUGH_BEDROCK_KEY";
    std::env::set_var(leak_env, "sk-busbar-secret-should-not-leak");
    std::env::remove_var(bedrock_env); // Bedrock passthrough: no static key (SigV4 per-request)

    // Provider WITH a non-empty resolved key (the leak case) + Bedrock-style provider whose key
    // env is unset (the legit case). Both providers need a model so validate() has full context.
    let mut providers = HashMap::new();
    providers.insert(
        "leaky".to_string(),
        make_provider("anthropic", "https://api.example.com", leak_env),
    );
    providers.insert(
        "bedrock".to_string(),
        make_provider("bedrock", "https://bedrock.example.com", bedrock_env),
    );
    let mut models = HashMap::new();
    models.insert("leakymodel".to_string(), make_model("leaky", 10));
    models.insert("bedrockmodel".to_string(), make_model("bedrock", 10));
    let mut cfg = make_root_cfg(providers, models, HashMap::new());
    cfg.auth = Some(make_auth("passthrough", vec![]));

    let cap = WarnCapture::default();
    let subscriber = tracing_subscriber::registry().with(cap.clone());
    let result = tracing::subscriber::with_default(subscriber, || validate(&cfg));

    std::env::remove_var(leak_env);

    // The combo is a WARN, not a hard error: passthrough has no token-allowlist requirement, so
    // validation still succeeds (the warning is the diagnostic, so a deliberate static-key
    // fallback is not broken).
    assert!(
        result.is_ok(),
        "passthrough + non-empty key is a warning, not a hard error; got: {result:?}"
    );

    let msgs = cap.0.lock().unwrap();
    assert!(
        msgs.iter()
            .any(|m| m.contains("inert dead config") && m.contains("leaky")),
        "expected a passthrough inert-configured-key warning naming the 'leaky' provider; got: {msgs:?}"
    );
    // The Bedrock-style provider with an EMPTY resolved key must NOT trip the warning — otherwise
    // a legit SigV4 passthrough deployment is spammed with a false-positive credential-leak alert.
    assert!(
            !msgs.iter().any(|m| m.contains("bedrock")),
            "a provider whose api_key_env resolves empty must NOT warn (legit SigV4 passthrough); got: {msgs:?}"
        );
}

#[test]
fn test_validate_passthrough_no_warn_when_all_keys_empty() {
    // Counter-case: with auth.mode=passthrough and EVERY provider's api_key_env unset, no
    // credential-leak warning fires — the guard keys off the RESOLVED value, not merely the
    // presence of the passthrough mode. This pins the false-positive boundary.
    use tracing_subscriber::layer::SubscriberExt as _;

    let empty_env = "BUSBAR_T_R22_PASSTHROUGH_EMPTY_KEY";
    std::env::remove_var(empty_env);

    let mut providers = HashMap::new();
    providers.insert(
        "p".to_string(),
        make_provider("anthropic", "https://api.example.com", empty_env),
    );
    let mut models = HashMap::new();
    models.insert("m".to_string(), make_model("p", 10));
    let mut cfg = make_root_cfg(providers, models, HashMap::new());
    cfg.auth = Some(make_auth("passthrough", vec![]));

    let cap = WarnCapture::default();
    let subscriber = tracing_subscriber::registry().with(cap.clone());
    let result = tracing::subscriber::with_default(subscriber, || validate(&cfg));

    assert!(result.is_ok(), "passthrough with empty keys must validate");
    let msgs = cap.0.lock().unwrap();
    assert!(
        !msgs.iter().any(|m| m.contains("credential-leak")),
        "no credential-leak warning must fire when every api_key_env resolves empty; got: {msgs:?}"
    );
}

#[test]
fn test_validate_none_mode_with_no_tokens_ok() {
    let (providers, models, pools) = valid_maps();
    let mut cfg = make_root_cfg(providers, models, pools);
    cfg.auth = Some(make_auth("none", vec![]));
    assert!(
        validate(&cfg).is_ok(),
        "mode 'none' carries no token requirement"
    );
}

#[test]
fn test_ssrf_blocks_metadata_denylist_by_default() {
    // Under the metadata-denylist model, ONLY cloud-metadata endpoints are blocked by default —
    // and every obfuscation form of each metadata IP must be caught, not just the canonical
    // spelling. The link-local /16 covers IMDS, ECS task-creds, Tencent, etc. in one range.
    for blocked in [
        // --- link-local /16 (IMDS, ECS, Tencent, …) ---
        "https://169.254.169.254/latest/meta-data/", // IMDS
        "https://169.254.169.254/",
        "http://169.254.169.254/", // http form (link-local ⇒ scheme ok, then metadata-blocked)
        "https://169.254.170.2/v2/credentials", // AWS ECS task-credentials
        "https://169.254.0.23/",   // Tencent metadata (still link-local)
        // --- non-link-local metadata literals ---
        "https://100.100.100.200/latest/meta-data/", // Alibaba ECS (inside CGNAT /10)
        "http://100.100.100.200/",
        "https://168.63.129.16/",   // Azure WireServer/platform
        "https://[fd00:ec2::254]/", // EC2 IMDSv6
        // --- metadata hostnames (case-insensitive, trailing-dot stripped) ---
        "https://metadata.google.internal/computeMetadata/v1/",
        "https://METADATA.INTERNAL/",
        "https://metadata.tencentyun.com/",
        "https://metadata.platformequinix.com/",
        "https://instance-data/latest/meta-data/",
        "https://instance-data.ec2.internal/",
        "https://metadata.google.internal./", // trailing-dot FQDN form
        // --- obfuscation forms of the metadata IPs (must apply to every literal) ---
        "https://[::ffff:169.254.169.254]/", // IMDS via IPv4-mapped IPv6
        "https://[::169.254.169.254]/",      // IMDS via IPv4-compatible IPv6
        "https://[::ffff:169.254.170.2]/",   // ECS creds via mapped IPv6
        "https://[::ffff:100.100.100.200]/", // Alibaba via mapped IPv6
        "https://[::ffff:168.63.129.16]/",   // Azure via mapped IPv6
        "https://2852039166/",               // IMDS via decimal-int (= 169.254.169.254)
        "https://0xa9fea9fe/",               // IMDS via hex
        "https://169.254.169.254./",         // IMDS, trailing dot
        "https://169%2E254%2E169%2E254/",    // IMDS, percent-encoded dots
        "https://169.254.169.254:8443/",     // IMDS with port
        "https://user:pass@169.254.169.254/latest", // IMDS behind userinfo
        // --- obfuscated inet_aton forms of IMDS (M2/H5: must be caught and canonicalized) ---
        "https://169.254.43518/", // 3-part inet_aton of 169.254.169.254
        "https://169.16689662/",  // 2-part inet_aton of 169.254.169.254
    ] {
        // M2: assert the ACTUAL returned host is a non-empty string (so a bug returning
        // Some("") / Some("garbage") cannot pass). The returned host is the normalized authority.
        let got = ssrf_blocked_host(blocked, &[], false, &[]);
        let host = got.as_deref().unwrap_or_else(|| {
            panic!("expected '{blocked}' to be flagged as a metadata SSRF target")
        });
        assert!(
            !host.is_empty(),
            "blocked '{blocked}' returned an EMPTY host string"
        );
    }
}

#[test]
fn test_ssrf_blocked_returns_exact_host_string() {
    // M2: pin the EXACT host string `ssrf_blocked_host` returns for representative targets, so a
    // regression returning `Some("")` / `Some("garbage")` (which `.is_some()` would accept) fails.
    assert_eq!(
        ssrf_blocked_host("https://169.254.169.254/latest", &[], false, &[]).as_deref(),
        Some("169.254.169.254")
    );
    assert_eq!(
        ssrf_blocked_host("https://user:pass@169.254.169.254:8443/x", &[], false, &[]).as_deref(),
        Some("169.254.169.254"),
        "userinfo and port must be stripped from the returned host"
    );
    assert_eq!(
        ssrf_blocked_host("https://metadata.google.internal/", &[], false, &[]).as_deref(),
        Some("metadata.google.internal")
    );
    assert_eq!(
        ssrf_blocked_host("https://100.100.100.200/", &[], false, &[]).as_deref(),
        Some("100.100.100.200")
    );
}

#[test]
fn test_expand_alternate_ipv4_imds_obfuscations() {
    // H5: DIRECT unit tests for the inet_aton canonicalizer. The 1-, 2-, and 3-part obfuscated
    // forms of the IMDS address all canonicalize to 169.254.169.254. (0xA9FEA9FE = 2852039166.)
    let imds: std::net::Ipv4Addr = "169.254.169.254".parse().unwrap();
    assert_eq!(
        expand_alternate_ipv4("2852039166"),
        Some(imds),
        "1-part decimal"
    );
    assert_eq!(
        expand_alternate_ipv4("169.16689662"),
        Some(imds),
        "2-part inet_aton"
    );
    assert_eq!(
        expand_alternate_ipv4("169.254.43518"),
        Some(imds),
        "3-part inet_aton"
    );
    // Don't-double-process invariant: an already-canonical dotted quad returns None (left to the
    // IpAddr parse path), so the expander never re-canonicalizes a normal address.
    assert_eq!(
        expand_alternate_ipv4("169.254.169.254"),
        None,
        "an already-canonical dotted quad must return None from the expander"
    );
    assert_eq!(expand_alternate_ipv4("8.8.8.8"), None);
    // And those obfuscated forms must be BLOCKED through the full guard.
    for base in [
        "https://2852039166/",
        "https://169.16689662/",
        "https://169.254.43518/",
    ] {
        assert!(
            ssrf_blocked_host(base, &[], false, &[]).is_some(),
            "obfuscated IMDS form '{base}' must be blocked"
        );
    }
}

#[test]
fn test_expand_alternate_ipv4_imds_hex_octal_forms() {
    // Companion to `test_expand_alternate_ipv4_imds_obfuscations` (which covers the DECIMAL
    // inet_aton forms): the canonicalizer must also collapse the HEX and OCTAL encodings of the
    // IMDS address 169.254.169.254 (= 0xA9FEA9FE = 2852039166 = octal 025177524776) so the SSRF
    // guard can't be bypassed by spelling the octets in base 16 or base 8.
    let imds: std::net::Ipv4Addr = "169.254.169.254".parse().unwrap();

    // HEX, single 32-bit integer (`0xA9FEA9FE`) and dotted per-octet hex (`0xA9.0xFE.0xA9.0xFE`).
    assert_eq!(
        expand_alternate_ipv4("0xA9FEA9FE"),
        Some(imds),
        "single-integer hex form of IMDS"
    );
    assert_eq!(
        expand_alternate_ipv4("0xA9.0xFE.0xA9.0xFE"),
        Some(imds),
        "dotted per-octet hex form of IMDS"
    );

    // OCTAL: single 32-bit integer and dotted per-octet octal (leading-zero octets).
    assert_eq!(
        expand_alternate_ipv4("025177524776"),
        Some(imds),
        "single-integer octal form of IMDS"
    );
    assert_eq!(
        expand_alternate_ipv4("0251.0376.0251.0376"),
        Some(imds),
        "dotted per-octet octal form of IMDS"
    );

    // Each form must be BLOCKED through the full guard (ssrf_blocked_host returns the host).
    for base in [
        "https://0xA9FEA9FE/",
        "https://0xA9.0xFE.0xA9.0xFE/",
        "https://025177524776/",
        "https://0251.0376.0251.0376/",
    ] {
        assert!(
            ssrf_blocked_host(base, &[], false, &[]).is_some(),
            "hex/octal-obfuscated IMDS form '{base}' must be blocked"
        );
    }
}

#[test]
fn test_reject_cidr_metadata_entries() {
    // F1: a `/`-bearing entry in any metadata host-list is a no-op (these lists match by EXACT
    // IP/hostname), so validate() must REJECT it at boot with a clear, key+value-naming error.

    // Global blocked list.
    let mut providers = HashMap::new();
    providers.insert(
        "p".to_string(),
        make_provider("openai", "https://api.openai.com", "API_KEY"),
    );
    let cfg = make_root_cfg_with_blocked(providers, vec!["169.254.0.0/16".to_string()]);
    let errs =
        validate(&cfg).expect_err("a CIDR blocked_metadata_hosts entry must fail validation");
    assert!(
        errs.iter()
            .any(|e| e.contains("security.blocked_metadata_hosts")
                && e.contains("169.254.0.0/16")
                && e.contains("CIDR")),
        "expected a CIDR rejection naming the key+value; got: {errs:?}"
    );

    // Global allow list.
    let mut providers = HashMap::new();
    providers.insert(
        "p".to_string(),
        make_provider("openai", "https://api.openai.com", "API_KEY"),
    );
    let mut cfg = make_root_cfg(providers, HashMap::new(), HashMap::new());
    cfg.allow_metadata_hosts = vec!["10.0.0.0/8".to_string()];
    let errs = validate(&cfg).expect_err("a CIDR allow_metadata_hosts entry must fail validation");
    assert!(
        errs.iter()
            .any(|e| e.contains("security.allow_metadata_hosts") && e.contains("10.0.0.0/8")),
        "expected a CIDR rejection naming security.allow_metadata_hosts; got: {errs:?}"
    );

    // Per-provider allow list.
    let mut providers = HashMap::new();
    providers.insert(
        "prov".to_string(),
        make_provider_allow_hosts("https://api.openai.com", &["169.254.169.254/32"]),
    );
    let cfg = make_root_cfg(providers, HashMap::new(), HashMap::new());
    let errs = validate(&cfg)
        .expect_err("a CIDR per-provider allow_metadata_hosts entry must fail validation");
    assert!(
        errs.iter()
            .any(|e| e.contains("provider 'prov' allow_metadata_hosts")
                && e.contains("169.254.169.254/32")),
        "expected a CIDR rejection naming the provider's allow_metadata_hosts; got: {errs:?}"
    );

    // Sanity: exact IPs/hostnames (no slash) do NOT trip the CIDR guard. (validate() may still
    // error for other reasons — assert specifically that no CIDR error is produced.)
    let mut providers = HashMap::new();
    providers.insert(
        "p".to_string(),
        make_provider("openai", "https://api.openai.com", "API_KEY"),
    );
    let mut cfg = make_root_cfg(providers, HashMap::new(), HashMap::new());
    cfg.blocked_metadata_hosts = vec!["169.254.169.254".to_string()];
    cfg.allow_metadata_hosts = vec!["metadata.example.com".to_string()];
    if let Err(errs) = validate(&cfg) {
        assert!(
            !errs.iter().any(|e| e.contains("CIDR")),
            "exact IP/hostname entries must not trip the CIDR guard; got: {errs:?}"
        );
    }
}

#[test]
fn test_global_allow_overrides_blocked_metadata_hosts() {
    // M3: global security.allow_metadata_hosts must override an entry in blocked_metadata_hosts
    // (allow always wins) — both at the guard level and through full validate().
    let blocked = vec!["10.77.77.77".to_string()];
    let allow = vec!["10.77.77.77".to_string()];
    assert!(
        ssrf_blocked_host("https://10.77.77.77/", &allow, false, &blocked).is_none(),
        "global allow_metadata_hosts must override blocked_metadata_hosts"
    );
    // Without the allow, it is blocked (proving the block entry is real).
    assert!(
        ssrf_blocked_host("https://10.77.77.77/", &[], false, &blocked).is_some(),
        "the host must be blocked when not allow-listed"
    );
    // Full validate(): global allow overrides global blocked.
    let mut providers = HashMap::new();
    providers.insert(
        "p".to_string(),
        make_provider("openai", "https://10.77.77.77/", "API_KEY"),
    );
    let mut cfg = make_root_cfg_with_blocked(providers, vec!["10.77.77.77".to_string()]);
    cfg.allow_metadata_hosts = vec!["10.77.77.77".to_string()];
    assert!(
        validate(&cfg).is_ok(),
        "global allow_metadata_hosts must override blocked_metadata_hosts in validate(); got: {:?}",
        validate(&cfg)
    );
}

#[test]
fn test_allow_all_metadata_beats_nonempty_blocked_list() {
    // M3: allow_all_metadata: true wins even with a NON-EMPTY blocked_metadata_hosts — the nuclear
    // override disables the guard wholesale.
    let blocked = vec!["10.0.0.7".to_string(), "metadata.x.example".to_string()];
    for base in [
        "https://169.254.169.254/", // hardcoded denylist
        "https://10.0.0.7/",        // operator-listed
        "https://metadata.x.example/",
    ] {
        assert!(
            ssrf_blocked_host(base, &[], true, &blocked).is_none(),
            "allow_all_metadata must unblock '{base}' even with a non-empty blocked list"
        );
    }
    let mut providers = HashMap::new();
    providers.insert(
        "p".to_string(),
        make_provider("openai", "https://10.0.0.7/", "API_KEY"),
    );
    let mut cfg = make_root_cfg_with_blocked(providers, vec!["10.0.0.7".to_string()]);
    cfg.allow_all_metadata = true;
    assert!(
        validate(&cfg).is_ok(),
        "allow_all_metadata must win over a non-empty blocked_metadata_hosts; got: {:?}",
        validate(&cfg)
    );
}

#[test]
fn test_ssrf_allows_private_and_loopback_by_default() {
    // Loopback / RFC-1918 / CGNAT / localhost are legitimate LOCAL-MODEL upstreams and are
    // ALLOWED with no flag — they are NOT metadata endpoints. (The link-local /16 minus the
    // metadata literals is still allowed too, but link-local is unusual for a model; the key
    // cases are loopback/RFC-1918/CGNAT.)
    for allowed in [
        "https://127.0.0.1/",
        "https://10.0.0.1/v1",
        "https://172.16.0.1/",
        "https://192.168.1.1:8443/",
        "https://[::1]/",
        "https://[::1]:443/",
        "https://[fe80::1]/", // IPv6 link-local (not a metadata literal)
        "https://[fc00::1]/", // IPv6 ULA
        "https://0.0.0.0/",
        "https://user:pass@10.0.0.5/path",
        "https://100.64.0.1/", // CGNAT (Tailscale)
        "https://100.127.255.255/",
        "https://[::ffff:10.0.0.1]/",   // RFC-1918 via mapped IPv6
        "https://[::ffff:100.64.0.1]/", // CGNAT via mapped IPv6
        "https://[::127.0.0.1]/",       // loopback via compatible IPv6
        "https://2130706433/",          // decimal int = 127.0.0.1 (private, allowed)
        "https://127.1/",               // short dotted form = 127.0.0.1
        "https://localhost/",
        "https://api.localhost:11434/v1",
        "https://service.internal.localhost/",
        "https://API.LOCALHOST/",
    ] {
        assert!(
                ssrf_blocked_host(allowed, &[], false, &[]).is_none(),
                "expected '{allowed}' to be ALLOWED (private/loopback is a local-model target, not metadata)"
            );
    }
}

#[test]
fn test_ssrf_blocks_backslash_authority_bypass() {
    // Regression (HIGH, re-audit): `https` is a WHATWG special scheme, so reqwest's `url` crate
    // rewrites every `\` to `/` while parsing — terminating the authority at the FIRST `\`. A
    // hand-parser that split only on `['/', '?', '#']` saw the whole `10.0.0.1\x.allowed.com` as
    // the host (passing every internal/metadata check) while reqwest connected to `10.0.0.1` /
    // `169.254.169.254` with the lane API key attached — a credential-relay SSRF. The guard must
    // normalize `\`→`/` BEFORE splitting so it sees the SAME authority boundary reqwest will.
    // The real host before the `\` here is a METADATA endpoint; the trick tries to disguise it as
    // a benign `allowed.com` suffix. The guard must still see the metadata target.
    for blocked in [
        "https://169.254.169.254\\a.b",
        "https://169.254.169.254\\x.allowed.com/v1/messages",
        "https://100.100.100.200\\evil.example.com/",
        "https://metadata.google.internal\\x.allowed.com",
        // Mixed delimiters: the backslash must still terminate the authority before the slash.
        "https://169.254.169.254\\@allowed.com/path",
    ] {
        assert!(
            ssrf_blocked_host(blocked, &[], false, &[]).is_some(),
            "expected '{blocked}' to be flagged: the backslash terminates the authority \
                 (reqwest rewrites \\ to /), so the real host is the metadata target before it"
        );
    }
    // A full validate() pass must reject a base_url using the backslash-authority trick to reach
    // a metadata host.
    let mut providers = HashMap::new();
    providers.insert(
        "p".to_string(),
        make_provider(
            "anthropic",
            "https://169.254.169.254\\x.allowed.com",
            "API_KEY",
        ),
    );
    let cfg = make_root_cfg(providers, HashMap::new(), HashMap::new());
    let errs = validate(&cfg).expect_err("backslash-authority base_url must fail validation");
    assert!(
        errs.iter()
            .any(|e| e.contains("blocked cloud-metadata host") && e.contains("169.254.169.254")),
        "expected a metadata-host error naming the real metadata host; got: {errs:?}"
    );
}

#[test]
fn test_validate_rejects_path_override_host_fusion() {
    // Regression (MEDIUM, re-audit): a provider `path` override is appended to base_url VERBATIM
    // at request time (`format!("{base}{wire_path}")`), and the composed string chooses the
    // connect host. base_url validation alone misses this: a path NOT starting with '/' fuses
    // into the authority — base_url `https://api.example.com` + path `.evil.com/v1` connects to
    // host `api.example.com.evil.com` with the lane API key attached (credential-relay SSRF).
    let mut providers = HashMap::new();
    let mut fused = make_provider("openai", "https://api.example.com", "API_KEY");
    fused.path = Some(".evil.com/v1/chat/completions".to_string());
    providers.insert("fused".to_string(), fused);
    let cfg = make_root_cfg(providers, HashMap::new(), HashMap::new());
    let errs = validate(&cfg).expect_err("a host-fusing path override must fail validation");
    assert!(
        errs.iter()
            .any(|e| e.contains("fused") && e.contains("must begin with '/'")),
        "expected a leading-slash path error for 'fused'; got: {errs:?}"
    );

    // The host-fusion vector is symmetric for any non-slash leading char that extends the host
    // label — a `@` (userinfo flip) or a bare label both fuse. base_url `https://api.example.com`
    // + path `@169.254.169.254/x` composes to `https://api.example.com@169.254.169.254/x`, whose
    // host is the IMDS endpoint with `api.example.com` demoted to userinfo. The leading-slash
    // rule rejects it (it does not start with '/'), and as belt-and-suspenders the composed url
    // is also an SSRF target — assert at minimum the leading-slash diagnostic fires.
    let mut providers2 = HashMap::new();
    let mut imds = make_provider("openai", "https://api.example.com", "API_KEY");
    imds.path = Some("@169.254.169.254/latest/meta-data".to_string());
    providers2.insert("imds".to_string(), imds);
    let cfg2 = make_root_cfg(providers2, HashMap::new(), HashMap::new());
    let errs2 = validate(&cfg2).expect_err("a userinfo-flip path override must fail validation");
    assert!(
        errs2
            .iter()
            .any(|e| e.contains("imds") && e.contains("must begin with '/'")),
        "expected a leading-slash path error for the userinfo-flip override; got: {errs2:?}"
    );
}

#[test]
fn test_validate_accepts_well_formed_path_override() {
    // The shipped catalog form — a leading-slash path on a public host — must validate. Mirrors
    // the `zai-payg` provider (`base_url: .../api/paas/v4` + `path: /chat/completions`).
    let mut providers = HashMap::new();
    let mut p = make_provider("openai", "https://api.example.com/api/paas/v4", "API_KEY");
    p.path = Some("/chat/completions".to_string());
    providers.insert("ok".to_string(), p);
    let cfg = make_root_cfg(providers, HashMap::new(), HashMap::new());
    assert!(
        validate(&cfg).is_ok(),
        "a leading-slash path override on a public host must validate"
    );
}

#[test]
fn test_ssrf_cgnat_allowed_but_alibaba_literal_blocked() {
    // CGNAT 100.64.0.0/10 is a legitimate local-model range (Tailscale) and is ALLOWED — EXCEPT
    // the single Alibaba metadata literal 100.100.100.200 that lives inside it, which stays
    // blocked. Addresses just outside the /10 are ordinary public addresses (also allowed).
    assert!(ssrf_blocked_host("https://100.64.0.0/", &[], false, &[]).is_none());
    assert!(ssrf_blocked_host("https://100.127.255.255/", &[], false, &[]).is_none());
    assert!(ssrf_blocked_host("https://100.63.255.255/", &[], false, &[]).is_none());
    assert!(ssrf_blocked_host("https://100.128.0.1/", &[], false, &[]).is_none());
    // The Alibaba metadata literal inside the CGNAT range stays blocked.
    assert!(
            ssrf_blocked_host("https://100.100.100.200/", &[], false, &[]).is_some(),
            "the Alibaba metadata literal 100.100.100.200 must stay blocked even though CGNAT is allowed"
        );
}

#[test]
fn test_validate_rejects_zero_weight_member() {
    let (providers, models, _) = valid_maps();
    let mut pools = HashMap::new();
    let mut zero = make_member("mymodel");
    zero.weight = 0;
    pools.insert("mypool".to_string(), make_pool(vec![zero]));
    let cfg = make_root_cfg(providers, models, pools);
    let errs = validate(&cfg).expect_err("a weight:0 pool member must fail validation");
    assert!(
        errs.iter()
            .any(|e| e.contains("weight must be >= 1") && e.contains("mymodel")),
        "expected a weight:0 rejection for 'mymodel'; got: {errs:?}"
    );
}

#[test]
fn test_validate_rejects_empty_pool_members() {
    // A pool with an EMPTY member list parses fine but is permanently un-routable: every
    // request to it exhausts immediately and 503s with a misleading "overloaded" message, with
    // no boot diagnostic. This is the empty-set twin of the weight:0 / max_concurrent:0 /
    // breaker n:0 fail-loud guards — reject it at startup. (Fails against old code, which had
    // no empty-members check and let such a pool boot.)
    let (providers, models, _) = valid_maps();
    let mut pools = HashMap::new();
    pools.insert("emptypool".to_string(), make_pool(vec![]));
    let cfg = make_root_cfg(providers, models, pools);
    let errs = validate(&cfg).expect_err("an empty-members pool must fail validation");
    assert!(
        errs.iter()
            .any(|e| e.contains("emptypool") && e.contains("no members")),
        "expected a no-members rejection for 'emptypool'; got: {errs:?}"
    );
}

#[test]
fn test_validate_accepts_pool_with_at_least_one_member() {
    // A pool with one or more members must NOT trip the empty-members guard.
    let (providers, models, pools) = valid_maps();
    let cfg = make_root_cfg(providers, models, pools);
    let result = validate(&cfg);
    if let Err(errs) = &result {
        assert!(
            !errs.iter().any(|e| e.contains("no members")),
            "a pool with a member must not trip the empty-members guard; got: {errs:?}"
        );
    }
}

#[test]
fn test_validate_accepts_positive_weight_member() {
    // The default weight (1) and any positive weight must validate.
    let (providers, models, _) = valid_maps();
    let mut pools = HashMap::new();
    let mut w = make_member("mymodel");
    w.weight = 5;
    pools.insert("mypool".to_string(), make_pool(vec![w]));
    let cfg = make_root_cfg(providers, models, pools);
    assert!(
        validate(&cfg).is_ok(),
        "a positive-weight pool member must validate"
    );
}

#[test]
fn test_ssrf_blocked_host_allows_public_targets() {
    // Public hostnames and public IPs must NOT be flagged.
    for ok in [
        "https://api.anthropic.com/v1/messages",
        "https://api.openai.com",
        "https://example.com:8443/v1",
        "https://8.8.8.8/",
        "https://[2606:4700:4700::1111]/",
        // Public hostnames whose right-most label merely CONTAINS "localhost" but is not the
        // reserved `.localhost` TLD must NOT be flagged — only an exact right-most `localhost`
        // label is loopback. These are ordinary public DNS names.
        "https://mylocalhost.com/",
        "https://notlocalhost.example.com/",
        "https://localhost.example.com/", // `localhost` is a left label, TLD is `com`
    ] {
        assert!(
            ssrf_blocked_host(ok, &[], false, &[]).is_none(),
            "expected '{ok}' to be allowed (not an SSRF target)"
        );
    }
}

#[test]
fn test_validate_rejects_https_internal_base_url() {
    // A full validate() pass must reject an https:// base_url pointing at IMDS.
    let mut providers = HashMap::new();
    providers.insert(
        "p".to_string(),
        make_provider("anthropic", "https://169.254.169.254/", "API_KEY"),
    );
    let cfg = make_root_cfg(providers, HashMap::new(), HashMap::new());
    let errs = validate(&cfg).expect_err("https IMDS base_url must fail validation");
    assert!(
        errs.iter()
            .any(|e| e.contains("blocked cloud-metadata host") && e.contains("169.254.169.254")),
        "expected an SSRF/metadata-host error; got: {errs:?}"
    );
}

#[test]
fn test_validate_rejects_unknown_fallback_pool() {
    let (providers, models, _) = valid_maps();
    let mut pools = HashMap::new();
    let mut pool = make_pool(vec![make_member("mymodel")]);
    pool.on_exhausted = Some(config::OnExhaustedCfg {
        action: "fallback_pool:does_not_exist".to_string(),
    });
    pools.insert("mypool".to_string(), pool);
    let cfg = make_root_cfg(providers, models, pools);
    let errs = validate(&cfg).expect_err("on_exhausted referencing an unknown pool must fail");
    assert!(
        errs.iter().any(
            |e| e.contains("on_exhausted references unknown fallback pool")
                && e.contains("does_not_exist")
        ),
        "expected a dangling-fallback-pool error; got: {errs:?}"
    );
}

#[test]
fn test_validate_accepts_existing_fallback_pool() {
    let (providers, models, _) = valid_maps();
    let mut pools = HashMap::new();
    let mut pool = make_pool(vec![make_member("mymodel")]);
    pool.on_exhausted = Some(config::OnExhaustedCfg {
        action: "fallback_pool:backup".to_string(),
    });
    pools.insert("mypool".to_string(), pool);
    // The referenced fallback pool exists → no error.
    pools.insert(
        "backup".to_string(),
        make_pool(vec![make_member("mymodel")]),
    );
    let cfg = make_root_cfg(providers, models, pools);
    assert!(
        validate(&cfg).is_ok(),
        "on_exhausted referencing an existing pool must validate"
    );
}

#[test]
fn test_validate_rejects_self_referential_fallback_pool() {
    // A pool whose on_exhausted fallback points at ITSELF (A -> A) never engages at runtime
    // (the loop guard terminates on re-entry) — reject it at boot.
    let (providers, models, _) = valid_maps();
    let mut pools = HashMap::new();
    let mut pool = make_pool(vec![make_member("mymodel")]);
    pool.on_exhausted = Some(config::OnExhaustedCfg {
        action: "fallback_pool:mypool".to_string(), // points at its own name
    });
    pools.insert("mypool".to_string(), pool);
    let cfg = make_root_cfg(providers, models, pools);
    let errs = validate(&cfg).expect_err("a self-referential fallback pool must fail validation");
    assert!(
        errs.iter()
            .any(|e| e.contains("references itself as its fallback pool") && e.contains("mypool")),
        "expected a self-referential fallback-pool error; got: {errs:?}"
    );
    // It must NOT be misreported as a dangling/unknown fallback pool (the pool exists).
    assert!(
        !errs
            .iter()
            .any(|e| e.contains("references unknown fallback pool")),
        "a self-reference must not be reported as an unknown fallback pool; got: {errs:?}"
    );
}

#[test]
fn test_validate_rejects_two_pool_fallback_cycle() {
    // A <-> B: pool A falls back to B and B falls back to A. The runtime loop guard collapses
    // the ring into a 503, so startup must reject it. The cycle must be reported EXACTLY ONCE
    // (not once per ring member).
    let (providers, models, _) = valid_maps();
    let mut pools = HashMap::new();
    let mut a = make_pool(vec![make_member("mymodel")]);
    a.on_exhausted = Some(config::OnExhaustedCfg {
        action: "fallback_pool:pool_b".to_string(),
    });
    let mut b = make_pool(vec![make_member("mymodel")]);
    b.on_exhausted = Some(config::OnExhaustedCfg {
        action: "fallback_pool:pool_a".to_string(),
    });
    pools.insert("pool_a".to_string(), a);
    pools.insert("pool_b".to_string(), b);
    let cfg = make_root_cfg(providers, models, pools);
    let errs = validate(&cfg).expect_err("an A<->B fallback cycle must fail validation");
    let cycle_errs: Vec<&String> = errs
        .iter()
        .filter(|e| e.contains("fallback_pool cycle detected"))
        .collect();
    assert_eq!(
        cycle_errs.len(),
        1,
        "an A<->B cycle must be reported exactly once; got: {errs:?}"
    );
    assert!(
        cycle_errs[0].contains("pool_a") && cycle_errs[0].contains("pool_b"),
        "the cycle diagnostic must name both ring members; got: {}",
        cycle_errs[0]
    );
}

#[test]
fn test_validate_rejects_three_pool_fallback_cycle() {
    // A -> B -> C -> A: a longer ring must also be rejected, and reported exactly once.
    let (providers, models, _) = valid_maps();
    let mut pools = HashMap::new();
    for (name, next) in [("p1", "p2"), ("p2", "p3"), ("p3", "p1")] {
        let mut p = make_pool(vec![make_member("mymodel")]);
        p.on_exhausted = Some(config::OnExhaustedCfg {
            action: format!("fallback_pool:{next}"),
        });
        pools.insert(name.to_string(), p);
    }
    let cfg = make_root_cfg(providers, models, pools);
    let errs = validate(&cfg).expect_err("a 3-pool fallback cycle must fail validation");
    let cycle_errs: Vec<&String> = errs
        .iter()
        .filter(|e| e.contains("fallback_pool cycle detected"))
        .collect();
    assert_eq!(
        cycle_errs.len(),
        1,
        "a 3-pool cycle must be reported exactly once; got: {errs:?}"
    );
}

#[test]
fn test_validate_accepts_acyclic_fallback_chain() {
    // A -> B -> C (no loop back) is a legitimate degraded-routing chain and must NOT be flagged
    // as a cycle (guard against an over-broad cycle detector). C has no fallback.
    let (providers, models, _) = valid_maps();
    let mut pools = HashMap::new();
    let mut a = make_pool(vec![make_member("mymodel")]);
    a.on_exhausted = Some(config::OnExhaustedCfg {
        action: "fallback_pool:chain_b".to_string(),
    });
    let mut b = make_pool(vec![make_member("mymodel")]);
    b.on_exhausted = Some(config::OnExhaustedCfg {
        action: "fallback_pool:chain_c".to_string(),
    });
    let c = make_pool(vec![make_member("mymodel")]);
    pools.insert("chain_a".to_string(), a);
    pools.insert("chain_b".to_string(), b);
    pools.insert("chain_c".to_string(), c);
    let cfg = make_root_cfg(providers, models, pools);
    assert!(
        validate(&cfg).is_ok(),
        "an acyclic A->B->C fallback chain must validate; got: {:?}",
        validate(&cfg)
    );
}

#[test]
fn test_validate_accepts_diamond_fallback_no_cycle() {
    // A->C and B->C (two pools share a downstream fallback) is NOT a cycle: C is visited from
    // two distinct walks but neither walk loops. Guards the min-member dedup logic against a
    // false positive on a converging (non-looping) graph.
    let (providers, models, _) = valid_maps();
    let mut pools = HashMap::new();
    let mut a = make_pool(vec![make_member("mymodel")]);
    a.on_exhausted = Some(config::OnExhaustedCfg {
        action: "fallback_pool:dia_c".to_string(),
    });
    let mut b = make_pool(vec![make_member("mymodel")]);
    b.on_exhausted = Some(config::OnExhaustedCfg {
        action: "fallback_pool:dia_c".to_string(),
    });
    let c = make_pool(vec![make_member("mymodel")]);
    pools.insert("dia_a".to_string(), a);
    pools.insert("dia_b".to_string(), b);
    pools.insert("dia_c".to_string(), c);
    let cfg = make_root_cfg(providers, models, pools);
    assert!(
        validate(&cfg).is_ok(),
        "a converging (diamond) fallback graph must validate; got: {:?}",
        validate(&cfg)
    );
}

#[test]
fn test_affinity_mode_is_a_closed_enum() {
    // `affinity.mode` is now an `AffinityMode` enum, so an unrecognized spelling ('sticky') is
    // rejected at DESERIALIZE time rather than by a hand-check in validate(). The one accepted
    // wire string ('session') is unchanged from the pre-enum `String` field.
    assert_eq!(
        serde_yaml::from_str::<config::AffinityMode>("session").unwrap(),
        config::AffinityMode::Session
    );
    assert!(
        serde_yaml::from_str::<config::AffinityMode>("sticky").is_err(),
        "'sticky' is not a supported affinity mode and must fail to deserialize"
    );
}

#[test]
fn test_validate_accepts_session_affinity_mode() {
    let (providers, models, _) = valid_maps();
    let mut pools = HashMap::new();
    let mut pool = make_pool(vec![make_member("mymodel")]);
    pool.affinity = Some(config::AffinityCfg {
        mode: config::AffinityMode::Session,
        header_name: Some("x-session-id".to_string()),
    });
    pools.insert("mypool".to_string(), pool);
    let cfg = make_root_cfg(providers, models, pools);
    assert!(
        validate(&cfg).is_ok(),
        "the supported 'session' affinity mode must validate"
    );
}

/// REGRESSION (audit c2r5): the provider `base_url` scheme check is CASE-INSENSITIVE (RFC 3986
/// §3.1) — an uppercase `HTTPS://` (which reqwest lowercases and accepts) must validate, not be
/// rejected with a misleading "must use http or https". Mirrors the webhook guard's `scheme_is`.
#[test]
fn test_validate_accepts_uppercase_url_scheme() {
    let (mut providers, models, _) = valid_maps();
    // Point an existing provider at an uppercase-scheme https URL.
    if let Some((_, p)) = providers.iter_mut().next() {
        p.base_url = "HTTPS://api.example.com".to_string();
    }
    let cfg = make_root_cfg(providers, models, HashMap::new());
    assert!(
        validate(&cfg).is_ok(),
        "an uppercase HTTPS:// scheme is RFC-valid and must not be rejected: {:?}",
        validate(&cfg)
    );
    // The scheme helper itself is case-insensitive and anchored on `://`.
    assert!(scheme_is("HTTPS://h", "https"));
    assert!(scheme_is("Http://h", "http"));
    assert!(!scheme_is("httpsx://h", "https"));
}

/// REGRESSION (audit c2r3): an EMPTY `affinity.header_name` must be REJECTED at boot. It passes
/// the ASCII + length checks but silently disables session affinity at runtime
/// (`headers.get("")` is always None) — the exact silent-disable the validator's comment promises
/// to catch.
#[test]
fn test_validate_rejects_empty_affinity_header_name() {
    let (providers, models, _) = valid_maps();
    let mut pools = HashMap::new();
    let mut pool = make_pool(vec![make_member("mymodel")]);
    pool.affinity = Some(config::AffinityCfg {
        mode: config::AffinityMode::Session,
        header_name: Some(String::new()),
    });
    pools.insert("mypool".to_string(), pool);
    let cfg = make_root_cfg(providers, models, pools);
    let err = validate(&cfg).expect_err("empty header_name must be rejected");
    assert!(
        err.iter().any(|e| e.contains("must not be empty")),
        "the error must name the empty-header-name problem: {err:?}"
    );
}

#[test]
fn test_pool_member_model_with_unresolvable_provider_is_not_unknown_model() {
    // A pool member that names a model which IS defined, but whose provider does not resolve,
    // must NOT be reported as an "unknown model" (the model exists). The model loop already
    // emits a "references unknown provider" error for the model itself; the pool-member check
    // must emit a distinct, accurate diagnostic pointing at the unresolvable provider rather
    // than misleadingly claiming the model is undefined.
    let mut providers = HashMap::new();
    providers.insert(
        "realprovider".to_string(),
        make_provider("anthropic", "https://api.example.com", "API_KEY"),
    );

    // `definedmodel` is a real model entry, but its provider `ghostprovider` is not configured.
    let mut models = HashMap::new();
    models.insert("definedmodel".to_string(), make_model("ghostprovider", 10));

    let mut pools = HashMap::new();
    pools.insert(
        "mypool".to_string(),
        make_pool(vec![make_member("definedmodel")]),
    );

    let cfg = make_root_cfg(providers, models, pools);
    let errs = validate(&cfg).unwrap_err_or_default(
        "a model with an unresolvable provider must fail validation".to_string(),
    );

    // The model loop must still report the root cause on the model itself.
    assert!(
        errs.iter().any(|e| e.contains("definedmodel")
            && e.contains("references unknown provider")
            && e.contains("ghostprovider")),
        "expected the model-level unknown-provider error; got: {errs:?}"
    );

    // The pool-member check must NOT call a DEFINED model "unknown".
    assert!(
        !errs
            .iter()
            .any(|e| e.contains("references unknown model 'definedmodel'")),
        "a defined model must not be reported as an unknown model; got: {errs:?}"
    );

    // It must instead emit the accurate provider-unresolvable diagnostic for the pool member.
    assert!(
        errs.iter().any(|e| e.contains("mypool")
            && e.contains("definedmodel")
            && e.contains("provider is unresolvable")),
        "expected a pool-member 'provider is unresolvable' diagnostic; got: {errs:?}"
    );
}

#[test]
fn test_pool_member_truly_unknown_model_still_reports_unknown_model() {
    // Guard the other side of the distinction: a member naming a model that is NOT defined at
    // all must still get the "references unknown model" diagnostic (not the new
    // provider-unresolvable one).
    let mut providers = HashMap::new();
    providers.insert(
        "realprovider".to_string(),
        make_provider("anthropic", "https://api.example.com", "API_KEY"),
    );

    let models = HashMap::new();

    let mut pools = HashMap::new();
    pools.insert(
        "mypool".to_string(),
        make_pool(vec![make_member("nosuchmodel")]),
    );

    let cfg = make_root_cfg(providers, models, pools);
    let errs = validate(&cfg)
        .unwrap_err_or_default("an undefined member model must fail validation".to_string());

    assert!(
        errs.iter()
            .any(|e| e.contains("references unknown model") && e.contains("nosuchmodel")),
        "a genuinely undefined model must still be reported as unknown; got: {errs:?}"
    );
    assert!(
        !errs.iter().any(|e| e.contains("provider is unresolvable")),
        "an undefined model must not get the provider-unresolvable message; got: {errs:?}"
    );
}

/// Build a single-pool config whose pool uses `route: webhook` with the given `policy.url`. The
/// pool has one member targeting a valid model+provider, so the ONLY thing under test is the
/// routing-webhook URL validation rule.
fn webhook_pool_cfg(url: Option<&str>) -> RootCfg {
    let mut providers = HashMap::new();
    providers.insert(
        "prov".to_string(),
        make_provider("anthropic", "https://api.example.com", "API_KEY"),
    );
    let mut models = HashMap::new();
    models.insert("m1".to_string(), make_model("prov", 4));
    let mut pool = make_pool(vec![make_member("m1")]);
    pool.gates = vec!["h".to_string()];
    let mut pools = HashMap::new();
    pools.insert("p1".to_string(), pool);
    let mut cfg = make_root_cfg(providers, models, pools);
    cfg.hooks.insert("h".to_string(), gate_hook(None, url, 150));
    cfg
}

/// A gate `HookCfg` with the given socket/webhook transport (test builder).
fn gate_hook(socket: Option<&str>, webhook: Option<&str>, timeout_ms: u64) -> config::HookCfg {
    config::HookCfg {
        kind: config::HookKind::Gate,
        socket: socket.map(str::to_string),
        webhook: webhook.map(str::to_string),
        timeout_ms,
        on_error: "weighted".to_string(),
        prompt: config::PromptAccess::No,
        user: config::UserAccess::No,
        priority: 0,
        at: None,
        settings: serde_json::Map::new(),
        on_empty: None,
        global: false,
        default: false,
    }
}

/// A minimal valid RootCfg with an empty hooks registry (for on_error chain tests).
fn hooks_test_cfg() -> RootCfg {
    let mut providers = HashMap::new();
    providers.insert(
        "prov".to_string(),
        make_provider("anthropic", "https://api.example.com", "API_KEY"),
    );
    let mut models = HashMap::new();
    models.insert("m1".to_string(), make_model("prov", 4));
    let pools = {
        let mut p = HashMap::new();
        p.insert("p1".to_string(), make_pool(vec![make_member("m1")]));
        p
    };
    make_root_cfg(providers, models, pools)
}

/// `on_error` naming an unknown fallback is a boot error (chains resolve against the registry).
#[test]
fn test_hook_on_error_unknown_name_rejected() {
    let mut cfg = hooks_test_cfg();
    let mut h = gate_hook(Some("/run/busbar/a.sock"), None, 150);
    h.on_error = "nonexistent".to_string();
    cfg.hooks.insert("a".to_string(), h);
    let errs = validate(&cfg).expect_err("an unknown on_error name must be rejected");
    assert!(
        errs.iter()
            .any(|e| e.contains("unknown fallback 'nonexistent'")),
        "{errs:?}"
    );
}

/// `on_error` naming a TAP is a boot error (a fallback must decide; a tap only observes).
#[test]
fn test_hook_on_error_tap_fallback_rejected() {
    let mut cfg = hooks_test_cfg();
    let mut gate = gate_hook(Some("/run/busbar/a.sock"), None, 150);
    gate.on_error = "watcher".to_string();
    let mut tap = gate_hook(Some("/run/busbar/t.sock"), None, 150);
    tap.kind = config::HookKind::Tap;
    cfg.hooks.insert("a".to_string(), gate);
    cfg.hooks.insert("watcher".to_string(), tap);
    let errs = validate(&cfg).expect_err("a tap fallback must be rejected");
    assert!(
        errs.iter()
            .any(|e| e.contains("fallback 'watcher' is a tap")),
        "{errs:?}"
    );
}

/// An on_error CYCLE (including a self-reference) is a boot error — every chain must terminate.
#[test]
fn test_hook_on_error_cycle_rejected() {
    // a -> b -> a
    let mut cfg = hooks_test_cfg();
    let mut a = gate_hook(Some("/run/busbar/a.sock"), None, 150);
    a.on_error = "b".to_string();
    let mut b = gate_hook(Some("/run/busbar/b.sock"), None, 150);
    b.on_error = "a".to_string();
    cfg.hooks.insert("a".to_string(), a);
    cfg.hooks.insert("b".to_string(), b);
    let errs = validate(&cfg).expect_err("an on_error cycle must be rejected");
    assert!(
        errs.iter().any(|e| e.contains("does not terminate")),
        "{errs:?}"
    );

    // self-reference
    let mut cfg = hooks_test_cfg();
    let mut selfy = gate_hook(Some("/run/busbar/s.sock"), None, 150);
    selfy.on_error = "s".to_string();
    cfg.hooks.insert("s".to_string(), selfy);
    let errs = validate(&cfg).expect_err("a self-referencing on_error must be rejected");
    assert!(
        errs.iter().any(|e| e.contains("does not terminate")),
        "{errs:?}"
    );
}

/// A terminating gate chain (a -> b -> weighted) and a strategy fallback are both accepted.
#[test]
fn test_hook_on_error_terminating_chain_ok() {
    let mut cfg = hooks_test_cfg();
    let mut a = gate_hook(Some("/run/busbar/a.sock"), None, 150);
    a.on_error = "b".to_string();
    let b = gate_hook(Some("/run/busbar/b.sock"), None, 150); // on_error: weighted
    cfg.hooks.insert("a".to_string(), a);
    cfg.hooks.insert("b".to_string(), b);
    if let Err(errs) = validate(&cfg) {
        assert!(
            !errs.iter().any(|e| e.contains("on_error")),
            "a terminating chain must not trip the on_error rule; got: {errs:?}"
        );
    }

    // A ranking-strategy fallback terminates the chain when the plugin is compiled in; when it
    // is compiled out, naming one is a boot error (compliance-by-compilation).
    let mut cfg = hooks_test_cfg();
    let mut c = gate_hook(Some("/run/busbar/c.sock"), None, 150);
    c.on_error = "cheapest".to_string();
    cfg.hooks.insert("c".to_string(), c);
    let result = validate(&cfg);
    #[cfg(feature = "hooks-ranking")]
    if let Err(errs) = result {
        assert!(
            !errs.iter().any(|e| e.contains("on_error")),
            "a strategy fallback must be accepted when compiled in; got: {errs:?}"
        );
    }
    #[cfg(not(feature = "hooks-ranking"))]
    {
        let errs = result.expect_err("a strategy fallback without the plugin must be rejected");
        assert!(
            errs.iter()
                .any(|e| e.contains("WITHOUT the `hooks-ranking` feature")),
            "{errs:?}"
        );
    }
}

#[test]
fn test_hook_reserved_name_rejected() {
    // A hook cannot reuse a built-in's name (ranking strategy or auth module) — registry name
    // uniqueness. Each reserved name, defined as a valid gate hook, must be rejected by name.
    for reserved in [
        "weighted",
        "cheapest",
        "fastest",
        "least_busy",
        "usage",
        "tokens",
        "admin-tokens",
    ] {
        let mut providers = HashMap::new();
        providers.insert(
            "prov".to_string(),
            make_provider("anthropic", "https://api.example.com", "API_KEY"),
        );
        let mut models = HashMap::new();
        models.insert("m1".to_string(), make_model("prov", 4));
        let pools = {
            let mut p = HashMap::new();
            p.insert("p1".to_string(), make_pool(vec![make_member("m1")]));
            p
        };
        let mut cfg = make_root_cfg(providers, models, pools);
        cfg.hooks.insert(
            reserved.to_string(),
            gate_hook(Some("/run/busbar/h.sock"), None, 150),
        );
        let errs = validate(&cfg).expect_err("a reserved hook name must be rejected");
        assert!(
            errs.iter()
                .any(|e| e.contains(&format!("hook '{reserved}'")) && e.contains("reserved")),
            "reserved hook name '{reserved}' must be rejected by name; got: {errs:?}"
        );
    }
}

#[test]
fn test_hook_at_most_one_default() {
    // Two hooks claiming `default: true` is a boot error naming both; one (or zero) is fine.
    let mut providers = HashMap::new();
    providers.insert(
        "prov".to_string(),
        make_provider("anthropic", "https://api.example.com", "API_KEY"),
    );
    let mut models = HashMap::new();
    models.insert("m1".to_string(), make_model("prov", 4));
    let pools = {
        let mut p = HashMap::new();
        p.insert("p1".to_string(), make_pool(vec![make_member("m1")]));
        p
    };
    let mut two = gate_hook(Some("/run/busbar/a.sock"), None, 150);
    two.default = true;
    let mut cfg = make_root_cfg(providers, models, pools);
    cfg.hooks.insert("rank_a".to_string(), two.clone());
    cfg.hooks.insert("rank_b".to_string(), two);
    let errs = validate(&cfg).expect_err("two defaults must be rejected");
    assert!(
        errs.iter()
            .any(|e| e.contains("default: true") && e.contains("rank_a") && e.contains("rank_b")),
        "the error must name both offending defaults; got: {errs:?}"
    );

    // Exactly one default is accepted (no default-rule error).
    cfg.hooks.remove("rank_b");
    if let Err(errs) = validate(&cfg) {
        assert!(
            !errs.iter().any(|e| e.contains("more than one hook sets")),
            "a single default must not trip the at-most-one rule; got: {errs:?}"
        );
    }
}

#[test]
fn test_hook_default_on_tap_rejected() {
    // `default: true` on a tap is meaningless (a tap never orders) → boot error.
    let mut providers = HashMap::new();
    providers.insert(
        "prov".to_string(),
        make_provider("anthropic", "https://api.example.com", "API_KEY"),
    );
    let mut models = HashMap::new();
    models.insert("m1".to_string(), make_model("prov", 4));
    let pools = {
        let mut p = HashMap::new();
        p.insert("p1".to_string(), make_pool(vec![make_member("m1")]));
        p
    };
    let mut tap = gate_hook(Some("/run/busbar/t.sock"), None, 150);
    tap.kind = config::HookKind::Tap;
    tap.default = true;
    let mut cfg = make_root_cfg(providers, models, pools);
    cfg.hooks.insert("watcher".to_string(), tap);
    let errs = validate(&cfg).expect_err("default tap must be rejected");
    assert!(
        errs.iter()
            .any(|e| e.contains("watcher") && e.contains("default") && e.contains("tap")),
        "error must name the default tap; got: {errs:?}"
    );
}

#[test]
fn test_hook_nonreserved_name_ok() {
    // A normal hook name is NOT flagged by the reserved-name rule.
    let mut providers = HashMap::new();
    providers.insert(
        "prov".to_string(),
        make_provider("anthropic", "https://api.example.com", "API_KEY"),
    );
    let mut models = HashMap::new();
    models.insert("m1".to_string(), make_model("prov", 4));
    let pools = {
        let mut p = HashMap::new();
        p.insert("p1".to_string(), make_pool(vec![make_member("m1")]));
        p
    };
    let mut cfg = make_root_cfg(providers, models, pools);
    cfg.hooks.insert(
        "headroom".to_string(),
        gate_hook(Some("/run/busbar/h.sock"), None, 150),
    );
    if let Err(errs) = validate(&cfg) {
        assert!(
            !errs.iter().any(|e| e.contains("reserved")),
            "a non-reserved hook name must not trip the reserved-name rule; got: {errs:?}"
        );
    }
}

#[test]
fn test_webhook_route_allows_loopback_sidecar() {
    // Loopback / localhost sidecars are the carve-out (the OTLP precedent): plaintext http:// is
    // permitted on loopback, and https loopback too.
    for ok in [
        "http://127.0.0.1:9000/route",
        "http://localhost:9000/route",
        "https://localhost:9000/route",
        "http://[::1]:9000/route",
    ] {
        let cfg = webhook_pool_cfg(Some(ok));
        let res = validate(&cfg);
        if let Err(errs) = res {
            assert!(
                !errs
                    .iter()
                    .any(|e| e.contains("hook 'h'") && e.contains("webhook")),
                "loopback sidecar '{ok}' must pass the routing-webhook guard; got: {errs:?}"
            );
        }
    }
}

#[test]
fn test_webhook_route_blocks_internal_and_metadata() {
    // Internal / cloud-metadata / RFC1918 / link-local targets are blocked even though loopback
    // is allowed — the routing webhook is NOT routed through the looser-than-base_url path blindly.
    for bad in [
        "https://169.254.169.254/route", // IMDS
        "https://10.0.0.5/route",        // RFC1918
        "https://metadata.google.internal/route",
        "http://example.com/route", // plaintext to a non-loopback host
    ] {
        let cfg = webhook_pool_cfg(Some(bad));
        let errs = validate(&cfg)
            .unwrap_err_or_default(format!("'{bad}' must fail routing-webhook validation"));
        assert!(
            errs.iter()
                .any(|e| e.contains("hook 'h'") && e.contains("webhook")),
            "internal/plaintext target '{bad}' must be rejected; got: {errs:?}"
        );
    }
}

#[test]
fn test_webhook_route_requires_url() {
    // A `route: webhook` pool with no `policy.url` is a misconfiguration caught at startup.
    let cfg = webhook_pool_cfg(None);
    let errs = validate(&cfg)
        .unwrap_err_or_default("missing webhook transport must fail validation".to_string());
    assert!(
        errs.iter()
            .any(|e| e.contains("hook 'h'") && e.contains("no transport")),
        "a hook with no transport must be reported; got: {errs:?}"
    );
}

/// Build a single-pool config whose pool uses `route: socket` with the given `policy.socket`
/// path. Exercises the routing-socket validation rule (unix platforms).
#[cfg(unix)]
fn socket_pool_cfg(socket: Option<&str>) -> RootCfg {
    let mut providers = HashMap::new();
    providers.insert(
        "prov".to_string(),
        make_provider("anthropic", "https://api.example.com", "API_KEY"),
    );
    let mut models = HashMap::new();
    models.insert("m1".to_string(), make_model("prov", 4));
    let mut pool = make_pool(vec![make_member("m1")]);
    pool.gates = vec!["h".to_string()];
    let mut pools = HashMap::new();
    pools.insert("p1".to_string(), pool);
    let mut cfg = make_root_cfg(providers, models, pools);
    cfg.hooks
        .insert("h".to_string(), gate_hook(socket, None, 150));
    cfg
}

/// `route: socket` with a valid absolute path passes the socket rule (the socket FILE need not
/// exist — the hook binary may start after busbar; only the path's shape is validated).
#[cfg(unix)]
#[test]
fn test_socket_route_accepts_absolute_path() {
    let cfg = socket_pool_cfg(Some("/run/busbar/hook.sock"));
    if let Err(errs) = validate(&cfg) {
        assert!(
            !errs
                .iter()
                .any(|e| e.contains("hook 'h'") && e.contains("socket")),
            "an absolute socket path must pass the socket rule; got: {errs:?}"
        );
    }
}

/// `route: socket` with a missing or empty `policy.socket` is a startup error.
#[cfg(unix)]
#[test]
fn test_socket_route_requires_socket_path() {
    for missing in [None, Some("")] {
        let cfg = socket_pool_cfg(missing);
        let errs = validate(&cfg)
            .unwrap_err_or_default("missing socket transport must fail validation".to_string());
        assert!(
            errs.iter()
                .any(|e| e.contains("hook 'h'") && e.contains("no transport")),
            "missing/empty socket path must be reported; got: {errs:?}"
        );
    }
}

/// A RELATIVE `policy.socket` path is a startup error (it would silently depend on busbar's CWD).
#[cfg(unix)]
#[test]
fn test_socket_route_rejects_relative_path() {
    let cfg = socket_pool_cfg(Some("run/hook.sock"));
    let errs = validate(&cfg)
        .unwrap_err_or_default("relative socket path must fail validation".to_string());
    assert!(
        errs.iter()
            .any(|e| e.contains("hook 'h'") && e.contains("absolute")),
        "relative socket path must be reported; got: {errs:?}"
    );
}

// Small ergonomic helper: like `expect_err` but with a custom message and returning the Vec.
trait UnwrapErrOrDefault {
    fn unwrap_err_or_default(self, msg: String) -> Vec<String>;
}
impl UnwrapErrOrDefault for Result<(), Vec<String>> {
    fn unwrap_err_or_default(self, msg: String) -> Vec<String> {
        self.err().unwrap_or_else(|| panic!("{msg}"))
    }
}

// ---- metadata-denylist model: local upstreams allowed by default; metadata blocked ----

/// Build a provider whose per-provider `allow_metadata_hosts` lists the given entries.
fn make_provider_allow_hosts(base_url: &str, hosts: &[&str]) -> config::ProviderCfg {
    let mut p = make_provider("openai", base_url, "API_KEY");
    p.allow_metadata_hosts = hosts.iter().map(|s| s.to_string()).collect();
    p
}

#[test]
fn test_local_upstreams_allowed_by_default_no_flag() {
    // The core use case: an operator fronts a local Ollama / vLLM / LM Studio. Under the
    // metadata-denylist model this validates with NO flag — plain http:// is allowed because the
    // host is private/loopback, and the SSRF guard allows everything that is not metadata.
    for base in [
        "http://localhost:11434",
        "http://127.0.0.1",
        "http://127.0.0.1:11434",
        "http://10.0.0.5:8000",     // RFC-1918
        "http://192.168.1.50:1234", // RFC-1918 (LM Studio)
        "http://172.16.3.4:8000",   // RFC-1918
        "http://100.64.0.5:8000",   // CGNAT (Tailscale)
        "http://[::1]:11434",       // IPv6 loopback
        "https://localhost",        // https local also fine
        "https://localhost:11434",
    ] {
        let mut providers = HashMap::new();
        providers.insert(
            "local".to_string(),
            make_provider("openai", base, "API_KEY"),
        );
        let cfg = make_root_cfg(providers, HashMap::new(), HashMap::new());
        assert!(
            validate(&cfg).is_ok(),
            "local base_url '{base}' should validate with no flag, got: {:?}",
            validate(&cfg)
        );
    }
}

#[test]
fn test_scheme_rule_public_http_rejected_https_allowed() {
    // PUBLIC http:// is rejected (cleartext would leak the API key on the wire); public https://
    // is allowed; local http:// is allowed (no off-box wiretap, local models are plaintext).
    // public http → rejected with the https-for-public-host diagnostic.
    let mut providers = HashMap::new();
    providers.insert(
        "pub".to_string(),
        make_provider("openai", "http://api.example.com", "API_KEY"),
    );
    let cfg = make_root_cfg(providers, HashMap::new(), HashMap::new());
    let errs = validate(&cfg).expect_err("public http base_url must be rejected");
    assert!(
        errs.iter()
            .any(|e| e.contains("must use https for a public host")),
        "expected the public-host https diagnostic; got: {errs:?}"
    );

    // public https → allowed; local http → allowed.
    for ok in ["https://api.example.com", "http://10.0.0.5:8000"] {
        let mut providers = HashMap::new();
        providers.insert("p".to_string(), make_provider("openai", ok, "API_KEY"));
        let cfg = make_root_cfg(providers, HashMap::new(), HashMap::new());
        assert!(
            validate(&cfg).is_ok(),
            "'{ok}' must validate (public https / local http); got: {:?}",
            validate(&cfg)
        );
    }
}

#[test]
fn test_metadata_blocked_by_default_every_form() {
    // SECURITY INVARIANT: every metadata form stays blocked by default (no flag). Covers the
    // canonical literals, the link-local /16 (IMDS, ECS), the non-link-local literals (Alibaba,
    // Azure), IMDSv6, the metadata hostnames, and the obfuscated encodings.
    for base in [
        "http://169.254.169.254/latest/meta-data/", // IMDSv4, plain http
        "https://169.254.169.254/",                 // IMDSv4, https
        "https://169.254.170.2/v2/credentials",     // AWS ECS task-credentials
        "https://100.100.100.200/",                 // Alibaba (CGNAT range)
        "https://168.63.129.16/",                   // Azure WireServer
        "http://[fd00:ec2::254]/latest/meta-data/", // EC2 IMDSv6
        "https://[fd00:ec2::254]/",
        // Metadata DNS names over https (a DNS name is not classed private/loopback, so an http
        // scheme rule would preempt the SSRF check; https reaches the metadata denylist directly).
        "https://metadata.google.internal/computeMetadata/v1/",
        "https://metadata.tencentyun.com/",
        "https://instance-data/latest/meta-data/",
        "http://[::ffff:169.254.169.254]/", // IMDS via IPv4-mapped IPv6
        "http://[::169.254.169.254]/",      // IMDS via IPv4-compatible IPv6
        "http://2852039166/",               // IMDS via decimal-int encoding
        "https://169%2E254%2E169%2E254/",   // IMDS via percent-encoded dots
        "https://169.254.169.254./",        // IMDS, trailing dot
    ] {
        // Direct guard call (no flag, no extra entries).
        assert!(
            ssrf_blocked_host(base, &[], false, &[]).is_some(),
            "metadata target '{base}' must be blocked by default"
        );
        // And full validate() pass.
        let mut providers = HashMap::new();
        providers.insert("p".to_string(), make_provider("openai", base, "API_KEY"));
        let cfg = make_root_cfg(providers, HashMap::new(), HashMap::new());
        let errs =
            validate(&cfg).expect_err(&format!("metadata base_url '{base}' must fail validation"));
        assert!(
            errs.iter()
                .any(|e| e.contains("blocked cloud-metadata host")),
            "expected a metadata-host error for '{base}'; got: {errs:?}"
        );
    }
}

#[test]
fn test_per_provider_allow_metadata_hosts_is_surgical_and_scoped() {
    // Per-provider `allow_metadata_hosts: ["169.254.169.254"]` unblocks ONLY that host for ONLY
    // that provider: a DIFFERENT metadata IP stays blocked, and another provider still blocks the
    // same IP. (https so the scheme rule passes — the override governs the SSRF denylist only.)
    let allow = vec!["169.254.169.254".to_string()];

    // Direct guard: the listed host is unblocked; a different metadata IP is still blocked.
    assert!(
        ssrf_blocked_host("https://169.254.169.254/", &allow, false, &[]).is_none(),
        "the listed host must be unblocked by the override"
    );
    assert!(
        ssrf_blocked_host("https://100.100.100.200/", &allow, false, &[]).is_some(),
        "a DIFFERENT metadata IP must stay blocked"
    );
    assert!(
        ssrf_blocked_host("https://169.254.170.2/", &allow, false, &[]).is_some(),
        "another link-local metadata IP must stay blocked (override is exact, not the /16)"
    );

    // Full validate(): provider `surgical` allows IMDS; provider `other` (no override) targeting a
    // different metadata IP must still fail.
    let mut providers = HashMap::new();
    providers.insert(
        "surgical".to_string(),
        make_provider_allow_hosts("https://169.254.169.254/", &["169.254.169.254"]),
    );
    let cfg = make_root_cfg(providers, HashMap::new(), HashMap::new());
    assert!(
        validate(&cfg).is_ok(),
        "the provider's own allow_metadata_hosts must let its IMDS base_url validate; got: {:?}",
        validate(&cfg)
    );

    // Another provider WITHOUT the override still blocks the same IP (scope is per-provider).
    let mut providers = HashMap::new();
    providers.insert(
        "other".to_string(),
        make_provider("openai", "https://169.254.169.254/", "API_KEY"),
    );
    let cfg = make_root_cfg(providers, HashMap::new(), HashMap::new());
    validate(&cfg).expect_err("a provider without the override must still block IMDS");
}

#[test]
fn test_global_allow_metadata_hosts_unblocks_all_providers() {
    // security.allow_metadata_hosts unblocks the listed host for EVERY provider.
    let mut providers = HashMap::new();
    providers.insert(
        "a".to_string(),
        make_provider("openai", "https://100.100.100.200/", "API_KEY"),
    );
    providers.insert(
        "b".to_string(),
        make_provider("openai", "https://100.100.100.200/", "API_KEY"),
    );
    let mut cfg = make_root_cfg(providers, HashMap::new(), HashMap::new());
    cfg.allow_metadata_hosts = vec!["100.100.100.200".to_string()];
    assert!(
        validate(&cfg).is_ok(),
        "security.allow_metadata_hosts must unblock the host for ALL providers; got: {:?}",
        validate(&cfg)
    );

    // A metadata host NOT in the global allow-list is still blocked.
    let mut providers = HashMap::new();
    providers.insert(
        "c".to_string(),
        make_provider("openai", "https://169.254.169.254/", "API_KEY"),
    );
    let mut cfg = make_root_cfg(providers, HashMap::new(), HashMap::new());
    cfg.allow_metadata_hosts = vec!["100.100.100.200".to_string()];
    validate(&cfg).expect_err("a host not in the global allow-list must stay blocked");
}

#[test]
fn test_allow_all_metadata_disables_guard_entirely() {
    // security.allow_all_metadata: true disables the metadata guard for everything.
    for base in [
        "https://169.254.169.254/",
        "https://metadata.google.internal/",
        "https://100.100.100.200/",
        "https://168.63.129.16/",
        "https://[fd00:ec2::254]/",
    ] {
        // Direct guard: allow_all=true ⇒ never blocked.
        assert!(
            ssrf_blocked_host(base, &[], true, &[]).is_none(),
            "allow_all_metadata must unblock '{base}'"
        );
        let mut providers = HashMap::new();
        providers.insert("meta".to_string(), make_provider("openai", base, "API_KEY"));
        let mut cfg = make_root_cfg(providers, HashMap::new(), HashMap::new());
        cfg.allow_all_metadata = true;
        assert!(
            validate(&cfg).is_ok(),
            "allow_all_metadata must let '{base}' validate; got: {:?}",
            validate(&cfg)
        );
    }
}

#[test]
fn test_allow_override_matches_obfuscated_spellings() {
    // An allow entry written as the canonical IP also unblocks that IP's obfuscated spellings
    // (mirroring how a block entry blocks all spellings). Allow `169.254.169.254` and confirm its
    // decimal-int, IPv4-mapped-IPv6, and trailing-dot forms are all permitted too.
    let allow = vec!["169.254.169.254".to_string()];
    for base in [
        "https://169.254.169.254/",         // canonical
        "http://2852039166/",               // decimal-int
        "http://[::ffff:169.254.169.254]/", // IPv4-mapped IPv6
        "https://169.254.169.254./",        // trailing dot
    ] {
        assert!(
            ssrf_blocked_host(base, &allow, false, &[]).is_none(),
            "an allow entry must unblock the obfuscated spelling '{base}'"
        );
    }
    // A DIFFERENT metadata IP's obfuscated form is still blocked.
    assert!(
        ssrf_blocked_host("https://168.63.129.16/", &allow, false, &[]).is_some(),
        "a non-allowed metadata IP must stay blocked"
    );
}

#[test]
fn test_blocked_metadata_hosts_extends_denylist() {
    // security.blocked_metadata_hosts appends to the hardcoded denylist. An RFC-1918 address that
    // is normally ALLOWED becomes blocked once listed; a DNS hostname likewise; and an obfuscated
    // spelling of a listed IP is caught too. An UN-listed RFC-1918 host stays allowed.
    // IP entry blocks the literal AND its mapped-IPv6 form.
    for base in [
        "https://10.99.99.99/",
        "https://[::ffff:10.99.99.99]/", // mapped form of the listed IP
    ] {
        assert!(
            ssrf_blocked_host(base, &[], false, &["10.99.99.99".to_string()]).is_some(),
            "'{base}' must be blocked once 10.99.99.99 is in blocked_metadata_hosts"
        );
    }
    // A different RFC-1918 host (not listed) stays allowed.
    assert!(
        ssrf_blocked_host(
            "https://10.0.0.1/",
            &[],
            false,
            &["10.99.99.99".to_string()]
        )
        .is_none(),
        "an un-listed private host must stay allowed"
    );
    // Hostname entry (case-insensitive).
    assert!(
        ssrf_blocked_host(
            "https://metadata.mycloud.example/",
            &[],
            false,
            &["metadata.mycloud.example".to_string()]
        )
        .is_some(),
        "a listed metadata hostname must be blocked"
    );

    // Full validate() pass: the provider base_url is RFC-1918 (normally allowed) but listed.
    let mut providers = HashMap::new();
    providers.insert(
        "p".to_string(),
        make_provider("openai", "https://10.99.99.99/", "API_KEY"),
    );
    let cfg = make_root_cfg_with_blocked(providers, vec!["10.99.99.99".to_string()]);
    let errs = validate(&cfg)
        .expect_err("a base_url listed in blocked_metadata_hosts must fail validation");
    assert!(
        errs.iter()
            .any(|e| e.contains("blocked cloud-metadata host") && e.contains("10.99.99.99")),
        "expected a metadata-host error for the listed host; got: {errs:?}"
    );

    // An allow-override beats even an operator-listed blocked host (allow always wins).
    let mut providers = HashMap::new();
    providers.insert(
        "p".to_string(),
        make_provider_allow_hosts("https://10.99.99.99/", &["10.99.99.99"]),
    );
    let cfg = make_root_cfg_with_blocked(providers, vec!["10.99.99.99".to_string()]);
    assert!(
        validate(&cfg).is_ok(),
        "allow_metadata_hosts must override an operator-listed blocked host; got: {:?}",
        validate(&cfg)
    );
}

#[test]
fn test_public_targets_unaffected() {
    // A normal public https provider validates and the guard allows it regardless of the flag.
    for base in [
        "https://api.openai.com",
        "https://api.anthropic.com/v1/messages",
        "https://8.8.8.8/",
    ] {
        assert!(ssrf_blocked_host(base, &[], false, &[]).is_none());
        assert!(ssrf_blocked_host(base, &[], true, &[]).is_none());
        let mut providers = HashMap::new();
        providers.insert("p".to_string(), make_provider("openai", base, "API_KEY"));
        let cfg = make_root_cfg(providers, HashMap::new(), HashMap::new());
        assert!(
            validate(&cfg).is_ok(),
            "public https '{base}' must validate"
        );
    }
}

#[test]
fn test_path_override_composition_under_metadata_rules() {
    // A leading-slash path on a local http base_url validates (composed url re-checked, allowed).
    let mut ok = make_provider("openai", "http://localhost:11434", "API_KEY");
    ok.path = Some("/v1/chat/completions".to_string());
    let mut providers = HashMap::new();
    providers.insert("local".to_string(), ok);
    let cfg = make_root_cfg(providers, HashMap::new(), HashMap::new());
    assert!(
        validate(&cfg).is_ok(),
        "local http base_url + leading-slash path should validate, got: {:?}",
        validate(&cfg)
    );

    // A path that fuses into the authority to re-home at IMDS is rejected by the leading-slash
    // rule (and the composed url is a metadata target).
    let mut evil = make_provider("openai", "https://api.example.com", "API_KEY");
    evil.path = Some(".169.254.169.254/latest".to_string()); // no leading slash → host fusion
    let mut providers = HashMap::new();
    providers.insert("evil".to_string(), evil);
    let cfg = make_root_cfg(providers, HashMap::new(), HashMap::new());
    validate(&cfg).expect_err("authority-fusing path must be rejected");

    // A leading-slash path whose composition still lands on a metadata host (base already
    // metadata-ish via an allowed-by-scheme local host, path extends to nothing risky) — verify
    // the composed-url metadata recheck fires when base is a benign public host but allow_metadata
    // is off and a path cannot smuggle a host (leading slash) — so this should PASS.
    let mut p = make_provider("openai", "https://api.example.com/api/paas/v4", "API_KEY");
    p.path = Some("/chat/completions".to_string());
    let mut providers = HashMap::new();
    providers.insert("ok".to_string(), p);
    let cfg = make_root_cfg(providers, HashMap::new(), HashMap::new());
    assert!(
        validate(&cfg).is_ok(),
        "well-formed leading-slash path on a public host must validate"
    );
}
