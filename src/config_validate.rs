// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Matthew Jackson

use std::collections::{HashMap, HashSet};

use crate::config::RootCfg;

/// Validate the loaded configuration and collect all errors at once.
/// Returns Ok(()) if valid; Err(Vec<String>) with all validation failures otherwise.
pub(crate) fn validate(cfg: &RootCfg) -> Result<(), Vec<String>> {
    let mut errors = Vec::new();

    // Collect provider names for pool-name conflict check and member resolution
    let provider_names: HashSet<&str> = cfg.providers.keys().map(|s| s.as_str()).collect();

    // Collect model names and their protocols for unknown-member and heterogeneity checks
    let mut model_protocols: HashMap<&str, &str> = HashMap::new();
    for (model_name, model_cfg) in &cfg.models {
        if let Some(provider_name) = cfg.providers.get(&model_cfg.provider) {
            model_protocols.insert(model_name.as_str(), provider_name.protocol.as_str());
        } else {
            errors.push(format!(
                "model '{}' references unknown provider '{}'",
                model_name, model_cfg.provider
            ));
        }
    }

    // Rule 1: Reject pool name == any provider name (disambiguation)
    for pool_name in cfg.pools.keys() {
        if provider_names.contains(pool_name.as_str()) {
            errors.push(format!(
                "pool name '{}' conflicts with provider name '{}'; pools and providers must have distinct names",
                pool_name, pool_name
            ));
        }
    }

    // Rule 4: Validate error_map values on every provider. An EMPTY error_map is valid — a provider
    // may have no provider-specific JSON error codes and rely on HTTP-status classification (the
    // circuit breaker), exactly like the shipped `anthropic` catalog entry. Only the entries that
    // ARE present must name a known StatusClass.
    for (provider_name, provider_cfg) in &cfg.providers {
        for (code, mapped_class) in &provider_cfg.error_map {
            if crate::config::status_class_from_str(mapped_class).is_none() {
                errors.push(format!(
                    "provider '{}' error_map code '{}': invalid StatusClass '{}', must be one of: rate_limit, overloaded, server_error, timeout, network, auth, billing, client_error",
                    provider_name, code, mapped_class
                ));
            }
        }

        // Validate the optional auth-style override (fail loud on typos).
        if let Some(auth) = &provider_cfg.auth {
            if !matches!(auth.as_str(), "bearer" | "api-key") {
                errors.push(format!(
                    "provider '{}' has invalid auth '{}': must be 'bearer' (default) or 'api-key'",
                    provider_name, auth
                ));
            }
        }
    }

    // Rule 2 & 3: Validate each pool's members
    for (pool_name, pool_cfg) in &cfg.pools {
        let mut member_protocols: HashSet<&str> = HashSet::new();

        for member in &pool_cfg.members {
            // Check if member references a known model
            if !model_protocols.contains_key(member.target.as_str()) {
                errors.push(format!(
                    "pool '{}' references unknown model '{}'",
                    pool_name, member.target
                ));
            } else {
                // Collect protocol for heterogeneity check (only for valid members)
                if let Some(&protocol) = model_protocols.get(member.target.as_str()) {
                    member_protocols.insert(protocol);
                }
            }
        }

        // Rule 3: Heterogeneous pool warning (WARN, not error)
        if member_protocols.len() > 1 {
            let mut protocols: Vec<&str> = member_protocols.iter().copied().collect();
            protocols.sort();
            tracing::warn!(
                pool = %pool_name,
                protocols = %protocols.join("+"),
                "heterogeneous pool: cross-protocol failover translates via the IR and may not preserve all provider features"
            );
        }
    }

    // Rule 5: Validate the auth mode (otherwise AuthMiddleware::new would panic at startup).
    if let Some(auth) = &cfg.auth {
        if crate::auth::AuthMode::from_config_str(&auth.mode).is_none() {
            errors.push(format!(
                "auth.mode '{}' is invalid: must be '{}', '{}', or '{}'",
                auth.mode,
                crate::auth::AuthMode::TOKEN,
                crate::auth::AuthMode::PASSTHROUGH,
                crate::auth::AuthMode::NONE
            ));
        }
    }

    if errors.is_empty() {
        Ok(())
    } else {
        Err(errors)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::config;

    fn make_root_cfg(
        providers: HashMap<String, config::ProviderCfg>,
        models: HashMap<String, config::ModelCfg>,
        pools: HashMap<String, config::PoolCfg>,
    ) -> RootCfg {
        config::RootCfg {
            listen: "0.0.0.0:8080".into(),
            auth: None,
            providers,
            models,
            pools,
        }
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
            auth: None,
            _legacy_api_key: None,
        }
    }

    fn make_model(provider: &str, max_concurrent: usize) -> config::ModelCfg {
        config::ModelCfg {
            max_requests: -1,
            provider: provider.into(),
            max_concurrent,
        }
    }

    fn make_pool(members: Vec<config::PoolMember>) -> config::PoolCfg {
        config::PoolCfg {
            members,
            breaker: None,
            failover: None,
            on_exhausted: None,
            affinity: None,
        }
    }

    fn make_member(target: &str) -> config::PoolMember {
        config::PoolMember {
            target: target.into(),
            weight: 1,
            context_max: None,
        }
    }

    #[test]
    fn test_validate_rejects_bad_auth_style() {
        let mut providers = HashMap::new();
        let mut p = make_provider("openai", "https://api.example.com", "API_KEY");
        p.auth = Some("oauth2".into()); // not a recognized auth style
        providers.insert("bad".to_string(), p);
        // A valid 'api-key' provider must NOT trigger an error.
        let mut ok = make_provider("openai", "https://res.openai.azure.com", "AZ_KEY");
        ok.auth = Some("api-key".into());
        providers.insert("good".to_string(), ok);

        let cfg = make_root_cfg(providers, HashMap::new(), HashMap::new());
        let errs = validate(&cfg).expect_err("bad auth must fail validation");
        assert!(
            errs.iter().any(|e| e.contains("invalid auth 'oauth2'")),
            "expected an invalid-auth error for 'oauth2'; got: {errs:?}"
        );
        assert!(
            !errs.iter().any(|e| e.contains("invalid auth 'api-key'")),
            "'api-key' is a valid auth style and must not error; got: {errs:?}"
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
                auth: None,
                _legacy_api_key: None,
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
                auth: None,
                _legacy_api_key: None,
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
                auth: None,
                _legacy_api_key: None,
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
                auth: None,
                _legacy_api_key: None,
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
                auth: None,
                _legacy_api_key: None,
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
                auth: None,
                _legacy_api_key: None,
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
}
