// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Matthew Jackson

use std::collections::HashMap;

use serde::Deserialize;

// Re-export status_class_from_str for config validation
pub(crate) use crate::breaker::status_class_from_str;

/// Expand ${VAR} tokens from environment. Unset var → error (fail loud).
pub(crate) fn interpolate_env(s: &str) -> Result<String, String> {
    let mut result = String::with_capacity(s.len());
    let mut chars = s.chars().peekable();

    while let Some(ch) = chars.next() {
        if ch == '$' && chars.peek() == Some(&'{') {
            chars.next(); // consume '{'
            let mut var_name = String::new();
            for ch in chars.by_ref() {
                if ch == '}' {
                    break;
                }
                var_name.push(ch);
            }
            if var_name.is_empty() {
                return Err("empty variable name in ${}".into());
            }
            let value = std::env::var(&var_name)
                .map_err(|_| format!("unset environment variable: {}", var_name))?;
            result.push_str(&value);
        } else {
            result.push(ch);
        }
    }

    Ok(result)
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)] // fields parsed but not wired (B-4xx routing)
pub(crate) struct RootCfg {
    #[serde(default = "default_listen")]
    pub(crate) listen: String,
    pub(crate) auth: Option<AuthCfg>,
    pub(crate) providers: HashMap<String, ProviderCfg>,
    pub(crate) models: HashMap<String, ModelCfg>,
    pub(crate) pools: HashMap<String, PoolCfg>,
}

#[allow(dead_code)] // v1 schema fields defined but not yet wired (B-4xx routing)
#[derive(Debug, Deserialize, Clone)]
pub(crate) struct AuthCfg {
    #[serde(default = "default_auth_mode")]
    pub(crate) mode: String,
    #[deprecated(since = "0.1.0", note = "use client_tokens allowlist instead")]
    #[serde(rename = "token", default)]
    pub(crate) _legacy_token: Option<String>,
    #[serde(default)]
    pub(crate) client_tokens: Vec<String>,
}

impl AuthCfg {
    /// Normalize legacy single-token format into allowlist.
    #[allow(deprecated)] // accessing deprecated field for normalization logic
    pub(crate) fn normalize(mut self) -> Self {
        if let Some(tok) = self._legacy_token.take() {
            // If client_tokens is empty and we have legacy token, promote it
            if self.client_tokens.is_empty() {
                self.client_tokens.push(tok);
            }
        }
        self
    }

    /// Create a default AuthCfg for initialization.
    #[allow(deprecated)] // accessing deprecated field in constructor
    pub(crate) fn default_none() -> Self {
        Self {
            mode: "none".to_string(),
            _legacy_token: None,
            client_tokens: vec![],
        }
    }
}

fn default_auth_mode() -> String {
    "none".to_string()
}

#[allow(dead_code)] // v1 schema fields defined but not yet wired (B-4xx routing)
#[derive(Debug, Deserialize)]
pub(crate) struct ProviderCfg {
    #[serde(default = "default_protocol")]
    pub(crate) protocol: String,
    pub(crate) base_url: String,
    pub(crate) api_key_env: String,
    #[serde(default)]
    pub(crate) health: Option<HealthCfg>,
    // error_map is REQUIRED on every provider — NO default (fail loud if missing)
    pub(crate) error_map: HashMap<String, String>,
    // Future fields (parse and be inert):
    #[serde(default, rename = "api_key")]
    pub(crate) _legacy_api_key: Option<String>,
}

fn default_protocol() -> String {
    "anthropic".to_string()
}

#[allow(dead_code)] // v1 schema fields defined but not yet wired (B-4xx routing)
#[derive(Debug, Deserialize, Clone)]
pub(crate) struct HealthCfg {
    pub(crate) interval_secs: Option<u64>,
    pub(crate) timeout_secs: Option<u64>,
}

#[derive(Debug, Deserialize, Clone)]
pub(crate) struct ModelCfg {
    #[serde(default = "neg1")]
    pub(crate) max_requests: i64,
    pub(crate) provider: String,
    pub(crate) max_concurrent: usize,
}

fn neg1() -> i64 {
    -1
}

#[allow(dead_code)] // v1 schema fields defined but not yet wired (B-4xx routing)
#[derive(Debug, Deserialize, Clone)]
pub(crate) struct PoolCfg {
    #[serde(default)]
    pub(crate) members: Vec<PoolMember>,
    #[serde(default)]
    pub(crate) breaker: Option<BreakerCfg>,
    #[serde(default)]
    pub(crate) failover: Option<FailoverCfg>,
    #[serde(default)]
    pub(crate) on_exhausted: Option<OnExhaustedCfg>,
    #[serde(default)]
    pub(crate) affinity: Option<AffinityCfg>,
}

#[allow(dead_code)] // v1 schema fields defined but not yet wired (B-4xx routing)
#[derive(Debug, Deserialize, Clone)]
pub(crate) struct PoolMember {
    pub(crate) target: String,
    #[serde(default = "default_weight")]
    pub(crate) weight: u32,
    #[serde(default)]
    pub(crate) context_max: Option<usize>,
}

fn default_weight() -> u32 {
    1
}

/// Trip mode for breaker configuration.
#[derive(Debug, Deserialize, Clone, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub(crate) enum BreakerTripMode {
    #[default]
    ErrorRate,
    Consecutive,
}

/// Trip configuration parameters (ADR-0002 defaults).
#[derive(Debug, Deserialize, Clone, Default)]
#[allow(dead_code)] // Fields defined for config, used by FSM logic
pub(crate) struct BreakerTripConfig {
    #[serde(default = "default_trip_mode")]
    pub mode: BreakerTripMode,
    #[serde(default = "default_window_s")]
    pub window_s: u64,
    #[serde(default = "default_threshold")]
    pub threshold: f64,
    #[serde(default = "default_min_requests")]
    pub min_requests: usize,
    #[serde(default = "default_consecutive_n")]
    pub n: u32,
}

fn default_trip_mode() -> BreakerTripMode {
    BreakerTripMode::ErrorRate
}

fn default_window_s() -> u64 {
    30
}

fn default_threshold() -> f64 {
    0.5
}

fn default_min_requests() -> usize {
    5
}

fn default_consecutive_n() -> u32 {
    3
}

/// Breaker configuration per pool with full trip settings (ADR-0002).
#[derive(Debug, Deserialize, Clone)]
#[allow(dead_code)] // Fields defined for config, used by FSM logic
pub(crate) struct BreakerCfg {
    #[serde(default = "default_cooldown")]
    pub base_cooldown_secs: u64,
    #[serde(default = "default_max_cooldown")]
    pub max_cooldown_secs: u64,
    #[serde(default)]
    pub trip: Option<BreakerTripConfig>,
}

impl Default for BreakerCfg {
    fn default() -> Self {
        Self {
            base_cooldown_secs: 15,
            max_cooldown_secs: 120,
            trip: Some(BreakerTripConfig::default()),
        }
    }
}

fn default_cooldown() -> u64 {
    10
}

fn default_max_cooldown() -> u64 {
    120
}

#[allow(dead_code)] // v1 schema fields defined but not yet wired (B-4xx routing)
#[derive(Debug, Deserialize, Clone)]
pub(crate) struct FailoverCfg {
    #[serde(default = "default_failover_deadline")]
    pub(crate) deadline_secs: u64,
    #[serde(default)]
    pub(crate) exclusions: Option<Vec<String>>,
    #[serde(default = "default_cap")]
    pub(crate) cap: usize,
}

fn default_failover_deadline() -> u64 {
    5
}

fn default_cap() -> usize {
    usize::MAX
}

#[allow(dead_code)] // v1 schema fields defined but not yet wired (B-4xx routing)
#[derive(Debug, Deserialize, Clone)]
pub(crate) struct OnExhaustedCfg {
    #[serde(default = "default_on_exhausted_action")]
    pub(crate) action: String,
}

fn default_on_exhausted_action() -> String {
    "reject".to_string()
}

#[allow(dead_code)] // v1 schema fields defined but not yet wired (B-4xx routing)
#[derive(Debug, Deserialize, Clone)]
pub(crate) struct AffinityCfg {
    #[serde(default = "default_affinity_mode")]
    pub(crate) mode: String,
    #[serde(default)]
    pub(crate) header_name: Option<String>,
}

fn default_affinity_mode() -> String {
    "session".to_string()
}

fn default_listen() -> String {
    "0.0.0.0:8080".into()
}

/// Provider definition - vetted knowledge shipped in providers.yaml (no keys).
#[derive(Debug, Deserialize, Clone)]
pub(crate) struct ProviderDef {
    pub(crate) protocol: String,
    pub(crate) base_url: String,
    #[serde(default)]
    pub(crate) error_map: HashMap<String, String>,
    #[serde(default)]
    pub(crate) health: Option<HealthCfg>,
}

/// Provider deployment - operator config in config.yaml (names provider + supplies key).
#[derive(Debug, Deserialize, Clone, Default)]
pub(crate) struct ProviderDeploy {
    pub(crate) api_key_env: String,
    #[serde(default)]
    pub(crate) protocol: Option<String>,
    #[serde(default)]
    pub(crate) base_url: Option<String>,
    #[serde(default)]
    pub(crate) error_map: Option<HashMap<String, String>>,
}

/// Deployment configuration - operator-owned config.yaml structure.
#[derive(Debug, Deserialize)]
pub(crate) struct DeployCfg {
    #[serde(default = "default_listen")]
    pub(crate) listen: String,
    pub(crate) auth: Option<AuthCfg>,
    pub(crate) providers: HashMap<String, ProviderDeploy>,
    pub(crate) models: HashMap<String, ModelCfg>,
    pub(crate) pools: HashMap<String, PoolCfg>,
}

/// Resolve DeployCfg + ProviderDef map into resolved RootCfg.
/// For each deployed provider, look up its definition by name; produce a resolved ProviderCfg
/// = def's protocol/base_url/error_map (with any config.yaml override applied) + the deployment's api_key_env.
pub(crate) fn resolve(
    deploy: &DeployCfg,
    defs: &HashMap<String, ProviderDef>,
) -> Result<RootCfg, Vec<String>> {
    let mut errors = Vec::new();
    let mut resolved_providers: HashMap<String, ProviderCfg> = HashMap::new();

    for (deploy_name, deploy_cfg) in &deploy.providers {
        // Look up the provider definition by name
        let def = match defs.get(deploy_name) {
            Some(d) => d,
            None => {
                errors.push(format!(
                    "provider '{}' referenced in config.yaml not found in providers.yaml",
                    deploy_name
                ));
                continue;
            }
        };

        // Apply overrides from deployment (rarely used)
        let protocol = deploy_cfg
            .protocol
            .clone()
            .unwrap_or_else(|| def.protocol.clone());
        let base_url = deploy_cfg
            .base_url
            .clone()
            .unwrap_or_else(|| def.base_url.clone());

        // Merge error_map: def's map with deployment override taking precedence
        let mut error_map = def.error_map.clone();
        if let Some(override_map) = &deploy_cfg.error_map {
            for (code, class) in override_map {
                error_map.insert(code.clone(), class.clone());
            }
        }

        resolved_providers.insert(
            deploy_name.clone(),
            ProviderCfg {
                protocol,
                base_url,
                api_key_env: deploy_cfg.api_key_env.clone(),
                health: def.health.clone(),
                error_map,
                _legacy_api_key: None,
            },
        );
    }

    if errors.is_empty() {
        Ok(RootCfg {
            listen: deploy.listen.clone(),
            auth: deploy.auth.clone().map(|a| a.normalize()),
            providers: resolved_providers,
            models: deploy.models.clone(),
            pools: deploy.pools.clone(),
        })
    } else {
        Err(errors)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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

    #[test]
    fn test_interpolate_env_no_vars() {
        let input = "plain-text-no-vars";
        let result = interpolate_env(input).unwrap();
        assert_eq!(result, "plain-text-no-vars");
    }

    // ADR-0008: Two-file resolution tests

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
                protocol: "anthropic".to_string(),
                base_url: "https://api.z.ai/api/anthropic".to_string(),
                error_map,
                health: None,
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
            },
        );

        let deploy = DeployCfg {
            listen: "0.0.0.0:8080".into(),
            auth: None,
            providers,
            models: HashMap::new(),
            pools: HashMap::new(),
        };

        let result = resolve(&deploy, &defs).expect("resolve should succeed");

        let provider_cfg = result
            .providers
            .get("z.ai")
            .expect("z.ai should be in resolved providers");
        assert_eq!(provider_cfg.protocol, "anthropic");
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
            },
        );

        let deploy = DeployCfg {
            listen: "0.0.0.0:8080".into(),
            auth: None,
            providers,
            models: HashMap::new(),
            pools: HashMap::new(),
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
                protocol: "anthropic".to_string(),
                base_url: "https://default.example.com".to_string(),
                error_map,
                health: None,
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
            },
        );

        let deploy = DeployCfg {
            listen: "0.0.0.0:8080".into(),
            auth: None,
            providers,
            models: HashMap::new(),
            pools: HashMap::new(),
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
                protocol: "anthropic".to_string(),
                base_url: "https://api.example.com".to_string(),
                error_map: HashMap::new(), // Empty but valid for resolution
                health: None,
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
            },
        );

        let deploy = DeployCfg {
            listen: "0.0.0.0:8080".into(),
            auth: None,
            providers,
            models: HashMap::new(),
            pools: HashMap::new(),
        };

        let result = resolve(&deploy, &defs).expect("resolve should succeed");
        let provider_cfg = result
            .providers
            .get("minimal")
            .expect("minimal should exist");
        assert!(provider_cfg.error_map.is_empty());
    }
}
