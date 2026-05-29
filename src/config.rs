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
#[derive(Debug, Deserialize)]
pub(crate) struct HealthCfg {
    pub(crate) interval_secs: Option<u64>,
    pub(crate) timeout_secs: Option<u64>,
}

#[derive(Debug, Deserialize)]
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
#[derive(Debug, Deserialize)]
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
#[derive(Debug, Deserialize)]
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

#[allow(dead_code)] // v1 schema fields defined but not yet wired (B-4xx routing)
#[derive(Debug, Deserialize)]
pub(crate) struct BreakerCfg {
    #[serde(default = "default_cooldown")]
    pub(crate) base_cooldown_secs: u64,
    #[serde(default = "default_max_cooldown")]
    pub(crate) max_cooldown_secs: u64,
}

fn default_cooldown() -> u64 {
    10
}

fn default_max_cooldown() -> u64 {
    120
}

#[allow(dead_code)] // v1 schema fields defined but not yet wired (B-4xx routing)
#[derive(Debug, Deserialize)]
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
#[derive(Debug, Deserialize)]
pub(crate) struct OnExhaustedCfg {
    #[serde(default = "default_on_exhausted_action")]
    pub(crate) action: String,
}

fn default_on_exhausted_action() -> String {
    "reject".to_string()
}

#[allow(dead_code)] // v1 schema fields defined but not yet wired (B-4xx routing)
#[derive(Debug, Deserialize)]
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
}
