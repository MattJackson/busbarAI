// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Matthew Jackson

use std::collections::HashMap;

use serde::Deserialize;

// Re-export status_class_from_str for config validation
pub(crate) use crate::breaker::status_class_from_str;

/// Reject an env-var value that could break out of the surrounding YAML scalar when substituted
/// into the raw config text BEFORE parsing. `interpolate_env` splices each value in verbatim, so a
/// value carrying a YAML-structural control character — most critically a NEWLINE or carriage
/// return — can close the quoted scalar it sits inside and inject sibling YAML nodes (e.g. an extra
/// `client_tokens` entry, or a rewritten `admin_token`). Since both `client_tokens` and
/// `admin_token` are interpolated from env vars inside double-quoted scalars in the shipped
/// `config.yaml`, whoever controls those env vars (a CI pipeline, secret store, orchestrator) could
/// otherwise silently widen the auth allowlist without editing the config file.
///
/// No legitimate secret, token, URL, or path value contains a raw control character, so blocking
/// the entire C0 control range (plus DEL and the C1 NEL/LS/PS line-breaks YAML also treats as line
/// boundaries) closes the structural-injection vector with effectively zero false positives. A
/// double-quote or `#` on its own is harmless without a line break to terminate the current scalar,
/// and YAML's own quoting handles them, so we do not over-reject those.
fn reject_yaml_unsafe_value(var_name: &str, value: &str) -> Result<(), String> {
    if let Some(bad) = value.chars().find(|c| {
        // C0 controls (incl. \n, \r, \t, NUL) and DEL, plus the Unicode line/paragraph separators
        // and NEL that YAML treats as line breaks (U+0085 NEL, U+2028 LS, U+2029 PS).
        c.is_control() || matches!(c, '\u{2028}' | '\u{2029}')
    }) {
        return Err(format!(
            "environment variable '{var_name}' contains a control character (U+{:04X}) that could \
             inject YAML structure during config interpolation; remove it",
            bad as u32
        ));
    }
    Ok(())
}

/// Expand ${VAR} tokens from environment. Unset var → error (fail loud). A substituted value that
/// carries a YAML-structural control character is rejected (see `reject_yaml_unsafe_value`) so an
/// env var cannot break out of the quoted scalar it lands in and inject extra YAML nodes.
pub(crate) fn interpolate_env(s: &str) -> Result<String, String> {
    let mut result = String::with_capacity(s.len());
    let mut chars = s.chars().peekable();

    while let Some(ch) = chars.next() {
        if ch == '$' && chars.peek() == Some(&'{') {
            chars.next(); // consume '{'
            let mut var_name = String::new();
            let mut closed = false;
            for ch in chars.by_ref() {
                if ch == '}' {
                    closed = true;
                    break;
                }
                var_name.push(ch);
            }
            // The inner loop also exits when the iterator is exhausted, so a token with no closing
            // brace (e.g. `${FOO`) would otherwise be treated as `${FOO}` — silently succeeding if
            // FOO happens to be set, or reporting a misleading "unset variable" if it is not. Reject
            // the malformed token loudly instead so config typos surface at boot.
            if !closed {
                return Err(format!(
                    "unclosed variable reference starting at '${{{var_name}'"
                ));
            }
            if var_name.is_empty() {
                return Err("empty variable name in ${}".into());
            }
            let value = std::env::var(&var_name)
                .map_err(|_| format!("unset environment variable: {}", var_name))?;
            // Reject a structurally-unsafe value BEFORE splicing it in, so it cannot break out of
            // the surrounding YAML scalar and inject sibling nodes (e.g. extra client_tokens).
            reject_yaml_unsafe_value(&var_name, &value)?;
            result.push_str(&value);
        } else {
            result.push(ch);
        }
    }

    Ok(result)
}

/// The fully-resolved runtime config. NOT deserialized from YAML: the on-disk shape is `DeployCfg`
/// (+ provider definitions), and `RootCfg` is constructed exclusively by [`resolve`]. It therefore
/// carries no `Deserialize` derive and no field-level serde defaults — those would be inert, and
/// implying a YAML parse path here would mislead a reader into reasoning about defaults that never
/// fire.
#[derive(Debug)]
pub(crate) struct RootCfg {
    pub(crate) listen: String,
    pub(crate) auth: Option<AuthCfg>,
    pub(crate) providers: HashMap<String, ProviderCfg>,
    pub(crate) models: HashMap<String, ModelCfg>,
    pub(crate) pools: HashMap<String, PoolCfg>,
}

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
            mode: crate::auth::AuthMode::NONE.to_string(),
            _legacy_token: None,
            client_tokens: vec![],
        }
    }
}

fn default_auth_mode() -> String {
    crate::auth::AuthMode::NONE.to_string()
}

#[derive(Debug, Deserialize)]
pub(crate) struct ProviderCfg {
    #[serde(default = "default_protocol")]
    pub(crate) protocol: String,
    pub(crate) base_url: String,
    pub(crate) api_key_env: String,
    /// Active health-probe settings for this provider's lanes (mode + interval + timeout).
    #[serde(default)]
    pub(crate) health: Option<HealthCfg>,
    // error_map is REQUIRED on every provider — NO default (fail loud if missing)
    pub(crate) error_map: HashMap<String, String>,
    /// Optional upstream request-path override (see ProviderDef::path).
    #[serde(default)]
    pub(crate) path: Option<String>,
    /// Optional auth-style override (see ProviderDef::auth).
    #[serde(default)]
    pub(crate) auth: Option<String>,
    // Future fields (parse and be inert):
    #[serde(default, rename = "api_key")]
    pub(crate) _legacy_api_key: Option<String>,
}

fn default_protocol() -> String {
    "anthropic".to_string()
}

/// Active health-probe mode for a provider's lanes.
#[derive(Debug, Deserialize, Clone, Copy, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub(crate) enum HealthMode {
    /// No active probing. Health is inferred purely from organic traffic (the breaker trips on
    /// real failures and recovers via the half-open probe). This is the default.
    #[default]
    None,
    /// Periodically re-probe ONLY lanes that are currently tripped (Open/HalfOpen), so a recovered
    /// upstream is picked back up promptly instead of waiting for organic traffic to probe it.
    Dead,
    /// Periodically probe EVERY lane, so a silently-dead upstream is tripped out before real
    /// traffic hits it. Sends a tiny billable request per interval — opt-in.
    Active,
}

#[derive(Debug, Deserialize, Clone)]
pub(crate) struct HealthCfg {
    /// Probing strategy (see `HealthMode`). Defaults to `none` — a `health:` block with only an
    /// interval does nothing until a mode is chosen.
    #[serde(default)]
    pub(crate) mode: HealthMode,
    /// Seconds between probes for this provider's lanes (default 30, floored at 1).
    #[serde(default)]
    pub(crate) interval_secs: Option<u64>,
    /// Per-probe request timeout in seconds (default 5, floored at 1).
    #[serde(default)]
    pub(crate) timeout_secs: Option<u64>,
}

#[derive(Debug, Deserialize, Clone)]
pub(crate) struct ModelCfg {
    #[serde(default = "neg1")]
    pub(crate) max_requests: i64,
    pub(crate) provider: String,
    pub(crate) max_concurrent: usize,
    /// Default max output tokens injected when a cross-protocol translation targets a backend that
    /// REQUIRES `max_tokens` (Anthropic Messages) and the source request omitted it (legal for
    /// OpenAI). Unset falls back to `crate::proto::DEFAULT_MAX_TOKENS`. Must be > 0 when set.
    #[serde(default)]
    pub(crate) default_max_tokens: Option<u32>,
}

fn neg1() -> i64 {
    -1
}

#[derive(Debug, Deserialize, Clone)]
pub(crate) struct PoolCfg {
    #[serde(default)]
    pub(crate) members: Vec<PoolMember>,
    /// Per-pool breaker settings (resolved into `store::BreakerCfg` at startup; drives trip
    /// thresholds and cooldown backoff for this pool's lanes).
    #[serde(default)]
    pub(crate) breaker: Option<BreakerCfg>,
    #[serde(default)]
    pub(crate) failover: Option<FailoverCfg>,
    #[serde(default)]
    pub(crate) on_exhausted: Option<OnExhaustedCfg>,
    #[serde(default)]
    pub(crate) affinity: Option<AffinityCfg>,
}

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
    // Matches `store::BreakerCfg::default()` (used when a pool omits the `breaker:` block), so the
    // base cooldown is a consistent 15s whether or not the block is present.
    15
}

fn default_max_cooldown() -> u64 {
    120
}

#[derive(Debug, Deserialize, Clone)]
pub(crate) struct FailoverCfg {
    #[serde(default = "default_failover_deadline")]
    pub(crate) deadline_secs: u64,
    /// Member model names excluded from this pool's candidate set — never selected (primary or
    /// failover). A per-pool blocklist for temporarily benching a member without editing `members`.
    #[serde(default)]
    pub(crate) exclusions: Option<Vec<String>>,
    #[serde(default = "default_cap")]
    pub(crate) cap: usize,
}

/// Default failover wall-clock budget (seconds) when a pool doesn't set `failover.deadline_secs`.
pub(crate) const DEFAULT_FAILOVER_DEADLINE_SECS: u64 = 120;
/// Default maximum failover hops per request when a pool doesn't set `failover.cap`.
pub(crate) const DEFAULT_FAILOVER_CAP: usize = 3;

fn default_failover_deadline() -> u64 {
    DEFAULT_FAILOVER_DEADLINE_SECS
}

fn default_cap() -> usize {
    DEFAULT_FAILOVER_CAP
}

#[derive(Debug, Deserialize, Clone)]
pub(crate) struct OnExhaustedCfg {
    #[serde(default = "default_on_exhausted_action")]
    pub(crate) action: String,
}

fn default_on_exhausted_action() -> String {
    "reject".to_string()
}

/// Pool exhaustion mode configuration.
/// Maps from config string `action` field to executable behavior when all members are tripped/excluded.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum OnExhausted {
    /// Status503: return 503 Service Unavailable with Retry-After header
    /// set to the soonest member's cooldown expiry.
    Status503,
    /// FallbackPool(name): route to a configured fallback pool by name.
    /// Guard against loops via depth cap (max 1) or visited pool tracking.
    FallbackPool(String),
    /// LeastBad: send to the member with soonest cooldown expiry even though Open.
    /// Log loudly that this is a degraded path.
    LeastBad,
}

impl OnExhausted {
    /// Parse an action string from config into an OnExhausted variant.
    /// Returns Err(String) for unknown actions - NO bare _ => allowed.
    pub(crate) fn parse(action: &str) -> Result<Self, String> {
        match action {
            "reject" | "503" | "status_503" => Ok(OnExhausted::Status503),
            "fallback_pool" => Err("fallback_pool requires a pool name argument".into()),
            "least_bad" | "least-bad" | "leastbad" => Ok(OnExhausted::LeastBad),
            // FallbackPool with name - parse as "fallback_pool:<pool_name>" format
            s if s.starts_with("fallback_pool:") => {
                let pool_name = &s["fallback_pool:".len()..];
                if pool_name.is_empty() {
                    Err("fallback_pool requires a non-empty pool name".into())
                } else {
                    Ok(OnExhausted::FallbackPool(pool_name.to_string()))
                }
            }
            // Explicit handling of common typos/variants for clarity
            "status503" => Ok(OnExhausted::Status503),
            "fallback" | "failover" => Err(format!(
                "'{}' is not a valid on_exhausted action; use 'fallback_pool:<pool_name>'",
                action
            )),
            // Unknown actions - explicit error, NO _ => catch-all
            unknown => Err(format!(
                "unknown on_exhausted action '{}': valid values are 'reject', '503', 'status_503', 'fallback_pool:<name>', or 'least_bad'",
                unknown
            )),
        }
    }
}

#[derive(Debug, Deserialize, Clone)]
pub(crate) struct AffinityCfg {
    /// Affinity mode. `session` (the default and only supported mode) pins a session to a lane
    /// using the header named by `header_name`.
    #[serde(default = "default_affinity_mode")]
    pub(crate) mode: String,
    /// Request header carrying the session id (defaults to `x-session-id` when unset).
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
    /// Optional override of the upstream request path appended to `base_url`. Defaults to the
    /// protocol's standard path. Use it for OpenAI-compatible providers that embed the API version
    /// in `base_url` and serve `/chat/completions` (no `/v1`), e.g. `base_url: .../api/paas/v4` +
    /// `path: /chat/completions`.
    #[serde(default)]
    pub(crate) path: Option<String>,
    /// Optional auth-style override. Defaults to the protocol's native auth (bearer for
    /// openai/anthropic/responses, `x-goog-api-key` for gemini, SigV4 for bedrock). Set to
    /// `api-key` for backends that authenticate with an `api-key: <key>` header instead of a
    /// bearer token — e.g. Azure OpenAI (which also carries `?api-version=` and the deployment in
    /// its `path`). Recognized values: `bearer` (default) | `api-key`.
    #[serde(default)]
    pub(crate) auth: Option<String>,
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
    /// Optional upstream request-path override (see ProviderDef::path).
    #[serde(default)]
    pub(crate) path: Option<String>,
    /// Optional auth-style override (see ProviderDef::auth).
    #[serde(default)]
    pub(crate) auth: Option<String>,
    /// Optional active health-probe settings (see ProviderDef::health). Overrides the catalog's
    /// `health` when set; this is the block the shipped `config.yaml` documents under a provider.
    #[serde(default)]
    pub(crate) health: Option<HealthCfg>,
    /// Legacy inline `api_key:` under a provider. Captured ONLY so an operator who sets it (the
    /// field name invites the mistake) gets a loud boot warning that inline keys are unsupported and
    /// `api_key_env` must be used — rather than the value being silently dropped by serde with no
    /// signal. busbar never reads a key from here; `resolve()` warns and discards it.
    #[serde(default, rename = "api_key")]
    pub(crate) _legacy_api_key: Option<String>,
}

/// Deployment configuration - operator-owned config.yaml structure.
#[derive(Debug, Deserialize)]
pub(crate) struct DeployCfg {
    #[serde(default = "default_listen")]
    pub(crate) listen: String,
    pub(crate) auth: Option<AuthCfg>,
    pub(crate) providers: HashMap<String, ProviderDeploy>,
    pub(crate) models: HashMap<String, ModelCfg>,
    /// Pools are optional: a deployment can route to models directly (`/<model>/v1/messages`)
    /// without defining any pool.
    #[serde(default)]
    pub(crate) pools: HashMap<String, PoolCfg>,
    /// Optional observability sinks (OTLP traces + request-log webhook). Metrics
    /// (`/metrics`) are always on and need no config.
    #[serde(default)]
    pub(crate) observability: Option<ObservabilityCfg>,
    /// optional governance (virtual keys, budgets, rate limits). Absent = disabled.
    #[serde(default)]
    pub(crate) governance: Option<GovernanceCfg>,
}

/// Governance config. When present + enabled, callers authenticate with virtual keys
/// (not the static auth token) and are subject to per-key allowed-pools / budgets / rate limits.
#[derive(Debug, Deserialize, Clone, Default)]
pub(crate) struct GovernanceCfg {
    #[serde(default)]
    pub(crate) enabled: bool,
    /// SQLite database path for the durable governance store. Defaults to `busbar-governance.db`.
    #[serde(default = "default_gov_db_path")]
    pub(crate) db_path: String,
    /// Flat cents charged per request for budget accounting. Defaults to 1.
    #[serde(default = "default_price_per_request_cents")]
    pub(crate) price_per_request_cents: i64,
    /// Cents charged per 1000 tokens (input + output), accrued from response usage. Defaults to 0.
    /// Total budget spend per request = price_per_request_cents + tokens/1000 * price_per_1k_tokens_cents.
    #[serde(default)]
    pub(crate) price_per_1k_tokens_cents: i64,
    /// bearer token guarding the /admin management API. None = admin API disabled.
    #[serde(default)]
    pub(crate) admin_token: Option<String>,
}

fn default_gov_db_path() -> String {
    "busbar-governance.db".to_string()
}

fn default_price_per_request_cents() -> i64 {
    1
}

/// Observability sinks. All fields optional; absent = that sink is disabled.
#[derive(Debug, Deserialize, Clone, Default)]
pub(crate) struct ObservabilityCfg {
    /// OTLP/HTTP traces endpoint (e.g. `http://localhost:4318/v1/traces`). When set, busbar
    /// installs an OpenTelemetry tracer + exports spans.
    #[serde(default)]
    pub(crate) otlp_endpoint: Option<String>,
    /// When set, busbar fires a best-effort (fire-and-forget) JSON request-log POST per request
    /// to this URL.
    #[serde(default)]
    pub(crate) request_log_webhook_url: Option<String>,
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

        // A legacy inline `api_key:` under a provider is NOT supported — keys come only from
        // `api_key_env`. Warn loudly and discard it (rather than letting serde drop it silently),
        // so an operator who set it learns why their key isn't taking effect.
        if deploy_cfg._legacy_api_key.is_some() {
            tracing::warn!(
                provider = %deploy_name,
                "inline `api_key:` under a provider is unsupported and ignored; set the key in the \
                 environment variable named by `api_key_env` instead"
            );
        }

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
                // Deployment health config wins over the catalog default (mirrors path/auth), so
                // the `health:` block documented in config.yaml actually takes effect.
                health: deploy_cfg.health.clone().or_else(|| def.health.clone()),
                error_map,
                // deployment override wins over the catalog default
                path: deploy_cfg.path.clone().or_else(|| def.path.clone()),
                auth: deploy_cfg.auth.clone().or_else(|| def.auth.clone()),
                _legacy_api_key: None,
            },
        );
    }

    // Governance is read from `DeployCfg` (it does not land on the resolved `RootCfg`, so
    // `config_validate::validate(&RootCfg)` cannot see it). Validate it here, on `resolve`'s
    // existing fail-loud error channel, so an enabled-but-admin-token-less governance block (which
    // silently locks the /admin API) is rejected at boot rather than discovered at runtime.
    if let Some(governance) = &deploy.governance {
        if let Err(gov_errors) =
            crate::config_validate::validate_governance(governance, deploy.auth.as_ref())
        {
            errors.extend(gov_errors);
        }
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
        let deploy: DeployCfg =
            serde_yaml::from_str(yaml).expect("config without pools must parse");
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
                auth: None,
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
                auth: None,
                // Deployment-side health (the block config.yaml documents under a provider).
                health: Some(HealthCfg {
                    mode: HealthMode::Dead,
                    interval_secs: Some(5),
                    timeout_secs: None,
                }),
                _legacy_api_key: None,
            },
        );
        let deploy = DeployCfg {
            listen: "0.0.0.0:8080".into(),
            auth: None,
            providers,
            models: HashMap::new(),
            pools: HashMap::new(),
            observability: None,
            governance: None,
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

    /// The shipped example config.yaml must parse and resolve cleanly against providers.yaml
    /// (every referenced provider/model exists; the example stays a working starting point).
    #[test]
    fn test_shipped_example_config_resolves() {
        // The example references these env-var placeholders (interpolation scans the whole file,
        // including the commented governance block).
        std::env::set_var("BUSBAR_CLIENT_TOKEN", "example-token");
        std::env::set_var("BUSBAR_ADMIN_TOKEN", "example-admin");
        let providers_raw =
            std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/providers.yaml"))
                .unwrap();
        let defs: HashMap<String, ProviderDef> =
            serde_yaml::from_str(&providers_raw).expect("parse providers.yaml");

        let config_raw =
            std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/config.yaml")).unwrap();
        let expanded = interpolate_env(&config_raw).expect("expand ${ENV} in example config.yaml");
        let deploy: DeployCfg = serde_yaml::from_str(&expanded).expect("parse example config.yaml");

        let cfg = resolve(&deploy, &defs).expect("example config.yaml must resolve");
        // Spot-check the progressively-complex pools all wired up.
        assert!(cfg.pools.contains_key("smart"));
        assert!(cfg.pools.contains_key("overflow"));
        assert!(cfg.models.contains_key("claude-sonnet"));

        // Env vars are process-global and tests run in parallel; clean up so this test cannot
        // leave BUSBAR_CLIENT_TOKEN/BUSBAR_ADMIN_TOKEN set for the rest of the run (which could
        // mask an "unset variable" assertion in another test).
        std::env::remove_var("BUSBAR_CLIENT_TOKEN");
        std::env::remove_var("BUSBAR_ADMIN_TOKEN");
    }

    /// The shipped providers.yaml catalog must parse, name only known protocols, and use HTTPS.
    #[test]
    fn test_shipped_providers_catalog_valid() {
        let path = concat!(env!("CARGO_MANIFEST_DIR"), "/providers.yaml");
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
                protocol: "anthropic".to_string(),
                base_url: "https://api.z.ai/api/anthropic".to_string(),
                error_map,
                health: None,
                path: None,
                auth: None,
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
                auth: None,
                health: None,
                _legacy_api_key: None,
            },
        );

        let deploy = DeployCfg {
            listen: "0.0.0.0:8080".into(),
            auth: None,
            providers,
            models: HashMap::new(),
            pools: HashMap::new(),
            observability: None,
            governance: None,
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
                protocol: "anthropic".to_string(),
                base_url: "https://api.example.com".to_string(),
                error_map: HashMap::new(),
                health: None,
                path: None,
                auth: None,
            },
        );
        let cfg = resolve(&deploy, &defs).expect("resolve");
        assert_eq!(
            cfg.providers["myprov"]._legacy_api_key, None,
            "inline api_key must never reach the resolved ProviderCfg"
        );
        assert_eq!(cfg.providers["myprov"].api_key_env, "MYPROV_KEY");
    }

    #[test]
    fn test_resolve_rejects_enabled_governance_without_admin_token() {
        // resolve() is the boot-time fail-loud channel for the governance block (which never lands
        // on RootCfg, so config_validate::validate cannot see it). An enabled governance block with
        // no admin_token silently locks the /admin API — resolve must reject it.
        let defs = HashMap::new();
        let deploy = DeployCfg {
            listen: "0.0.0.0:8080".into(),
            auth: None,
            providers: HashMap::new(),
            models: HashMap::new(),
            pools: HashMap::new(),
            observability: None,
            governance: Some(GovernanceCfg {
                enabled: true,
                db_path: "busbar-governance.db".to_string(),
                price_per_request_cents: 1,
                price_per_1k_tokens_cents: 0,
                admin_token: None,
            }),
        };
        let errs = resolve(&deploy, &defs)
            .expect_err("enabled governance without admin_token must fail resolution");
        assert!(
            errs.iter().any(|e| e.contains("governance.admin_token")),
            "expected an admin-token lockout error; got: {errs:?}"
        );
    }

    #[test]
    fn test_resolve_accepts_enabled_governance_with_admin_token() {
        let defs = HashMap::new();
        let deploy = DeployCfg {
            listen: "0.0.0.0:8080".into(),
            auth: None,
            providers: HashMap::new(),
            models: HashMap::new(),
            pools: HashMap::new(),
            observability: None,
            governance: Some(GovernanceCfg {
                enabled: true,
                db_path: "busbar-governance.db".to_string(),
                price_per_request_cents: 1,
                price_per_1k_tokens_cents: 0,
                admin_token: Some("operator-secret".to_string()),
            }),
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
                auth: None,
                health: None,
                _legacy_api_key: None,
            },
        );

        let deploy = DeployCfg {
            listen: "0.0.0.0:8080".into(),
            auth: None,
            providers,
            models: HashMap::new(),
            pools: HashMap::new(),
            observability: None,
            governance: None,
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
                path: None,
                auth: None,
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
                auth: None,
                health: None,
                _legacy_api_key: None,
            },
        );

        let deploy = DeployCfg {
            listen: "0.0.0.0:8080".into(),
            auth: None,
            providers,
            models: HashMap::new(),
            pools: HashMap::new(),
            observability: None,
            governance: None,
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
                path: None,
                auth: None,
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
                auth: None,
                health: None,
                _legacy_api_key: None,
            },
        );

        let deploy = DeployCfg {
            listen: "0.0.0.0:8080".into(),
            auth: None,
            providers,
            models: HashMap::new(),
            pools: HashMap::new(),
            observability: None,
            governance: None,
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
}
