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
        // A configured default_max_tokens of 0 would be injected verbatim into a translated request
        // and rejected upstream — fail loud at startup rather than per-request.
        if model_cfg.default_max_tokens == Some(0) {
            errors.push(format!(
                "model '{}' has default_max_tokens: 0; must be > 0 (or omit it to use the {} fallback)",
                model_name,
                crate::proto::DEFAULT_MAX_TOKENS
            ));
        }
        // A `max_concurrent: 0` lane builds a `Semaphore::new(0)` at startup (main.rs), which never
        // grants a permit — every request to the lane is permanently capacity-exhausted with no
        // boot-time diagnostic. Reject it loudly here rather than silently black-holing the lane.
        if model_cfg.max_concurrent == 0 {
            errors.push(format!(
                "model '{}' has max_concurrent: 0; must be >= 1",
                model_name
            ));
        }
    }

    // All model names, used for the pool/model collision check below (the `named` route resolves
    // pools before models, so a pool sharing a model's name would permanently shadow that model).
    let model_names: HashSet<&str> = cfg.models.keys().map(|s| s.as_str()).collect();

    // Rule 1: Reject a pool name that collides with any provider name OR any model name. Pools,
    // providers, and models must all have distinct names: a pool named like a provider is
    // ambiguous, and a pool named like a model silently shadows that model on the `named` route.
    for pool_name in cfg.pools.keys() {
        if provider_names.contains(pool_name.as_str()) {
            errors.push(format!(
                "pool name '{}' conflicts with provider name '{}'; pools and providers must have distinct names",
                pool_name, pool_name
            ));
        }
        if model_names.contains(pool_name.as_str()) {
            errors.push(format!(
                "pool name '{}' conflicts with model name '{}'; pools and models must have distinct names",
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

        // The resolved base_url is the actual upstream target for signed (API-key-bearing) calls.
        // It is operator-controllable via a config.yaml override, so enforce `https://` at startup:
        // a plaintext `http://` upstream leaks the API key on the wire, and an `http://169.254.169.254/`
        // / `file://` / internal override is an SSRF target. Mirror the shipped-catalog test assertion
        // as a hard validation rule rather than a test-only check.
        if !provider_cfg.base_url.starts_with("https://") {
            errors.push(format!(
                "provider '{}' base_url must use https (got '{}')",
                provider_name, provider_cfg.base_url
            ));
        } else if let Some(host) = ssrf_blocked_host(&provider_cfg.base_url) {
            // The `https://` prefix alone does not stop SSRF: `https://169.254.169.254/`,
            // `https://[::1]/`, `https://10.0.0.1/`, `https://metadata.google.internal/` etc. all
            // pass the scheme check yet point busbar's signed (API-key-bearing) traffic at the cloud
            // metadata service or an internal host. Reject internal/loopback/link-local/private
            // targets and known metadata hostnames at startup (fail-loud).
            errors.push(format!(
                "provider '{}' base_url '{}' targets a blocked internal/metadata host '{}' (loopback, link-local, RFC-1918 private, or cloud metadata endpoints are not permitted)",
                provider_name, provider_cfg.base_url, host
            ));
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

        // Rule 6: Validate the per-pool breaker trip parameters. Pathological-but-parseable values
        // produce a breaker that either never protects the backend or trips it open on the first
        // hiccup, defeating the failure-handling guarantee. Reject them at startup (fail-loud).
        if let Some(breaker) = &pool_cfg.breaker {
            // The escalating cooldown clamps at max_cooldown_secs, so a max below the base would
            // pin every cooldown below the configured base — reject the inversion.
            if breaker.max_cooldown_secs < breaker.base_cooldown_secs {
                errors.push(format!(
                    "pool '{}' breaker max_cooldown_secs ({}) must be >= base_cooldown_secs ({})",
                    pool_name, breaker.max_cooldown_secs, breaker.base_cooldown_secs
                ));
            }
            if let Some(trip) = &breaker.trip {
                // min_requests is the floor below which error-rate trips are suppressed; 0 makes the
                // floor vacuous so a single error in an otherwise-empty window can trip.
                if trip.min_requests == 0 {
                    errors.push(format!(
                        "pool '{}' breaker trip.min_requests must be >= 1 (got 0)",
                        pool_name
                    ));
                }
                // window_s is the sliding-window length; a 0 window holds no outcomes so the
                // count is always below min_requests and the error-rate breaker never trips.
                if trip.window_s == 0 {
                    errors.push(format!(
                        "pool '{}' breaker trip.window_s must be >= 1 (got 0)",
                        pool_name
                    ));
                }
                match trip.mode {
                    crate::config::BreakerTripMode::ErrorRate => {
                        // threshold is an error-rate fraction; the rate is capped at 1.0, so a
                        // threshold > 1.0 can never trip and <= 0.0 trips on the first error.
                        if !(trip.threshold > 0.0 && trip.threshold <= 1.0) {
                            errors.push(format!(
                                "pool '{}' breaker trip.threshold must be in (0.0, 1.0] for error_rate mode (got {})",
                                pool_name, trip.threshold
                            ));
                        }
                    }
                    crate::config::BreakerTripMode::Consecutive => {
                        // n is the consecutive-failure streak length; n == 0 makes `streak >= 0`
                        // always true so the lane trips on every evaluation.
                        if trip.n == 0 {
                            errors.push(format!(
                                "pool '{}' breaker trip.n must be >= 1 for consecutive mode (got 0)",
                                pool_name
                            ));
                        }
                    }
                }
            }
        }

        // Rule 7: A well-formed `on_exhausted: fallback_pool:<name>` whose `<name>` is not a
        // configured pool parses fine but silently misses at runtime (forward.rs's
        // `fallback_pools.get(name)` returns None) and cascades to a generic 503 — the configured
        // degraded-routing policy never engages, with no boot diagnostic. Mirror the member-target
        // resolution check and fail loud. (A malformed action string already `die`s in main.rs at
        // parse time; here we only catch the well-formed-but-dangling case.)
        if let Some(on_exhausted) = &pool_cfg.on_exhausted {
            if let Ok(crate::config::OnExhausted::FallbackPool(target)) =
                crate::config::OnExhausted::parse(&on_exhausted.action)
            {
                if !cfg.pools.contains_key(&target) {
                    errors.push(format!(
                        "pool '{}' on_exhausted references unknown fallback pool '{}'",
                        pool_name, target
                    ));
                }
            }
        }

        // Rule 8: `affinity.mode` is a free-form String defaulting to "session", and "session" is
        // the only supported mode (route.rs's `affinity_header_for` falls back to the default
        // header for anything else). An unrecognized mode (e.g. "sticky") is silently accepted and
        // degrades to default behavior with no diagnostic — reject it to uphold the fail-loud
        // invariant the rest of validate() enforces.
        if let Some(affinity) = &pool_cfg.affinity {
            if affinity.mode != "session" {
                errors.push(format!(
                    "pool '{}' affinity.mode '{}' is invalid: the only supported mode is 'session'",
                    pool_name, affinity.mode
                ));
            }
        }
    }

    // Rule 5: Validate the auth mode (otherwise AuthMiddleware::new would panic at startup).
    if let Some(auth) = &cfg.auth {
        match crate::auth::AuthMode::from_config_str(&auth.mode) {
            None => {
                errors.push(format!(
                    "auth.mode '{}' is invalid: must be '{}', '{}', or '{}'",
                    auth.mode,
                    crate::auth::AuthMode::TOKEN,
                    crate::auth::AuthMode::PASSTHROUGH,
                    crate::auth::AuthMode::NONE
                ));
            }
            Some(crate::auth::AuthMode::Token) => {
                // Token mode with no client tokens rejects 100% of requests with no startup signal —
                // the locked-out mirror of the loudly-warned open-relay (mode: none) case. `normalize()`
                // promotes a single legacy `token:` into the allowlist, so account for it here too.
                if effective_client_tokens_empty(auth) {
                    errors.push(
                        "auth.mode is 'token' but no client_tokens are configured; token mode requires at least one client token (otherwise every request is rejected)".to_string(),
                    );
                }
            }
            // Passthrough/None carry no token-allowlist requirement.
            Some(crate::auth::AuthMode::Passthrough) | Some(crate::auth::AuthMode::None) => {}
        }
    }

    if errors.is_empty() {
        Ok(())
    } else {
        Err(errors)
    }
}

/// True when an `AuthCfg` would resolve to an empty client-token allowlist after `normalize()`.
/// `normalize()` promotes a single legacy `token:` into the allowlist only when `client_tokens`
/// is empty, so the effective set is empty iff `client_tokens` is empty AND no legacy token is set.
#[allow(deprecated)] // intentionally reading the deprecated legacy-token field to mirror normalize()
fn effective_client_tokens_empty(auth: &crate::config::AuthCfg) -> bool {
    auth.client_tokens.is_empty() && auth._legacy_token.is_none()
}

/// Return `Some(host)` if the given `https://` URL points at an SSRF-sensitive target (loopback,
/// link-local, RFC-1918 private, unique-local IPv6, or a known cloud metadata hostname), else
/// `None`. The host is extracted by string slicing (no URL crate): strip the scheme, take up to the
/// first `/`, `?`, or `#`, drop any `user@` prefix, then separate an IPv6 `[...]` literal or an
/// `host:port` from its port. IP literals are parsed with `IpAddr` and checked against the blocked
/// ranges; non-IP hostnames are matched case-insensitively against the metadata hostname list.
fn ssrf_blocked_host(url: &str) -> Option<String> {
    use std::net::{IpAddr, Ipv4Addr};

    // Strip "https://" (caller guarantees this prefix).
    let rest = url.strip_prefix("https://")?;
    // Authority is everything before the first path/query/fragment delimiter.
    let authority = rest.split(['/', '?', '#']).next().unwrap_or(rest);
    // Drop any "userinfo@" prefix.
    let host_port = authority.rsplit('@').next().unwrap_or(authority);

    // Separate host from port, handling bracketed IPv6 literals (`[::1]:443`).
    let host: &str = if let Some(after_bracket) = host_port.strip_prefix('[') {
        // `[<ipv6>]` optionally followed by `:port`.
        match after_bracket.split_once(']') {
            Some((inner, _)) => inner,
            None => after_bracket, // malformed; treat the remainder as the host
        }
    } else {
        // `host` or `host:port` — split on the last colon only when the left side has no colon
        // (a bare IPv6 without brackets would contain multiple colons; rsplit_once on a single
        // `:` host:port is the common case).
        match host_port.rsplit_once(':') {
            // If the left part still contains a colon it's a bare IPv6 literal; keep the whole.
            Some((left, _)) if !left.contains(':') => left,
            _ => host_port,
        }
    };

    if host.is_empty() {
        return None;
    }

    // Known cloud metadata / internal hostnames (case-insensitive).
    const METADATA_HOSTS: &[&str] = &["metadata.google.internal", "metadata.internal"];
    let host_lc = host.to_ascii_lowercase();
    if METADATA_HOSTS.contains(&host_lc.as_str()) {
        return Some(host.to_string());
    }

    // IP-literal checks. A hostname that does not parse as an IP is allowed (DNS targets are not
    // resolved here; the metadata-host list above covers the well-known names).
    let blocked = match host.parse::<IpAddr>() {
        Ok(IpAddr::V4(v4)) => {
            v4.is_loopback()            // 127.0.0.0/8
                || v4.is_private()      // 10/8, 172.16/12, 192.168/16
                || v4.is_link_local()   // 169.254.0.0/16 (covers IMDS 169.254.169.254)
                || v4.is_unspecified()  // 0.0.0.0
                || v4 == Ipv4Addr::new(169, 254, 169, 254)
        }
        Ok(IpAddr::V6(v6)) => {
            v6.is_loopback()            // ::1
                || v6.is_unspecified()  // ::
                || is_unique_local_v6(&v6)   // fc00::/7
                || is_link_local_v6(&v6)     // fe80::/10
                || v6.to_ipv4_mapped().is_some_and(|m| {
                    m.is_loopback() || m.is_private() || m.is_link_local() || m.is_unspecified()
                })
        }
        Err(_) => false,
    };

    blocked.then(|| host.to_string())
}

/// IPv6 unique-local range `fc00::/7` (the first 7 bits are `1111110`).
fn is_unique_local_v6(addr: &std::net::Ipv6Addr) -> bool {
    (addr.segments()[0] & 0xfe00) == 0xfc00
}

/// IPv6 link-local range `fe80::/10` (the first 10 bits are `1111111010`).
fn is_link_local_v6(addr: &std::net::Ipv6Addr) -> bool {
    (addr.segments()[0] & 0xffc0) == 0xfe80
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
            default_max_tokens: None,
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

    #[allow(deprecated)] // exercising the deprecated legacy-token field on purpose
    fn make_auth(mode: &str, client_tokens: Vec<&str>, legacy: Option<&str>) -> config::AuthCfg {
        config::AuthCfg {
            mode: mode.into(),
            _legacy_token: legacy.map(|s| s.to_string()),
            client_tokens: client_tokens.into_iter().map(|s| s.to_string()).collect(),
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
        window_s: u64,
        threshold: f64,
        min_requests: usize,
        n: u32,
    ) -> config::BreakerTripConfig {
        config::BreakerTripConfig {
            mode,
            window_s,
            threshold,
            min_requests,
            n,
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
        for bad in [
            "http://api.example.com",
            "http://169.254.169.254/latest/meta-data/",
            "file:///etc/shadow",
            "",
        ] {
            let mut providers = HashMap::new();
            providers.insert("p".to_string(), make_provider("anthropic", bad, "API_KEY"));
            let cfg = make_root_cfg(providers, HashMap::new(), HashMap::new());
            let errs = validate(&cfg)
                .unwrap_err_or_default(format!("non-https base_url '{bad}' must fail validation"));
            assert!(
                errs.iter()
                    .any(|e| e.contains("base_url must use https") && e.contains('p')),
                "expected an https base_url error for '{bad}'; got: {errs:?}"
            );
        }
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
                "trip.window_s must be >= 1",
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
                "trip.n must be >= 1",
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
    fn test_validate_rejects_token_mode_with_no_tokens() {
        let (providers, models, pools) = valid_maps();
        let mut cfg = make_root_cfg(providers, models, pools);
        cfg.auth = Some(make_auth("token", vec![], None));
        let errs = validate(&cfg).expect_err("token mode with no tokens must fail validation");
        assert!(
            errs.iter()
                .any(|e| e.contains("token mode requires at least one client token")),
            "expected a token-mode lockout error; got: {errs:?}"
        );
    }

    #[test]
    fn test_validate_token_mode_with_tokens_ok() {
        // Both the allowlist form and the legacy single-token form satisfy the requirement.
        for auth in [
            make_auth("token", vec!["secret"], None),
            make_auth("token", vec![], Some("legacy-secret")),
        ] {
            let (providers, models, pools) = valid_maps();
            let mut cfg = make_root_cfg(providers, models, pools);
            cfg.auth = Some(auth);
            assert!(
                validate(&cfg).is_ok(),
                "token mode with at least one token must validate"
            );
        }
    }

    #[test]
    fn test_validate_none_mode_with_no_tokens_ok() {
        let (providers, models, pools) = valid_maps();
        let mut cfg = make_root_cfg(providers, models, pools);
        cfg.auth = Some(make_auth("none", vec![], None));
        assert!(
            validate(&cfg).is_ok(),
            "mode 'none' carries no token requirement"
        );
    }

    #[test]
    fn test_ssrf_blocked_host_rejects_internal_targets() {
        // IP literals and metadata hostnames over https must be flagged.
        for blocked in [
            "https://169.254.169.254/latest/meta-data/",
            "https://169.254.169.254/",
            "https://127.0.0.1/",
            "https://10.0.0.1/v1",
            "https://172.16.0.1/",
            "https://192.168.1.1:8443/",
            "https://[::1]/",
            "https://[::1]:443/",
            "https://[fe80::1]/",
            "https://[fc00::1]/",
            "https://metadata.google.internal/computeMetadata/v1/",
            "https://METADATA.INTERNAL/",
            "https://0.0.0.0/",
            "https://user:pass@10.0.0.5/path",
        ] {
            assert!(
                ssrf_blocked_host(blocked).is_some(),
                "expected '{blocked}' to be flagged as an SSRF target"
            );
        }
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
        ] {
            assert!(
                ssrf_blocked_host(ok).is_none(),
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
                .any(|e| e.contains("blocked internal/metadata host")
                    && e.contains("169.254.169.254")),
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
    fn test_validate_rejects_bad_affinity_mode() {
        let (providers, models, _) = valid_maps();
        let mut pools = HashMap::new();
        let mut pool = make_pool(vec![make_member("mymodel")]);
        pool.affinity = Some(config::AffinityCfg {
            mode: "sticky".to_string(),
            header_name: None,
        });
        pools.insert("mypool".to_string(), pool);
        let cfg = make_root_cfg(providers, models, pools);
        let errs = validate(&cfg).expect_err("an unsupported affinity.mode must fail validation");
        assert!(
            errs.iter()
                .any(|e| e.contains("affinity.mode 'sticky' is invalid")),
            "expected an invalid affinity-mode error; got: {errs:?}"
        );
    }

    #[test]
    fn test_validate_accepts_session_affinity_mode() {
        let (providers, models, _) = valid_maps();
        let mut pools = HashMap::new();
        let mut pool = make_pool(vec![make_member("mymodel")]);
        pool.affinity = Some(config::AffinityCfg {
            mode: "session".to_string(),
            header_name: Some("x-session-id".to_string()),
        });
        pools.insert("mypool".to_string(), pool);
        let cfg = make_root_cfg(providers, models, pools);
        assert!(
            validate(&cfg).is_ok(),
            "the supported 'session' affinity mode must validate"
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
}
