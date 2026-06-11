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
        // The exact twin of the `max_concurrent: 0` foot-gun on the lifetime-budget axis. main.rs
        // computes `limited = max_requests >= 0`, so `max_requests: 0` yields `limited=true,
        // budget=0`; store::usable() then rejects any lane with `limited && budget <= 0`, making the
        // lane permanently un-admissible from the first request with no boot diagnostic. A negative
        // value (-1) means unlimited via neg1(), so only 0 is pathological. Reject it loudly here.
        if model_cfg.max_requests == 0 {
            errors.push(format!(
                "model '{}' has max_requests: 0; a lane with a zero lifetime budget never admits a request — use a positive cap, or omit it (default -1 = unlimited)",
                model_name
            ));
        }
        // Reserved-name check (same rule as the pool and provider loops below): a model named `admin`
        // is reached at `POST /admin/v1/messages`, which the auth middleware classifies as the
        // operator admin surface (guarded by admin_token, not a client/virtual-key token). So the
        // model is unreachable to normal clients AND, in governance mode, the admin branch inserts
        // `GovCtx::default()` (key: None) which skips per-model `allowed_pools` enforcement — a
        // governance bypass. Reject at boot rather than ship a silently-inaccessible / governance-
        // bypassing model. (`reserved_admin_name` centralises the rule across models/pools/providers
        // so none can drift from the auth-middleware `is_admin` boundary.)
        if reserved_admin_name(model_name) {
            errors.push(format!(
                "model name '{}' is reserved: 'admin' is a built-in management prefix (the auth middleware routes /admin and /admin/* to the operator admin surface), so a model reachable via /{}/v1/messages is unreachable to clients and bypasses per-model governance; rename it",
                model_name, model_name
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
        // Reserved-name check: the auth middleware classifies any request path that is exactly
        // `/admin` or starts with `/admin/` as the operator admin surface (guarded by the governance
        // admin_token, NOT a client/virtual-key token). A pool named `admin` is reached at
        // `POST /admin/v1/messages`, which the middleware intercepts as an admin request — so a
        // normal client_token / virtual-key holder gets a 401 and the pool is permanently
        // unreachable; worse, in governance mode the admin branch inserts `GovCtx::default()`
        // (key: None), so an admin-token holder reaching the pool this way bypasses per-pool
        // allowed_pools enforcement entirely. The collision also extends to any name whose first
        // path segment would be `admin` — i.e. a name equal to `admin` or beginning with `admin/`.
        // Reject these at boot rather than shipping a silently-inaccessible / governance-bypassing
        // pool. (`reserved_admin_name` centralises the rule so the pool and provider checks — and
        // the auth-middleware `is_admin` boundary — cannot drift.)
        if reserved_admin_name(pool_name) {
            errors.push(format!(
                "pool name '{}' is reserved: 'admin' is a built-in management prefix (the auth middleware routes /admin and /admin/* to the operator admin surface), so a pool reachable via that path is unreachable to clients and bypasses per-pool governance; rename it",
                pool_name
            ));
        }
    }

    // The same reserved-prefix collision applies to PROVIDER names: a provider named `admin` is
    // reachable via the adhoc route `POST /admin/<model>/v1/messages`, which the auth middleware
    // intercepts as an admin request for the identical reason. Reject it symmetrically.
    for provider_name in cfg.providers.keys() {
        if reserved_admin_name(provider_name) {
            errors.push(format!(
                "provider name '{}' is reserved: 'admin' is a built-in management prefix (the auth middleware routes /admin and /admin/* to the operator admin surface), so a provider reachable via the adhoc /admin/<model> route is unreachable to clients; rename it",
                provider_name
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
                    "provider '{}' error_map code '{}': invalid StatusClass '{}', must be one of: rate_limit, overloaded, server_error, timeout, network, auth, billing, client_error, context_length",
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

        // The `path` override is appended to `base_url` VERBATIM at request time
        // (`format!("{base}{wire_path}")` in forward.rs), and the composed string is then parsed by
        // reqwest's `url` crate to choose the connect host. base_url validation alone is therefore
        // NOT sufficient: a `path` that does not begin with `/` FUSES into the authority — e.g.
        // base_url `https://api.openai.com` + path `.evil.com/v1` yields
        // `https://api.openai.com.evil.com/v1`, whose host is `api.openai.com.evil.com`, redirecting
        // the lane's signed (API-key-bearing) traffic to an attacker host (credential-relay SSRF).
        // Likewise a `path` smuggling a `@` / `//` / `\` could re-home the authority. Defend in two
        // layers: (1) require a leading `/` so the override can only ever extend the PATH, never the
        // authority; (2) re-run the COMPOSED url through the same ssrf_blocked_host guard so any host
        // it could still introduce is caught with the identical internal/metadata block set as
        // base_url. (The composed string is only checked when base_url is itself an accepted https
        // URL — a bad base_url already errors above.)
        if let Some(path) = &provider_cfg.path {
            if !path.starts_with('/') {
                errors.push(format!(
                    "provider '{}' path '{}' must begin with '/': a path override is appended to base_url verbatim, so a path that does not start with '/' fuses into the host (e.g. base_url + '{}') and can redirect signed traffic to an attacker-controlled host",
                    provider_name, path, path
                ));
            } else if provider_cfg.base_url.starts_with("https://") {
                let composed = format!("{}{}", provider_cfg.base_url, path);
                if let Some(host) = ssrf_blocked_host(&composed) {
                    errors.push(format!(
                        "provider '{}' base_url+path '{}' targets a blocked internal/metadata host '{}' (loopback, link-local, RFC-1918 private, or cloud metadata endpoints are not permitted)",
                        provider_name, composed, host
                    ));
                }
            }
        }
    }

    // Rule 2 & 3: Validate each pool's members
    for (pool_name, pool_cfg) in &cfg.pools {
        let mut member_protocols: HashSet<&str> = HashSet::new();

        for member in &pool_cfg.members {
            // A `weight: 0` member is silently mis-balanced by the SWRR selector: it contributes 0
            // to the running total and its current_weight never increases, so it is never selected
            // while peers are healthy; an all-zero pool degenerates to always returning the first
            // candidate with no load distribution — and no boot diagnostic. Reject it (mirroring the
            // max_concurrent:0 / breaker n:0 fail-loud rules). Excluding a member is expressed via
            // `exclusions`, not weight 0.
            if member.weight == 0 {
                errors.push(format!(
                    "pool '{}' member '{}' weight must be >= 1 (got 0)",
                    pool_name, member.target
                ));
            }
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
            // A `base_cooldown_secs: 0` or `max_cooldown_secs: 0` parses fine but yields a degenerate
            // breaker with NO cooldown: when the breaker trips open it would re-admit the failing
            // backend immediately (the cooldown window is zero seconds), defeating the back-off the
            // breaker exists to provide. This is the cooldown-axis twin of the trip.* zero-floor
            // guards below (min_requests/window_s/n >= 1) — reject a zero floor on EITHER cooldown
            // field at boot rather than ship a breaker that never actually pauses the backend. (The
            // inversion check below additionally requires max >= base; the two together pin both
            // fields to >= 1 with max >= base.)
            if breaker.base_cooldown_secs == 0 {
                errors.push(format!(
                    "pool '{}' breaker base_cooldown_secs must be >= 1 (got 0); a zero cooldown re-admits a tripped backend immediately, defeating the breaker's back-off",
                    pool_name
                ));
            }
            if breaker.max_cooldown_secs == 0 {
                errors.push(format!(
                    "pool '{}' breaker max_cooldown_secs must be >= 1 (got 0); a zero cooldown re-admits a tripped backend immediately, defeating the breaker's back-off",
                    pool_name
                ));
            }
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

        // Rule 6b: Validate the per-pool failover budget. `failover.deadline_secs == 0` is the exact
        // twin of the `max_concurrent: 0` / breaker `window_s: 0` foot-guns: `RequestCtx::new(0)` sets
        // `deadline = start.saturating_add(0) == start`, and the failover loop checks
        // `request_ctx.expired(now())` at the TOP of the very first (primary) iteration with
        // `now >= deadline`. Because `now()` is read fresh and is always `>= start`, the primary attempt
        // is rejected with a 503 before it runs — the pool serves ZERO requests with no boot diagnostic.
        // Reject it loudly here, mirroring the rest of validate()'s fail-loud invariant. (`cap == 0` is
        // benign: the `0..=cap` loop still runs the primary once, so it is NOT rejected.)
        if let Some(failover) = &pool_cfg.failover {
            if failover.deadline_secs == 0 {
                errors.push(format!(
                    "pool '{}' failover.deadline_secs must be >= 1; a 0 budget rejects the primary attempt before it runs (every request 503s)",
                    pool_name
                ));
            }
            // Rule 6c: Each `failover.exclusions` entry is a MEMBER MODEL NAME removed from this
            // pool's candidate set at runtime (the selector benches it; primary and failover never
            // pick it). The exclusions are matched against the pool's member targets, so a misspelled
            // or stale entry (e.g. `betaa` for member `beta`) resolves to nothing and silently fails
            // to bench the member the operator intended — and an exclusion that DOES name a member,
            // applied across every member, empties the pool. Mirror the member-target resolution rule
            // (`member.target` is the candidate name) and fail loud on an exclusion that names no
            // member of THIS pool, the same way Rule 7 catches a dangling fallback-pool reference.
            if let Some(exclusions) = &failover.exclusions {
                let member_targets: HashSet<&str> =
                    pool_cfg.members.iter().map(|m| m.target.as_str()).collect();
                for excluded in exclusions {
                    if !member_targets.contains(excluded.as_str()) {
                        errors.push(format!(
                            "pool '{}' failover.exclusions references '{}', which is not a member of the pool; an exclusion must name one of the pool's members (otherwise it silently benches nothing)",
                            pool_name, excluded
                        ));
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
            // Passthrough carries no token-allowlist requirement, but it has a credential-LEAK
            // foot-gun: forward.rs selects the upstream key as `caller_token.unwrap_or(lane.api_key)`,
            // so an UNAUTHENTICATED caller (no token) in passthrough mode gets busbar's OWN configured
            // lane key (resolved from the provider's `api_key_env`) substituted upstream. A passthrough
            // deployment is meant to forward the CALLER's credential, never a configured one — so a
            // provider whose `api_key_env` resolves to a NON-EMPTY value is the leak signal.
            //
            // We WARN (not hard-reject): a legit Bedrock-ingress passthrough provider authenticates
            // per-request with SigV4 from the AWS credential chain, so its `api_key_env` normally
            // resolves EMPTY and never trips this — but an operator may also have a deliberate
            // static-key fallback provider, and rejecting would break that. Mirror main.rs's
            // single env read (`std::env::var(api_key_env)`) so the guard sees the SAME value the
            // lane will, and surface a prominent boot warning naming each offending provider. The
            // resolved `_legacy_api_key` is always None (config::resolve discards+warns on it), so
            // `api_key_env` is the only key source to check.
            Some(crate::auth::AuthMode::Passthrough) => {
                for (provider_name, provider_cfg) in &cfg.providers {
                    let resolved_key = std::env::var(&provider_cfg.api_key_env).unwrap_or_default();
                    if !resolved_key.trim().is_empty() {
                        tracing::warn!(
                            provider = %provider_name,
                            api_key_env = %provider_cfg.api_key_env,
                            "auth.mode=passthrough with a NON-EMPTY configured api_key for this \
                             provider is a credential-leak risk: in passthrough mode an \
                             UNAUTHENTICATED caller (no token) has busbar's OWN configured lane key \
                             substituted upstream (caller_token.unwrap_or(lane.api_key)), forwarding \
                             your secret on the caller's behalf. A passthrough deployment should \
                             forward the CALLER credential, never a configured one. Unset the \
                             environment variable named by api_key_env (Bedrock-ingress passthrough \
                             signs per-request via SigV4 and needs no static key), or switch to \
                             auth.mode=token to gate callers."
                        );
                    }
                }
            }
            Some(crate::auth::AuthMode::None) => {
                // mode=none is an open relay: `validate_token` admits every request unconditionally,
                // so a configured `client_tokens` allowlist has ZERO enforcement effect. An operator
                // who set BOTH `mode: none` and a `client_tokens` list believes the list constrains
                // access while the server is wide open. This is not a hard boot error (none mode is
                // intentionally permissive and may be deliberate in dev), but it MUST be loud — warn
                // here at boot (config-visible) in addition to the runtime warning AuthMiddleware::new
                // emits. NB: this is a no-op when no tokens are listed (the common none-mode case).
                if !effective_client_tokens_empty(auth) {
                    tracing::warn!(
                        "auth.mode=none ignores the configured client_tokens: None mode is an open \
                         relay that admits every request regardless of token, so the allowlist has \
                         no enforcement effect. Set auth.mode=token to enforce it."
                    );
                }
            }
        }
    }

    if errors.is_empty() {
        Ok(())
    } else {
        Err(errors)
    }
}

/// Validate the optional governance block (read separately from the resolved `RootCfg`, so it
/// cannot ride along in `validate(&RootCfg)`). Called from `config::resolve`, whose `Err(Vec<String>)`
/// is surfaced as a fail-loud boot error — the same channel `validate` uses.
///
/// When `governance.enabled` is true but `admin_token` is unset, `GovState::admin_token()` returns
/// `None`, so the `/admin` auth branch's `authorized` is permanently `false`: the admin API is
/// SILENTLY locked (every admin call 401s) with no startup diagnostic. An operator who enabled
/// governance to manage virtual keys discovers this only at runtime. Mirror the `token` mode with no
/// `client_tokens` fail-loud pattern and reject it at boot. A disabled governance block carries no
/// requirement (the admin surface is inert anyway).
///
/// `auth` is the deployment's auth block (read separately, like governance, so neither lands on
/// `RootCfg`). `governance.enabled` combined with `auth.mode=passthrough` is a self-contradictory
/// deployment: governance requires every request to resolve to an enabled virtual key, which
/// supersedes passthrough's "accept any caller credential and forward it upstream" intent — so a
/// server an operator believes is in passthrough silently rejects every caller lacking a virtual
/// key (a behaviour inversion that could cause a production outage). The auth runtime emits a
/// one-time warning, but only `resolve`/this validator can see BOTH blocks at boot, so reject the
/// combination here with a clear diagnostic rather than letting it pass to a runtime warning.
pub(crate) fn validate_governance(
    governance: &crate::config::GovernanceCfg,
    auth: Option<&crate::config::AuthCfg>,
) -> Result<(), Vec<String>> {
    let mut errors = Vec::new();
    if governance.enabled
        && governance
            .admin_token
            .as_deref()
            // A WHITESPACE-ONLY admin_token (e.g. " " or "\t") passes a bare `is_empty()` guard but is
            // functionally unusable: it is a degenerate secret an operator cannot reasonably present,
            // and `${BUSBAR_ADMIN_TOKEN}` expanding to an all-blanks value would silently lock the
            // /admin API exactly as an unset token does. Reject blank-only here too (trim then test)
            // so the boot diagnostic fires for the whitespace case, not just the truly-empty one.
            .is_none_or(|t| t.trim().is_empty())
    {
        errors.push(
            "governance.enabled is true but no governance.admin_token is configured; the /admin management API is unreachable (every admin call returns 401). Set governance.admin_token (e.g. admin_token: ${BUSBAR_ADMIN_TOKEN})".to_string(),
        );
    }
    if governance.enabled
        && auth.is_some_and(|a| {
            crate::auth::AuthMode::from_config_str(&a.mode)
                == Some(crate::auth::AuthMode::Passthrough)
        })
    {
        errors.push(
            "governance.enabled is true together with auth.mode=passthrough; governance supersedes passthrough (every request must resolve to an enabled virtual key), so passthrough's accept-and-forward-caller-credential semantics are NOT honoured and every caller without a virtual key is silently rejected. This combination is unsupported; set auth.mode=token (or omit the auth block) alongside governance.".to_string(),
        );
    }
    if errors.is_empty() {
        Ok(())
    } else {
        Err(errors)
    }
}

/// True when a pool / provider `name` would collide with the built-in `/admin` operator surface.
///
/// The auth middleware (`auth::auth_middleware`) classifies a request as admin with the
/// PATH-BOUNDARY-SAFE test `path == "/admin" || path.starts_with("/admin/")` — deliberately NOT a
/// bare `starts_with("/admin")`, so sibling names like `adminx` / `admin_portal` are NOT admin
/// (see `test_admin_prefix_is_boundary_safe`). A pool/provider name lands as a path SEGMENT
/// (`/<name>/v1/messages`, or `/admin/<model>/...` for the adhoc provider route), so a name collides
/// with the admin surface IFF the segment is exactly `admin`. We mirror that exact boundary here
/// rather than the finding's looser `starts_with("admin")` (which would wrongly reject the safe
/// `adminx` the boundary test proves is a normal route). A name containing a `/` could also smuggle
/// an `admin/` first segment, so reject that family too.
fn reserved_admin_name(name: &str) -> bool {
    name == "admin" || name.starts_with("admin/") || name.split('/').next() == Some("admin")
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
/// Percent-decode a host string (`%XX` → byte), mirroring the RFC 3986 decoding the `url` crate
/// applies to host components at request time. Invalid escapes (`%` not followed by two hex digits)
/// are left verbatim so a malformed host stays malformed (it will still fail every IP/hostname check
/// and be allowed, but it can never be SMUGGLED PAST a check by hiding a blocked literal behind an
/// escape). Only ASCII results are surfaced as decoded bytes; non-UTF-8 decoded output falls back to
/// the original so we never fabricate a misleading host. No new dependency — a small manual scan.
fn percent_decode_host(host: &str) -> String {
    let bytes = host.as_bytes();
    let mut out: Vec<u8> = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            let hi = (bytes[i + 1] as char).to_digit(16);
            let lo = (bytes[i + 2] as char).to_digit(16);
            if let (Some(hi), Some(lo)) = (hi, lo) {
                out.push((hi * 16 + lo) as u8);
                i += 3;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    match String::from_utf8(out) {
        Ok(s) => s,
        // Decoded bytes are not valid UTF-8: keep the original literal rather than a lossy host.
        Err(_) => host.to_string(),
    }
}

fn ssrf_blocked_host(url: &str) -> Option<String> {
    use std::net::{IpAddr, Ipv4Addr};

    // Strip "https://" (caller guarantees this prefix).
    let rest = url.strip_prefix("https://")?;
    // Normalize backslashes to forward slashes BEFORE splitting the authority. `https` is a WHATWG
    // "special" scheme, so reqwest's `url` crate converts every `\` to `/` while parsing — meaning a
    // `base_url` like `https://10.0.0.1\x.allowed.com` is parsed by reqwest with authority `10.0.0.1`
    // (the `\` terminates the authority exactly as `/` would) and then CONNECTS to `10.0.0.1` /
    // `169.254.169.254`, even though a hand-parser that split only on `['/', '?', '#']` would see the
    // whole `10.0.0.1\x.allowed.com` as the host (which passes every internal/metadata check) — an
    // SSRF credential-relay bypass. Mirroring reqwest's `\`→`/` rewrite here makes the guard see the
    // SAME authority boundary the connecting stack will, closing the bypass.
    let rest = rest.replace('\\', "/");
    // Authority is everything before the first path/query/fragment delimiter.
    let authority = rest.split(['/', '?', '#']).next().unwrap_or(rest.as_str());
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

    // Percent-decode the host BEFORE any check below. The guard operates on the literal config
    // string, but the `url` crate `reqwest` uses percent-decodes host components per RFC 3986 at
    // request time — so a `base_url` like `https://169%2E254%2E169%2E254/` would pass every check
    // here (not in METADATA_HOSTS, not a parseable `IpAddr`, and the `%` defeats
    // `is_alternate_ipv4_encoding`) yet could resolve to the IMDS target downstream. Decoding here
    // makes the guard's safety property independent of the URL library's normalization details.
    let host_decoded = percent_decode_host(host);
    let host = host_decoded.as_str();

    // Normalize a single trailing FQDN-root dot off the host BEFORE any check below. glibc
    // getaddrinfo (reqwest's default resolver) treats a trailing dot as a rooted FQDN and still
    // resolves the literal it precedes — so `https://127.0.0.1./`, `https://169.254.169.254./`,
    // and `https://10.0.0.1./` connect to exactly the loopback / IMDS / RFC1918 targets the bare
    // forms do. Without stripping it, an IP-literal+dot does NOT parse as `IpAddr` (so the
    // loopback/link-local/private arms never fire), is not in `METADATA_HOSTS`, and fails
    // `is_alternate_ipv4_encoding` (the trailing empty segment makes `all_numeric` false) — an SSRF
    // credential-relay bypass. Stripping here covers IP literals, alternate encodings, and the
    // `localhost.` FQDN spelling uniformly (the explicit `localhost.` METADATA_HOSTS entry below is
    // now redundant but kept as belt-and-suspenders).
    let host = host.strip_suffix('.').unwrap_or(host);

    // Known cloud metadata / internal hostnames (case-insensitive). `localhost` does NOT parse as
    // an `IpAddr` and is not an alternate IPv4 encoding, so without listing it here it would slip
    // past every IP-range check below and a `base_url: https://localhost:11434/` would forward
    // inbound API keys to a loopback service (e.g. a local Ollama or metadata sidecar) — an SSRF
    // credential-relay. The trailing-dot `localhost.` spelling is normalized off above.
    const METADATA_HOSTS: &[&str] = &[
        "metadata.google.internal",
        "metadata.internal",
        "localhost",
        "localhost.",
    ];
    let host_lc = host.to_ascii_lowercase();
    if METADATA_HOSTS.contains(&host_lc.as_str()) {
        return Some(host.to_string());
    }

    // Block any `*.localhost` subdomain too. RFC 6761 reserves the entire `.localhost` TLD to
    // loopback, and glibc getaddrinfo (reqwest's default resolver) resolves `api.localhost`,
    // `service.localhost`, etc. to 127.0.0.1 — so a `base_url: https://api.localhost:11434/` would
    // forward inbound API keys to a co-located loopback service (SSRF credential-relay) exactly as
    // the bare `localhost` entry guards against. The exact-label `localhost` spelling is already
    // covered by METADATA_HOSTS above; here we catch the subdomain case by testing the right-most
    // label. This mirrors `observability::host_is_internal` so the two SSRF guards stay at parity.
    // The trailing-dot FQDN-root spelling (`sub.localhost.`) was normalized off above.
    if host_lc
        .rsplit_once('.')
        .is_some_and(|(_, tld)| tld == "localhost")
    {
        return Some(host.to_string());
    }

    // Alternate / non-canonical IP encodings that Rust's `IpAddr::from_str` REJECTS but the OS
    // resolver (glibc getaddrinfo, used by reqwest's default resolver) still interprets as an
    // IPv4 address — decimal int (`2130706433` = 127.0.0.1), hex (`0x7f000001`), octal
    // (`017700000001`), and short dotted forms (`127.1`, `10.0.1`). A canonical-only `parse()`
    // would treat these as opaque DNS hostnames (allowed), yet they connect to loopback / the IMDS
    // endpoint (`2852039166` = 169.254.169.254) at request time — defeating the SSRF guard. Flag
    // any host that looks like one of these alternate IPv4 encodings as blocked.
    if is_alternate_ipv4_encoding(host) {
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
                || is_cgnat_shared_v4(&v4) // 100.64.0.0/10 (RFC 6598 CGNAT, routable in cloud VPCs)
                || v4 == Ipv4Addr::new(169, 254, 169, 254)
        }
        Ok(IpAddr::V6(v6)) => {
            v6.is_loopback()            // ::1
                || v6.is_unspecified()  // ::
                || is_unique_local_v6(&v6)   // fc00::/7
                || is_link_local_v6(&v6)     // fe80::/10
                // An IPv6 literal that embeds an IPv4 address reaches the same v4 target as the bare
                // `a.b.c.d` form, so it MUST apply the IDENTICAL block set as the direct IPv4 arm
                // above — otherwise `https://[::ffff:100.64.0.1]/` slips past while `https://100.64.0.1/`
                // is rejected (an SSRF credential-relay gap). Use `to_ipv4()` rather than
                // `to_ipv4_mapped()`: it is a SUPERSET that also covers the IPv4-COMPATIBLE form
                // (`[::a.b.c.d]`, e.g. `[::127.0.0.1]` / `[::169.254.169.254]`), where the leading
                // `segments()[0] == 0` makes the ULA/link-local masks miss and `to_ipv4_mapped()`
                // returns None — yet a connecting stack still routes it to the embedded v4 target.
                || v6.to_ipv4().is_some_and(|m| {
                    m.is_loopback()
                        || m.is_private()
                        || m.is_link_local()
                        || m.is_unspecified()
                        || is_cgnat_shared_v4(&m)
                        || m == Ipv4Addr::new(169, 254, 169, 254)
                })
        }
        Err(_) => false,
    };

    blocked.then(|| host.to_string())
}

/// RFC 6598 Shared Address Space `100.64.0.0/10` (a.k.a. CGNAT). Not covered by
/// `Ipv4Addr::is_private()`, yet routable inside AWS/GCP VPCs and many Kubernetes clusters where it
/// fronts internal services — so it is an SSRF target the private/link-local checks miss. The /10
/// is the addresses whose first octet is 100 and whose top two bits of the second octet are `01`.
fn is_cgnat_shared_v4(v4: &std::net::Ipv4Addr) -> bool {
    let o = v4.octets();
    o[0] == 100 && (o[1] & 0xC0) == 64
}

/// True when `host` is an alternate (non-dotted-quad) IPv4 encoding that `IpAddr::from_str` rejects
/// but the OS resolver still maps to an IPv4 address: a bare decimal integer (`2130706433`), a
/// `0x`/`0X` hex literal (`0x7f000001`), a leading-zero octal literal (`017700000001`), or a dotted
/// form with FEWER than four octets (`127.1`, `10.0.1`). These bypass the canonical IP-literal
/// checks while still resolving to loopback / link-local / private targets at connect time, so they
/// must be treated as blocked. A canonical four-octet dotted-quad is NOT matched here (it is handled
/// by the `parse::<IpAddr>()` path); a normal DNS hostname (containing a non-digit, non-`.` char in
/// a way that isn't all-hex-after-`0x`) is not matched either.
fn is_alternate_ipv4_encoding(host: &str) -> bool {
    if host.is_empty() {
        return false;
    }

    // Whole-host `0x...` / `0X...` hex literal (e.g. `0x7f000001`). Only when there is no `.`;
    // a dotted per-octet hex form (`0x7f.0.0.1`) is handled by the dotted branch below.
    if !host.contains('.') {
        if let Some(hex) = host.strip_prefix("0x").or_else(|| host.strip_prefix("0X")) {
            return !hex.is_empty() && hex.bytes().all(|b| b.is_ascii_hexdigit());
        }
    }

    // Dotted form: split on '.'. A canonical dotted-quad has exactly 4 parts and parses via
    // `IpAddr` — leave it to that path. Fewer than 4 numeric parts (e.g. `127.1`, `10.0.1`) is an
    // alternate short form getaddrinfo expands; flag it. Any part using a `0x` hex or leading-zero
    // octal encoding is also an alternate form.
    if host.contains('.') {
        let parts: Vec<&str> = host.split('.').collect();
        // Every part must be a numeric encoding (decimal, hex, or octal) for this to be an IP-ish
        // host at all; if any part has a non-numeric character it's a DNS name → not our concern.
        let all_numeric = parts.iter().all(|p| {
            if let Some(hex) = p.strip_prefix("0x").or_else(|| p.strip_prefix("0X")) {
                !hex.is_empty() && hex.bytes().all(|b| b.is_ascii_hexdigit())
            } else {
                !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit())
            }
        });
        if !all_numeric {
            return false;
        }
        // Short dotted form (fewer than 4 parts) is an alternate encoding getaddrinfo expands.
        if parts.len() < 4 {
            return true;
        }
        // Four numeric parts: alternate iff any part is hex (`0x`) or leading-zero octal.
        return parts.iter().any(|p| {
            p.starts_with("0x")
                || p.starts_with("0X")
                || (p.len() > 1 && p.starts_with('0') && p.bytes().all(|b| b.is_ascii_digit()))
        });
    }

    // No '.', not `0x`: a bare all-digits host is a decimal integer IP encoding (e.g. `2130706433`).
    host.bytes().all(|b| b.is_ascii_digit())
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
    fn test_ssrf_blocks_localhost() {
        // `localhost` does not parse as an IpAddr and is not an alternate IPv4 encoding, so without
        // an explicit entry it would slip past every IP-range check and forward inbound keys to a
        // loopback service (SSRF credential-relay). Both `localhost` and the trailing-dot FQDN form
        // must be flagged, case-insensitively, with or without a port.
        for blocked in [
            "https://localhost/",
            "https://localhost:11434/",
            "https://LOCALHOST/v1",
            "https://localhost./",
            "https://localhost.:443/api",
        ] {
            assert!(
                ssrf_blocked_host(blocked).is_some(),
                "expected '{blocked}' to be flagged as an SSRF target"
            );
        }
        // A full validate() pass must reject a localhost base_url.
        let mut providers = HashMap::new();
        providers.insert(
            "p".to_string(),
            make_provider("anthropic", "https://localhost:11434/", "API_KEY"),
        );
        let cfg = make_root_cfg(providers, HashMap::new(), HashMap::new());
        let errs = validate(&cfg).expect_err("a localhost base_url must fail validation");
        assert!(
            errs.iter()
                .any(|e| e.contains("blocked internal/metadata host") && e.contains("localhost")),
            "expected an SSRF/metadata-host error for localhost; got: {errs:?}"
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
        // A pool named `admin` is reached at `/admin/v1/messages`, which the auth middleware
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
        // Regression (MEDIUM, final audit): a MODEL named `admin` is reached at `/admin/v1/messages`,
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
            deadline_secs: 0,
            exclusions: None,
            cap: 3,
        });
        pools.insert("mypool".to_string(), pool);
        let cfg = make_root_cfg(providers, models, pools);
        let errs = validate(&cfg).expect_err("failover.deadline_secs: 0 must fail validation");
        assert!(
            errs.iter()
                .any(|e| e.contains("failover.deadline_secs must be >= 1") && e.contains("mypool")),
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
            deadline_secs: 30,
            exclusions: None,
            cap: 0,
        });
        pools.insert("mypool".to_string(), pool);
        let cfg = make_root_cfg(providers, models, pools);
        assert!(
            validate(&cfg).is_ok(),
            "a positive failover.deadline_secs with cap:0 must validate"
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
            deadline_secs: 30,
            exclusions: Some(vec!["mymodell".to_string()]), // typo: pool member is `mymodel`
            cap: 3,
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
            deadline_secs: 30,
            exclusions: Some(vec!["secondmodel".to_string()]), // a real member — benched on purpose
            cap: 3,
        });
        pools.insert("mypool".to_string(), pool);
        let cfg = make_root_cfg(providers, models, pools);
        assert!(
            validate(&cfg).is_ok(),
            "a failover exclusion naming a real pool member must validate"
        );
    }

    #[test]
    fn test_validate_governance_requires_admin_token_when_enabled() {
        // governance.enabled with no admin_token silently locks the /admin API (every call 401s);
        // must fail loud at boot. An empty-string token is treated as absent (GovState::admin_token
        // would hand the constant-time compare an empty secret).
        for missing in [None, Some(String::new())] {
            let gov = config::GovernanceCfg {
                enabled: true,
                db_path: "busbar-governance.db".to_string(),
                price_per_request_cents: 1,
                price_per_1k_tokens_cents: 0,
                admin_token: missing.clone(),
            };
            let errs = validate_governance(&gov, None)
                .expect_err("enabled governance without admin_token must fail");
            assert!(
                errs.iter().any(|e| e.contains("governance.admin_token")
                    && e.contains("/admin management API is unreachable")),
                "expected an admin-token lockout error for {missing:?}; got: {errs:?}"
            );
        }
    }

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
                enabled: true,
                db_path: "busbar-governance.db".to_string(),
                price_per_request_cents: 1,
                price_per_1k_tokens_cents: 0,
                admin_token: Some(blank.to_string()),
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
            enabled: true,
            db_path: "busbar-governance.db".to_string(),
            price_per_request_cents: 1,
            price_per_1k_tokens_cents: 0,
            admin_token: Some("  real-secret  ".to_string()),
        };
        assert!(
            validate_governance(&gov, None).is_ok(),
            "an admin_token with a non-blank core must validate (we do not reject surrounding space)"
        );
    }

    #[test]
    fn test_validate_governance_ok_when_enabled_with_admin_token() {
        let gov = config::GovernanceCfg {
            enabled: true,
            db_path: "busbar-governance.db".to_string(),
            price_per_request_cents: 1,
            price_per_1k_tokens_cents: 0,
            admin_token: Some("an-operator-secret".to_string()),
        };
        assert!(
            validate_governance(&gov, None).is_ok(),
            "enabled governance WITH an admin_token must validate"
        );
    }

    #[test]
    fn test_validate_governance_disabled_carries_no_requirement() {
        // A disabled governance block (the admin surface is inert) must not require an admin_token.
        let gov = config::GovernanceCfg {
            enabled: false,
            db_path: "busbar-governance.db".to_string(),
            price_per_request_cents: 1,
            price_per_1k_tokens_cents: 0,
            admin_token: None,
        };
        assert!(
            validate_governance(&gov, None).is_ok(),
            "disabled governance carries no admin_token requirement"
        );
    }

    #[allow(deprecated)] // constructing AuthCfg with the legacy `_legacy_token` field in test
    fn auth_cfg(mode: &str) -> config::AuthCfg {
        config::AuthCfg {
            mode: mode.to_string(),
            _legacy_token: None,
            client_tokens: vec![],
        }
    }

    #[test]
    fn test_validate_governance_rejects_passthrough_combination() {
        // Regression: governance.enabled + auth.mode=passthrough is a self-contradictory deployment.
        // Governance supersedes passthrough (every request must resolve to an enabled virtual key),
        // so an operator who believes they are in passthrough silently rejects every caller lacking
        // a virtual key — a behaviour inversion that must fail loud at boot, not pass to a runtime
        // warning. Case-insensitive / whitespace-tolerant, matching AuthMode::from_config_str.
        for mode in ["passthrough", "  PassThrough "] {
            let gov = config::GovernanceCfg {
                enabled: true,
                db_path: "busbar-governance.db".to_string(),
                price_per_request_cents: 1,
                price_per_1k_tokens_cents: 0,
                admin_token: Some("an-operator-secret".to_string()),
            };
            let errs = validate_governance(&gov, Some(&auth_cfg(mode)))
                .expect_err("governance + passthrough must be rejected at boot");
            assert!(
                errs.iter()
                    .any(|e| e.contains("auth.mode=passthrough") && e.contains("governance")),
                "expected a governance+passthrough rejection for mode {mode:?}; got: {errs:?}"
            );
        }
    }

    #[test]
    fn test_validate_governance_allows_token_and_none_modes() {
        // governance + auth.mode=token (or none) is the supported pairing and must NOT be rejected
        // on the passthrough ground.
        for mode in ["token", "none"] {
            let gov = config::GovernanceCfg {
                enabled: true,
                db_path: "busbar-governance.db".to_string(),
                price_per_request_cents: 1,
                price_per_1k_tokens_cents: 0,
                admin_token: Some("an-operator-secret".to_string()),
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
            enabled: false,
            db_path: "busbar-governance.db".to_string(),
            price_per_request_cents: 1,
            price_per_1k_tokens_cents: 0,
            admin_token: None,
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
                fn record_debug(
                    &mut self,
                    field: &tracing::field::Field,
                    value: &dyn std::fmt::Debug,
                ) {
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
        // Regression (LOW #10): in passthrough mode forward.rs selects the upstream key as
        // `caller_token.unwrap_or(lane.api_key)`, so an UNAUTHENTICATED caller (no token) gets
        // busbar's OWN configured lane key (resolved from `api_key_env`) substituted upstream — a
        // credential leak. A passthrough deployment should forward the CALLER credential, never a
        // configured one. validate() must emit a prominent boot WARNING for any provider whose
        // `api_key_env` resolves to a NON-EMPTY value while auth.mode=passthrough. A legit Bedrock-
        // ingress passthrough provider authenticates per-request via SigV4 and resolves an EMPTY key,
        // so it must NOT warn — that is the second half of this test.
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
        cfg.auth = Some(make_auth("passthrough", vec![], None));

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
                .any(|m| m.contains("credential-leak") && m.contains("leaky")),
            "expected a passthrough credential-leak warning naming the 'leaky' provider; got: {msgs:?}"
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
        cfg.auth = Some(make_auth("passthrough", vec![], None));

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
            // RFC 6598 CGNAT shared address space (100.64.0.0/10) — routable in cloud VPCs.
            "https://100.64.0.1/",
            "https://100.64.1.1/",
            "https://100.127.255.255/",
            // IPv4-mapped IPv6 forms of internal targets MUST be blocked identically to the bare v4
            // form: the mapped branch reaches the same host, so a parity gap is an SSRF bypass.
            "https://[::ffff:100.64.0.1]/", // CGNAT (RFC 6598) via mapped IPv6
            "https://[::ffff:169.254.169.254]/", // IMDS via mapped IPv6
            "https://[::ffff:127.0.0.1]/",  // loopback via mapped IPv6
            "https://[::ffff:10.0.0.1]/",   // RFC-1918 private via mapped IPv6
            "https://[::ffff:169.254.1.1]:8443/", // link-local via mapped IPv6, with port
            // IPv4-COMPATIBLE IPv6 forms (`[::a.b.c.d]`, leading segment 0, NOT the `::ffff:` mapped
            // prefix). `to_ipv4_mapped()` returns None for these and the ULA/link-local masks miss
            // (segments()[0]==0), but `to_ipv4()` still yields the embedded v4 a connecting stack
            // routes internally — so they MUST be blocked identically to the bare v4 form.
            "https://[::127.0.0.1]/", // loopback via IPv4-compatible IPv6
            "https://[::169.254.169.254]/", // IMDS via IPv4-compatible IPv6
            "https://[::10.0.0.1]/v1", // RFC-1918 private via IPv4-compatible IPv6
            "https://[::100.64.0.1]:8443/", // CGNAT (RFC 6598) via IPv4-compatible IPv6, with port
            // Alternate IPv4 encodings the OS resolver maps to loopback / IMDS but `IpAddr` rejects.
            "https://2130706433/",          // decimal int = 127.0.0.1
            "https://0x7f000001/",          // hex = 127.0.0.1
            "https://017700000001/",        // octal-ish leading-zero = 127.0.0.1
            "https://127.1/",               // short dotted form = 127.0.0.1
            "https://10.0.1/",              // short dotted form = 10.0.0.1
            "https://2852039166/",          // decimal int = 169.254.169.254 (IMDS)
            "https://0x0a.0x00.0x00.0x01/", // per-octet hex
            // Trailing-dot FQDN-root spellings of IP literals. glibc getaddrinfo treats the trailing
            // dot as a rooted FQDN and still resolves the literal, but an IP+dot does NOT parse as
            // `IpAddr` and is not in METADATA_HOSTS — without the normalize-trailing-dot step these
            // slipped past every check (an SSRF credential-relay bypass).
            "https://127.0.0.1./",        // loopback, trailing dot
            "https://169.254.169.254./",  // IMDS, trailing dot
            "https://10.0.0.1./v1",       // RFC1918, trailing dot
            "https://192.168.1.1.:8443/", // RFC1918 with port, trailing dot
            // Percent-encoded host components. The `url` crate `reqwest` uses decodes these per
            // RFC 3986, so the guard must decode them too — otherwise the `%` defeats every check
            // and a blocked literal is smuggled past config validation (SSRF credential-relay).
            "https://169%2E254%2E169%2E254/", // IMDS, percent-encoded dots
            "https://127%2e0%2e0%2e1/",       // loopback, percent-encoded dots (lowercase hex)
            "https://%31%30.0.0.1/",          // "10.0.0.1" with first octet percent-encoded
            // The well-known loopback name and any `*.localhost` subdomain. RFC 6761 reserves the
            // whole `.localhost` TLD to loopback and glibc getaddrinfo resolves these to 127.0.0.1,
            // so a `base_url` using one would relay inbound API keys to a co-located loopback
            // service (SSRF credential-relay). Must be at parity with `host_is_internal`.
            "https://localhost/",
            "https://localhost:11434/v1",
            "https://localhost./", // trailing-dot FQDN-root spelling, normalized off
            "https://api.localhost/",
            "https://api.localhost:11434/v1",
            "https://service.internal.localhost/",
            "https://API.LOCALHOST/",    // case-insensitive
            "https://sub.localhost./v1", // subdomain + trailing dot
        ] {
            assert!(
                ssrf_blocked_host(blocked).is_some(),
                "expected '{blocked}' to be flagged as an SSRF target"
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
        for blocked in [
            "https://10.0.0.1\\x.allowed.com",
            "https://10.0.0.1\\x.allowed.com/v1/messages",
            "https://169.254.169.254\\a.b",
            "https://127.0.0.1\\evil.example.com/",
            "https://localhost\\x.allowed.com",
            // Mixed delimiters: the backslash must still terminate the authority before the slash.
            "https://10.0.0.1\\@allowed.com/path",
        ] {
            assert!(
                ssrf_blocked_host(blocked).is_some(),
                "expected '{blocked}' to be flagged: the backslash terminates the authority \
                 (reqwest rewrites \\ to /), so the real host is the internal target before it"
            );
        }
        // A full validate() pass must reject a base_url using the backslash-authority trick.
        let mut providers = HashMap::new();
        providers.insert(
            "p".to_string(),
            make_provider("anthropic", "https://10.0.0.1\\x.allowed.com", "API_KEY"),
        );
        let cfg = make_root_cfg(providers, HashMap::new(), HashMap::new());
        let errs = validate(&cfg).expect_err("backslash-authority base_url must fail validation");
        assert!(
            errs.iter()
                .any(|e| e.contains("blocked internal/metadata host") && e.contains("10.0.0.1")),
            "expected an SSRF/metadata-host error naming the real internal host; got: {errs:?}"
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
        let errs2 =
            validate(&cfg2).expect_err("a userinfo-flip path override must fail validation");
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
    fn test_ssrf_cgnat_boundary() {
        // 100.64.0.0/10 spans 100.64.0.0 .. 100.127.255.255. Just outside the /10 must be allowed:
        // 100.63.255.255 (below) and 100.128.0.1 (above) are public.
        assert!(ssrf_blocked_host("https://100.64.0.0/").is_some());
        assert!(ssrf_blocked_host("https://100.127.255.255/").is_some());
        assert!(
            ssrf_blocked_host("https://100.63.255.255/").is_none(),
            "100.63.255.255 is below the CGNAT /10 and is a public address"
        );
        assert!(
            ssrf_blocked_host("https://100.128.0.1/").is_none(),
            "100.128.0.1 is above the CGNAT /10 and is a public address"
        );
    }

    #[test]
    fn test_alternate_ipv4_encoding_detection() {
        // Alternate encodings of loopback / internal addresses are flagged.
        assert!(is_alternate_ipv4_encoding("2130706433")); // decimal 127.0.0.1
        assert!(is_alternate_ipv4_encoding("0x7f000001")); // hex
        assert!(is_alternate_ipv4_encoding("0X7F000001")); // hex, uppercase prefix
        assert!(is_alternate_ipv4_encoding("017700000001")); // leading-zero octal
        assert!(is_alternate_ipv4_encoding("127.1")); // short dotted
        assert!(is_alternate_ipv4_encoding("10.0.1")); // short dotted
        assert!(is_alternate_ipv4_encoding("0x7f.0.0.1")); // per-octet hex
        assert!(is_alternate_ipv4_encoding("0177.0.0.1")); // per-octet octal
                                                           // A canonical dotted-quad is NOT flagged here (handled by the IpAddr parse path).
        assert!(!is_alternate_ipv4_encoding("127.0.0.1"));
        assert!(!is_alternate_ipv4_encoding("8.8.8.8"));
        // A real DNS hostname is not flagged.
        assert!(!is_alternate_ipv4_encoding("api.openai.com"));
        assert!(!is_alternate_ipv4_encoding("example.com"));
        assert!(!is_alternate_ipv4_encoding(""));
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
