// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Matthew Jackson

use std::collections::{HashMap, HashSet};

use crate::config::RootCfg;

/// Maximum byte-length of an `affinity.header_name`. HTTP header field-names must be ASCII; an
/// over-long name is rejected at boot so a bad value cannot silently disable affinity at header
/// construction time (the `http` crate rejects non-ASCII/over-long names as an error).
const MAX_AFFINITY_HEADER_NAME_LEN: usize = 64;
// SSRF obfuscation-defense primitives shared with the observability/OTLP webhook guard — the
// byte-identical atoms live in one tested leaf so the two SSRF guards can never drift apart.
use crate::net_guard::{
    is_alternate_ipv4_encoding, is_cgnat_shared_v4, is_link_local_v6, is_unique_local_v6,
};

/// Validate the loaded configuration and collect all errors at once.
/// Returns Ok(()) if valid; Err(Vec<String>) with all validation failures otherwise.
pub(crate) fn validate(cfg: &RootCfg) -> Result<(), Vec<String>> {
    let mut errors = Vec::new();

    // The metadata host-lists are matched by EXACT IP/hostname (see `host_matches_any`); a CIDR/slash
    // entry silently never matches — a confusing no-op. Reject any `/`-bearing entry at boot so a bad
    // config fails fast. Covers the two global lists here and each provider's list inside the loop.
    reject_cidr_metadata_entries(
        "security.blocked_metadata_hosts",
        &cfg.blocked_metadata_hosts,
        &mut errors,
    );
    reject_cidr_metadata_entries(
        "security.allow_metadata_hosts",
        &cfg.allow_metadata_hosts,
        &mut errors,
    );

    // The reasoning effort table drives word<->number projection at the egress seam (the
    // cross-protocol thinking carry). A zero entry would project thinking budgets below every
    // provider minimum (Anthropic floors at 1024) and a non-ascending table makes bucketization
    // non-monotonic (a LARGER numeric budget mapping back to a SMALLER effort word). Reject both
    // at boot rather than ship a table that silently corrupts the mapping.
    {
        let b = cfg.limits.reasoning_effort_budgets;
        if b.minimal == 0 || b.low == 0 || b.medium == 0 || b.high == 0 {
            errors.push(format!(
                "limits.reasoning_effort_budgets entries must be > 0 (got {}/{}/{}/{})",
                b.minimal, b.low, b.medium, b.high
            ));
        }
        if !(b.minimal <= b.low && b.low <= b.medium && b.medium <= b.high) {
            errors.push(format!(
                "limits.reasoning_effort_budgets must be ascending (minimal <= low <= medium <= high); got {}/{}/{}/{}",
                b.minimal, b.low, b.medium, b.high
            ));
        }
    }

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
        // `attempt_timeout_ms: 0` would race a zero-duration `tokio::time::timeout` against
        // `req.send()` — the timer wins before the connection is even attempted, so EVERY attempt
        // on the lane "times out" instantly and the lane is permanently un-usable (breaker-tripped
        // on first touch) with no boot diagnostic. The same fail-loud rule as max_concurrent:0.
        // Disabling the cap is expressed by omitting the field, not by 0.
        if model_cfg.attempt_timeout_ms == Some(0) {
            errors.push(format!(
                "model '{}' has attempt_timeout_ms: 0; a zero cap fails every attempt instantly — use a positive millisecond value, or omit it to disable the per-attempt cap",
                model_name
            ));
        }
        // `upstream_model`, when set, is sent to the provider as the wire model id — an empty or
        // whitespace-only override would put a blank model on the wire (a guaranteed upstream 400/404)
        // with no boot diagnostic. Reject it loudly; omit the field to fall back to the config key.
        if let Some(um) = &model_cfg.upstream_model {
            if um.trim().is_empty() {
                errors.push(format!(
                    "model '{}' has an empty upstream_model; set a non-empty provider model id, or omit it to use the config key",
                    model_name
                ));
            }
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
        // The provider's `protocol` selects a built-in `Protocol` from the registry at lane
        // construction. An unknown protocol used to escape this multi-error collection entirely and
        // surface as a lone `die()` deep in `main.rs` (lane build) — so an operator with several
        // config mistakes saw only the first one. Validate it HERE against the single source of truth
        // (`proto::KNOWN_PROTOCOLS`, the same list `ProtocolRegistry::with_builtins` builds from) so a
        // bad protocol is collected alongside every other error. `main.rs`'s `die()` remains a
        // defensive (now unreachable) backstop.
        if !crate::proto::KNOWN_PROTOCOLS.contains(&provider_cfg.protocol.as_str()) {
            errors.push(format!(
                "provider '{}' has unknown protocol '{}': must be one of: {}",
                provider_name,
                provider_cfg.protocol,
                crate::proto::KNOWN_PROTOCOLS.join(", ")
            ));
        }

        // Per-provider active-health-probe settings. `interval_secs`/`timeout_secs` are floored at 1
        // by the prober at use, but a literal 0 in config signals operator confusion (a 0 interval/
        // timeout is never what's intended); reject it at boot so the config is honest about what
        // runs — mirroring the global health.default_probe_* checks in validate_limits.
        if let Some(health) = &provider_cfg.health {
            if health.interval_secs == Some(0) {
                errors.push(format!(
                    "provider '{}' health.interval_secs must be >= 1 (got 0)",
                    provider_name
                ));
            }
            if health.timeout_secs == Some(0) {
                errors.push(format!(
                    "provider '{}' health.timeout_secs must be >= 1 (got 0)",
                    provider_name
                ));
            }
        }

        for (code, mapped_class) in &provider_cfg.error_map {
            if crate::config::status_class_from_str(mapped_class).is_none() {
                errors.push(format!(
                    "provider '{}' error_map code '{}': invalid StatusClass '{}', must be one of: rate_limit, overloaded, server_error, timeout, network, auth, billing, client_error, context_length",
                    provider_name, code, mapped_class
                ));
            }
        }

        // The optional auth-style override (`bearer` / `api-key`) is now a `ProviderAuth` enum, so an
        // invalid spelling is rejected at deserialize time — no hand-check needed here.

        // The resolved base_url is the actual upstream target for signed (API-key-bearing) calls.
        // It is operator config (a client never chooses a provider URL — it picks a model NAME that
        // maps through a pool to an operator URL), so there is no client-driven SSRF. Two startup
        // rules apply:
        //
        // SCHEME — keyed off whether the host is PRIVATE/LOOPBACK, not off a flag. A PUBLIC host MUST
        // use `https://` (cleartext would leak the API key on the wire to an off-box wiretap); a
        // PRIVATE/LOOPBACK host (a local Ollama / vLLM / LM Studio on `localhost`, `127.0.0.1`,
        // RFC-1918, or a Tailscale CGNAT address) MAY use plain `http://` — local models rarely
        // terminate TLS and there is no off-box hop to wiretap. So `http://localhost:11434` and
        // `http://10.0.0.5:8000` validate with NO flag, while `http://api.example.com` is rejected.
        // The allow-overrides for THIS provider: the union of its own `allow_metadata_hosts` and the
        // global `security.allow_metadata_hosts`. A host on the denylist is unblocked iff it appears
        // in this union (or `allow_all_metadata` is set). Built once and passed to both the base_url
        // and the path-override SSRF checks below so the two reason over the identical carve-out set.
        reject_cidr_metadata_entries(
            &format!("provider '{provider_name}' allow_metadata_hosts"),
            &provider_cfg.allow_metadata_hosts,
            &mut errors,
        );
        let allow_overrides: Vec<String> = provider_cfg
            .allow_metadata_hosts
            .iter()
            .chain(cfg.allow_metadata_hosts.iter())
            .cloned()
            .collect();

        let base_url = &provider_cfg.base_url;
        let host_for_scheme = extract_normalized_host(base_url);
        let host_is_local = host_for_scheme
            .as_deref()
            .map(host_is_private_or_loopback)
            .unwrap_or(false);
        let scheme_ok =
            base_url.starts_with("https://") || (host_is_local && base_url.starts_with("http://"));
        if !scheme_ok {
            errors.push(if base_url.starts_with("http://") {
                // An http:// scheme that failed the check ⇒ the host is public (or unparseable):
                // plaintext to a public host would leak the key.
                format!(
                    "provider '{}' base_url must use https for a public host (got '{}'); plaintext http is permitted only for a private/loopback local-model upstream",
                    provider_name, base_url
                )
            } else {
                format!(
                    "provider '{}' base_url must use http or https (got '{}')",
                    provider_name, base_url
                )
            });
        } else if let Some(host) = ssrf_blocked_host(
            base_url,
            &allow_overrides,
            cfg.allow_all_metadata,
            &cfg.blocked_metadata_hosts,
        ) {
            // SSRF — block the cloud-metadata DENYLIST (hardcoded + operator additions). A passing
            // scheme alone does not stop SSRF: `https://169.254.169.254/`, `http://100.100.100.200/`,
            // `https://metadata.google.internal/`, etc. point busbar's key-bearing traffic at a
            // credential-leaking metadata service. Everything NOT on the denylist (loopback, RFC-1918,
            // CGNAT, public) is allowed — so local models just work. The three escape hatches (this
            // provider's `allow_metadata_hosts`, the global `security.allow_metadata_hosts`, and the
            // nuclear `security.allow_all_metadata`) carve exceptions (then `ssrf_blocked_host`
            // returns None).
            errors.push(format!(
                "provider '{}' base_url '{}' targets a blocked cloud-metadata host '{}' (cloud-metadata/IMDS endpoints are denied; to override add the host to this provider's allow_metadata_hosts, or security.allow_metadata_hosts to unblock it for all providers, or set security.allow_all_metadata: true to disable the guard entirely — and security.blocked_metadata_hosts extends the denylist)",
                provider_name, base_url, host
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
            } else if scheme_ok {
                let composed = format!("{}{}", provider_cfg.base_url, path);
                if let Some(host) = ssrf_blocked_host(
                    &composed,
                    &allow_overrides,
                    cfg.allow_all_metadata,
                    &cfg.blocked_metadata_hosts,
                ) {
                    errors.push(format!(
                        "provider '{}' base_url+path '{}' targets a blocked cloud-metadata host '{}' (cloud-metadata/IMDS endpoints are denied; to override add the host to this provider's allow_metadata_hosts, or security.allow_metadata_hosts, or set security.allow_all_metadata: true)",
                        provider_name, composed, host
                    ));
                }
            }
        }
    }

    // Rule 2 & 3: Validate each pool's members
    for (pool_name, pool_cfg) in &cfg.pools {
        let mut member_protocols: HashSet<&str> = HashSet::new();

        // A pool with NO members parses fine but is permanently un-routable: the selector has zero
        // candidates, so every request to the pool exhausts immediately and the forward loop returns
        // a generic 503 with a misleading "overloaded" message — the pool boots and then 503s every
        // request, with no boot diagnostic. This is the empty-set twin of the per-member
        // weight:0 / max_concurrent:0 / breaker n:0 fail-loud guards: reject it here so the operator
        // learns at startup that the pool can never serve a request, rather than diagnosing it from
        // a runtime "overloaded" that points at nothing.
        if pool_cfg.members.is_empty() {
            errors.push(format!(
                "pool '{}' has no members; a pool with an empty member list is un-routable — every request to it 503s with a misleading 'overloaded' message. Add at least one member, or remove the pool",
                pool_name
            ));
        }

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
            // `cost_per_mtok` drives the native `cheapest` policy's ascending sort. A NaN value makes
            // that sort's comparator non-total (NaN compares unordered, so the ordering is undefined
            // and a member can be silently mis-ranked), and a NEGATIVE cost is nonsensical and would
            // sort ahead of every legitimate member. Reject both at boot rather than ship a broken
            // ranking. (An UNSET cost is fine — it's inert and only the `cheapest` policy reads it.)
            if let Some(cost) = member.cost_per_mtok {
                if !cost.is_finite() || cost < 0.0 {
                    errors.push(format!(
                        "pool '{}' member '{}' cost_per_mtok must be a finite, non-negative number (got {}); it drives the 'cheapest' policy's sort, which a NaN or negative value corrupts",
                        pool_name, member.target, cost
                    ));
                }
            }
            // Member-level `attempt_timeout_ms: 0` — same instant-fail foot-gun as the model-level
            // check above, but the member override is consulted FIRST by the engine, so a zero here
            // poisons the member even when the model's own value is sane. Same fail-loud rule.
            if member.attempt_timeout_ms == Some(0) {
                errors.push(format!(
                    "pool '{}' member '{}' has attempt_timeout_ms: 0; a zero cap fails every attempt instantly — use a positive millisecond value, or omit it to inherit the model's setting",
                    pool_name, member.target
                ));
            }
            // Resolve the member target. `model_protocols` only holds models whose provider
            // resolved (the model loop above skips a model whose provider is unknown), so a bare
            // `!model_protocols.contains_key` lumps two distinct failures under one misleading
            // "unknown model" message: a target that names NO configured model, and a target that
            // DOES name a configured model whose `provider` is unresolvable (already reported by the
            // model loop). Distinguish them with the `model_names` set (every configured model name)
            // so the operator sees the accurate diagnostic — "unknown model" only when the model is
            // genuinely absent, and an unresolvable-provider message that points at the real fault
            // otherwise.
            if let Some(&protocol) = model_protocols.get(member.target.as_str()) {
                // Collect protocol for heterogeneity check (only for fully-resolved members).
                member_protocols.insert(protocol);
            } else if model_names.contains(member.target.as_str()) {
                // The model exists but its provider did not resolve (the model loop already pushed
                // the `references unknown provider` error for it). Emit a member-level message that
                // names the real cause rather than claiming the model is undefined.
                errors.push(format!(
                    "pool '{}' member '{}' references model '{}', which is defined but whose provider is unresolvable; fix that model's provider reference (the model's 'references unknown provider' error is reported separately)",
                    pool_name, member.target, member.target
                ));
            } else {
                errors.push(format!(
                    "pool '{}' references unknown model '{}'",
                    pool_name, member.target
                ));
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
                if trip.window_secs == 0 {
                    errors.push(format!(
                        "pool '{}' breaker trip.window_secs must be >= 1 (got 0)",
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
                        if trip.consecutive_n == 0 {
                            errors.push(format!(
                                "pool '{}' breaker trip.consecutive_n must be >= 1 for consecutive mode (got 0)",
                                pool_name
                            ));
                        }
                    }
                }
            }
        }

        // Rule 6b: Validate the per-pool failover budget. `failover.timeout_secs == 0` is the exact
        // twin of the `max_concurrent: 0` / breaker `window_s: 0` foot-guns: `RequestCtx::new(0)` sets
        // `deadline = start.saturating_add(0) == start`, and the failover loop checks
        // `request_ctx.expired(now())` at the TOP of the very first (primary) iteration with
        // `now >= deadline`. Because `now()` is read fresh and is always `>= start`, the primary attempt
        // is rejected with a 503 before it runs — the pool serves ZERO requests with no boot diagnostic.
        // Reject it loudly here, mirroring the rest of validate()'s fail-loud invariant. (`cap == 0` is
        // benign: the `0..=cap` loop still runs the primary once, so it is NOT rejected.)
        if let Some(failover) = &pool_cfg.failover {
            if failover.timeout_secs == 0 {
                errors.push(format!(
                    "pool '{}' failover.timeout_secs must be >= 1; a 0 budget rejects the primary attempt before it runs (every request 503s)",
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
                } else if target == *pool_name {
                    // Self-referential fallback (pool A -> fallback A): the runtime loop guard
                    // (forward.rs `RequestCtx::visited_pools`) silently terminates the chain on the
                    // re-entry, so the configured degraded-routing policy never actually engages — A
                    // exhausts, "falls back" to itself, is recognised as already-visited, and 503s.
                    // A fallback pointing at its own owner is never meaningful; reject it at boot
                    // rather than ship a self-cancelling policy with no diagnostic. (This is the
                    // length-1 case the general cycle walk below would also catch, called out
                    // explicitly for a precise diagnostic.)
                    errors.push(format!(
                        "pool '{}' on_exhausted references itself as its fallback pool ('{}'); a self-referential fallback never engages — the runtime loop guard terminates it on re-entry — so it 503s exactly as having no fallback would. Point it at a different pool or remove on_exhausted",
                        pool_name, target
                    ));
                }
            }
        }

        // Rule 8: `affinity.mode` is now an `AffinityMode` enum (`session` is the only variant), so an
        // unrecognized spelling is rejected at deserialize time — no hand-check needed there.
        // `affinity.header_name`, however, becomes an outbound/inbound HTTP HEADER NAME: a non-ASCII
        // or over-long value can't be a valid header field-name (the `http` crate rejects it at
        // header construction), so a bad value would either panic the build or silently disable
        // affinity. Validate it at boot: ASCII only, non-empty, and a sane <= 64-char bound.
        if let Some(affinity) = &pool_cfg.affinity {
            if let Some(header_name) = &affinity.header_name {
                if !header_name.is_ascii() {
                    errors.push(format!(
                        "pool '{}' affinity.header_name '{}' must be ASCII (an HTTP header field-name cannot contain non-ASCII bytes)",
                        pool_name, header_name
                    ));
                }
                if header_name.len() > MAX_AFFINITY_HEADER_NAME_LEN {
                    errors.push(format!(
                        "pool '{}' affinity.header_name is {} chars; must be <= {}",
                        pool_name,
                        header_name.len(),
                        MAX_AFFINITY_HEADER_NAME_LEN
                    ));
                }
            }
        }
    }

    // Rule 7b: Multi-hop fallback cycle (A -> B -> A, or any longer ring). The per-pool self-ref
    // check above (Rule 7) only catches the length-1 case; a chain that exits the originating pool
    // and loops back through one or more intermediaries is just as defeated at runtime — forward.rs's
    // `RequestCtx::visited_pools` guard terminates the walk the moment it re-enters an already-visited
    // pool, so the configured degraded-routing policy still collapses into a 503 with no boot
    // diagnostic. Detect it at startup by following each pool's resolved fallback edge until the chain
    // either ends (no on_exhausted / non-fallback action), hits a dangling target (already reported
    // by Rule 7), or revisits a pool. To report each distinct cycle EXACTLY ONCE (a 2-ring would
    // otherwise be reported from both members), emit only when the originating `pool_name` is the
    // lexicographically smallest member of the cycle it sits on.
    for pool_name in cfg.pools.keys() {
        // Walk the fallback chain from this pool, recording the ordered path. Stop at the first
        // repeat (the visited check is the terminator; the chain can be at most `pools.len()` long
        // before it must repeat). Names are owned because the resolved target lives inside the parsed
        // `OnExhausted::FallbackPool(String)`, which does not outlive the parse call.
        let mut path: Vec<String> = Vec::new();
        let mut cursor: String = pool_name.clone();
        loop {
            if path.contains(&cursor) {
                // `cursor` closes a cycle. Identify the cycle's members (from the first occurrence
                // of `cursor` in `path` to the end) and report only if this originating pool is the
                // smallest-named member, so each ring is reported once.
                let start = path.iter().position(|p| *p == cursor).unwrap_or(0);
                let ring = &path[start..];
                let min_member = ring
                    .iter()
                    .min()
                    .map(String::as_str)
                    .unwrap_or(cursor.as_str());
                if pool_name.as_str() == min_member && ring.len() > 1 {
                    let mut display: Vec<&str> = ring.iter().map(String::as_str).collect();
                    display.push(cursor.as_str()); // close the ring visually (A -> B -> A)
                    errors.push(format!(
                        "fallback_pool cycle detected: {}; on_exhausted fallback chains must not loop — the runtime loop guard terminates a cycle on re-entry, so every pool in the ring 503s instead of degrading. Break the cycle (point one pool at a non-looping pool or remove its on_exhausted)",
                        display.join(" -> ")
                    ));
                }
                break;
            }
            // Resolve this pool's fallback edge, if any, before pushing so we can stop cleanly.
            let Some(next) = resolve_fallback_target(cfg, &cursor) else {
                break; // chain ends here (no fallback or non-fallback action)
            };
            path.push(cursor);
            // A dangling target was already reported by Rule 7; do not chase it (it is not a pool).
            if !cfg.pools.contains_key(&next) {
                break;
            }
            cursor = next;
        }
    }

    // Rule (routing/webhook): a `route: webhook` pool MUST carry a `policy.url`, and that URL MUST
    // pass the routing-webhook SSRF guard (the OTLP loopback carve-out: loopback/localhost sidecars
    // allowed, link-local/IMDS/RFC1918/CGNAT/cloud-metadata blocked; plaintext http:// only on
    // loopback). Rejected at startup rather than silently degrading to SWRR at runtime, so an operator
    // who asked for a webhook policy learns immediately that it is misconfigured.
    for (pool_name, pool_cfg) in &cfg.pools {
        if pool_cfg.route != crate::config::RouteKind::Webhook {
            continue;
        }
        let url = pool_cfg.policy.as_ref().and_then(|p| p.url.as_deref());
        if let Err(msg) = crate::observability::validate_routing_webhook_url(url) {
            errors.push(format!(
                "pool '{pool_name}' route: webhook is invalid: {msg}"
            ));
        }
    }

    // Rule (routing/socket): a `route: socket` pool MUST carry a non-empty, ABSOLUTE `policy.socket`
    // path (a relative path silently depends on busbar's CWD — a classic deploy footgun). The socket
    // FILE may not exist yet (the hook binary can start after busbar; connection is lazy), so only
    // the path's shape is validated. Rejected at startup rather than silently degrading to SWRR, so
    // an operator who asked for a socket hook learns immediately that it is misconfigured. On
    // non-unix platforms the transport is unavailable — also a startup error, pointing at webhook.
    for (pool_name, pool_cfg) in &cfg.pools {
        if pool_cfg.route != crate::config::RouteKind::Socket {
            continue;
        }
        if !cfg!(unix) {
            errors.push(format!(
                "pool '{pool_name}' route: socket is not available on this platform (Unix domain \
                 sockets); use route: webhook for an out-of-process routing hook here"
            ));
            continue;
        }
        match pool_cfg.policy.as_ref().and_then(|p| p.socket.as_deref()) {
            None | Some("") => errors.push(format!(
                "pool '{pool_name}' route: socket requires policy.socket (the hook binary's Unix \
                 domain socket path)"
            )),
            Some(path) if !path.starts_with('/') => errors.push(format!(
                "pool '{pool_name}' policy.socket must be an absolute path (got '{path}'); a \
                 relative path depends on busbar's working directory"
            )),
            Some(_) => {}
        }
    }

    // Rule 5: Validate auth-block semantics. `auth.mode` is now a parsed `AuthMode` enum (an invalid
    // spelling fails at deserialize, so there is no longer an unknown-mode arm here). The legacy
    // single-token `token:` field was removed in 1.0.0; `AuthCfg` is now `deny_unknown_fields`, so a
    // stale `token:` key fails AT PARSE with serde's "unknown field `token`" — no validate-time check
    // needed (and no silent credential drop).
    if let Some(auth) = &cfg.auth {
        match auth.mode {
            crate::auth::AuthMode::Token => {
                // Token mode with no client tokens rejects 100% of requests with no startup signal —
                // the locked-out mirror of the loudly-warned open-relay (mode: none) case.
                if effective_client_tokens_empty(auth) {
                    errors.push(
                        "auth.mode is 'token' but no client_tokens are configured; token mode requires at least one client token (otherwise every request is rejected)".to_string(),
                    );
                }
            }
            // Passthrough carries no token-allowlist requirement, but a configured upstream key on a
            // passthrough provider is a MISCONFIGURATION worth flagging. forward.rs selects the upstream
            // key as `caller_token.unwrap_or("")`: an UNAUTHENTICATED caller in passthrough mode
            // forwards an EMPTY credential (the provider returns 401/403 attributed to the caller), NOT
            // busbar's configured lane key. A passthrough deployment is meant to forward the CALLER's
            // credential, never a configured one — so a provider whose `api_key_env` resolves to a
            // NON-EMPTY value is a config smell (a key busbar will never use on this provider).
            //
            // We WARN (not hard-reject): a legit Bedrock-ingress passthrough provider authenticates
            // per-request with SigV4 from the AWS credential chain, so its `api_key_env` normally
            // resolves EMPTY and never trips this — but an operator may also have a deliberate
            // static-key fallback provider, and rejecting would break that. Mirror main.rs's
            // single env read (`std::env::var(api_key_env)`) so the guard sees the SAME value the
            // lane will, and surface a prominent boot warning naming each offending provider. The
            // resolved `_legacy_api_key` is always None (config::resolve discards+warns on it), so
            // `api_key_env` is the only key source to check.
            crate::auth::AuthMode::Passthrough => {
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
            crate::auth::AuthMode::None => {
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

    // Operational-limit sanity checks (NEVER CODED CAPS). A 0 or absurd value here would break the
    // gateway rather than tune it; reject loudly at boot. Deliberately permissive — only the few
    // values where 0/absurd is a foot-gun are constrained (e.g. `max_inbound_concurrent` accepts ANY
    // usize incl. 0, the unlimited default).
    validate_limits(&cfg.limits, &mut errors);

    if errors.is_empty() {
        Ok(())
    } else {
        Err(errors)
    }
}

/// Range-check the resolved operational limits. Pushes a message per violation (collect-all, like the
/// rest of `validate`). The bounds are intentionally loose: each default is the production working
/// value, so we only reject values that would make a subsystem non-functional.
fn validate_limits(limits: &crate::config::LimitsResolved, errors: &mut Vec<String>) {
    use crate::config::{REQUEST_BODY_MAX_BYTES_CEIL, REQUEST_BODY_MAX_BYTES_FLOOR};

    // Timeouts must be >= 1s — a 0s timeout fires instantly and breaks the path it guards.
    if limits.upstream_request_timeout_secs < 1 {
        errors.push(
            "limits.upstream_request_timeout_secs must be >= 1 (0 would time out every upstream call \
             instantly)"
                .to_string(),
        );
    }
    if limits.tls_handshake_timeout_secs < 1 {
        errors.push(
            "limits.tls_handshake_timeout_secs must be >= 1 (0 would abort every TLS handshake)"
                .to_string(),
        );
    }
    if limits.webhook_delivery_timeout_secs < 1 {
        errors.push(
            "observability.webhook_delivery_timeout_secs must be >= 1 (0 would abort every webhook \
             delivery)"
                .to_string(),
        );
    }
    if limits.max_inflight_webhook_deliveries < 1 {
        errors.push(
            "observability.max_inflight_webhook_deliveries must be >= 1 (a 0-permit semaphore admits \
             nothing, silently dropping every webhook delivery)"
                .to_string(),
        );
    }
    // The honored-Retry-After ceiling and hard-down cooldown must be >= 1s to be meaningful.
    if limits.max_honored_retry_after_secs < 1 {
        errors.push(
            "limits.max_honored_retry_after_secs must be >= 1 (a 0 ceiling would clamp every honored \
             Retry-After to 0)"
                .to_string(),
        );
    }
    if limits.hard_down_cooldown_secs < 1 {
        errors.push(
            "limits.hard_down_cooldown_secs must be >= 1 (a 0 sticky cooldown would re-ready a \
             hard-down lane immediately)"
                .to_string(),
        );
    }
    // Request-body cap: too small rejects legitimate requests; absurdly large is a memory foot-gun
    // (the body is buffered per request). Bound it to a sane window.
    if limits.request_body_max_bytes < REQUEST_BODY_MAX_BYTES_FLOOR {
        errors.push(format!(
            "limits.request_body_max_bytes ({}) is below the {REQUEST_BODY_MAX_BYTES_FLOOR}-byte floor \
             — too small to admit a minimal request",
            limits.request_body_max_bytes
        ));
    }
    if limits.request_body_max_bytes > REQUEST_BODY_MAX_BYTES_CEIL {
        errors.push(format!(
            "limits.request_body_max_bytes ({}) exceeds the {REQUEST_BODY_MAX_BYTES_CEIL}-byte ceiling \
             — the body is buffered per request, so this risks memory exhaustion",
            limits.request_body_max_bytes
        ));
    }
    // The error-body buffer cap must be >= 1 byte (0 would buffer nothing, losing every upstream
    // error body). The pool-idle, gauge-limit, and probe defaults are all safe at any value (0
    // pool-idle = no keep-alive; 0 gauge limit = emit none). `governance.rate_sweep_interval == 0` is
    // rejected separately in `validate_governance` — a 0 there would disable the rate-map eviction
    // sweep, so it is a hard error rather than a silently-accepted default.
    if limits.upstream_error_body_max_bytes < 1 {
        errors.push(
            "limits.upstream_error_body_max_bytes must be >= 1 (0 would buffer no upstream error body)"
                .to_string(),
        );
    }
    // The translation-injected max_tokens fallback must be > 0 (a 0 is rejected upstream). This is the
    // GLOBAL fallback; the per-model `default_max_tokens: 0` case is already rejected in the model loop.
    if limits.default_max_tokens < 1 {
        errors.push(
            "limits.default_max_tokens must be >= 1 (0 would be injected verbatim and rejected upstream)"
                .to_string(),
        );
    }
    // SQLite busy_timeout must be >= 0 (rusqlite rejects negative). 0 means "fail immediately on lock"
    // — degraded but not broken, so only reject a negative value.
    if limits.sqlite_busy_timeout_ms < 0 {
        errors.push(format!(
            "governance.sqlite_busy_timeout_ms ({}) must be >= 0",
            limits.sqlite_busy_timeout_ms
        ));
    }
    // Probe fallbacks: the prober floors them at 1 at use, but a 0 here signals operator confusion;
    // reject so the config is honest about what runs.
    if limits.default_probe_interval_secs < 1 {
        errors.push("health.default_probe_interval_secs must be >= 1".to_string());
    }
    if limits.default_probe_timeout_secs < 1 {
        errors.push("health.default_probe_timeout_secs must be >= 1".to_string());
    }
    if limits.default_policy_timeout_ms < 1 {
        errors.push(
            "routing.default_policy_timeout_ms must be >= 1 (0 would make every policy decision time \
             out instantly)"
                .to_string(),
        );
    }
    // NOTE: `max_inbound_concurrent` is intentionally UNCONSTRAINED — any usize including 0 (the
    // unlimited default) is valid.
}

/// Validate the optional governance block (read separately from the resolved `RootCfg`, so it
/// cannot ride along in `validate(&RootCfg)`). Called from `config::resolve`, whose `Err(Vec<String>)`
/// is surfaced as a fail-loud boot error — the same channel `validate` uses.
///
/// When `governance.enabled` is true but `admin_token` is unset, `GovState::admin_token_hash()` returns
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
    // WARN (not a hard error): with `price_per_request_cents == 0`, a request that consumes no
    // tokens (or a key priced solely on a flat fee) accrues a ZERO charge, so the per-request
    // budget admission gate never closes — a key with `max_budget_cents` set is admitted without
    // bound on request COUNT (only token-priced spend counts). Request-count admission control
    // therefore requires a non-zero flat fee when a budget is in play. This is a deliberate
    // configuration (a deployment may price purely by tokens), so we warn rather than reject.
    if governance.enabled && governance.price_per_request_cents == 0 {
        tracing::warn!(
            "governance.price_per_request_cents is 0: a zero flat fee means a request can accrue a \
             zero charge, so per-request COUNT-based budget admission never closes — a virtual key \
             with max_budget_cents set is not bounded on request count (only token-priced spend is \
             counted). If you rely on a budget to cap request volume, set a non-zero \
             price_per_request_cents."
        );
    }
    if governance.enabled && auth.is_some_and(|a| a.mode == crate::auth::AuthMode::Passthrough) {
        errors.push(
            "governance.enabled is true together with auth.mode=passthrough; governance supersedes passthrough (every request must resolve to an enabled virtual key), so passthrough's accept-and-forward-caller-credential semantics are NOT honoured and every caller without a virtual key is silently rejected. This combination is unsupported; set auth.mode=token (or omit the auth block) alongside governance.".to_string(),
        );
    }
    // A 0 sweep interval would disable the rate-map's idle-entry eviction sweep entirely — it rides on
    // the non-obvious `u32::is_multiple_of(0) == false`, so the sweep never fires and entries for silent
    // keys stay resident until restart. Rate limiting itself stays correct (`check_rate`'s per-key
    // stale-reset is independent of the sweep), but the surprising "0 == disabled" semantics are a
    // footgun. Reject it fail-loud, consistent with every other "must be >= 1" cadence in this validator.
    if governance.rate_sweep_interval == 0 {
        errors.push(
            "governance.rate_sweep_interval is 0; must be >= 1. A value of 0 disables the rate-map idle-entry sweep, leaking entries for silent keys until restart. The default is 256 (sweep every 256 admissions); use a larger value to make sweeps rarer.".to_string(),
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

/// Resolve the single `on_exhausted: fallback_pool:<name>` edge out of `pool_name`, if it has one.
/// Returns `Some(target)` only for a well-formed FallbackPool action; `None` for a pool with no
/// `on_exhausted`, a non-fallback action (reject/least_bad), or an unparseable action (already
/// rejected elsewhere at parse time). The returned name is owned because it lives inside the parsed
/// `OnExhausted` value, which does not outlive this call. Used by the Rule 7b fallback-cycle walk.
fn resolve_fallback_target(cfg: &RootCfg, pool_name: &str) -> Option<String> {
    let on_exhausted = cfg.pools.get(pool_name)?.on_exhausted.as_ref()?;
    match crate::config::OnExhausted::parse(&on_exhausted.action) {
        Ok(crate::config::OnExhausted::FallbackPool(target)) => Some(target),
        Ok(_) | Err(_) => None,
    }
}

/// True when an `AuthCfg` resolves to an empty client-token allowlist. As of 1.0.0 the legacy
/// `token:` field was removed (setting it is now a hard parse error via `deny_unknown_fields`), so
/// the effective set is empty iff `client_tokens` is empty.
fn effective_client_tokens_empty(auth: &crate::config::AuthCfg) -> bool {
    auth.client_tokens.is_empty()
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

/// Extract the connect host from a `base_url`, normalized the SAME way the connecting stack
/// (reqwest's `url` crate + glibc getaddrinfo) sees it: scheme stripped, backslashes folded to
/// forward slashes, authority isolated, userinfo dropped, port removed (IPv6 brackets handled),
/// percent-decoded, and a single trailing FQDN-root dot removed. Returns the lowercased-comparison
/// is left to the caller; the returned string preserves original case but with the above
/// normalizations applied. `None` when the scheme is not http/https or the host is empty.
///
/// Centralizing this means the SSRF metadata check and the private/loopback scheme classifier both
/// reason over the EXACT host the connecting stack will, so neither can be bypassed by an authority
/// trick (backslash, userinfo flip, percent-encoded dots, trailing dot) that only one of them
/// normalized away.
fn extract_normalized_host(url: &str) -> Option<String> {
    // Strip the scheme. The host extraction is scheme-agnostic; accept either prefix so an
    // `http://` upstream is still run through the metadata block.
    let rest = url
        .strip_prefix("https://")
        .or_else(|| url.strip_prefix("http://"))?;
    // Normalize backslashes to forward slashes BEFORE splitting the authority. `https` is a WHATWG
    // "special" scheme, so reqwest's `url` crate converts every `\` to `/` while parsing — meaning a
    // `base_url` like `https://10.0.0.1\x.allowed.com` is parsed by reqwest with authority `10.0.0.1`
    // (the `\` terminates the authority exactly as `/` would) and then CONNECTS to `10.0.0.1` /
    // `169.254.169.254`, even though a hand-parser that split only on `['/', '?', '#']` would see the
    // whole `10.0.0.1\x.allowed.com` as the host — an SSRF credential-relay bypass. Mirroring
    // reqwest's `\`→`/` rewrite here makes the guard see the SAME authority boundary the connecting
    // stack will, closing the bypass.
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

    // Percent-decode the host BEFORE returning. The guard operates on the literal config string, but
    // the `url` crate reqwest uses percent-decodes host components per RFC 3986 at request time — so
    // a `base_url` like `https://169%2E254%2E169%2E254/` would pass every check (not a parseable
    // `IpAddr`, and the `%` defeats `is_alternate_ipv4_encoding`) yet resolve to the IMDS target
    // downstream. Decoding here makes the safety property independent of URL-library details.
    let host_decoded = percent_decode_host(host);

    // Normalize a single trailing FQDN-root dot. glibc getaddrinfo treats a trailing dot as a rooted
    // FQDN and still resolves the literal it precedes — so `169.254.169.254.` connects to exactly the
    // IMDS target the bare form does. Without stripping, an IP-literal+dot does NOT parse as
    // `IpAddr`, defeating every range check.
    let host = host_decoded
        .strip_suffix('.')
        .unwrap_or(host_decoded.as_str());

    Some(host.to_string())
}

/// True when `host` (already normalized by [`extract_normalized_host`]) is a private, loopback, or
/// link-local target — the legitimate LOCAL-MODEL destinations (Ollama / vLLM / LM Studio on
/// `localhost`, `127.0.0.1`, RFC-1918, or a Tailscale CGNAT address). Used to KEY THE SCHEME RULE:
/// plaintext `http://` is permitted to these (a local model rarely terminates TLS and there is no
/// off-box wiretap), while a PUBLIC host must use `https://` (cleartext would leak the API key on the
/// wire). This is NOT the SSRF decision — under the metadata-denylist model these hosts are ALLOWED
/// as upstreams; this predicate only governs whether plaintext is acceptable for the hop.
fn host_is_private_or_loopback(host: &str) -> bool {
    use std::net::IpAddr;

    let host_lc = host.to_ascii_lowercase();
    // `localhost` and the `*.localhost` TLD (RFC 6761) resolve to loopback.
    if host_lc == "localhost"
        || host_lc
            .rsplit_once('.')
            .is_some_and(|(_, tld)| tld == "localhost")
    {
        return true;
    }
    // Obfuscated IPv4 encodings that resolve to an internal address (decimal int, hex, octal, short
    // dotted) — treat as private so they at least don't get the public-host plaintext rejection on a
    // technicality. (They are an unusual way to spell a local model, but a connecting stack maps them
    // to an IPv4 target all the same.)
    if is_alternate_ipv4_encoding(host) {
        return true;
    }
    match host.parse::<IpAddr>() {
        Ok(IpAddr::V4(v4)) => {
            v4.is_loopback()        // 127.0.0.0/8
                || v4.is_private()  // 10/8, 172.16/12, 192.168/16
                || v4.is_link_local() // 169.254.0.0/16
                || v4.is_unspecified() // 0.0.0.0
                || is_cgnat_shared_v4(&v4) // 100.64.0.0/10 (RFC 6598 CGNAT, Tailscale)
        }
        Ok(IpAddr::V6(v6)) => {
            let embedded = v6.to_ipv4();
            v6.is_loopback()        // ::1
                || v6.is_unspecified() // ::
                || is_unique_local_v6(&v6) // fc00::/7
                || is_link_local_v6(&v6)   // fe80::/10
                || embedded.is_some_and(|m| {
                    m.is_loopback()
                        || m.is_private()
                        || m.is_link_local()
                        || m.is_unspecified()
                        || is_cgnat_shared_v4(&m)
                })
        }
        Err(_) => false,
    }
}

/// Push an error for every entry in a metadata host-list config key that contains a `/` (CIDR /
/// slash). These lists (`security.blocked_metadata_hosts`, `security.allow_metadata_hosts`, and each
/// provider's `allow_metadata_hosts`) are matched by EXACT IP/hostname via `host_matches_any` — a
/// CIDR like `169.254.0.0/16` never parses as an `Ipv4Addr` and never equals a connect-host string,
/// so it silently matches nothing (a confusing no-op that reads as a working rule). Reject it at boot
/// with a clear message naming the key + offending value, so the operator learns CIDR is unsupported
/// here and lists exact IPs/hostnames instead.
fn reject_cidr_metadata_entries(key: &str, entries: &[String], errors: &mut Vec<String>) {
    for entry in entries {
        if entry.contains('/') {
            errors.push(format!(
                "{key} entry '{entry}' contains '/' (CIDR is not supported here): these lists are matched by EXACT IP or hostname, so a CIDR/slash entry silently never matches and is a no-op. List exact IPs/hostnames instead (e.g. '169.254.169.254', not '169.254.0.0/16')"
            ));
        }
    }
}

/// True when the already-normalized `host` (as produced by [`extract_normalized_host`]) matches any
/// entry in `entries`, using the EXACT canonicalization the denylist block check uses for operator-
/// supplied `blocked_metadata_hosts`. This is shared by the allow-override path so an allow entry
/// unblocks every spelling of an IP the same way a block entry blocks every spelling:
///   * a hostname entry matches case-insensitively, trailing dot stripped;
///   * an IP-literal entry matches the parsed connect-host AND its IPv4-mapped/compatible-IPv6 and
///     alternate-encoding (decimal-int / hex / octal / short-dotted) spellings.
///
/// Empty / whitespace-only entries never match.
fn host_matches_any(host: &str, entries: &[String]) -> bool {
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    if entries.is_empty() {
        return false;
    }

    // Hostname / verbatim match (case-insensitive, trailing dot stripped on the entry).
    for entry in entries {
        let entry_norm = entry.trim().trim_end_matches('.');
        if !entry_norm.is_empty() && entry_norm.eq_ignore_ascii_case(host) {
            return true;
        }
    }

    // IP-literal entries: parse each once so an entry like `169.254.169.254` also matches this host's
    // mapped-IPv6 and alternate-encoding spellings, mirroring the block path's `extra_v4`/`extra_v6`.
    let entry_v4: Vec<Ipv4Addr> = entries
        .iter()
        .filter_map(|e| e.trim().trim_end_matches('.').parse::<Ipv4Addr>().ok())
        .collect();
    let entry_v6: Vec<Ipv6Addr> = entries
        .iter()
        .filter_map(|e| e.trim().trim_end_matches('.').parse::<Ipv6Addr>().ok())
        .collect();
    if entry_v4.is_empty() && entry_v6.is_empty() {
        return false;
    }

    // Alternate / obfuscated encodings of THIS host expand to a canonical v4 and re-check.
    if let Some(expanded) = expand_alternate_ipv4(host) {
        if entry_v4.contains(&expanded) {
            return true;
        }
    }

    match host.parse::<IpAddr>() {
        Ok(IpAddr::V4(v4)) => entry_v4.contains(&v4),
        Ok(IpAddr::V6(v6)) => {
            let embedded = v6.to_ipv4();
            entry_v6.contains(&v6) || embedded.is_some_and(|m| entry_v4.contains(&m))
        }
        Err(_) => false,
    }
}

/// Return `Some(host)` if the given URL targets a CLOUD-METADATA endpoint that must be blocked, else
/// `None`. This is the SSRF guard under the metadata-denylist model.
///
/// Threat model: a client can NEVER influence a provider `base_url` — it picks a model NAME, which
/// maps through an operator pool to an operator-configured URL. So there is no client-driven SSRF.
/// The ONLY real risk is an operator typo / templated-config accidentally pointing a key-bearing lane
/// at a credential-leaking metadata service. Therefore: block a comprehensive metadata DENYLIST and
/// ALLOW EVERYTHING ELSE — loopback, RFC-1918, CGNAT, and public are all legitimate upstreams (local
/// Ollama/vLLM "just works" with no flag).
///
/// The hardcoded denylist:
///   * link-local `169.254.0.0/16` — catches IMDS `169.254.169.254`, AWS ECS task-creds
///     `169.254.170.2`, Tencent `169.254.0.23`, and any other link-local metadata in one range
///     (nothing legitimate runs on link-local);
///   * `100.100.100.200` (Alibaba Cloud ECS, inside the otherwise-allowed CGNAT /10);
///   * `168.63.129.16` (Azure WireServer / platform);
///   * the EC2 IMDSv6 `fd00:ec2::254`;
///   * the metadata hostnames in `METADATA_HOSTS`.
///
/// All IP entries are matched through the SAME obfuscation defenses (IPv4-mapped/compatible IPv6,
/// decimal-int / hex / octal encoding, percent-encoded dots, trailing-dot FQDN), not just IMDS.
///
/// `extra_blocked` is `security.blocked_metadata_hosts` — operator additions APPENDED to the
/// hardcoded list (the answer to an unknown cloud's metadata IP/hostname).
///
/// Precedence (the LOCKED one-rule matrix): a host is blocked IFF
/// `!allow_all` AND on-denylist(hardcoded ∪ `extra_blocked`) AND NOT in `allow_overrides`.
///
/// * `allow_all` is `security.allow_all_metadata` — the nuclear override; when `true` the guard is
///   fully disabled and the function always returns `None`.
/// * `allow_overrides` is the UNION of the provider's `allow_metadata_hosts` and the global
///   `security.allow_metadata_hosts` — a surgical carve-out. An entry is matched with the SAME
///   canonicalization as the block check (an IP entry unblocks all its obfuscated spellings —
///   decimal-int, IPv4-mapped/compatible IPv6, trailing-dot — mirroring how a block entry blocks
///   all spellings; a hostname entry matches case-insensitively, trailing dot stripped). Allow
///   always wins: a host on the denylist that ALSO appears in `allow_overrides` is permitted.
fn ssrf_blocked_host(
    url: &str,
    allow_overrides: &[String],
    allow_all: bool,
    extra_blocked: &[String],
) -> Option<String> {
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    // Nuclear override: the metadata guard is disabled wholesale.
    if allow_all {
        return None;
    }

    let host = extract_normalized_host(url)?;
    let host = host.as_str();

    // Surgical allow-override: if THIS host matches any allow entry (with the same canonicalization
    // the block check uses), it is permitted regardless of the denylist. Computed up front so allow
    // unconditionally wins over every block arm below.
    if host_matches_any(host, allow_overrides) {
        return None;
    }

    // Cloud-metadata / IMDS hostnames (case-insensitive). The IPv4 / IPv6 metadata literals are
    // caught in the IP arms below; these are the DNS names a connecting stack would resolve.
    const METADATA_HOSTS: &[&str] = &[
        "metadata.google.internal",
        "metadata.internal",
        "metadata.tencentyun.com",
        "metadata.platformequinix.com",
        "instance-data",
        "instance-data.ec2.internal",
    ];
    let host_lc = host.to_ascii_lowercase();
    if METADATA_HOSTS.contains(&host_lc.as_str()) {
        return Some(host.to_string());
    }

    // Operator-supplied extensions to the denylist (`security.blocked_metadata_hosts`). Matched with
    // the SAME canonicalization the allow-override path uses (hostname case-insensitive; IP literal
    // matched against the parsed connect-host and its mapped-IPv6 / alternate-encoding spellings), so
    // an operator who writes `10.99.99.99` also blocks `[::ffff:10.99.99.99]` and the decimal-int
    // form. `host_matches_any` is the single shared canonicalizer for both allow and block.
    if host_matches_any(host, extra_blocked) {
        return Some(host.to_string());
    }

    // The hardcoded metadata IP literals.
    //  * link-local `169.254.0.0/16` (IMDS `169.254.169.254`, ECS `169.254.170.2`, Tencent
    //    `169.254.0.23`, …);
    //  * Alibaba `100.100.100.200`; Azure `168.63.129.16`; Oracle Cloud (OCI) `192.0.0.192`;
    //    EC2 IMDSv6 `fd00:ec2::254`.
    let imds_v6 = Ipv6Addr::new(0xfd00, 0x0ec2, 0, 0, 0, 0, 0, 0x254);
    let alibaba_v4 = Ipv4Addr::new(100, 100, 100, 200);
    let azure_v4 = Ipv4Addr::new(168, 63, 129, 16);
    // OCI's IMDS lives at the globally-routable-shaped `192.0.0.192` — NOT caught by link-local /
    // private / CGNAT / unspecified, so it needs an explicit literal like Alibaba/Azure.
    let oci_v4 = Ipv4Addr::new(192, 0, 0, 192);
    // Predicate: is this PARSED v4 address a hardcoded metadata target? (link-local /16 + the
    // non-link-local literals.)
    let is_metadata_v4 = |v4: &Ipv4Addr| -> bool {
        v4.is_link_local() || *v4 == alibaba_v4 || *v4 == azure_v4 || *v4 == oci_v4
    };

    // Alternate / non-canonical IPv4 encodings (decimal int `2852039166` = 169.254.169.254, hex,
    // octal, short dotted) that `IpAddr::from_str` rejects but the OS resolver still maps to an IPv4
    // target. Expand them to a canonical address and re-check against the metadata predicate, so an
    // obfuscated metadata literal is caught while a non-metadata obfuscated form (e.g. a decimal
    // loopback) is simply allowed (it is not a metadata target).
    if let Some(expanded) = expand_alternate_ipv4(host) {
        if is_metadata_v4(&expanded) {
            return Some(host.to_string());
        }
    }

    // Canonical IP-literal checks. A hostname that does not parse as an IP and is not in the lists
    // above is ALLOWED — private/loopback/CGNAT/public upstreams are all legitimate.
    let is_blocked = match host.parse::<IpAddr>() {
        Ok(IpAddr::V4(v4)) => is_metadata_v4(&v4),
        Ok(IpAddr::V6(v6)) => {
            // An IPv6 literal embedding an IPv4 address reaches the same v4 target as the bare form,
            // so apply the IDENTICAL metadata predicate to the embedded v4 (covers `[::ffff:a.b.c.d]`
            // mapped AND `[::a.b.c.d]` compatible via `to_ipv4()`).
            let embedded = v6.to_ipv4();
            v6 == imds_v6 || embedded.is_some_and(|m| is_metadata_v4(&m))
        }
        Err(_) => false,
    };

    is_blocked.then(|| host.to_string())
}

/// The hardcoded cloud-metadata denylist entries, as human-readable strings — the single source of
/// truth `ssrf_blocked_host` enforces, surfaced for the `--print-metadata-blocklist` CLI flag and the
/// startup count so `main.rs` does NOT duplicate the list. The CIDR / individual literals are spelled
/// the way an operator would recognize them; the obfuscation defenses (mapped-IPv6, decimal-int,
/// trailing-dot) apply to each but are not enumerated here.
pub(crate) fn metadata_denylist_entries() -> Vec<String> {
    [
        // Link-local /16 — IMDS 169.254.169.254, AWS ECS task-creds 169.254.170.2, Tencent
        // 169.254.0.23, and every other link-local metadata endpoint.
        "169.254.0.0/16",
        "100.100.100.200", // Alibaba Cloud ECS
        "168.63.129.16",   // Azure WireServer / platform
        "192.0.0.192",     // Oracle Cloud (OCI) IMDS
        "fd00:ec2::254",   // AWS EC2 IMDSv6
        "metadata.google.internal",
        "metadata.internal",
        "metadata.tencentyun.com",
        "metadata.platformequinix.com",
        "instance-data",
        "instance-data.ec2.internal",
    ]
    .iter()
    .map(|s| s.to_string())
    .collect()
}

/// Expand an alternate (non-dotted-quad) IPv4 encoding to its canonical [`std::net::Ipv4Addr`], the
/// way glibc getaddrinfo (reqwest's default resolver) would. Returns `None` for a canonical
/// dotted-quad (handled by `IpAddr::parse`), a DNS name, or an out-of-range value. Used by the SSRF
/// guard to re-check an obfuscated literal (e.g. decimal `2852039166` → `169.254.169.254`) against
/// the metadata denylist rather than blocking ALL obfuscated forms indiscriminately.
///
/// Handles: a whole-host `0x`/`0X` hex or bare decimal/octal integer (interpreted as a 32-bit
/// address); and the inet_aton "parts" forms — 1, 2, 3, or 4 dotted components where the LAST part
/// absorbs the remaining low bytes (`a` = 32-bit; `a.b` = a<<24 | b(24-bit); `a.b.c` = a<<24 |
/// b<<16 | c(16-bit); `a.b.c.d` = the usual quad). Each component may itself be decimal, `0x` hex, or
/// leading-zero octal.
fn expand_alternate_ipv4(host: &str) -> Option<std::net::Ipv4Addr> {
    if host.is_empty() {
        return None;
    }

    // Parse a single inet_aton component: `0x..`/`0X..` hex, leading-zero octal, or decimal.
    fn parse_component(p: &str) -> Option<u64> {
        if p.is_empty() {
            return None;
        }
        if let Some(hex) = p.strip_prefix("0x").or_else(|| p.strip_prefix("0X")) {
            if hex.is_empty() || !hex.bytes().all(|b| b.is_ascii_hexdigit()) {
                return None;
            }
            u64::from_str_radix(hex, 16).ok()
        } else if p.len() > 1 && p.starts_with('0') {
            // Leading-zero octal (e.g. `0177`). All digits must be 0-7.
            if !p.bytes().all(|b| (b'0'..=b'7').contains(&b)) {
                return None;
            }
            u64::from_str_radix(p, 8).ok()
        } else {
            if !p.bytes().all(|b| b.is_ascii_digit()) {
                return None;
            }
            p.parse::<u64>().ok()
        }
    }

    let parts: Vec<&str> = host.split('.').collect();
    let vals: Vec<u64> = parts
        .iter()
        .map(|p| parse_component(p))
        .collect::<Option<Vec<u64>>>()?;

    // A canonical dotted-quad (4 parts, each a plain 0..=255 decimal with no hex/octal prefix) is
    // left to `IpAddr::parse`. A component is "alternate" if it is out of u8 range OR uses a hex/octal
    // prefix; the quad is canonical iff NO component is alternate.
    let is_alternate_octet = |p: &&str, v: &u64| {
        *v > 255
            || p.starts_with("0x")
            || p.starts_with("0X")
            || (p.len() > 1 && p.starts_with('0'))
    };
    let is_canonical_quad = parts.len() == 4
        && !parts
            .iter()
            .zip(&vals)
            .any(|(p, v)| is_alternate_octet(p, v));
    if is_canonical_quad {
        return None;
    }

    let addr: u32 = match vals.as_slice() {
        // `a` — the whole 32-bit address.
        [a] => u32::try_from(*a).ok()?,
        // `a.b` — a is the top octet, b the low 24 bits.
        [a, b] => {
            if *a > 0xff || *b > 0x00ff_ffff {
                return None;
            }
            ((*a as u32) << 24) | (*b as u32)
        }
        // `a.b.c` — a, b top two octets, c the low 16 bits.
        [a, b, c] => {
            if *a > 0xff || *b > 0xff || *c > 0x0000_ffff {
                return None;
            }
            ((*a as u32) << 24) | ((*b as u32) << 16) | (*c as u32)
        }
        // `a.b.c.d` — the usual quad (reached only for the alternate-encoding case, e.g. per-octet
        // hex/octal, since a canonical quad returned above).
        [a, b, c, d] => {
            if *a > 0xff || *b > 0xff || *c > 0xff || *d > 0xff {
                return None;
            }
            ((*a as u32) << 24) | ((*b as u32) << 16) | ((*c as u32) << 8) | (*d as u32)
        }
        _ => return None,
    };
    Some(std::net::Ipv4Addr::from(addr))
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
            listen: crate::config::DEFAULT_LISTEN_ADDR.into(),
            tls: None,
            auth: None,
            providers,
            models,
            pools,
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
            auth: None,
            _legacy_api_key: None,
            allow_metadata_hosts: Vec::new(),
        }
    }

    fn make_model(provider: &str, max_concurrent: usize) -> config::ModelCfg {
        config::ModelCfg {
            reasoning: None,
            max_requests: -1,
            provider: provider.into(),
            max_concurrent,
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
            route: config::RouteKind::default(),
            policy: None,
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
        config::AuthCfg {
            mode: crate::auth::AuthMode::from_config_str(mode)
                .unwrap_or_else(|| panic!("invalid auth mode in test: {mode}")),
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
        // Regression: a MODEL named `admin` is reached at `/admin/v1/messages`,
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
                budget_on_store_error: Default::default(),
                sqlite_busy_timeout_ms: crate::config::DEFAULT_SQLITE_BUSY_TIMEOUT_MS,
                rate_sweep_interval: crate::config::DEFAULT_RATE_SWEEP_INTERVAL,
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
                budget_on_store_error: Default::default(),
                sqlite_busy_timeout_ms: crate::config::DEFAULT_SQLITE_BUSY_TIMEOUT_MS,
                rate_sweep_interval: crate::config::DEFAULT_RATE_SWEEP_INTERVAL,
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
            budget_on_store_error: Default::default(),
            sqlite_busy_timeout_ms: crate::config::DEFAULT_SQLITE_BUSY_TIMEOUT_MS,
            rate_sweep_interval: crate::config::DEFAULT_RATE_SWEEP_INTERVAL,
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
            budget_on_store_error: Default::default(),
            sqlite_busy_timeout_ms: crate::config::DEFAULT_SQLITE_BUSY_TIMEOUT_MS,
            rate_sweep_interval: crate::config::DEFAULT_RATE_SWEEP_INTERVAL,
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
            enabled: true,
            db_path: "busbar-governance.db".to_string(),
            price_per_request_cents: 1,
            price_per_1k_tokens_cents: 0,
            admin_token: Some("an-operator-secret".to_string()),
            budget_on_store_error: Default::default(),
            sqlite_busy_timeout_ms: crate::config::DEFAULT_SQLITE_BUSY_TIMEOUT_MS,
            rate_sweep_interval: 0,
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
            enabled: false,
            db_path: "busbar-governance.db".to_string(),
            price_per_request_cents: 1,
            price_per_1k_tokens_cents: 0,
            admin_token: None,
            budget_on_store_error: Default::default(),
            sqlite_busy_timeout_ms: crate::config::DEFAULT_SQLITE_BUSY_TIMEOUT_MS,
            rate_sweep_interval: crate::config::DEFAULT_RATE_SWEEP_INTERVAL,
        };
        assert!(
            validate_governance(&gov, None).is_ok(),
            "disabled governance carries no admin_token requirement"
        );
    }

    fn auth_cfg(mode: &str) -> config::AuthCfg {
        config::AuthCfg {
            mode: crate::auth::AuthMode::from_config_str(mode)
                .unwrap_or_else(|| panic!("invalid auth mode in test: {mode}")),
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
                budget_on_store_error: Default::default(),
                sqlite_busy_timeout_ms: crate::config::DEFAULT_SQLITE_BUSY_TIMEOUT_MS,
                rate_sweep_interval: crate::config::DEFAULT_RATE_SWEEP_INTERVAL,
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
                budget_on_store_error: Default::default(),
                sqlite_busy_timeout_ms: crate::config::DEFAULT_SQLITE_BUSY_TIMEOUT_MS,
                rate_sweep_interval: crate::config::DEFAULT_RATE_SWEEP_INTERVAL,
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
            budget_on_store_error: Default::default(),
            sqlite_busy_timeout_ms: crate::config::DEFAULT_SQLITE_BUSY_TIMEOUT_MS,
            rate_sweep_interval: crate::config::DEFAULT_RATE_SWEEP_INTERVAL,
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
                .any(|e| e.contains("token mode requires at least one client token")),
            "expected a token-mode lockout error; got: {errs:?}"
        );
    }

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
            ssrf_blocked_host("https://user:pass@169.254.169.254:8443/x", &[], false, &[])
                .as_deref(),
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
        let errs =
            validate(&cfg).expect_err("a CIDR allow_metadata_hosts entry must fail validation");
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
                .any(|e| e.contains("blocked cloud-metadata host")
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
        let errs =
            validate(&cfg).expect_err("a self-referential fallback pool must fail validation");
        assert!(
            errs.iter()
                .any(|e| e.contains("references itself as its fallback pool")
                    && e.contains("mypool")),
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
        pool.route = config::RouteKind::Webhook;
        pool.policy = Some(config::PolicyCfg {
            url: url.map(str::to_string),
            socket: None,
            timeout_ms: 150,
            on_error: config::PolicyOnError::default(),
            send_prompt: false,
            send_user: false,
            name: None,
        });
        let mut pools = HashMap::new();
        pools.insert("p1".to_string(), pool);
        make_root_cfg(providers, models, pools)
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
                    !errs.iter().any(|e| e.contains("route: webhook")),
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
                    .any(|e| e.contains("p1") && e.contains("route: webhook")),
                "internal/plaintext target '{bad}' must be rejected; got: {errs:?}"
            );
        }
    }

    #[test]
    fn test_webhook_route_requires_url() {
        // A `route: webhook` pool with no `policy.url` is a misconfiguration caught at startup.
        let cfg = webhook_pool_cfg(None);
        let errs = validate(&cfg)
            .unwrap_err_or_default("missing policy.url must fail validation".to_string());
        assert!(
            errs.iter()
                .any(|e| e.contains("route: webhook") && e.contains("required")),
            "missing url must be reported; got: {errs:?}"
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
        pool.route = config::RouteKind::Socket;
        pool.policy = Some(config::PolicyCfg {
            url: None,
            socket: socket.map(str::to_string),
            timeout_ms: 150,
            on_error: config::PolicyOnError::default(),
            send_prompt: false,
            send_user: false,
            name: None,
        });
        let mut pools = HashMap::new();
        pools.insert("p1".to_string(), pool);
        make_root_cfg(providers, models, pools)
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
                    .any(|e| e.contains("route: socket") || e.contains("policy.socket")),
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
                .unwrap_err_or_default("missing policy.socket must fail validation".to_string());
            assert!(
                errs.iter()
                    .any(|e| e.contains("route: socket") && e.contains("requires policy.socket")),
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
            .unwrap_err_or_default("relative policy.socket must fail validation".to_string());
        assert!(
            errs.iter()
                .any(|e| e.contains("policy.socket") && e.contains("absolute")),
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
            let errs = validate(&cfg)
                .expect_err(&format!("metadata base_url '{base}' must fail validation"));
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
}
