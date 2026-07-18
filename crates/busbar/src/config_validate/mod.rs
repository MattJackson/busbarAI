// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

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
        // is reached at `POST /api/v1/admin/messages`, which the auth middleware classifies as the
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
        // `POST /api/v1/admin/messages`, which the middleware intercepts as an admin request — so a
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
        // Case-INSENSITIVE scheme check (RFC 3986 §3.1) — a raw `starts_with("https://")` rejected
        // the valid uppercase spelling reqwest would accept, and diverged from the webhook guard's
        // `scheme_is`. (found: audit c2r5.)
        let scheme_ok =
            scheme_is(base_url, "https") || (host_is_local && scheme_is(base_url, "http"));
        if !scheme_ok {
            errors.push(if scheme_is(base_url, "http") {
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
        // (`format!("{base}{wire_path}")` in proxy engine), and the composed string is then parsed by
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
        // Same guards for `path_base` (the URL-model base override, e.g. Vertex): it is prepended to
        // the per-request `/{model}:verb` and appended to base_url, so it must begin with '/' and the
        // composed host must not be a blocked metadata endpoint.
        if let Some(path_base) = &provider_cfg.path_base {
            if !path_base.starts_with('/') {
                errors.push(format!(
                    "provider '{}' path_base '{}' must begin with '/': it is appended to base_url verbatim, so a value that does not start with '/' fuses into the host and can redirect signed traffic to an attacker-controlled host",
                    provider_name, path_base
                ));
            } else if scheme_ok {
                let composed = format!("{}{}", provider_cfg.base_url, path_base);
                if let Some(host) = ssrf_blocked_host(
                    &composed,
                    &allow_overrides,
                    cfg.allow_all_metadata,
                    &cfg.blocked_metadata_hosts,
                ) {
                    errors.push(format!(
                        "provider '{}' base_url+path_base '{}' targets a blocked cloud-metadata host '{}' (cloud-metadata/IMDS endpoints are denied; to override add the host to this provider's allow_metadata_hosts, or security.allow_metadata_hosts, or set security.allow_all_metadata: true)",
                        provider_name, composed, host
                    ));
                }
            }
        }
        // `oauth-client-credentials` needs a token endpoint + scope to run the exchange; without them
        // a lane would boot but never mint a token (every request 401s). Fail at validate time. The
        // token_url carries the client_secret, so it must be https for a public host (loopback/private
        // may use http, mirroring base_url).
        if matches!(
            provider_cfg.auth,
            Some(crate::config::ProviderAuth::OAuthClientCredentials)
        ) {
            if provider_cfg
                .token_url
                .as_deref()
                .unwrap_or("")
                .trim()
                .is_empty()
            {
                errors.push(format!(
                    "provider '{}' uses auth: oauth-client-credentials but has no `token_url` (the OAuth token endpoint the client credentials are POSTed to)",
                    provider_name
                ));
            } else if let Some(tu) = &provider_cfg.token_url {
                // token_url carries the client secret in the POST body, so it gets the SAME two guards
                // as base_url — not a lone scheme check: (1) case-INSENSITIVE https requirement (http
                // permitted only for a private/loopback token endpoint; a raw `starts_with("http://")`
                // let `HTTPS://`/scheme-less/`FTP://` bypass it, the exact base_url bug from audit c2r5),
                // and (2) the SSRF/metadata denylist — an operator typo/template pointing token_url at
                // IMDS or metadata.google.internal would POST the client secret straight to it. (found:
                // full audit.)
                let host_private = extract_normalized_host(tu)
                    .as_deref()
                    .map(host_is_private_or_loopback)
                    .unwrap_or(false);
                let tu_scheme_ok =
                    scheme_is(tu, "https") || (host_private && scheme_is(tu, "http"));
                if !tu_scheme_ok {
                    errors.push(if scheme_is(tu, "http") {
                        format!(
                            "provider '{}' token_url must use https for a public host (got '{}'); it carries the client secret, so plaintext http is permitted only for a private/loopback token endpoint",
                            provider_name, tu
                        )
                    } else {
                        format!(
                            "provider '{}' token_url must use http or https (got '{}')",
                            provider_name, tu
                        )
                    });
                } else if let Some(host) = ssrf_blocked_host(
                    tu,
                    &allow_overrides,
                    cfg.allow_all_metadata,
                    &cfg.blocked_metadata_hosts,
                ) {
                    errors.push(format!(
                        "provider '{}' token_url '{}' targets a blocked cloud-metadata host '{}' (the client secret is POSTed there; cloud-metadata/IMDS endpoints are denied — override via this provider's allow_metadata_hosts, security.allow_metadata_hosts, or security.allow_all_metadata)",
                        provider_name, tu, host
                    ));
                }
            }
            if provider_cfg.scope.as_deref().unwrap_or("").trim().is_empty() {
                errors.push(format!(
                    "provider '{}' uses auth: oauth-client-credentials but has no `scope`",
                    provider_name
                ));
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
        // configured pool parses fine but silently misses at runtime (proxy engine's
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
                    // (proxy engine `RequestCtx::visited_pools`) silently terminates the chain on the
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
                // Non-empty: an empty header name is not a valid HTTP field-name, and it PASSES the
                // ASCII + length checks (`"".is_ascii()` is true, `0 > 64` is false) yet silently
                // disables affinity at runtime (`headers.get("")` is always None) — the exact
                // "silently disable affinity" failure this validator's own comment promises to
                // catch. (found: audit c2r3.)
                if header_name.is_empty() {
                    errors.push(format!(
                        "pool '{}' affinity.header_name must not be empty (an empty HTTP header field-name silently disables session affinity)",
                        pool_name
                    ));
                }
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
    // and loops back through one or more intermediaries is just as defeated at runtime — proxy engine's
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

    // Rule (hooks/registry): every entry in the top-level `hooks:` registry is validated once, here.
    // A hook declares EXACTLY ONE transport (`socket` XOR `webhook`); a webhook URL must pass the
    // routing SSRF guard (OTLP loopback carve-out: loopback/localhost sidecars allowed, link-local/
    // IMDS/RFC1918/CGNAT/cloud-metadata blocked; plaintext http:// only on loopback); a socket path
    // must be non-empty + ABSOLUTE (a relative path silently depends on busbar's CWD) and the platform
    // must support Unix domain sockets. Rejected at startup, never a silent degrade.
    for (hook_name, hook) in &cfg.hooks {
        match (hook.socket.as_deref(), hook.webhook.as_deref()) {
            (None, None) | (Some(""), None) | (None, Some("")) => errors.push(format!(
                "hook '{hook_name}' declares no transport: set exactly one of `socket` (a Unix \
                 domain socket path) or `webhook` (an https URL)"
            )),
            (Some(_), Some(_)) => errors.push(format!(
                "hook '{hook_name}' declares BOTH `socket` and `webhook`: a hook has exactly one \
                 transport"
            )),
            (Some(path), None) => {
                if !cfg!(unix) {
                    errors.push(format!(
                        "hook '{hook_name}' uses a `socket` transport, unavailable on this platform \
                         (Unix domain sockets); use a `webhook` hook here"
                    ));
                } else if !path.starts_with('/') {
                    errors.push(format!(
                        "hook '{hook_name}' `socket` must be an absolute path (got '{path}'); a \
                         relative path depends on busbar's working directory"
                    ));
                }
            }
            (None, Some(url)) => {
                if let Err(msg) = crate::observability::validate_routing_webhook_url(Some(url)) {
                    errors.push(format!("hook '{hook_name}' `webhook` is invalid: {msg}"));
                }
            }
        }
        // `prompt: rw` grants the REWRITE arm, which only a GATE can return — a tap is fire-and-forget
        // and never replies, so `rw` on a tap is a config error (it would silently never rewrite).
        if hook.prompt == crate::config::PromptAccess::Rw
            && hook.kind == crate::config::HookKind::Tap
        {
            errors.push(format!(
                "hook '{hook_name}' is a tap with `prompt: rw`, but only a gate can rewrite (a tap \
                 never replies). Use `kind: gate`, or lower to `prompt: ro`."
            ));
        }
        // `default: true` marks the hook as a pool's base ORDERING — but a tap is fire-and-forget and
        // never replies, so it can never order. A default tap is meaningless; reject it (the base
        // must be an ordering gate, or the compiled-in backstop).
        if hook.default && hook.kind == crate::config::HookKind::Tap {
            errors.push(format!(
                "hook '{hook_name}' is a tap with `default: true`, but a tap cannot be a pool's base \
                 ordering (it never replies). Only a gate can be the default."
            ));
        }
    }

    // Rule (hooks/reserved-names): a hook in ANY layer (base config, overlay, or the runtime
    // register API — all three write paths share `config::RESERVED_HOOK_NAMES`) may NOT take a name
    // a built-in answers to or an `on_error` terminal word. Registry uniqueness + the closed
    // `on_error` string union (see the const's doc). A collision is a boot error naming the offender.
    for hook_name in cfg.hooks.keys() {
        if crate::config::RESERVED_HOOK_NAMES.contains(&hook_name.as_str()) {
            errors.push(format!(
                "hook '{hook_name}' uses a reserved name (a built-in ranking strategy, auth module, \
                 or on_error terminal); rename the hook — a hook can never shadow a reserved word"
            ));
        }
    }

    // Rule (hooks/at-most-one-default): AT MOST ONE hook may claim `default: true` — it becomes the
    // base ordering a pool inherits when it names none, REPLACING the compiled-in backstop. Two
    // defaults are ambiguous (which base?), so >1 is a boot error naming every offender. This runs on
    // the resolved config, so it fires at boot AND on every admin apply (the apply path re-resolves +
    // re-validates), closing "add a second default live." 0 defaults ⇒ the compiled-in backstop; the
    // single-default check needs no lower bound.
    {
        let mut defaults: Vec<&str> = cfg
            .hooks
            .iter()
            .filter(|(_, h)| h.default)
            .map(|(name, _)| name.as_str())
            .collect();
        if defaults.len() > 1 {
            defaults.sort_unstable();
            errors.push(format!(
                "more than one hook sets `default: true` ({}); at most one hook may be the default \
                 base ordering",
                defaults.join(", ")
            ));
        }
    }

    // Rule (hooks/pool-ref): every gate a pool names (`hook:` / the non-strategy names in
    // `hooks: [...]`) must reference a registry entry that is a GATE (a tap can't influence
    // routing). Dangling or wrong-kind references are startup errors that name the hook.
    for (pool_name, pool_cfg) in &cfg.pools {
        for hook_name in &pool_cfg.gates {
            match cfg.hooks.get(hook_name) {
                None => errors.push(format!(
                    "pool '{pool_name}' references unknown hook '{hook_name}'; define it under \
                     top-level `hooks:`"
                )),
                Some(h) if h.kind != crate::config::HookKind::Gate => errors.push(format!(
                    "pool '{pool_name}' hook '{hook_name}' is a tap, but a hook named in a pool's \
                     `hooks:` list must be a gate (fire-and-wait); a tap cannot influence routing"
                )),
                Some(_) => {}
            }
        }
    }

    // Rule (hooks/on_error): a hook's `on_error` is a NAME — a reserved terminal (`weighted` |
    // `reject` | `first`), a built-in ranking strategy, or another registry GATE (a fallback
    // chain: when the hook fails, the named fallback fires; if THAT fails, its own on_error
    // chains further). Boot proves every chain TERMINATES: an unknown name, a tap fallback, or a
    // cycle (including self-reference) is a startup error — the safety guarantee that a failing
    // gate always bottoms out on something that cannot fail.
    for (hook_name, hook) in &cfg.hooks {
        let mut visited: Vec<&str> = vec![hook_name.as_str()];
        let mut current: &str = hook.on_error.as_str();
        loop {
            // A reserved terminal ends the chain (weighted/reject/first cannot fail).
            if crate::config::on_error_terminal(current).is_some() {
                break;
            }
            // A built-in ranking strategy is infallible (sync, no I/O) — it terminates the chain.
            // Compiled out (`--no-default-features`), naming one is a boot error, never a silent
            // degrade (the same compliance-by-compilation stance as the pool strategy rule).
            if matches!(
                current,
                crate::config::STRATEGY_CHEAPEST
                    | crate::config::STRATEGY_FASTEST
                    | crate::config::STRATEGY_LEAST_BUSY
                    | crate::config::STRATEGY_USAGE
            ) {
                if cfg!(not(feature = "hooks-ranking")) {
                    errors.push(format!(
                        "hook '{hook_name}' on_error names the built-in ranking strategy \
                         '{current}' but this binary was built WITHOUT the `hooks-ranking` \
                         feature. Rebuild with default features or use nothing|weighted|reject|first."
                    ));
                }
                break;
            }
            if visited.contains(&current) {
                errors.push(format!(
                    "hook on_error chain does not terminate: {} -> {current} is a cycle; every \
                     chain must bottom out on nothing|weighted|reject|first or a ranking strategy",
                    visited.join(" -> ")
                ));
                break;
            }
            let Some(next) = cfg.hooks.get(current) else {
                errors.push(format!(
                    "hook '{hook_name}' on_error names unknown fallback '{current}'; use a \
                     reserved terminal (nothing|weighted|reject|first), a ranking strategy, or another \
                     gate in the `hooks:` registry"
                ));
                break;
            };
            if next.kind != crate::config::HookKind::Gate {
                errors.push(format!(
                    "hook '{hook_name}' on_error fallback '{current}' is a tap; a fallback must \
                     be a gate (fire-and-wait) — a tap cannot decide"
                ));
                break;
            }
            visited.push(current);
            current = next.on_error.as_str();
        }
    }

    // Rule (admin_auth/known-modules): every name in the `admin_auth:` chain must resolve to a
    // compiled-in admin auth module. `admin-tokens` is the only built-in; when it is compiled OUT
    // (`--no-default-features`) the DEFAULT chain still names it — that combination simply leaves
    // the admin API disabled (all-Pass ⇒ denied), matching the no-token posture, so it is not an
    // error here; a CONFIGURED admin token with the module absent is rejected by
    // `validate_governance` (a silent admin lockout must be loud). An unknown name is always a
    // boot error — a typo must never silently drop an auth module.
    for name in &cfg.admin_auth {
        if name != "admin-tokens" {
            errors.push(format!(
                "admin_auth names unknown module '{name}'; the built-in admin module is \
                 `admin-tokens` (external admin modules are registered at compile time)"
            ));
        }
    }

    // Rule (group_map/admin-scope): every `group_map.<group>.admin_scope` must be a known scope
    // token. A typo'd scope must fail at boot, never silently grant nothing at runtime.
    for (group, entry) in &cfg.group_map {
        if let Some(scope) = entry.admin_scope.as_deref() {
            if crate::admin::v1::contract::Scope::parse(scope).is_none() {
                errors.push(format!(
                    "group_map '{group}' has unknown admin_scope '{scope}': expected read-only, \
                     hooks-register, or full"
                ));
            }
        }
    }

    // Rule (auth.modules/max-scope): every `auth.modules.<name>.max_admin_scope` must be a known
    // scope token (typos fail at boot), and `full` — lifting the default read-only ceiling on an
    // external chain — is a LOUD boot warning: it is the explicit opt-in §2.4 requires.
    if let Some(auth) = cfg.auth.as_ref() {
        for (module, mc) in &auth.modules {
            if let Some(scope) = mc.max_admin_scope.as_deref() {
                match crate::admin::v1::contract::Scope::parse(scope) {
                    None => errors.push(format!(
                        "auth.modules '{module}' has unknown max_admin_scope '{scope}': expected                          read-only, hooks-register, or full"
                    )),
                    Some(crate::admin::v1::contract::Scope::Full) => tracing::warn!(
                        module,
                        "auth.modules grants max_admin_scope: full — principals identified by                          this module can hold FULL admin authority (the default ceiling is                          read-only); make sure this chain is trusted end to end"
                    ),
                    Some(_) => {}
                }
            }
        }
    }

    // Rule (hooks/global-ref): every name in `global_hooks:` must reference a registry entry.
    for name in &cfg.global_hooks {
        if !cfg.hooks.contains_key(name) {
            errors.push(format!(
                "global_hooks references unknown hook '{name}'; define it under top-level `hooks:`"
            ));
        }
    }

    // Rule (compliance-by-compilation): the non-weighted ranking strategies are the `hooks-ranking`
    // plugin. When it's compiled OUT (`--no-default-features`), a pool `policy: <non-weighted>` is a
    // BOOT ERROR — never a silent degrade to weighted. (Inert in the default build; `weighted` always
    // works — it's the engine's inline SWRR floor, not a plugin.)
    #[cfg(not(feature = "hooks-ranking"))]
    for (pool_name, pool_cfg) in &cfg.pools {
        if pool_cfg.policy != crate::config::PoolPolicy::Weighted {
            errors.push(format!(
                "pool '{pool_name}' names the {:?} ranking strategy but this binary was built \
                 WITHOUT the `hooks-ranking` feature — the built-in ranking strategies are absent. \
                 Rebuild with default features, use `hooks: [weighted]` (or name no strategy), or \
                 reference an external ranking hook.",
                pool_cfg.policy
            ));
        }
    }

    // Rule 5: Validate auth-block semantics. `auth.chain` is a list of module names + `upstream_
    // credentials` a snake_case enum, both validated below. `AuthCfg` is `deny_unknown_fields`, so a
    // stale `mode:`/`token:` key fails AT PARSE with serde's "unknown field" — a loud clean-break
    // boot error, no validate-time check needed (and no silent credential drop).
    if let Some(auth) = &cfg.auth {
        // Every module name in the chain must resolve to a COMPILED-IN auth module (only `tokens`
        // today, and only when the `auth-tokens` feature is on). An unknown OR uncompiled name is a
        // hard boot error — never a silently-dropped module (which would silently open the relay).
        for name in &auth.chain {
            let available = name == "tokens" && cfg!(feature = "auth-tokens");
            if !available {
                if name == "tokens" {
                    // `--no-default-features` (compliance build): tokens auth is absent.
                    errors.push(
                        "auth.chain names 'tokens' but this binary was built WITHOUT the \
                         `auth-tokens` feature — the token auth module is absent from the binary. \
                         Rebuild with default features, or configure a different auth module."
                            .to_string(),
                    );
                } else {
                    errors.push(format!(
                        "auth.chain names unknown module '{name}': the only built-in auth module is \
                         'tokens' (external modules are added at compile time)"
                    ));
                }
            }
        }
        let chain_has_tokens = auth.chain.iter().any(|n| n == "tokens");

        // `tokens` in the chain with no client_tokens rejects 100% of requests with no startup signal
        // — the locked-out mirror of the loudly-warned open-relay (empty chain) case.
        if chain_has_tokens && effective_client_tokens_empty(auth) {
            errors.push(
                "auth.chain includes 'tokens' but no client_tokens are configured; the tokens module requires at least one client token (otherwise every request is rejected)".to_string(),
            );
        }

        // An empty chain is an open relay: it admits every request unconditionally, so a configured
        // `client_tokens` allowlist has ZERO enforcement effect. Not a hard error (an empty chain may
        // be a deliberate dev open-relay), but it MUST be loud. No-op when no tokens are listed.
        if auth.chain.is_empty() && !effective_client_tokens_empty(auth) {
            tracing::warn!(
                "auth.chain is empty (open relay) but client_tokens are configured: an empty chain \
                 admits every request regardless of token, so the allowlist has no enforcement \
                 effect. Add 'tokens' to auth.chain to enforce it."
            );
        }

        // `upstream_credentials: passthrough` with a NON-EMPTY configured api_key on a provider is a
        // credential-leak risk: proxy engine selects the upstream key as `caller_token.unwrap_or("")`,
        // so an UNAUTHENTICATED caller forwards an EMPTY credential (the provider 401/403s the
        // caller), NOT busbar's configured lane key — but a non-empty configured key means busbar's
        // OWN secret gets substituted upstream on the caller's behalf. WARN (not hard-reject): a
        // legit Bedrock-ingress passthrough provider signs per-request via SigV4 and resolves EMPTY
        // here, and a deliberate static-key fallback provider is valid too.
        if auth.upstream_credentials == crate::auth::UpstreamCreds::Passthrough {
            for (provider_name, provider_cfg) in &cfg.providers {
                let resolved_key = std::env::var(&provider_cfg.api_key_env).unwrap_or_default();
                if !resolved_key.trim().is_empty() {
                    tracing::warn!(
                        provider = %provider_name,
                        api_key_env = %provider_cfg.api_key_env,
                        "upstream_credentials: passthrough with a NON-EMPTY configured api_key for \
                         this provider is a credential-leak risk: an UNAUTHENTICATED caller has \
                         busbar's OWN configured lane key substituted upstream \
                         (caller_token.unwrap_or(lane.api_key)), forwarding your secret on the \
                         caller's behalf. Passthrough should forward the CALLER credential, never a \
                         configured one. Unset the environment variable named by api_key_env \
                         (Bedrock-ingress passthrough signs per-request via SigV4 and needs no static \
                         key), or use upstream_credentials: own to gate callers with an auth chain."
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
/// `RootCfg`). `governance.enabled` combined with `upstream_credentials: passthrough` is a self-contradictory
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
    // A configured admin token with the `admin-tokens` module compiled OUT would silently disable
    // the admin API (the chain all-Passes) — a silent lockout must be a loud boot error instead.
    #[cfg(not(feature = "auth-admin-tokens"))]
    if governance
        .admin_token
        .as_deref()
        .is_some_and(|t| !t.trim().is_empty())
    {
        errors.push(
            "governance.admin_token is configured but this binary was built WITHOUT the \
             `auth-admin-tokens` feature — the admin API would be silently disabled. Rebuild with \
             default features or wire an external admin auth module."
                .to_string(),
        );
    }
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
            "governance.enabled is true but no governance.admin_token is configured; the /api/v1/admin management API is unreachable (every admin call returns 401). Set governance.admin_token (e.g. admin_token: ${BUSBAR_ADMIN_TOKEN})".to_string(),
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
    if governance.enabled
        && auth.is_some_and(|a| a.upstream_credentials == crate::auth::UpstreamCreds::Passthrough)
    {
        errors.push(
            "governance.enabled is true together with upstream_credentials: passthrough; governance supersedes passthrough (every request must resolve to an enabled virtual key), so passthrough's accept-and-forward-caller-credential semantics are NOT honoured and every caller without a virtual key is silently rejected. This combination is unsupported; use upstream_credentials: own (with an auth chain, or omit the auth block) alongside governance.".to_string(),
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
/// percent-decoded, and a single trailing FQDN-root dot removed. Lowercasing for comparison is left
/// to the caller; the returned string preserves original case but with the above normalizations
/// applied. `None` when the scheme is not http/https or the host is empty.
///
/// Centralizing this means the SSRF metadata check and the private/loopback scheme classifier both
/// reason over the EXACT host the connecting stack will, so neither can be bypassed by an authority
/// trick (backslash, userinfo flip, percent-encoded dots, trailing dot) that only one of them
/// normalized away.
/// `url`'s scheme equals `scheme`, compared CASE-INSENSITIVELY per RFC 3986 §3.1 — the same guard
/// `observability::scheme_is` uses for webhook URLs. A raw `starts_with("https://")` rejects the
/// valid uppercase spelling `HTTPS://host/` that reqwest's `Url::parse` lowercases and accepts, so
/// the provider base_url scheme check must match the webhook guard's case-insensitivity. (audit c2r5.)
fn scheme_is(url: &str, scheme: &str) -> bool {
    url.split_once("://")
        .is_some_and(|(s, _)| s.eq_ignore_ascii_case(scheme))
}

/// Strip an `http`/`https` scheme case-insensitively, returning the authority+path remainder.
fn strip_scheme(url: &str) -> Option<&str> {
    let (scheme, rest) = url.split_once("://")?;
    (scheme.eq_ignore_ascii_case("https") || scheme.eq_ignore_ascii_case("http")).then_some(rest)
}

fn extract_normalized_host(url: &str) -> Option<String> {
    // Strip the scheme (case-insensitively — see `scheme_is`). The host extraction is
    // scheme-agnostic; accept either prefix so an `http://` upstream is still metadata-checked.
    let rest = strip_scheme(url)?;
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
///   * `192.0.0.192` (Oracle Cloud / OCI IMDS — globally-routable-shaped, so it needs an explicit literal);
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
#[path = "tests/tests.rs"]
mod tests;
