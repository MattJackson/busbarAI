// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors
//
// busbar — a native-protocol LLM gateway. It fronts many LLM providers and routes each request to
// a model or to a weighted pool of models, translating losslessly between wire protocols and
// protecting each backend with a circuit breaker. The name is electrical: a busbar takes one feed
// and fans it out across many breakered circuits.
//
// Routing — all SIX ingress protocols are first-class; a native SDK can point its base URL at
// busbar unmodified (clients append the protocol path themselves). Mirrors the `--help` ENDPOINTS
// block and the README routing table:
//   POST /<model>/v1/messages              Anthropic-format ingress (single model)
//   POST /<pool>/v1/messages               a config-defined pool (weighted selection + failover)
//   POST /<provider>/<model>/v1/messages   ad-hoc: a specific configured provider+model
//   POST /v1/chat/completions              OpenAI-format ingress (model from the body)
//   POST /v2/chat                          Cohere-format ingress (model from the body)
//   POST /v1/responses                     OpenAI Responses-API ingress (model from the body)
//   POST /v1/models/<model>:<action>       Gemini-format ingress (stable v1 alias)
//   POST /v1beta/models/<model>:<action>   Gemini-format ingress (v1beta)
//   POST /model/<modelId>/converse[-stream] Bedrock Converse / ConverseStream ingress
//   GET  /v1/models  /v1beta/models        list models (dialect by protocol fingerprint)
//   GET  /stats  /healthz  /metrics
//
// Each model is a "lane" with its own concurrency semaphore, optional lifetime request budget, and
// per-(pool,lane) circuit-breaker health. A pool stacks its members' concurrency into one aggregate
// and distributes via smooth weighted round-robin. Ingress and backend protocols may differ: the
// request and response are translated through a superset intermediate representation (see
// `proto`/`ir`), so e.g. an OpenAI-format client can drive a Gemini or Bedrock backend, or a native
// Responses/Cohere/Gemini/Bedrock client can drive any configured backend.
//
// Failure handling (see `breaker`): transient upstream faults (5xx / overload / rate-limit /
// timeout / network) arm an escalating cooldown; billing and auth faults open the breaker with a
// long sticky cooldown; client-supplied 4xx are relayed verbatim and never penalize the lane; an
// exhausted lifetime budget disables the lane. Tripped lanes recover via a half-open probe.

// busbar contains ZERO `unsafe` code; enforce that as a compile-time guarantee so any future PR that
// introduces an `unsafe` block fails to build rather than slipping in unreviewed.
#![forbid(unsafe_code)]

mod admin;
mod auth;
mod billing;
mod breaker;
mod config;
mod config_validate;
mod endpoints;
mod eventstream;
mod forward;
mod governance;
mod handlers;
mod health;
mod ir;
mod json;
mod limits;
mod lossless;
mod media;
mod metrics;
mod net_guard;
mod observability;
mod operation;
mod plugins;
mod proto;
mod route;
mod router;
mod routing;
mod sigv4;
mod state;
mod store;
#[cfg(test)]
mod test_support;
mod tls;

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use axum::{routing::get, routing::post, Router};

use auth::AuthMiddleware;

use proto::ProtocolRegistry;
use state::{App, Lane, WeightedLane};
use store::{InMemoryStore, LaneData};

// The upstream-request timeout, pool-idle, and request-body caps that used to live here as `const`s
// are now operator-tunable (`limits.upstream_request_timeout_secs` / `pool_max_idle_per_host` /
// `request_body_max_bytes`), each defaulting to its historical value at the config layer. They are
// threaded from `cfg.limits` into the client builder and router below; the egress translate-body cap
// is COUPLED to `request_body_max_bytes` via `crate::limits::translate_body_max_bytes`.

/// Environment variable name for the providers.yaml path.
const ENV_PROVIDERS: &str = "BUSBAR_PROVIDERS";
/// Environment variable name for the config.yaml path.
const ENV_CONFIG: &str = "BUSBAR_CONFIG";
/// Default path to the providers definition file.
const DEFAULT_PROVIDERS_PATH: &str = "/etc/busbar/providers.yaml";
/// Default path to the deployment config file.
const DEFAULT_CONFIG_PATH: &str = "/etc/busbar/config.yaml";
/// Response header name for the W3C Server-Timing field.
const HEADER_SERVER_TIMING: &str = "server-timing";
/// Sentinel value stored in the `UPSTREAM_RTT_US` task-local when NO upstream hop was dispatched
/// (admin / health / early error). `server_timing_dur_ms` treats this as "report the full request
/// time" rather than subtracting a nonexistent RTT. Only this exact u64::MAX meaning is replaced
/// with the const; overflow/conversion fallbacks that happen to produce u64::MAX are NOT this.
const NO_UPSTREAM_RTT: u64 = u64::MAX;

/// Handle CLI flags before any environment or file access, so they work without a configured
/// deployment. Returns `Some(exit_code)` when the process should exit (after printing), `None` to
/// proceed to normal startup. busbar takes no positional arguments and is configured via
/// environment + YAML; an unrecognized flag is a usage error rather than a silent server start.
fn handle_cli_flags() -> Option<i32> {
    let mut args = std::env::args().skip(1);
    match args.next().as_deref() {
        None => None, // no args → run the gateway
        Some("--version" | "-V") => {
            println!("busbar {}", env!("CARGO_PKG_VERSION"));
            Some(0)
        }
        Some("--print-metadata-blocklist") => {
            // Print the EFFECTIVE cloud-metadata denylist the running binary enforces: the hardcoded
            // set (single source of truth in config_validate) UNION the operator's
            // `security.blocked_metadata_hosts`. The hardcoded set always prints (no config needed);
            // the operator extension is appended best-effort if BUSBAR_CONFIG is readable + parseable,
            // so the flag is useful even before a deployment is wired up. One entry per line, exit 0.
            let mut entries = config_validate::metadata_denylist_entries();
            let config_path =
                std::env::var(ENV_CONFIG).unwrap_or_else(|_| DEFAULT_CONFIG_PATH.into());
            if let Ok(raw) = std::fs::read_to_string(&config_path) {
                if let Ok(interpolated) = config::interpolate_env(&raw) {
                    match serde_yaml::from_str::<config::DeployCfg>(&interpolated) {
                        Ok(deploy) => {
                            if let Some(sec) = deploy.security {
                                entries.extend(sec.blocked_metadata_hosts);
                            }
                        }
                        Err(_) => {
                            // The config did not parse (e.g. an unknown/typo'd key now rejected by
                            // deny_unknown_fields). Don't silently print an INCOMPLETE denylist that
                            // omits the operator's `security.blocked_metadata_hosts` — warn instead.
                            // (Deliberately NOT echoing the error, which could quote a config value;
                            // the normal boot path surfaces the precise parse error.)
                            eprintln!(
                                "warning: config at {config_path} did not parse; printing the built-in \
                                 metadata denylist only (security.blocked_metadata_hosts skipped). Run \
                                 busbar normally to see the parse error."
                            );
                        }
                    }
                }
            }
            for entry in entries {
                println!("{entry}");
            }
            Some(0)
        }
        Some("--help" | "-h") => {
            println!(
                "busbar {ver} — native-protocol LLM gateway

USAGE:
    busbar              run the gateway (configured entirely via environment + YAML)
    busbar --help       print this help
    busbar --version    print the version
    busbar --print-metadata-blocklist
                        print the effective cloud-metadata SSRF denylist and exit

ENVIRONMENT:
    BUSBAR_PROVIDERS    path to providers.yaml  (default: /etc/busbar/providers.yaml)
    BUSBAR_CONFIG       path to config.yaml     (default: /etc/busbar/config.yaml)
    RUST_LOG            log level: error|warn|info|debug|trace  (default: info)

ENDPOINTS (once running, listen address from config.yaml `listen`):
    POST /<model>/v1/messages              Anthropic-format ingress (single model)
    POST /<pool>/v1/messages               route to a configured pool
    POST /<provider>/<model>/v1/messages   ad-hoc direct route
    POST /v1/chat/completions              OpenAI-format ingress
    POST /v2/chat                          Cohere-format ingress
    POST /v1/responses                     Responses-API ingress
    POST /v1/models/<model>:<action>       Gemini-format ingress (stable v1)
    POST /v1beta/models/<model>:<action>   Gemini-format ingress
    POST /model/<modelId>/converse         Bedrock Converse ingress
    POST /model/<modelId>/converse-stream  Bedrock Converse streaming ingress
    GET  /v1/models  /v1beta/models        list models (answers in the caller's dialect)
    GET  /stats  /healthz  /metrics

Docs: https://getbusbar.com   ·   Source: https://github.com/MattJackson/busbarAI",
                ver = env!("CARGO_PKG_VERSION")
            );
            Some(0)
        }
        Some(other) => {
            eprintln!("busbar: unrecognized argument '{other}'. Try 'busbar --help'.");
            Some(2)
        }
    }
}

/// Print a clean startup error to stderr and exit non-zero. Used for misconfiguration and other
/// boot-time failures so the operator sees a one-line message instead of a Rust panic backtrace.
fn die(msg: impl std::fmt::Display) -> ! {
    eprintln!("[error] {msg}");
    std::process::exit(1);
}

/// Return the open-relay banner to emit when the auth chain is EMPTY (open front door), or `None`
/// when an auth module is engaged. `chain_empty` = the resolved `auth.chain` is empty. `auth_present`
/// distinguishes an explicit empty chain (operator opted in) from a missing `auth:` block
/// (serde-defaulted to open — the silent foot-gun the banner must call out).
fn open_relay_banner(chain_empty: bool, auth_present: bool) -> Option<&'static str> {
    if !chain_empty {
        return None;
    }
    Some(if auth_present {
        "auth is DISABLED (auth.chain is empty) — busbar is running as an OPEN RELAY; do not run this in production"
    } else {
        "auth is DISABLED: no `auth:` block in config — busbar is running as an OPEN RELAY (anyone can use it). Add `auth:` with `chain: [tokens]` (and `client_tokens`) before exposing it; do not run this in production"
    })
}

/// Resolve each model's single `context_max` from the pool members that reference it.
///
/// A model is realized as exactly one lane (keyed by model name in `by_model`), so its
/// context window must be single-valued across every pool that lists it. We accept the same
/// `context_max` repeated (including the same `Some(_)` in multiple pools, and a mix of an
/// explicit value with `None` — the explicit value wins, since `None` only means "unspecified
/// here"), but reject two DIFFERENT explicit limits for the same model: that is an operator
/// contradiction that previously resolved nondeterministically to whichever pool iterated last.
fn resolve_model_context_max(
    pools: &HashMap<String, config::PoolCfg>,
) -> Result<HashMap<String, Option<usize>>, String> {
    let mut resolved: HashMap<String, Option<usize>> = HashMap::new();
    for pool in pools.values() {
        for m in &pool.members {
            match resolved.get(&m.target) {
                // First sighting of this model, or this member adds no opinion (None) — keep what
                // we have / record what we got.
                None => {
                    resolved.insert(m.target.clone(), m.context_max);
                }
                Some(None) => {
                    // Previously unspecified; let any value (including another None) refine it.
                    resolved.insert(m.target.clone(), m.context_max);
                }
                Some(Some(existing)) => match m.context_max {
                    // No opinion here, or an identical opinion — both fine, keep the explicit value.
                    None => {}
                    Some(c) if c == *existing => {}
                    Some(c) => {
                        return Err(format!(
                            "model '{}' has conflicting context_max across pools ({} vs {}); a model maps to one lane and must declare a single context_max",
                            m.target, existing, c
                        ));
                    }
                },
            }
        }
    }
    Ok(resolved)
}

#[tokio::main]
async fn main() {
    // CLI flags first — these must work without a configured deployment (no env/file access).
    if let Some(code) = handle_cli_flags() {
        std::process::exit(code);
    }

    // Install the Prometheus recorder on a background thread. Its one-time clock calibration
    // (quanta's TSC calibration, ~200ms) would otherwise block the listener; deferring it lets
    // busbar bind and serve (incl. /healthz) in tens of ms. `/metrics` renders empty until the
    // recorder is live, and the sliver of requests in that startup window go uncounted — an
    // acceptable trade for a daemon/k8s readiness path. Emission macros are no-ops until then.
    std::thread::spawn(metrics::init);

    // Read providers.yaml (shipped definitions)
    let providers_path =
        std::env::var(ENV_PROVIDERS).unwrap_or_else(|_| DEFAULT_PROVIDERS_PATH.into());
    let raw_providers = std::fs::read_to_string(&providers_path).unwrap_or_else(|e| {
        die(format!(
            "cannot read providers file '{providers_path}': {e} (set {ENV_PROVIDERS})"
        ))
    });
    let interpolated_providers = config::interpolate_env(&raw_providers)
        .unwrap_or_else(|e| die(format!("providers.yaml: {e}")));
    let defs: HashMap<String, config::ProviderDef> = serde_yaml::from_str(&interpolated_providers)
        .unwrap_or_else(|e| die(format!("providers.yaml: invalid YAML: {e}")));

    // Read config.yaml (deployment)
    let config_path = std::env::var(ENV_CONFIG).unwrap_or_else(|_| DEFAULT_CONFIG_PATH.into());
    let raw_config = std::fs::read_to_string(&config_path).unwrap_or_else(|e| {
        die(format!(
            "cannot read config file '{config_path}': {e} (set {ENV_CONFIG})"
        ))
    });
    let interpolated_config =
        config::interpolate_env(&raw_config).unwrap_or_else(|e| die(format!("config.yaml: {e}")));
    let deploy: config::DeployCfg = serde_yaml::from_str(&interpolated_config)
        .unwrap_or_else(|e| die(format!("config.yaml: invalid YAML: {e}")));

    // Optional observability sinks; grab before `deploy` is borrowed by resolve.
    let observability_cfg = deploy.observability.clone().unwrap_or_default();
    // Governance config; grab before `deploy` is borrowed by resolve.
    let governance_cfg = deploy.governance.clone();

    // Install the tracing subscriber now (stderr fmt always; OTLP export if configured) so all
    // subsequent startup and request-path logging is captured.
    observability::init_logging(observability_cfg.otlp_endpoint.as_deref());

    // First line in the logs: which build is running. Operators need this to confirm a deploy /
    // correlate logs to a release without shelling in to run `--version`.
    tracing::info!(version = env!("CARGO_PKG_VERSION"), "busbar starting");
    // Stamp process start for the `GET /admin/v1/info` uptime read.
    admin::mark_start();

    // Resolve deployment + definitions into resolved RootCfg
    let cfg = config::resolve(&deploy, &defs)
        .unwrap_or_else(|errs| die(format!("config errors:\n  - {}", errs.join("\n  - "))));
    // No normalization step exists: config::resolve passes the auth block through as-is
    // (`deploy.auth.clone()`). The legacy single-token `token:` field was removed in 1.0.0, so there
    // is nothing to promote; the only post-resolve step is the `unwrap_or_else(default_none)` fallback
    // for an absent `auth:` block.
    let auth_cfg = cfg
        .auth
        .clone()
        .unwrap_or_else(config::AuthCfg::default_none);

    // Validate configuration before building lanes
    if let Err(validation_errors) = config_validate::validate(&cfg) {
        for err in &validation_errors {
            eprintln!("[error] {}", err);
        }
        std::process::exit(1);
    }

    // Install the resolved operational limits process-wide BEFORE any subsystem reads them. The
    // values threaded explicitly (client/store/router/TLS) read `cfg.limits` directly; the deep
    // call-stack sites (forward translate-body cap, metrics gauge limit, observability webhook
    // timeout, governance sqlite/sweep, health probe fallbacks, routing policy timeout) read these.
    limits::install(&cfg.limits);

    // Metadata-SSRF protection status (discoverability). When the nuclear `allow_all_metadata` is set
    // the guard is OFF — that is a security-relevant degradation, so WARN. Otherwise report the count
    // of blocked hosts (hardcoded denylist ∪ security.blocked_metadata_hosts) and point at the CLI
    // flag that dumps the full list.
    if cfg.allow_all_metadata {
        tracing::warn!("metadata protection DISABLED — all cloud-metadata endpoints reachable");
    } else {
        let blocked =
            config_validate::metadata_denylist_entries().len() + cfg.blocked_metadata_hosts.len();
        tracing::info!(
            "metadata protection: {blocked} hosts blocked (--print-metadata-blocklist to view)"
        );
    }

    let mut lanes_data = Vec::new();
    // Validated provider handle for each lane, captured in lockstep with `lanes_data` below. The
    // first loop already resolves `cfg.providers.get(&mc.provider)` (failing loud via `die` on a
    // missing provider), so the lane-build loop reuses that handle instead of re-looking it up —
    // there is no second lookup and no `expect` on the startup path.
    let mut lane_provider_cfgs: Vec<&config::ProviderCfg> = Vec::new();
    let mut by_model = HashMap::new();
    // Per-model configured default_max_tokens (injected at the translation seam for protocols that
    // require max_tokens). Captured here because `cfg.models` is consumed by this loop.
    let mut model_default_max_tokens: std::collections::HashMap<String, Option<u32>> =
        std::collections::HashMap::new();
    // Single source of truth for each provider's resolved API key. The secret-bearing env read
    // happens exactly once per provider here; both the empty-key warning below and the later
    // `Lane.api_key` population reuse this value, so the warning and the captured key can never
    // diverge (and we don't read the same env var twice).
    let mut provider_api_keys: HashMap<String, String> = HashMap::new();
    // Build lanes in a DETERMINISTIC order (sorted by model name) rather than `cfg.models`'
    // HashMap iteration order, which is randomized per process start. Lane index is assigned here
    // (`by_model` → `lanes_data.len()`), so a random iteration order gave each lane a different
    // index every boot — surfacing as non-reproducible `/stats` lane ordering and metric lane-series
    // identity that shifts across restarts (a scrape/dashboard annoyance and a flaky-test source).
    // Sorting makes the whole observable surface stable. (Mirrors the deterministic-resolution fix
    // already applied to `model_context_max` below.)
    let mut sorted_models: Vec<_> = cfg.models.into_iter().collect();
    sorted_models.sort_by(|a, b| a.0.cmp(&b.0));
    for (model, mc) in sorted_models {
        model_default_max_tokens.insert(model.clone(), mc.default_max_tokens);
        let provider_cfg = cfg.providers.get(&mc.provider).unwrap_or_else(|| {
            die(format!(
                "model '{model}' references unknown provider '{}'",
                mc.provider
            ))
        });
        let key = provider_api_keys
            .entry(mc.provider.clone())
            .or_insert_with(|| std::env::var(&provider_cfg.api_key_env).unwrap_or_default());
        if key.is_empty() {
            eprintln!(
                "[warn] provider {} key env {} empty",
                mc.provider, provider_cfg.api_key_env
            );
        }
        let limited = mc.max_requests >= 0;
        by_model.insert(model.clone(), lanes_data.len());
        lane_provider_cfgs.push(provider_cfg);
        lanes_data.push(LaneData {
            model: model.clone(),
            provider: mc.provider.clone(),
            max: mc.max_concurrent,
            sem: std::sync::Arc::new(tokio::sync::Semaphore::new(mc.max_concurrent)),
            limited,
            budget: if limited { mc.max_requests } else { -1 },
            cooldown_until: 0,
            streak: 0,
            dead: false,
            dead_reason: String::new(),
            ok: 0,
            err: 0,
            client_fault: 0,
            upstream_model: mc.upstream_model.clone(),
            attempt_timeout_ms: mc.attempt_timeout_ms,
            reasoning: mc.reasoning.unwrap_or(false),
        });

        eprintln!(
            "  model {} via {} ({}) max {}{}",
            model,
            mc.provider,
            provider_cfg.base_url.trim_end_matches('/'),
            mc.max_concurrent,
            // Surface the alias→wire-id indirection at boot so an operator can see this lane sends a
            // different model string upstream than the config key it's filed under.
            match &mc.upstream_model {
                Some(u) => format!(" → upstream {u}"),
                None => String::new(),
            }
        );
    }

    let registry = ProtocolRegistry::with_builtins();

    // Build a map from model name to context_max. A model is one lane shared across every pool that
    // names it, so its context_max must be single-valued. Previously the last pool to iterate (in
    // nondeterministic HashMap order) silently won, so a model carrying `context_max: Some(128000)`
    // in one pool and `None` (or a different limit) in another could end up with whichever value the
    // iteration happened to land on — defeating the context-length failover exclusion in forward.rs
    // and losing pool-specific limits without a diagnostic. Resolve it deterministically and fail
    // loud on a genuine conflict instead.
    let model_context_max = match resolve_model_context_max(&cfg.pools) {
        Ok(map) => map,
        Err(conflict) => die(conflict),
    };

    let mut lanes = Vec::new();
    for (idx, ld) in lanes_data.iter().enumerate() {
        // Reuse the provider handle resolved (and validated via `die`) in the lanes_data loop above,
        // captured in lockstep into `lane_provider_cfgs`. No redundant re-lookup / `expect` here.
        let provider_cfg = lane_provider_cfgs[idx];
        let protocol = registry.get(&provider_cfg.protocol).unwrap_or_else(|| {
            die(format!(
                "provider '{}' uses unknown protocol '{}' (supported: anthropic, openai, gemini, bedrock, responses, cohere)",
                ld.provider, provider_cfg.protocol
            ))
        });
        lanes.push(Lane {
            model: ld.model.clone(),
            provider: ld.provider.clone(),
            base_url: provider_cfg.base_url.trim_end_matches('/').to_string(),
            // Reuse the single env read captured in the lanes_data loop above (same source of truth
            // as the empty-key warning); no second read of the secret-bearing env var.
            api_key: provider_api_keys
                .get(&ld.provider)
                .cloned()
                .unwrap_or_default(),
            protocol,
            max: ld.max,
            error_map: Arc::new(provider_cfg.error_map.clone()),
            context_max: model_context_max.get(&ld.model).copied().flatten(),
            path: provider_cfg.path.clone(),
            auth: provider_cfg.auth,
            health: provider_cfg.health.clone(),
            upstream_model: ld.upstream_model.clone(),
            attempt_timeout_ms: ld.attempt_timeout_ms,
            reasoning: ld.reasoning,
            default_max_tokens: model_default_max_tokens.get(&ld.model).copied().flatten(),
        });
    }

    let mut pools = HashMap::new();
    for (name, pool) in &cfg.pools {
        // Wire per-member weights from config into the pool structure.
        // Each pool member has a weight; default is 1 if not specified.
        let weighted_members: Vec<WeightedLane> = pool
            .members
            .iter()
            .map(|m| {
                let lane_idx = *by_model.get(&m.target).unwrap_or_else(|| {
                    die(format!(
                        "pool '{name}' references unknown model '{}'",
                        m.target
                    ))
                });
                WeightedLane {
                    idx: lane_idx,
                    weight: m.weight, // from config PoolMember.weight (default 1)
                    // Per-member attempt cap: one model, different hang budgets per pool/workload.
                    attempt_timeout_ms: m.attempt_timeout_ms,
                    reasoning: m.reasoning,
                }
            })
            .collect();
        pools.insert(name.clone(), weighted_members);
    }

    eprintln!("busbar: {} models, {} pools", lanes.len(), pools.len());
    for (n, wl_vec) in &pools {
        let agg: usize = wl_vec.iter().map(|wl| lanes[wl.idx].max).sum();
        eprintln!(
            "  pool /{} = [{}] aggregate {}",
            n,
            wl_vec
                .iter()
                .map(|wl| lanes[wl.idx].model.clone())
                .collect::<Vec<_>>()
                .join(", "),
            agg
        );
    }

    let listen = cfg.listen.clone();
    let tls_cfg = cfg.tls.clone();

    // Loud warning for auth.mode=none (open relay). Not fatal — busbar still starts (useful for
    // local dev) — but operators must not run this in production. NOTE: an ABSENT `auth:` block
    // serde-defaults to mode=none too (`AuthCfg::default_none`), so a config that merely omits
    // `auth:` silently becomes an open relay. Surface this at ERROR level (not warn — a warn is
    // suppressed under RUST_LOG=error, the very level an operator most likely runs in production)
    // AND unconditionally on stderr, so the open-relay state cannot be masked by log configuration.
    if let Some(banner) = open_relay_banner(auth_cfg.chain.is_empty(), cfg.auth.is_some()) {
        eprintln!("[error] {banner}");
        tracing::error!("{banner}");
    }

    let auth_mw = Arc::new(AuthMiddleware::new(&auth_cfg));
    // Thread the operator-configured hard-down cooldown + honored-Retry-After ceiling into the store
    // (both default to their historical const at the config layer).
    let store = Arc::new(InMemoryStore::new_with_limits(
        lanes_data.clone(),
        cfg.limits.hard_down_cooldown_secs,
        cfg.limits.max_honored_retry_after_secs,
    ));

    // Global default failover config — the fallback for pools that don't set their own. A fixed
    // default (not "whatever pool HashMap iteration happens to yield first", which was
    // nondeterministic across restarts).
    let failover_cfg = Some(crate::config::FailoverCfg {
        timeout_secs: crate::config::DEFAULT_FAILOVER_DEADLINE_SECS,
        exclusions: None,
        max_hops: crate::config::DEFAULT_FAILOVER_CAP,
    });

    // The fallback-pool routing table: on_exhausted `fallback_pool:<name>` looks a pool up here,
    // so it mirrors the pools map (any pool can be a fallback target).
    let fallback_pools = pools.clone();

    // The shared upstream HTTP client, built ONCE. Constructed before the pool-runtime loop so the
    // webhook routing transport can reuse it (a clone shares the connection pool + the `redirect:none`
    // SSRF posture); the same client is then moved into `App` below.
    let upstream_client = reqwest::Client::builder()
        .timeout(Duration::from_secs(
            cfg.limits.upstream_request_timeout_secs,
        ))
        .pool_max_idle_per_host(cfg.limits.pool_max_idle_per_host)
        // SSRF guard: do NOT follow redirects. The startup SSRF blocklist (config_validate.rs
        // ssrf_blocked_host) only vets the configured base_url; it does not see redirect targets.
        // reqwest's default policy follows up to 10 redirects, so a compromised/malicious upstream
        // could 30x-redirect a vetted base_url to an internal address (169.254.169.254 metadata,
        // localhost, RFC1918) and busbar would follow it — forwarding the signed request
        // (x-api-key / SigV4 Authorization on same-host redirects) to the internal target,
        // defeating the blocklist at runtime. Upstream AI provider APIs do not redirect as part of
        // normal operation, so disabling redirect following entirely closes the vector at no cost.
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .expect("build upstream HTTP client");

    // Per-pool runtime config (failover/exclusions), keyed by pool name.
    let mut pool_runtime = std::collections::HashMap::new();
    for (pool_name, pool_cfg) in &cfg.pools {
        pool_runtime.insert(
            pool_name.clone(),
            state::PoolRuntime {
                failover: pool_cfg.failover.clone(),
                affinity: pool_cfg.affinity.clone(),
                breaker: pool_cfg.breaker.as_ref().map(store::BreakerCfg::from),
                // Operator-declared member metadata (tier/cost/tags) keyed by lane idx, for the
                // routing Candidate projection. Mirrors the WeightedLane construction's target→lane
                // mapping (by_model). Read only inside the policy arm of the seam.
                members: pool_cfg
                    .members
                    .iter()
                    .filter_map(|m| {
                        by_model.get(&m.target).map(|&idx| {
                            (
                                idx,
                                state::MemberMeta {
                                    tier: m.tier.clone(),
                                    cost_per_mtok: m.cost_per_mtok,
                                    tags: m.tags.clone(),
                                },
                            )
                        })
                    })
                    .collect(),
                // Resolve the routing policy ONCE here. `route: weighted` (default) ⇒ `None` ⇒ the
                // zero-cost inline SWRR path; the webhook transport reuses the shared upstream client.
                policy: routing::resolve_policy(pool_cfg, &cfg.hooks, &upstream_client),
            },
        );
    }

    // Parse on_exhausted configs per pool
    let mut on_exhausted_cfgs = std::collections::HashMap::new();
    for (pool_name, pool_cfg) in &cfg.pools {
        if let Some(ref on_exc) = pool_cfg.on_exhausted {
            match crate::config::OnExhausted::parse(&on_exc.action) {
                Ok(mode) => {
                    tracing::info!(pool = %pool_name, on_exhausted = ?mode, "pool exhaustion policy");
                    on_exhausted_cfgs.insert(pool_name.clone(), mode);
                }
                Err(e) => die(format!(
                    "pool '{pool_name}' has invalid on_exhausted action '{}': {e}",
                    on_exc.action
                )),
            }
        } else {
            // Default to Status503 if not specified
            on_exhausted_cfgs.insert(pool_name.clone(), crate::config::OnExhausted::Status503);
        }
    }

    // open the governance store + load the virtual-key cache when enabled.
    let governance = match governance_cfg {
        Some(g) if g.enabled => match governance::SqliteStore::open(&g.db_path) {
            Ok(store) => {
                match governance::GovState::new(
                    Arc::new(store),
                    g.price_per_request_cents,
                    g.price_per_1k_tokens_cents,
                    g.admin_token.clone(),
                ) {
                    Ok(gs) => {
                        // Thread the budget store-error fail-mode (allow|deny) onto GovState.
                        let gs = gs.with_budget_on_store_error(g.budget_on_store_error);
                        eprintln!("busbar: governance enabled (sqlite {})", g.db_path);
                        Some(Arc::new(gs))
                    }
                    Err(e) => {
                        eprintln!("[error] governance init failed: {e}");
                        std::process::exit(1);
                    }
                }
            }
            Err(e) => {
                eprintln!("[error] governance db open failed ({}): {e}", g.db_path);
                std::process::exit(1);
            }
        },
        _ => None,
    };

    // Resolve the global rewrite hooks (prompt: rw gates in global_hooks) into priority-ordered
    // transports ONCE. Empty unless the operator configured a rewrite hook — zero cost by default.
    let rewrite_hooks =
        routing::resolve_rewrite_hooks(&cfg.hooks, &cfg.global_hooks, &upstream_client);
    // Resolve the global request-stage tap hooks the same way. Empty unless configured.
    let tap_hooks = routing::resolve_tap_hooks(&cfg.hooks, &cfg.global_hooks, &upstream_client);

    let app = Arc::new(App {
        lanes,
        store,
        by_model,
        pools,
        client: upstream_client.clone(),
        auth: auth_mw.clone(),
        rewrite_hooks,
        tap_hooks,
        hook_registry: cfg.hooks.clone(),
        global_hooks: cfg.global_hooks.clone(),
        failover_cfg,
        pool_runtime,
        fallback_pools,
        on_exhausted_cfgs,
        governance,
        default_max_tokens: cfg.limits.default_max_tokens,
        reasoning_effort_budgets: {
            let b = cfg.limits.reasoning_effort_budgets;
            [b.minimal, b.low, b.medium, b.high]
        },
    });

    // configure the request-log webhook (reusing the pooled client). No-op if unset.
    observability::configure_webhook(
        observability_cfg.request_log_webhook_url.clone(),
        app.client.clone(),
    );

    // Spawn the active health probers (one per lane with a probing mode). No-op when every lane is
    // `mode: none` / has no `health:` block.
    health::spawn_probers(app.clone());

    // Build the router with the operator-configured ingress body cap + optional inbound-concurrency
    // layer (0 = unlimited / no layer, today's default). `cfg` is moved field-by-field below, so read
    // the two values first.
    let router = build_router_with_limits(
        app,
        cfg.limits.request_body_max_bytes,
        cfg.limits.max_inbound_concurrent,
        observability_cfg.emit_server_timing,
    );

    let listener = tokio::net::TcpListener::bind(&listen)
        .await
        .unwrap_or_else(|e| die(format!("cannot bind listen address '{listen}': {e}")));
    // Graceful shutdown: on ctrl_c (SIGINT) or SIGTERM, stop accepting new connections, let
    // in-flight requests drain, then flush the OTLP tracer so the final (most diagnostic) spans are
    // exported rather than dropped when the runtime tears down. The signal future is panic-free —
    // a failed registration logs and parks forever (so a missing signal facility degrades to "no
    // graceful shutdown", never a crash), and `shutdown_tracing()` is a no-op when OTLP is off.
    match tls_cfg {
        // DEFAULT PATH — no `tls:` block. Serves plain HTTP over the TcpListener with graceful
        // shutdown, via the shared native hyper loop so the plain listener gets the SAME slow-loris
        // header-read timeout the TLS listener has (the prior `axum::serve` path exposed no such
        // bound). Behavior is otherwise identical: TCP_NODELAY on, graceful drain on shutdown.
        None => {
            tracing::info!(%listen, "busbar listening");
            if let Err(e) = tls::serve_plain(listener, router, shutdown_signal()).await {
                die(format!("server error: {e}"));
            }
        }
        // TLS PATH — terminate TLS natively (+ mTLS if client_ca_file is set). Cert/key/CA are loaded
        // and validated here so a bad path/parse fails fast at startup (`die`) rather than per
        // request. The crypto provider is installed once before building the ServerConfig.
        Some(tls) => {
            tls::install_crypto_provider();
            let server_config = tls::build_server_config(&tls)
                .unwrap_or_else(|e| die(format!("TLS configuration error: {e}")));
            let mtls = tls.client_ca_file.is_some();
            tracing::info!(%listen, mtls, "busbar listening (TLS)");
            if let Err(e) = tls::serve(listener, router, server_config, shutdown_signal()).await {
                die(format!("server error: {e}"));
            }
        }
    }
    observability::shutdown_tracing();
}

/// Resolve when the process receives a shutdown signal (SIGINT/ctrl_c, or SIGTERM on Unix). Used as
/// the `axum::serve(...).with_graceful_shutdown` future. Never panics: a signal-handler
/// registration error is logged and the corresponding branch parks forever, so the other branch
/// still triggers shutdown and a registration failure can never abort a worker.
async fn shutdown_signal() {
    let ctrl_c = async {
        if let Err(e) = tokio::signal::ctrl_c().await {
            tracing::warn!(error = %e, "failed to install ctrl_c handler; SIGINT shutdown disabled");
            std::future::pending::<()>().await;
        }
    };

    #[cfg(unix)]
    let terminate = async {
        match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            Ok(mut sig) => {
                sig.recv().await;
            }
            Err(e) => {
                tracing::warn!(error = %e, "failed to install SIGTERM handler; SIGTERM shutdown disabled");
                std::future::pending::<()>().await;
            }
        }
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {}
        _ = terminate => {}
    }
    tracing::info!("shutdown signal received; draining in-flight requests");
}

/// Infer the INGRESS protocol from a request path so an unmatched/wrong-method request can be
/// answered in the protocol the client was speaking, not a generic shape. The prefixes mirror the
/// route table: OpenAI (`/v1/chat/completions`), Responses (`/v1/responses`), Cohere (`/v2/chat`),
/// Gemini (`/v1/models/...`, `/v1beta/models/...`), Bedrock (`/model/...`), and Anthropic
/// (`.../v1/messages`). When nothing matches we default to `openai` — its envelope is the most
/// widely understood and is what a generic HTTP client probing `/` is most likely to parse. This is
/// inference for ERROR shaping only; it never routes a real request.
fn proto_for_path(path: &str) -> &'static str {
    // Delegate to the CANONICAL classifier in `proto` so the fallback/405 handlers and
    // `auth.rs::unauthorized_response` cannot drift for the same path (the bug this fixes: a
    // non-Converse `/model/foo/bar` path was shaped as bedrock here but openai by auth — contradictory
    // error envelopes for one path, a protocol indistinguishability gap). The canonical version
    // requires the `/converse`/`/converse-stream` suffix before classifying `/model/...` as bedrock.
    proto::proto_for_path(path)
}

/// Render a native ingress-protocol error envelope (`application/json`) for the fallback handlers,
/// attaching the `x-amzn-*` headers when the inferred protocol is Bedrock so the response is
/// indistinguishable from a real vendor 404/405. Shared by [`fallback_handler`] (404, unmatched
/// path) and [`method_not_allowed_handler`] (405, wrong method on a valid path).
pub(crate) fn fallback_error_response(
    path: &str,
    status: axum::http::StatusCode,
    kind: &str,
    message: &str,
) -> axum::response::Response {
    use axum::response::IntoResponse;
    let proto = proto_for_path(path);
    let protocol = proto::protocol_for(proto);
    let body = match &protocol {
        Some(p) => p.writer().write_error(status.as_u16(), kind, message),
        // proto_for_path only ever returns a registered protocol literal, so this is unreachable in
        // practice; shape a generic OpenAI-style envelope rather than panic on the request path.
        None => serde_json::json!({ "error": { "message": message, "type": kind } }),
    };
    let mut resp = (
        status,
        [(
            axum::http::header::CONTENT_TYPE,
            axum::http::HeaderValue::from_static(crate::forward::APPLICATION_JSON),
        )],
        body.to_string(),
    )
        .into_response();
    // Provider-specific error RESPONSE HEADERS (Bedrock `x-amzn-RequestId`/`x-amzn-errortype`;
    // Anthropic `request-id` mirrored from the body) — dispatched via the writer vtable so this
    // fallback handler matches the shape produced by `forward::ingress_error` on the hot path,
    // with no provider name-branch here.
    if let Some(p) = &protocol {
        p.writer()
            .attach_error_response_headers(resp.headers_mut(), kind, &body);
    }
    resp
}

// NOTE: the 404 fallback handler is superseded by `route::protocol_dispatch`, which owns the
// catch-all and reproduces the same native-envelope 404 shaping for non-protocol paths.

/// 405 fallback: a valid ingress path hit with the wrong method (e.g. GET on a POST-only ingress).
/// axum's built-in 405 is an `Allow`-header-only empty body; reshape to the protocol-native envelope
/// so an SDK sees a vendor-shaped error instead of a bare proxy tell.
async fn method_not_allowed_handler(uri: axum::http::Uri) -> axum::response::Response {
    fallback_error_response(
        uri.path(),
        axum::http::StatusCode::METHOD_NOT_ALLOWED,
        crate::admin::ERR_TYPE_INVALID_REQUEST,
        "method not allowed for this resource",
    )
}

/// The exact body axum 0.7's `DefaultBodyLimit` emits when a request exceeds the limit: its
/// extractor rejection (`FailedToBufferBody::LengthLimitError`) renders a 413 with this literal
/// `text/plain` body. This is the SENTINEL used to distinguish axum's OWN body-limit 413 from a
/// forward-path-relayed upstream 413: the reshape acts only on a response whose body is
/// exactly this marker, so a relayed upstream 413 (any other body, JSON or not) passes through
/// untouched. (Pinned to axum's wire shape; covered by `test_reshape_oversized_413_passthrough`.)
const AXUM_BODY_LIMIT_413_MARKER: &[u8] = b"length limit exceeded";

/// Reshape an oversized-body rejection into a protocol-native error. axum's `DefaultBodyLimit`
/// rejects a too-large request with HTTP 413 and a bare `text/plain` body (`"length limit
/// exceeded"`) — a router/proxy tell no native vendor API emits. This middleware wraps the
/// body-limit layer: it captures the request path, runs the inner
/// stack, and when the result is axum's OWN body-limit 413 (identified by the
/// [`AXUM_BODY_LIMIT_413_MARKER`] sentinel body — NOT merely any non-JSON 413), it replaces that
/// response with the inferred ingress protocol's native JSON `request_too_large` envelope (Bedrock
/// variants also gain `x-amzn-*` headers, via [`fallback_error_response`]). Any other 413 — a
/// forward-path-relayed UPSTREAM 413 (whatever its content-type), or one a real ingress handler
/// already shaped as JSON — is passed through untouched.
async fn reshape_body_limit_413(
    req: axum::http::Request<axum::body::Body>,
    next: axum::middleware::Next,
) -> axum::response::Response {
    let path = req.uri().path().to_owned();
    let resp = next.run(req).await;
    reshape_oversized_413(&path, resp).await
}

/// Compute the `Server-Timing` `dur` value (milliseconds) for a request: Busbar's own processing
/// time = total request wall-clock minus the upstream round-trip. `upstream_us == u64::MAX` means
/// "no upstream hop" (admin/health/early error), so the full time is reported. Saturating, so clock
/// skew (upstream measured slightly larger than total) can never underflow into a huge value.
fn server_timing_dur_ms(total_us: u64, upstream_us: u64) -> f64 {
    let internal_us = if upstream_us == NO_UPSTREAM_RTT {
        total_us
    } else {
        total_us.saturating_sub(upstream_us)
    };
    internal_us as f64 / 1000.0
}

/// Outermost middleware: stamps a standard `Server-Timing: busbar;dur=<ms>` response header
/// reporting the latency Busbar itself added — total request wall-clock MINUS the upstream
/// round-trip — so operators (and browser DevTools / APM tools) can see the gateway's own cost
/// in-band on every response, without scraping `/metrics` or wiring traces. The upstream RTT is
/// recorded by the forward path into the [`forward::UPSTREAM_RTT_US`] task-local for the duration
/// of this scope; a request that never dispatched upstream (admin / health / early error) reports
/// its full processing time. W3C `Server-Timing` `dur` is milliseconds; emitted at µs precision.
async fn server_timing(
    axum::extract::State(emit): axum::extract::State<bool>,
    req: axum::http::Request<axum::body::Body>,
    next: axum::middleware::Next,
) -> axum::response::Response {
    use std::sync::atomic::Ordering;
    let slot = std::sync::Arc::new(std::sync::atomic::AtomicU64::new(NO_UPSTREAM_RTT));
    let start = std::time::Instant::now();
    let mut resp = forward::UPSTREAM_RTT_US
        .scope(slot.clone(), next.run(req))
        .await;
    // Gated by `observability.emit_server_timing` (default false). When disabled, NO Server-Timing
    // header is emitted at all — the inner stack still runs unchanged, only the header is suppressed
    // (the header is an in-band busbar fingerprint an operator may want to hide). We still scope the
    // RTT task-local so disabling this never changes any other timing behavior.
    if emit {
        let total_us = u64::try_from(start.elapsed().as_micros()).unwrap_or(u64::MAX);
        let dur_ms = server_timing_dur_ms(total_us, slot.load(Ordering::Relaxed));
        if let Ok(v) = axum::http::HeaderValue::from_str(&format!("busbar;dur={dur_ms:.3}")) {
            resp.headers_mut()
                .insert(axum::http::HeaderName::from_static(HEADER_SERVER_TIMING), v);
        }
    }
    resp
}

/// Pure reshaping step of [`reshape_body_limit_413`], split out so it is unit-testable without
/// constructing a `Next`. Returns `resp` unchanged unless it is axum's OWN body-limit 413 —
/// identified by status 413 with a non-JSON content-type AND a body exactly equal to
/// [`AXUM_BODY_LIMIT_413_MARKER`] — in which case it is replaced by the inferred ingress protocol's
/// native JSON `request_too_large` envelope. A 413 a real ingress handler already shaped as
/// `application/json`, or any forward-relayed UPSTREAM 413 (different/non-marker body), is passed
/// through verbatim (the body is buffered to inspect the sentinel, then re-attached unchanged).
async fn reshape_oversized_413(
    path: &str,
    resp: axum::response::Response,
) -> axum::response::Response {
    if resp.status() != axum::http::StatusCode::PAYLOAD_TOO_LARGE {
        return resp;
    }
    // A handler (or upstream relay) that already produced an `application/json` 413 is a native
    // too-large envelope — leave it alone without even buffering the body; re-wrapping would
    // corrupt it, and axum's own body-limit reject is never JSON.
    let is_json = resp
        .headers()
        .get(axum::http::header::CONTENT_TYPE)
        .and_then(|h| h.to_str().ok())
        .is_some_and(|ct| ct.starts_with(crate::forward::APPLICATION_JSON));
    if is_json {
        return resp;
    }
    // Non-JSON 413: it could be axum's OWN body-limit reject (reshape it) OR a forward-relayed
    // UPSTREAM 413 that happens to be non-JSON (e.g. a `text/plain`/`text/html` upstream error —
    // must pass through untouched). Distinguish by the sentinel body. Buffer the body so
    // we can compare it; if it is not the sentinel, re-attach the buffered bytes verbatim.
    use http_body_util::BodyExt as _;
    let (parts, body) = resp.into_parts();
    let bytes = match body.collect().await {
        Ok(collected) => collected.to_bytes(),
        // A 413 body that fails to buffer cannot be confirmed as axum's sentinel; pass the
        // already-consumed parts through with an empty body rather than reshape a non-axum reject.
        Err(_) => return axum::response::Response::from_parts(parts, axum::body::Body::empty()),
    };
    if bytes.as_ref() != AXUM_BODY_LIMIT_413_MARKER {
        // A relayed upstream 413 (or any non-axum 413): pass through untouched, body re-attached.
        return axum::response::Response::from_parts(parts, axum::body::Body::from(bytes));
    }
    fallback_error_response(
        path,
        axum::http::StatusCode::PAYLOAD_TOO_LARGE,
        // CANONICAL kind for an oversized payload across the protocol writers.
        crate::forward::KIND_REQUEST_TOO_LARGE,
        "request body exceeds the maximum allowed size",
    )
}

/// Build the busbar HTTP router for a given `App` state with default limits. Factored out so the
/// full route table + auth middleware can be exercised end-to-end in tests; production (`main`) calls
/// `build_router_with_limits` with the operator-configured values, so this convenience wrapper is
/// reached only from the test harness.
#[cfg_attr(not(test), allow(dead_code))]
pub(crate) fn build_router(app: std::sync::Arc<state::App>) -> Router {
    // Convenience builder for tests / callers without an explicit limits handle: the historical 32
    // MiB body cap (via the installed `limits`, falling back to the default when uninstalled) and NO
    // inbound-concurrency layer (`0` = unlimited) — byte-for-byte today's behavior. Production goes
    // through `build_router_with_limits` with the operator-configured values.
    build_router_with_limits(
        app,
        limits::translate_body_max_bytes(),
        crate::config::DEFAULT_MAX_INBOUND_CONCURRENT,
        crate::config::DEFAULT_EMIT_SERVER_TIMING,
    )
}

/// Router builder with EXPLICIT limits, so a test can assert the body-size and inbound-concurrency
/// wiring without touching the process-wide install. `max_inbound_concurrent == 0` ⇒ NO concurrency
/// layer is added (a true no-op, today's behavior); `> 0` wraps the whole router in a tower
/// `GlobalConcurrencyLimitLayer` as the OUTERMOST layer.
fn build_router_with_limits(
    app: std::sync::Arc<state::App>,
    request_body_max_bytes: usize,
    max_inbound_concurrent: usize,
    emit_server_timing: bool,
) -> Router {
    let router = Router::new()
        .route("/stats", get(endpoints::stats))
        .route("/healthz", get(endpoints::healthz))
        .route("/metrics", get(metrics::handler))
        // virtual-key management API (admin-token guarded in auth_middleware). The unversioned
        // `/admin/keys*` routes are the DEPRECATED alias (design-admin-api-v1 §0.1); the canonical
        // frozen surface is `/admin/v1/*`. Both point at the same handlers today.
        .route("/admin/keys", post(admin::create_key).get(admin::list_keys))
        .route(
            "/admin/keys/{id}",
            get(admin::get_key)
                .delete(admin::delete_key)
                .patch(admin::update_key),
        )
        .route("/admin/keys/{id}/usage", get(admin::key_usage))
        // ── Admin API v1 — the FROZEN, additive-only surface tooling builds against ────────────────
        // Keys CRUD is served here on the legacy handlers under the versioned prefix (migration into
        // the layered service is a follow-up slice); the v1-NATIVE endpoints (`info`, and the config/
        // hooks/auth surface as it lands) are mounted via the `AdminTransport` adapter below.
        .route(
            "/admin/v1/keys",
            post(admin::create_key).get(admin::list_keys),
        )
        .route(
            "/admin/v1/keys/{id}",
            get(admin::get_key)
                .delete(admin::delete_key)
                .patch(admin::update_key),
        )
        .route("/admin/v1/keys/{id}/usage", get(admin::key_usage))
        // busbar's OWN API keeps explicit routes (it is not a protocol dialect): discovery, admin,
        // health/metrics/stats above, and the named/adhoc conveniences below.
        // OpenAI list-models: SDKs call `models.list()` first; UIs build pickers from it.
        // Governance-scoped like /stats (restricted keys see only their reachable names).
        .route("/v1/models", get(endpoints::list_models))
        .route("/v1beta/models", get(endpoints::list_models_v1beta))
        .route("/{name}/v1/messages", post(route::named))
        .route("/{provider}/{model}/v1/messages", post(route::adhoc))
        // EVERY protocol endpoint — chat and the 1.2 operations, all six dialects — flows through the
        // catch-all: Router (dumb protocol ID from path+headers) → that protocol's RequestHandler
        // (reads path+body, decides the operation) → its OperationHandler cell. Adding a protocol or
        // an operation never touches this file. Unknown paths / wrong methods keep the pre-collapse
        // native-envelope 404/405 shaping (no bare-proxy tells).
        .fallback(route::protocol_dispatch)
        // Wrong-method hits on a VALID path (axum's built-in 405) get the same native-envelope
        // treatment as the 404 fallback above.
        .method_not_allowed_fallback(method_not_allowed_handler);
    // Mount the Admin API v1 via the ports-and-adapters transport layer (a shared typed service
    // behind a pluggable wire format). The JSON-REST adapter is the transport today; a GraphQL / MCP /
    // gRPC adapter later is a one-line swap here over the SAME service.
    let router = admin::transport::mount(router, &admin::JsonV1);
    // The router's state is a swappable `AppHandle` (the config-apply hot-swap seam). Every handler
    // reads the CURRENT snapshot via the `CurrentApp` extractor; the auth middleware loads it too.
    // Until an admin apply calls `swap()`, this is behaviorally identical to a fixed `Arc<App>`.
    let handle = std::sync::Arc::new(state::AppHandle::new(app));
    let router = router
        .layer(axum::middleware::from_fn_with_state(
            handle.clone(),
            auth::auth_middleware,
        ))
        // Cap request body size (buffered before the handler) to bound per-request memory. Driven by
        // `limits.request_body_max_bytes` (default 32 MiB); COUPLED with the egress translate-body cap
        // (`limits::translate_body_max_bytes`) — both read the SAME knob so an accepted request is
        // always buffer-translatable on the cross-protocol path.
        .layer(axum::extract::DefaultBodyLimit::max(request_body_max_bytes))
        // Outermost: reshape the body-limit layer's bare-text 413 into a protocol-native JSON
        // envelope. Must wrap the `DefaultBodyLimit` layer above, so it is applied LAST (the last
        // `.layer()` is the outermost on the response path) and therefore sees that layer's 413.
        .layer(axum::middleware::from_fn(reshape_body_limit_413))
        // Outermost: stamp the `Server-Timing: busbar;dur=<ms>` gateway-overhead header on every
        // response (times the full inner stack). Must be the LAST `.layer()` so it wraps everything.
        // Gated on `observability.emit_server_timing` (default false): when false the header is fully
        // suppressed (see `server_timing`). The `bool` state is independent of the router's `App`
        // state, so it is wired with its own `from_fn_with_state`.
        .layer(axum::middleware::from_fn_with_state(
            emit_server_timing,
            server_timing,
        ))
        .with_state(handle);

    apply_inbound_concurrency_limit(router, max_inbound_concurrent)
}

/// OUTERMOST inbound-concurrency cap. `max_inbound_concurrent == 0` (the default) returns the router
/// UNCHANGED — NO layer is added, a true no-op so nothing changes unless an operator opts in. When
/// `> 0`, a tower `GlobalConcurrencyLimitLayer` (ONE shared semaphore across ALL requests) wraps the
/// whole router: requests beyond the cap queue for a permit rather than overrunning. Applied as the
/// last `.layer()` so it is outermost (it must admission-control before any inner work, including body
/// buffering). Factored out so the add-only-when-`>0` rule is unit-testable in isolation.
fn apply_inbound_concurrency_limit(router: Router, max_inbound_concurrent: usize) -> Router {
    if max_inbound_concurrent > 0 {
        router.layer(tower::limit::GlobalConcurrencyLimitLayer::new(
            max_inbound_concurrent,
        ))
    } else {
        router
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{PoolCfg, PoolMember};

    /// The inbound-concurrency cap is added as a layer ONLY when `max_inbound_concurrent > 0`. This
    /// drives `apply_inbound_concurrency_limit` over a minimal router whose handler PARKS on a barrier
    /// (held until we release it), so two requests are genuinely concurrent. With cap = 1 the second
    /// request cannot complete until the first releases its permit (the layer is present); with cap =
    /// 0 both complete immediately (NO layer — today's behavior).
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn test_inbound_concurrency_layer_added_only_when_positive() {
        use std::sync::Arc;
        use tokio::sync::{Barrier, Notify};

        async fn run_router(router: Router) -> std::time::Duration {
            // Serve on an ephemeral port; fire two concurrent GETs to the parking handler.
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let addr = listener.local_addr().unwrap();
            let server = tokio::spawn(async move {
                axum::serve(listener, router).await.unwrap();
            });
            let url = format!("http://{addr}/park");
            let client = reqwest::Client::new();
            let start = std::time::Instant::now();
            let (a, b) = tokio::join!(client.get(&url).send(), client.get(&url).send());
            a.unwrap();
            b.unwrap();
            let elapsed = start.elapsed();
            server.abort();
            elapsed
        }

        // Handler that signals arrival then waits on a barrier; the barrier of size 2 only releases
        // once BOTH requests have arrived — so if a layer serializes them to 1-at-a-time, the second
        // never arrives, the barrier never releases, and the handler instead falls back to a short
        // timeout. We detect the cap via that timeout path (capped run takes the timeout; uncapped run
        // releases immediately).
        fn make_router(barrier: Arc<Barrier>, _gate: Arc<Notify>) -> Router {
            Router::new().route(
                "/park",
                axum::routing::get(move || {
                    let barrier = barrier.clone();
                    async move {
                        // If both requests run concurrently the barrier releases at once. If a cap
                        // serializes them, this wait blocks until the per-request timeout fires.
                        let _ = tokio::time::timeout(
                            std::time::Duration::from_millis(300),
                            barrier.wait(),
                        )
                        .await;
                        "ok"
                    }
                }),
            )
        }

        // Uncapped (cap = 0): NO layer, both requests reach the barrier concurrently → fast release.
        let uncapped = apply_inbound_concurrency_limit(
            make_router(Arc::new(Barrier::new(2)), Arc::new(Notify::new())),
            0,
        );
        let uncapped_elapsed = run_router(uncapped).await;

        // Capped (cap = 1): the layer serializes admission, so the two requests can NOT both reach the
        // barrier at once → the first handler waits out its 300ms timeout before the second is admitted.
        let capped = apply_inbound_concurrency_limit(
            make_router(Arc::new(Barrier::new(2)), Arc::new(Notify::new())),
            1,
        );
        let capped_elapsed = run_router(capped).await;

        assert!(
            uncapped_elapsed < std::time::Duration::from_millis(250),
            "cap=0 must add NO layer: both requests reach the barrier concurrently and release fast, \
             got {uncapped_elapsed:?}"
        );
        assert!(
            capped_elapsed >= std::time::Duration::from_millis(300),
            "cap=1 must serialize admission: the first request waits out its timeout before the \
             second is admitted, got {capped_elapsed:?}"
        );
    }

    fn pool(members: Vec<PoolMember>) -> PoolCfg {
        PoolCfg {
            members,
            breaker: None,
            failover: None,
            on_exhausted: None,
            affinity: None,
            policy: crate::config::PoolPolicy::default(),
            hook: None,
        }
    }

    fn member(target: &str, context_max: Option<usize>) -> PoolMember {
        PoolMember {
            reasoning: None,
            target: target.to_string(),
            weight: 1,
            attempt_timeout_ms: None,
            context_max,
            tier: None,
            cost_per_mtok: None,
            tags: Vec::new(),
        }
    }

    #[test]
    fn test_resolve_model_context_max_explicit_wins_over_none() {
        // The same model in pool A with Some(128000) and pool B with None must resolve to the
        // explicit limit regardless of iteration order — None never clobbers a real value.
        let mut pools = HashMap::new();
        pools.insert("a".to_string(), pool(vec![member("m", Some(128_000))]));
        pools.insert("b".to_string(), pool(vec![member("m", None)]));
        let resolved = resolve_model_context_max(&pools).expect("None must not override Some");
        assert_eq!(resolved.get("m"), Some(&Some(128_000)));
    }

    #[test]
    fn test_resolve_model_context_max_identical_values_ok() {
        // The same explicit limit repeated across pools is consistent, not a conflict.
        let mut pools = HashMap::new();
        pools.insert("a".to_string(), pool(vec![member("m", Some(64_000))]));
        pools.insert("b".to_string(), pool(vec![member("m", Some(64_000))]));
        let resolved =
            resolve_model_context_max(&pools).expect("identical values must not conflict");
        assert_eq!(resolved.get("m"), Some(&Some(64_000)));
    }

    #[test]
    fn test_resolve_model_context_max_conflict_is_loud() {
        // Two DIFFERENT explicit limits for the same model is an operator contradiction: fail loud
        // (deterministic error) rather than silently pick whichever pool iterated last.
        let mut pools = HashMap::new();
        pools.insert("a".to_string(), pool(vec![member("m", Some(128_000))]));
        pools.insert("b".to_string(), pool(vec![member("m", Some(32_000))]));
        let err = resolve_model_context_max(&pools)
            .expect_err("conflicting context_max must be rejected");
        assert!(err.contains("conflicting context_max"), "got: {err}");
        assert!(err.contains('m'), "error must name the model; got: {err}");
        assert!(
            err.contains("128000") && err.contains("32000"),
            "error must show both values; got: {err}"
        );
    }

    #[test]
    fn test_resolve_model_context_max_none_everywhere() {
        let mut pools = HashMap::new();
        pools.insert("a".to_string(), pool(vec![member("m", None)]));
        pools.insert("b".to_string(), pool(vec![member("m", None)]));
        let resolved = resolve_model_context_max(&pools).expect("all-None resolves to None");
        assert_eq!(resolved.get("m"), Some(&None));
    }

    #[test]
    fn test_open_relay_banner_distinguishes_absent_vs_explicit_none() {
        // Absent `auth:` block (empty chain): banner must flag the silent open-relay foot-gun.
        let absent = open_relay_banner(true, false).expect("empty chain must produce a banner");
        assert!(
            absent.contains("OPEN RELAY") && absent.contains("no `auth:` block"),
            "absent-auth banner must call out the missing block; got: {absent}"
        );
        // Explicit empty chain: still an open relay, but the operator opted in.
        let explicit = open_relay_banner(true, true).expect("explicit empty chain must banner");
        assert!(
            explicit.contains("OPEN RELAY") && explicit.contains("auth.chain is empty"),
            "explicit-empty banner must reference auth.chain is empty; got: {explicit}"
        );
    }

    #[test]
    fn test_open_relay_banner_silent_when_auth_engaged() {
        // A non-empty chain emits nothing — the banner is exclusively for the open-relay state.
        assert!(open_relay_banner(false, true).is_none());
    }

    /// The fallback handlers infer the ingress protocol from the
    /// request path so a 404/405 is shaped in the client's own protocol, not a bare axum body.
    #[test]
    fn test_proto_for_path_inference() {
        assert_eq!(proto_for_path("/v1/chat/completions"), "openai");
        assert_eq!(proto_for_path("/v1/responses"), "responses");
        assert_eq!(proto_for_path("/v2/chat"), "cohere");
        // Both the stable v1 and v1beta Gemini surfaces infer gemini.
        assert_eq!(
            proto_for_path("/v1/models/gemini-pro:generateContent"),
            "gemini"
        );
        assert_eq!(
            proto_for_path("/v1beta/models/gemini-pro:streamGenerateContent"),
            "gemini"
        );
        // REGRESSION: an OpenAI-SDK `model.retrieve` hits
        // `GET /v1/models/{model_id}` — NO `:<action>` colon. That must infer OpenAI (so the 405/404
        // error is OpenAI-decodable), not Gemini, even though it shares the `/v1/models/` prefix.
        assert_eq!(proto_for_path("/v1/models/gpt-4o"), "openai");
        assert_eq!(proto_for_path("/v1/models"), "openai"); // list-models (no trailing id)
                                                            // A `/v1/models/` path WITH a colon action is still the Gemini surface.
        assert_eq!(
            proto_for_path("/v1/models/gemini-1.5-pro:generateContent"),
            "gemini"
        );
        // `/v1beta/models/...` is Gemini-only even without a colon (OpenAI has no v1beta surface).
        assert_eq!(proto_for_path("/v1beta/models/gemini-pro"), "gemini");
        assert_eq!(
            proto_for_path("/model/anthropic.claude/converse"),
            "bedrock"
        );
        assert_eq!(
            proto_for_path("/model/anthropic.claude/converse-stream"),
            "bedrock"
        );
        assert_eq!(proto_for_path("/my-model/v1/messages"), "anthropic");
        // REGRESSION: a NON-Converse `/model/...` path must NOT be classified as bedrock
        // (it lacks the `/converse`/`/converse-stream` suffix). The previous unconditional
        // `starts_with("/model/")` shaped it as bedrock here while auth shaped it as openai —
        // contradictory error envelopes for one path. The canonical classifier now requires the
        // suffix, so a bare `/model/foo/bar` falls through to the OpenAI default, matching auth.rs.
        assert_eq!(
            proto_for_path("/model/foo/bar"),
            "openai",
            "non-Converse /model/ path must align with auth.rs (openai), not bedrock"
        );
        assert_eq!(proto_for_path("/model/foo/predict"), "openai");
        // Unknown path defaults to the widely-understood OpenAI envelope.
        assert_eq!(proto_for_path("/totally/unknown"), "openai");
    }

    /// REGRESSION: the two `proto_for_path` classifiers (main.rs fallback/405 handlers
    /// and `auth.rs` 401 shaping) must agree for EVERY path — they now share one canonical
    /// implementation in `proto`, so this guards that main.rs's delegate matches the canonical source
    /// across the full table including the previously-divergent non-Converse `/model/` paths.
    #[test]
    fn test_proto_for_path_matches_canonical() {
        for path in [
            "/v1/chat/completions",
            "/v1/responses",
            "/v2/chat",
            "/v1/models/gemini-pro:generateContent",
            "/v1beta/models/gemini-pro:streamGenerateContent",
            "/v1/models/gpt-4o",
            "/v1/models",
            "/model/anthropic.claude/converse",
            "/model/anthropic.claude/converse-stream",
            "/model/foo/bar",
            "/model/foo/predict",
            "/my-model/v1/messages",
            "/v1/messages",
            "/totally/unknown",
        ] {
            assert_eq!(
                proto_for_path(path),
                proto::proto_for_path(path),
                "main.rs proto_for_path must equal the canonical proto::proto_for_path for {path}"
            );
        }
    }

    /// A 404 fallback on a Bedrock path must carry the native `__type` envelope AND the `x-amzn-*`
    /// headers a real AWS endpoint always emits — never axum's empty body (a proxy tell).
    #[test]
    fn test_fallback_bedrock_404_is_native_envelope_with_amzn_headers() {
        let resp = fallback_error_response(
            "/model/some.model/converse",
            axum::http::StatusCode::NOT_FOUND,
            crate::admin::ERR_TYPE_NOT_FOUND,
            "missing",
        );
        assert_eq!(resp.status(), axum::http::StatusCode::NOT_FOUND);
        assert_eq!(
            resp.headers()
                .get(axum::http::header::CONTENT_TYPE)
                .and_then(|h| h.to_str().ok()),
            Some("application/json"), // golden wire-contract literal (kept bare on purpose)
            "fallback must be application/json, not bare text"
        );
        assert!(
            resp.headers().get("x-amzn-requestid").is_some(),
            "bedrock fallback must carry x-amzn-RequestId"
        );
        assert!(
            resp.headers().get("x-amzn-errortype").is_some(),
            "bedrock fallback must carry x-amzn-errortype"
        );
    }

    /// A 404 fallback on the OpenAI path is shaped as the OpenAI error envelope (no amzn headers).
    #[tokio::test]
    async fn test_fallback_openai_404_is_json_no_amzn_headers() {
        let resp = fallback_error_response(
            "/v1/chat/completions",
            axum::http::StatusCode::NOT_FOUND,
            // REGRESSION: the fallback 404 emits the CANONICAL `not_found_error` kind, so
            // an OpenAI-inferred 404 carries `{"error":{"type":"not_found_error"}}`, not `not_found`.
            crate::admin::ERR_TYPE_NOT_FOUND,
            "missing",
        );
        assert_eq!(
            resp.headers()
                .get(axum::http::header::CONTENT_TYPE)
                .and_then(|h| h.to_str().ok()),
            Some("application/json") // golden wire-contract literal (kept bare on purpose)
        );
        // Guard the canonical kind reaches the body via the OpenAI writer's verbatim passthrough.
        use http_body_util::BodyExt as _;
        let bytes = resp.into_body().collect().await.unwrap().to_bytes();
        let v: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(
            v["error"]["type"],
            "not_found_error", // golden wire-contract literal (kept bare on purpose)
            "OpenAI-inferred 404 must carry the canonical not_found_error type, not not_found"
        );
        let resp = fallback_error_response(
            "/v1/chat/completions",
            axum::http::StatusCode::NOT_FOUND,
            crate::admin::ERR_TYPE_NOT_FOUND,
            "missing",
        );
        assert!(
            resp.headers().get("x-amzn-requestid").is_none(),
            "non-bedrock fallback must NOT carry x-amzn-* headers"
        );
    }

    /// `Server-Timing` reports Busbar's OWN processing time = total − upstream RTT, with the
    /// no-upstream sentinel reporting the full time and clock skew saturating to zero (never a
    /// huge underflowed value).
    #[test]
    fn test_server_timing_dur_ms() {
        // total 1090µs − upstream 1000µs = 90µs internal = 0.090 ms.
        assert!((server_timing_dur_ms(1090, 1000) - 0.090).abs() < 1e-9);
        // No upstream hop (sentinel) → report the full time (e.g. /healthz at 57µs).
        assert!((server_timing_dur_ms(57, NO_UPSTREAM_RTT) - 0.057).abs() < 1e-9);
        // Clock skew (upstream measured ≥ total) saturates to 0, never underflows.
        assert_eq!(server_timing_dur_ms(500, 800), 0.0);
    }

    /// REGRESSION: axum's `DefaultBodyLimit` rejects an
    /// oversized body with a bare `text/plain` 413 (`"length limit exceeded"`) — a router/proxy
    /// tell. `reshape_oversized_413` must turn that into a protocol-native `application/json`
    /// envelope. Against the OLD code (no reshaping layer) the response stayed `text/plain`, so this
    /// assertion on `application/json` fails; after the fix it passes.
    #[tokio::test]
    async fn test_oversized_body_413_reshaped_to_json_not_plain_text() {
        use axum::response::IntoResponse;
        use http_body_util::BodyExt as _;

        // Simulate exactly what axum's DefaultBodyLimit emits: a 413 with a bare text/plain body.
        let axum_native_413 = (
            axum::http::StatusCode::PAYLOAD_TOO_LARGE,
            [(
                axum::http::header::CONTENT_TYPE,
                axum::http::HeaderValue::from_static("text/plain; charset=utf-8"),
            )],
            "length limit exceeded",
        )
            .into_response();

        let reshaped = reshape_oversized_413("/v1/chat/completions", axum_native_413).await;
        assert_eq!(reshaped.status(), axum::http::StatusCode::PAYLOAD_TOO_LARGE);
        let ct = reshaped
            .headers()
            .get(axum::http::header::CONTENT_TYPE)
            .and_then(|h| h.to_str().ok());
        assert_eq!(
            ct,
            Some("application/json"), // golden wire-contract literal (kept bare on purpose)
            "oversized-body 413 must be reshaped to application/json, not the bare text/plain tell"
        );
        let bytes = reshaped.into_body().collect().await.unwrap().to_bytes();
        // Must be valid JSON (not the plain-text "length limit exceeded" string).
        let v: serde_json::Value =
            serde_json::from_slice(&bytes).expect("reshaped 413 body must be valid JSON");
        assert!(
            v.get("error").is_some(),
            "OpenAI-inferred 413 must carry an `error` envelope; got {v}"
        );
        assert_ne!(
            String::from_utf8_lossy(&bytes),
            "length limit exceeded",
            "the axum plain-text body must not survive reshaping"
        );
    }

    /// REGRESSION: a Bedrock-inferred oversized-body 413 must carry the native AWS
    /// `__type` envelope AND the `x-amzn-*` headers, indistinguishable from a real Bedrock reject.
    #[tokio::test]
    async fn test_oversized_body_413_bedrock_native_envelope_with_amzn_headers() {
        use axum::response::IntoResponse;
        use http_body_util::BodyExt as _;

        let axum_native_413 = (
            axum::http::StatusCode::PAYLOAD_TOO_LARGE,
            [(
                axum::http::header::CONTENT_TYPE,
                axum::http::HeaderValue::from_static("text/plain; charset=utf-8"),
            )],
            "length limit exceeded",
        )
            .into_response();

        let reshaped = reshape_oversized_413("/model/some.model/converse", axum_native_413).await;
        assert_eq!(reshaped.status(), axum::http::StatusCode::PAYLOAD_TOO_LARGE);
        assert_eq!(
            reshaped
                .headers()
                .get(axum::http::header::CONTENT_TYPE)
                .and_then(|h| h.to_str().ok()),
            Some("application/json") // golden wire-contract literal (kept bare on purpose)
        );
        assert!(
            reshaped.headers().get("x-amzn-requestid").is_some(),
            "bedrock 413 must carry x-amzn-RequestId"
        );
        assert!(
            reshaped.headers().get("x-amzn-errortype").is_some(),
            "bedrock 413 must carry x-amzn-errortype"
        );
        let bytes = reshaped.into_body().collect().await.unwrap().to_bytes();
        let v: serde_json::Value =
            serde_json::from_slice(&bytes).expect("reshaped bedrock 413 body must be valid JSON");
        assert!(
            v.get("__type").is_some(),
            "bedrock 413 must carry the native __type envelope; got {v}"
        );
    }

    /// A non-413 response (or a 413 a handler already shaped as JSON) must pass through
    /// `reshape_oversized_413` untouched — the layer only rewrites the bare-text body-limit reject.
    #[tokio::test]
    async fn test_reshape_oversized_413_passthrough() {
        use axum::response::IntoResponse;
        use http_body_util::BodyExt as _;

        // Non-413: untouched.
        let ok = (axum::http::StatusCode::OK, "hello").into_response();
        let passed = reshape_oversized_413("/v1/chat/completions", ok).await;
        assert_eq!(passed.status(), axum::http::StatusCode::OK);
        let bytes = passed.into_body().collect().await.unwrap().to_bytes();
        assert_eq!(
            &bytes[..],
            b"hello",
            "non-413 body must pass through verbatim"
        );

        // 413 that is ALREADY application/json: untouched (re-wrapping would corrupt it).
        let already_json = (
            axum::http::StatusCode::PAYLOAD_TOO_LARGE,
            [(
                axum::http::header::CONTENT_TYPE,
                axum::http::HeaderValue::from_static(crate::forward::APPLICATION_JSON),
            )],
            r#"{"error":{"type":"request_too_large","message":"native"}}"#,
        )
            .into_response();
        let passed = reshape_oversized_413("/v1/chat/completions", already_json).await;
        let bytes = passed.into_body().collect().await.unwrap().to_bytes();
        let v: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(
            v["error"]["message"], "native",
            "an already-JSON 413 must be passed through, not re-wrapped"
        );
    }

    /// REGRESSION: a forward-path-relayed UPSTREAM 413 with a NON-JSON content-type (e.g.
    /// an upstream that itself answers 413 with a `text/plain`/`text/html` body that is NOT axum's
    /// own `length limit exceeded` marker) must pass through `reshape_oversized_413` UNTOUCHED —
    /// reshaping it would clobber the upstream's relayed error with busbar's own envelope.
    ///
    /// Against the OLD code (which reshaped ANY non-JSON 413) this body would be rewritten into
    /// busbar's `request_too_large` JSON, so the `text/plain` content-type + verbatim-body
    /// assertions below fail; after the sentinel gate they pass.
    #[tokio::test]
    async fn test_relayed_upstream_413_not_reshaped() {
        use axum::response::IntoResponse;
        use http_body_util::BodyExt as _;

        // An upstream-relayed 413 whose body is NOT axum's body-limit sentinel.
        let upstream_413 = (
            axum::http::StatusCode::PAYLOAD_TOO_LARGE,
            [(
                axum::http::header::CONTENT_TYPE,
                axum::http::HeaderValue::from_static("text/plain; charset=utf-8"),
            )],
            "upstream says: prompt is too long",
        )
            .into_response();

        let passed = reshape_oversized_413("/v1/chat/completions", upstream_413).await;
        assert_eq!(passed.status(), axum::http::StatusCode::PAYLOAD_TOO_LARGE);
        // Content-type must remain the upstream's text/plain — NOT rewritten to application/json.
        assert_eq!(
            passed
                .headers()
                .get(axum::http::header::CONTENT_TYPE)
                .and_then(|h| h.to_str().ok()),
            Some("text/plain; charset=utf-8"), // golden wire-contract literal (kept bare on purpose)
            "a relayed upstream 413 must keep its own content-type, not be reshaped to JSON"
        );
        let bytes = passed.into_body().collect().await.unwrap().to_bytes();
        assert_eq!(
            &bytes[..],
            b"upstream says: prompt is too long",
            "a relayed upstream 413 body must pass through verbatim, not be clobbered"
        );
    }

    /// The sentinel gate must be exact: a non-JSON 413 whose body equals axum's
    /// [`AXUM_BODY_LIMIT_413_MARKER`] IS reshaped (it is axum's own reject), confirming the
    /// passthrough above is driven by the body content and not merely the content-type.
    #[tokio::test]
    async fn test_axum_marker_413_is_reshaped_even_as_plain_text() {
        use axum::response::IntoResponse;
        use http_body_util::BodyExt as _;

        let axum_native_413 = (
            axum::http::StatusCode::PAYLOAD_TOO_LARGE,
            [(
                axum::http::header::CONTENT_TYPE,
                axum::http::HeaderValue::from_static("text/plain; charset=utf-8"),
            )],
            std::str::from_utf8(AXUM_BODY_LIMIT_413_MARKER).unwrap(),
        )
            .into_response();

        let reshaped = reshape_oversized_413("/v1/chat/completions", axum_native_413).await;
        assert_eq!(
            reshaped
                .headers()
                .get(axum::http::header::CONTENT_TYPE)
                .and_then(|h| h.to_str().ok()),
            Some("application/json"), // golden wire-contract literal (kept bare on purpose)
            "axum's own body-limit 413 (sentinel body) must be reshaped to JSON"
        );
        let bytes = reshaped.into_body().collect().await.unwrap().to_bytes();
        let v: serde_json::Value =
            serde_json::from_slice(&bytes).expect("reshaped 413 body must be valid JSON");
        assert!(v.get("error").is_some());
    }
}
