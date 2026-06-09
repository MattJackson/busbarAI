// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Matthew Jackson
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

mod admin;
mod auth;
mod breaker;
mod config;
mod config_validate;
mod eventstream;
mod forward;
mod governance;
mod handlers;
mod health;
mod ir;
mod metrics;
mod observability;
mod proto;
mod route;
mod sigv4;
mod state;
mod store;
#[cfg(test)]
mod test_support;

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use axum::{routing::get, routing::post, Router};

use auth::AuthMiddleware;

use proto::ProtocolRegistry;
use state::{App, Lane, WeightedLane};
use store::{InMemoryStore, LaneData};

/// Per-request timeout for upstream calls. Generous because it must cover long streamed
/// completions, not just time-to-first-byte.
const UPSTREAM_REQUEST_TIMEOUT_SECS: u64 = 300;
/// Max idle keep-alive connections the shared HTTP client pools per upstream host.
const POOL_MAX_IDLE_PER_HOST: usize = 64;
/// Maximum accepted request body size. Caps memory per request (the body is buffered before
/// handling) so a hostile/oversized payload can't exhaust memory — generous enough for long
/// histories and multimodal/base64 image content, but bounded. (axum's default is only 2 MiB.)
const MAX_REQUEST_BODY_BYTES: usize = 32 * 1024 * 1024;

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
        Some("--help" | "-h") => {
            println!(
                "busbar {ver} — native-protocol LLM gateway

USAGE:
    busbar              run the gateway (configured entirely via environment + YAML)
    busbar --help       print this help
    busbar --version    print the version

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
    GET  /stats  /healthz  /metrics

Docs: https://github.com/MattJackson/busbarAI",
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

/// Return the open-relay banner to emit when auth resolves to `mode=none`, or `None` when auth is
/// engaged. `auth_present` distinguishes an explicit `mode: none` (operator opted in) from a
/// missing `auth:` block (serde-defaulted to none — the silent foot-gun the banner must call out).
/// Returns `None` for every non-`None` mode (and for an unparseable mode, which validation already
/// rejects upstream) so the caller emits nothing.
fn open_relay_banner(mode: Option<auth::AuthMode>, auth_present: bool) -> Option<&'static str> {
    if mode != Some(auth::AuthMode::None) {
        return None;
    }
    Some(if auth_present {
        "auth is DISABLED (auth.mode=none) — busbar is running as an OPEN RELAY; do not run this in production"
    } else {
        "auth is DISABLED: no `auth:` block in config — busbar is running as an OPEN RELAY (anyone can use it). Add `auth:` with `mode: token` (and `client_tokens`) before exposing it; do not run this in production"
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
        std::env::var("BUSBAR_PROVIDERS").unwrap_or_else(|_| "/etc/busbar/providers.yaml".into());
    let raw_providers = std::fs::read_to_string(&providers_path).unwrap_or_else(|e| {
        die(format!(
            "cannot read providers file '{providers_path}': {e} (set BUSBAR_PROVIDERS)"
        ))
    });
    let interpolated_providers = config::interpolate_env(&raw_providers)
        .unwrap_or_else(|e| die(format!("providers.yaml: {e}")));
    let defs: HashMap<String, config::ProviderDef> = serde_yaml::from_str(&interpolated_providers)
        .unwrap_or_else(|e| die(format!("providers.yaml: invalid YAML: {e}")));

    // Read config.yaml (deployment)
    let config_path =
        std::env::var("BUSBAR_CONFIG").unwrap_or_else(|_| "/etc/busbar/config.yaml".into());
    let raw_config = std::fs::read_to_string(&config_path).unwrap_or_else(|e| {
        die(format!(
            "cannot read config file '{config_path}': {e} (set BUSBAR_CONFIG)"
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

    // Resolve deployment + definitions into resolved RootCfg
    let cfg = config::resolve(&deploy, &defs)
        .unwrap_or_else(|errs| die(format!("config errors:\n  - {}", errs.join("\n  - "))));
    // cfg.auth is ALREADY normalized: config::resolve calls AuthCfg::normalize() on the auth block
    // (legacy single-token promotion). Normalizing again here would be redundant work and obscure
    // the single-normalization invariant, so just clone the resolved value.
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

    let mut lanes_data = Vec::new();
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
    for (model, mc) in cfg.models {
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
        });

        eprintln!(
            "  model {} via {} ({}) max {}",
            model,
            mc.provider,
            provider_cfg.base_url.trim_end_matches('/'),
            mc.max_concurrent
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
    for ld in &lanes_data {
        let provider_cfg = cfg
            .providers
            .get(&ld.provider)
            .expect("lane provider exists in resolved config (validated above)");
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
            auth: provider_cfg.auth.clone(),
            health: provider_cfg.health.clone(),
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

    // Loud warning for auth.mode=none (open relay). Not fatal — busbar still starts (useful for
    // local dev) — but operators must not run this in production. NOTE: an ABSENT `auth:` block
    // serde-defaults to mode=none too (`AuthCfg::default_none`), so a config that merely omits
    // `auth:` silently becomes an open relay. Surface this at ERROR level (not warn — a warn is
    // suppressed under RUST_LOG=error, the very level an operator most likely runs in production)
    // AND unconditionally on stderr, so the open-relay state cannot be masked by log configuration.
    if let Some(banner) = open_relay_banner(
        auth::AuthMode::from_config_str(&auth_cfg.mode),
        cfg.auth.is_some(),
    ) {
        eprintln!("[error] {banner}");
        tracing::error!("{banner}");
    }

    let auth_mw = Arc::new(AuthMiddleware::new(&auth_cfg));
    let store = Arc::new(InMemoryStore::new(lanes_data.clone()));

    // Global default failover config — the fallback for pools that don't set their own. A fixed
    // default (not "whatever pool HashMap iteration happens to yield first", which was
    // nondeterministic across restarts).
    let failover_cfg = Some(crate::config::FailoverCfg {
        deadline_secs: crate::config::DEFAULT_FAILOVER_DEADLINE_SECS,
        exclusions: None,
        cap: crate::config::DEFAULT_FAILOVER_CAP,
    });

    // The fallback-pool routing table: on_exhausted `fallback_pool:<name>` looks a pool up here,
    // so it mirrors the pools map (any pool can be a fallback target).
    let fallback_pools = pools.clone();

    // Per-pool runtime config (failover/exclusions), keyed by pool name.
    let mut pool_runtime = std::collections::HashMap::new();
    for (pool_name, pool_cfg) in &cfg.pools {
        pool_runtime.insert(
            pool_name.clone(),
            state::PoolRuntime {
                failover: pool_cfg.failover.clone(),
                affinity: pool_cfg.affinity.clone(),
                breaker: pool_cfg.breaker.as_ref().map(store::BreakerCfg::from),
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

    let app = Arc::new(App {
        lanes,
        store,
        by_model,
        pools,
        client: reqwest::Client::builder()
            .timeout(Duration::from_secs(UPSTREAM_REQUEST_TIMEOUT_SECS))
            .pool_max_idle_per_host(POOL_MAX_IDLE_PER_HOST)
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
            .expect("build upstream HTTP client"),
        auth: auth_mw.clone(),
        auth_mode: auth_mw.mode,
        failover_cfg,
        pool_runtime,
        fallback_pools,
        on_exhausted_cfgs,
        governance,
    });

    // configure the request-log webhook (reusing the pooled client). No-op if unset.
    observability::configure_webhook(
        observability_cfg.request_log_webhook_url.clone(),
        app.client.clone(),
    );

    // Spawn the active health probers (one per lane with a probing mode). No-op when every lane is
    // `mode: none` / has no `health:` block.
    health::spawn_probers(app.clone());

    let router = build_router(app);

    let listener = tokio::net::TcpListener::bind(&listen)
        .await
        .unwrap_or_else(|e| die(format!("cannot bind listen address '{listen}': {e}")));
    tracing::info!(%listen, "busbar listening");
    // Graceful shutdown: on ctrl_c (SIGINT) or SIGTERM, stop accepting new connections, let
    // in-flight requests drain, then flush the OTLP tracer so the final (most diagnostic) spans are
    // exported rather than dropped when the runtime tears down. The signal future is panic-free —
    // a failed registration logs and parks forever (so a missing signal facility degrades to "no
    // graceful shutdown", never a crash), and `shutdown_tracing()` is a no-op when OTLP is off.
    let serve = axum::serve(listener, router).with_graceful_shutdown(shutdown_signal());
    if let Err(e) = serve.await {
        die(format!("server error: {e}"));
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
fn fallback_error_response(
    path: &str,
    status: axum::http::StatusCode,
    kind: &str,
    message: &str,
) -> axum::response::Response {
    use axum::response::IntoResponse;
    let proto = proto_for_path(path);
    let body = match proto::protocol_for(proto) {
        Some(p) => p.writer().write_error(status.as_u16(), kind, message),
        // proto_for_path only ever returns a registered protocol literal, so this is unreachable in
        // practice; shape a generic OpenAI-style envelope rather than panic on the request path.
        None => serde_json::json!({ "error": { "message": message, "type": kind } }),
    };
    let mut resp = (
        status,
        [(
            axum::http::header::CONTENT_TYPE,
            axum::http::HeaderValue::from_static("application/json"),
        )],
        body.to_string(),
    )
        .into_response();
    if proto == "bedrock" {
        let headers = resp.headers_mut();
        if let Some(id) = proto::synth_amzn_request_id() {
            if let Ok(hv) = axum::http::HeaderValue::from_str(&id) {
                headers.insert(axum::http::HeaderName::from_static("x-amzn-requestid"), hv);
            }
        }
        let errortype = proto::error_kind_to_bedrock_type(kind);
        if let Ok(hv) = axum::http::HeaderValue::from_str(errortype) {
            headers.insert(axum::http::HeaderName::from_static("x-amzn-errortype"), hv);
        }
    }
    resp
}

/// 404 fallback: an unmatched path. A real vendor backend answers an unknown route with its native
/// JSON error envelope, never axum's empty body — so reshape to the inferred protocol's `not_found`
/// shape (see [`fallback_error_response`]).
async fn fallback_handler(uri: axum::http::Uri) -> axum::response::Response {
    fallback_error_response(
        uri.path(),
        axum::http::StatusCode::NOT_FOUND,
        // CANONICAL kind: `not_found_error` (matches `route.rs`'s 404s and what every writer expects).
        // The previous `not_found` passed through the OpenAI writer verbatim, so a 404 on an
        // OpenAI-inferred path emitted `{"error":{"type":"not_found"}}` — a non-canonical type that
        // breaks native SDK exception mapping and is a distinguishability tell.
        "not_found_error",
        "the requested resource was not found",
    )
}

/// 405 fallback: a valid ingress path hit with the wrong method (e.g. GET on a POST-only ingress).
/// axum's built-in 405 is an `Allow`-header-only empty body; reshape to the protocol-native envelope
/// so an SDK sees a vendor-shaped error instead of a bare proxy tell.
async fn method_not_allowed_handler(uri: axum::http::Uri) -> axum::response::Response {
    fallback_error_response(
        uri.path(),
        axum::http::StatusCode::METHOD_NOT_ALLOWED,
        "invalid_request_error",
        "method not allowed for this resource",
    )
}

/// Build the busbar HTTP router for a given `App` state. Factored out of `main` so the full
/// route table + auth middleware can be exercised end-to-end in tests.
pub(crate) fn build_router(app: std::sync::Arc<state::App>) -> Router {
    Router::new()
        .route("/stats", get(handlers::stats))
        .route("/healthz", get(handlers::healthz))
        .route("/metrics", get(metrics::handler))
        // virtual-key management API (admin-token guarded in auth_middleware).
        .route("/admin/keys", post(admin::create_key).get(admin::list_keys))
        .route("/admin/keys/:id", axum::routing::delete(admin::delete_key))
        .route("/admin/keys/:id/usage", get(admin::key_usage))
        .route("/v1/chat/completions", post(route::openai_ingress))
        // Cohere v2 + OpenAI Responses ingress: model+stream in the body (body-model protocols).
        .route("/v2/chat", post(route::cohere_ingress))
        .route("/v1/responses", post(route::responses_ingress))
        // Gemini ingress: model+action packed into the last path segment with a colon. axum can't
        // split on a `:` inside a segment, so capture the tail with a wildcard and split in-handler.
        // Both the stable `v1` and the `v1beta` surfaces are wire-identical for generateContent /
        // streamGenerateContent; the google-generativeai / Gen AI SDKs use either, so a client pinned
        // to the stable `v1` endpoint must also resolve here rather than fall through to a bare 404.
        .route("/v1/models/*rest", post(route::gemini_ingress))
        .route("/v1beta/models/*rest", post(route::gemini_ingress))
        // Bedrock Converse ingress: model in the path, stream selected by the endpoint suffix.
        .route("/model/:model_id/converse", post(route::bedrock_converse))
        .route(
            "/model/:model_id/converse-stream",
            post(route::bedrock_converse_stream),
        )
        .route("/:name/v1/messages", post(route::named))
        .route("/:provider/:model/v1/messages", post(route::adhoc))
        // Global fallback for unmatched paths (404) and wrong-method hits on a valid path (405).
        // axum's built-in responses are an EMPTY body (404) or an `Allow`-header-only 405 — both bare
        // text, which a native vendor SDK cannot decode and which fingerprint busbar as a router/proxy
        // (the §8.1 transparency gap). Reshape into the inferred ingress protocol's native JSON error
        // envelope so a client probing an unsupported edge still sees a vendor-shaped error.
        .fallback(fallback_handler)
        // Wrong-method hits on a VALID path (axum's built-in 405) get the same native-envelope
        // treatment as the 404 fallback above.
        .method_not_allowed_fallback(method_not_allowed_handler)
        .layer(axum::middleware::from_fn_with_state(
            app.clone(),
            auth::auth_middleware,
        ))
        // Cap request body size (buffered before the handler) to bound per-request memory.
        .layer(axum::extract::DefaultBodyLimit::max(MAX_REQUEST_BODY_BYTES))
        .with_state(app)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{PoolCfg, PoolMember};

    fn pool(members: Vec<PoolMember>) -> PoolCfg {
        PoolCfg {
            members,
            breaker: None,
            failover: None,
            on_exhausted: None,
            affinity: None,
        }
    }

    fn member(target: &str, context_max: Option<usize>) -> PoolMember {
        PoolMember {
            target: target.to_string(),
            weight: 1,
            context_max,
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
        // Absent `auth:` block: banner must flag the silent open-relay foot-gun.
        let absent = open_relay_banner(Some(auth::AuthMode::None), false)
            .expect("mode=none must produce a banner");
        assert!(
            absent.contains("OPEN RELAY") && absent.contains("no `auth:` block"),
            "absent-auth banner must call out the missing block; got: {absent}"
        );
        // Explicit mode: none: still an open relay, but the operator opted in.
        let explicit = open_relay_banner(Some(auth::AuthMode::None), true)
            .expect("explicit none must produce a banner");
        assert!(
            explicit.contains("OPEN RELAY") && explicit.contains("auth.mode=none"),
            "explicit-none banner must reference auth.mode=none; got: {explicit}"
        );
    }

    #[test]
    fn test_open_relay_banner_silent_when_auth_engaged() {
        // Token / passthrough modes (and an unparseable mode, already rejected by validation) emit
        // nothing — the banner is exclusively for the open-relay state.
        assert!(open_relay_banner(Some(auth::AuthMode::Token), true).is_none());
        assert!(open_relay_banner(Some(auth::AuthMode::Passthrough), true).is_none());
        assert!(open_relay_banner(None, true).is_none());
    }

    /// MEDIUM/conformance (main.rs:569): the fallback handlers infer the ingress protocol from the
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
        // REGRESSION (MEDIUM/conformance, main.rs:589): an OpenAI-SDK `model.retrieve` hits
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
        // REGRESSION (R7 MEDIUM): a NON-Converse `/model/...` path must NOT be classified as bedrock
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

    /// REGRESSION (R7 MEDIUM): the two `proto_for_path` classifiers (main.rs fallback/405 handlers
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
            "not_found_error",
            "missing",
        );
        assert_eq!(resp.status(), axum::http::StatusCode::NOT_FOUND);
        assert_eq!(
            resp.headers()
                .get(axum::http::header::CONTENT_TYPE)
                .and_then(|h| h.to_str().ok()),
            Some("application/json"),
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
            // REGRESSION (R7 MEDIUM): the fallback 404 emits the CANONICAL `not_found_error` kind, so
            // an OpenAI-inferred 404 carries `{"error":{"type":"not_found_error"}}`, not `not_found`.
            "not_found_error",
            "missing",
        );
        assert_eq!(
            resp.headers()
                .get(axum::http::header::CONTENT_TYPE)
                .and_then(|h| h.to_str().ok()),
            Some("application/json")
        );
        // Guard the canonical kind reaches the body via the OpenAI writer's verbatim passthrough.
        use http_body_util::BodyExt as _;
        let bytes = resp.into_body().collect().await.unwrap().to_bytes();
        let v: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(
            v["error"]["type"], "not_found_error",
            "OpenAI-inferred 404 must carry the canonical not_found_error type, not not_found"
        );
        let resp = fallback_error_response(
            "/v1/chat/completions",
            axum::http::StatusCode::NOT_FOUND,
            "not_found_error",
            "missing",
        );
        assert!(
            resp.headers().get("x-amzn-requestid").is_none(),
            "non-bedrock fallback must NOT carry x-amzn-* headers"
        );
    }
}
