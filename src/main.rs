// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Matthew Jackson
//
// busbar — a native-protocol LLM gateway. It fronts many LLM providers and routes each request to
// a model or to a weighted pool of models, translating losslessly between wire protocols and
// protecting each backend with a circuit breaker. The name is electrical: a busbar takes one feed
// and fans it out across many breakered circuits.
//
// Routing (clients append the protocol path themselves):
//   POST /<model>/v1/messages            a single model (Anthropic-format ingress)
//   POST /<pool>/v1/messages             a config-defined pool (weighted selection + failover)
//   POST /<provider>/<model>/v1/messages ad-hoc: a specific configured provider+model
//   POST /v1/chat/completions            OpenAI-format ingress (model from the body)
//   GET  /stats  /healthz  /metrics
//
// Each model is a "lane" with its own concurrency semaphore, optional lifetime request budget, and
// per-(pool,lane) circuit-breaker health. A pool stacks its members' concurrency into one aggregate
// and distributes via smooth weighted round-robin. Ingress and backend protocols may differ: the
// request and response are translated through a superset intermediate representation (see
// `proto`/`ir`), so e.g. an OpenAI-format client can drive a Gemini or Bedrock backend.
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
    for (model, mc) in cfg.models {
        model_default_max_tokens.insert(model.clone(), mc.default_max_tokens);
        let provider_cfg = cfg.providers.get(&mc.provider).unwrap_or_else(|| {
            die(format!(
                "model '{model}' references unknown provider '{}'",
                mc.provider
            ))
        });
        let key = std::env::var(&provider_cfg.api_key_env).unwrap_or_default();
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

    // Build a map from model name to context_max (pools can have different context_max per member).
    let mut model_context_max: std::collections::HashMap<String, Option<usize>> =
        std::collections::HashMap::new();
    for pool in cfg.pools.values() {
        for m in &pool.members {
            // Later members override earlier ones if same target appears multiple times
            model_context_max.insert(m.target.clone(), m.context_max);
        }
    }

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
            api_key: std::env::var(&provider_cfg.api_key_env).unwrap_or_default(),
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
    // local dev) — but operators must not run this in production.
    if let Some(ref acfg) = cfg.auth {
        if auth::AuthMode::from_config_str(&acfg.mode) == Some(auth::AuthMode::None) {
            tracing::warn!(
                "auth is DISABLED (auth.mode=none) — this is an open relay; do not run in production"
            );
        }
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
    if let Err(e) = axum::serve(listener, router).await {
        die(format!("server error: {e}"));
    }
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
        .route("/v1beta/models/*rest", post(route::gemini_ingress))
        // Bedrock Converse ingress: model in the path, stream selected by the endpoint suffix.
        .route("/model/:model_id/converse", post(route::bedrock_converse))
        .route(
            "/model/:model_id/converse-stream",
            post(route::bedrock_converse_stream),
        )
        .route("/:name/v1/messages", post(route::named))
        .route("/:provider/:model/v1/messages", post(route::adhoc))
        .layer(axum::middleware::from_fn_with_state(
            app.clone(),
            auth::auth_middleware,
        ))
        // Cap request body size (buffered before the handler) to bound per-request memory.
        .layer(axum::extract::DefaultBodyLimit::max(MAX_REQUEST_BODY_BYTES))
        .with_state(app)
}
