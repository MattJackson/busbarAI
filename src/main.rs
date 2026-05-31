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

#[tokio::main]
async fn main() {
    // Install the Prometheus recorder before anything emits metrics.
    metrics::init();

    // Read providers.yaml (shipped definitions)
    let providers_path =
        std::env::var("BUSBAR_PROVIDERS").unwrap_or_else(|_| "/etc/busbar/providers.yaml".into());
    let raw_providers = std::fs::read_to_string(&providers_path).expect("read BUSBAR_PROVIDERS");
    let interpolated_providers =
        config::interpolate_env(&raw_providers).expect("expand ${ENV} variables in providers.yaml");
    let defs: HashMap<String, config::ProviderDef> =
        serde_yaml::from_str(&interpolated_providers).expect("parse providers.yaml");

    // Read config.yaml (deployment)
    let config_path =
        std::env::var("BUSBAR_CONFIG").unwrap_or_else(|_| "/etc/busbar/config.yaml".into());
    let raw_config = std::fs::read_to_string(&config_path).expect("read BUSBAR_CONFIG");
    let interpolated_config =
        config::interpolate_env(&raw_config).expect("expand ${ENV} variables in config");
    let deploy: config::DeployCfg =
        serde_yaml::from_str(&interpolated_config).expect("parse config.yaml as DeployCfg");

    // Optional observability sinks; grab before `deploy` is borrowed by resolve.
    let observability_cfg = deploy.observability.clone().unwrap_or_default();
    // Governance config; grab before `deploy` is borrowed by resolve.
    let governance_cfg = deploy.governance.clone();

    // Install the tracing subscriber now (stderr fmt always; OTLP export if configured) so all
    // subsequent startup and request-path logging is captured.
    observability::init_logging(observability_cfg.otlp_endpoint.as_deref());

    // Resolve deployment + definitions into resolved RootCfg
    let cfg =
        config::resolve(&deploy, &defs).expect("resolve provider deployments from providers.yaml");
    let auth_cfg = cfg
        .auth
        .as_ref()
        .map(|a| a.clone().normalize())
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
    for (model, mc) in cfg.models {
        let provider_cfg = cfg
            .providers
            .get(&mc.provider)
            .unwrap_or_else(|| panic!("model {model} -> unknown provider {}", mc.provider));
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
        let provider_cfg = cfg.providers.get(&ld.provider).unwrap();
        let protocol = registry.get(&provider_cfg.protocol).unwrap_or_else(|| {
            panic!(
                "unknown protocol '{}' for provider {}",
                provider_cfg.protocol, ld.provider
            )
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
                    panic!("pool {} references unknown model {}", name, m.target)
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
                    eprintln!("  pool /{}: on_exhausted = {:?}", pool_name, mode);
                    on_exhausted_cfgs.insert(pool_name.clone(), mode);
                }
                Err(e) => {
                    panic!(
                        "pool '{}' has invalid on_exhausted action '{}': {}",
                        pool_name, on_exc.action, e
                    );
                }
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

    let listener = tokio::net::TcpListener::bind(&listen).await.expect("bind");
    eprintln!("busbar listening on {listen}");
    axum::serve(listener, router).await.unwrap();
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
        .route("/:name/v1/messages", post(route::named))
        .route("/:provider/:model/v1/messages", post(route::adhoc))
        .layer(axum::middleware::from_fn_with_state(
            app.clone(),
            auth::auth_middleware,
        ))
        .with_state(app)
}
