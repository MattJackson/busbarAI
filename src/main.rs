// busbar — central LLM gateway: round-robin across lanes like a busbar across circuits.
// a PATH that names what they want. Anthropic `/v1/messages` format (v1).
//
// Clean user API (clients append /v1/messages themselves, per the Anthropic SDK):
//   POST /<name>                  name = a model OR a config-defined pool
//        /glm-4.5                 -> that single model
//        /glm                     -> pool: round-robin glm-5.1+glm-4.6+glm-4.5
//        /haiku                   -> claude-haiku via anthropic
//   POST /<provider>/<model>      ad-hoc: any provider+model, no pool needed
//        /z.ai/glm-4.6
//   GET  /stats  /healthz
//
// A round-robin pool stacks its models' per-model concurrency caps into one
// aggregate (10+10+3 = 23). Each model is a "lane" with its own semaphore +
// smart health handling. The caller's own model/key fields are ignored — the
// router rewrites `model` and injects the provider's key. No per-client keys.
//
// Smart lane health:
//   2xx                          -> relay, reset streak
//   billing (z.ai 1113)          -> STOP lane permanently (empty wallet won't heal)
//   auth (401/403)               -> STOP lane permanently (bad key/config)
//   rate limit (429 / z.ai 1302) -> escalating cooldown (15s*streak, cap 120s)
//   5xx / network / timeout      -> short cooldown (10s)
//   other 4xx (400/404/422)      -> RELAY to caller, do NOT penalize the lane
//   max_requests budget hit      -> disable lane (cost cap)
//
// v2: OpenAI-protocol providers (P4/A5500 /v1/chat/completions) need Anthropic
// <-> OpenAI translation; not handled here. All v1 lanes are Anthropic-format.

mod auth;
mod breaker;
mod config;
mod config_validate;
mod forward;
mod handlers;
mod proto;
mod route;
mod state;
mod store;
#[cfg(test)]
mod test_support;

use std::collections::HashMap;
use std::sync::atomic::AtomicUsize;
use std::sync::Arc;
use std::time::Duration;

use axum::{routing::get, routing::post, Router};

use auth::AuthMiddleware;
use config::RootCfg;
use state::{App, Lane, ProtocolKind};
use store::{InMemoryStore, LaneData};

#[tokio::main]
async fn main() {
    let path = std::env::var("BUSBAR_CONFIG").unwrap_or_else(|_| "/etc/busbar/config.yaml".into());

    let raw_content = std::fs::read_to_string(&path).expect("read BUSBAR_CONFIG");
    let interpolated =
        config::interpolate_env(&raw_content).expect("expand ${ENV} variables in config");
    let cfg: RootCfg = serde_yaml::from_str(&interpolated).expect("parse config YAML");
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
            inflight: 0,
            ok: 0,
            err: 0,
        });

        eprintln!(
            "  model {} via {} ({}) max {}",
            model,
            mc.provider,
            provider_cfg.base_url.trim_end_matches('/'),
            mc.max_concurrent
        );
    }

    let mut lanes = Vec::new();
    for ld in &lanes_data {
        let proto = if ld.provider == "anthropic" {
            ProtocolKind::Anthropic(crate::proto::AnthropicProtocol::new())
        } else {
            panic!(
                "unknown protocol '{}' for provider {}",
                ld.provider,
                cfg.providers.get(&ld.provider).unwrap().protocol
            );
        };

        let provider_cfg = cfg.providers.get(&ld.provider).unwrap();
        lanes.push(Lane {
            model: ld.model.clone(),
            provider: ld.provider.clone(),
            base_url: provider_cfg.base_url.trim_end_matches('/').to_string(),
            api_key: std::env::var(&provider_cfg.api_key_env).unwrap_or_default(),
            protocol: proto,
            max: ld.max,
        });
    }

    let mut pools = HashMap::new();
    for (name, pool) in cfg.pools {
        let members: Vec<String> = pool.members.iter().map(|m| m.target.clone()).collect();
        let idx: Vec<usize> = members
            .iter()
            .map(|m| {
                *by_model
                    .get(m)
                    .unwrap_or_else(|| panic!("pool {name} references unknown model {m}"))
            })
            .collect();
        pools.insert(name, idx);
    }

    eprintln!("busbar: {} models, {} pools", lanes.len(), pools.len());
    for (n, idx) in &pools {
        let agg: usize = idx.iter().map(|&i| lanes[i].max).sum();
        eprintln!(
            "  pool /{} = [{}] aggregate {}",
            n,
            idx.iter()
                .map(|&i| lanes[i].model.clone())
                .collect::<Vec<_>>()
                .join(", "),
            agg
        );
    }

    let listen = cfg.listen.clone();

    // Loud warning for auth.mode=none (open relay)
    if let Some(ref acfg) = cfg.auth {
        let normalized = acfg.clone().normalize();
        if normalized.mode == "none" {
            eprintln!("[FATAL] AUTH DISABLED — open relay; this is a security risk in production");
        }
    }

    let auth_mw = Arc::new(AuthMiddleware::new(&auth_cfg));
    let store = Arc::new(InMemoryStore::new(lanes_data.clone()));

    let app = Arc::new(App {
        lanes,
        store,
        by_model,
        pools,
        rr: AtomicUsize::new(0),
        client: reqwest::Client::builder()
            .timeout(Duration::from_secs(300))
            .pool_max_idle_per_host(64)
            .build()
            .unwrap(),
        auth: auth_mw.clone(),
        auth_mode: auth_mw.mode,
    });

    let router = Router::new()
        .route("/stats", get(handlers::stats))
        .route("/healthz", get(handlers::healthz))
        .route("/:name/v1/messages", post(route::named))
        .route("/:provider/:model/v1/messages", post(route::adhoc))
        .layer(axum::middleware::from_fn_with_state(
            app.clone(),
            auth::auth_middleware,
        ))
        .with_state(app);

    let listener = tokio::net::TcpListener::bind(&listen).await.expect("bind");
    eprintln!("busbar listening on {listen}");
    axum::serve(listener, router).await.unwrap();
}
