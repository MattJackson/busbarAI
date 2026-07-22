use crate::governance::{GovState, MemoryStore, NewKeySpec};
use crate::test_support::TestApp;
use std::sync::Arc;

/// A `tracing::Layer` that records the messages of WARN-level events it sees, so a test can
/// assert a particular `tracing::warn!` fired (mirrors the established pattern in config.rs /
/// config_validate.rs / eventstream.rs).
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
        // Capture the rendered message AND every other field (e.g. the structured `pool` /
        // `key_name` on create_key's diagnostic) so a test can assert on a field value, not just
        // the static message text. Fields are flattened into one `key=value` string per event.
        #[derive(Default)]
        struct Vis {
            message: String,
            fields: String,
        }
        impl Vis {
            fn record(&mut self, field: &tracing::field::Field, rendered: String) {
                if field.name() == "message" {
                    self.message = rendered;
                } else {
                    if !self.fields.is_empty() {
                        self.fields.push(' ');
                    }
                    self.fields
                        .push_str(&format!("{}={}", field.name(), rendered));
                }
            }
        }
        impl tracing::field::Visit for Vis {
            fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
                self.record(field, format!("{value:?}"));
            }
            fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
                self.record(field, value.to_string());
            }
        }
        let mut vis = Vis::default();
        event.record(&mut vis);
        if let Ok(mut msgs) = self.0.lock() {
            msgs.push(format!("{} {}", vis.message, vis.fields));
        }
    }
}

/// Build a router whose App has governance enabled with a known admin token, returning the
/// listen address + the live server handle.
async fn serve_with_gov(gov: Arc<GovState>) -> (std::net::SocketAddr, tokio::task::JoinHandle<()>) {
    let app = TestApp::new().governance(gov).build();
    let router = crate::build_router(app);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    (addr, handle)
}

/// `GET /api/v1/admin/info` flows end-to-end through the ports-and-adapters stack (JSON-REST
/// transport → service → contract view): admin-token guarded, returns the version, the
/// compiled-in plugin proof (with the default build's `tokens`/`ranking` present + the always-on
/// `weighted_floor`), and the topology counts. Proves the transport is mounted and the frozen
/// v1 surface answers.
#[tokio::test]
async fn test_admin_v1_info_reports_version_features_and_topology() {
    crate::metrics::init();
    let store = Arc::new(MemoryStore::new());
    let gov = Arc::new(GovState::new(store, Some("admintok".to_string())).unwrap());
    let (addr, handle) = serve_with_gov(gov).await;
    let client = reqwest::Client::new();

    // Wrong token → 401 (the v1 surface is admin-guarded like the rest of /admin).
    let unauth = client
        .get(format!("http://{addr}/api/v1/admin/info"))
        .send()
        .await
        .unwrap();
    assert_eq!(
        unauth.status().as_u16(),
        401,
        "v1/info must be admin-guarded"
    );

    let resp = client
        .get(format!("http://{addr}/api/v1/admin/info"))
        .header("x-admin-token", "admintok")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), 200);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(
        body["version"].as_str(),
        Some(env!("CARGO_PKG_VERSION")),
        "info must report the build version"
    );
    // The `weighted_floor` is ALWAYS true (non-removable). `tokens`/`ranking` are present iff their
    // feature is compiled in — so the compliance-by-compilation proof holds under
    // `--no-default-features` too (the lists are empty there).
    assert_eq!(body["build"]["weighted_floor"], serde_json::json!(true));
    let auth_modules = body["build"]["auth_modules"].as_array().unwrap();
    assert_eq!(
            auth_modules.iter().any(|m| m == "tokens"),
            cfg!(feature = "auth-tokens"),
            "auth_modules must contain `tokens` iff the auth-tokens feature is compiled in: {auth_modules:?}"
        );
    let hook_plugins = body["build"]["hook_plugins"].as_array().unwrap();
    assert_eq!(
            hook_plugins.iter().any(|m| m == "ranking"),
            cfg!(feature = "hooks-ranking"),
            "hook_plugins must contain `ranking` iff the hooks-ranking feature is compiled in: {hook_plugins:?}"
        );
    // Topology keys are present and numeric (exact counts depend on the TestApp fixture).
    assert!(body["topology"]["pools"].is_number());
    assert!(body["topology"]["models"].is_number());
    assert!(body["topology"]["providers"].is_number());
    // No overlay configured in this fixture → persistence off.
    assert_eq!(body["config_persistence"], false);

    handle.abort();
}

/// The topology read surface (`/api/v1/admin/pools`, `/models`, `/providers`) flows through the
/// service and projects the pool/model/provider views. Built on a two-lane, two-provider fixture
/// so the provider aggregation + pool membership are observable.
#[tokio::test]
async fn test_admin_v1_topology_reads_pools_models_providers() {
    use crate::test_support::LaneSpec;
    crate::metrics::init();
    let store = Arc::new(MemoryStore::new());
    let gov = Arc::new(GovState::new(store, Some("admintok".to_string())).unwrap());

    let app = TestApp::new()
        .governance(gov)
        .lane(
            LaneSpec::new(
                "model-a",
                crate::proto::Protocol::anthropic(),
                "http://127.0.0.1:1/",
            )
            .provider("prov-x"),
        )
        .lane(
            LaneSpec::new(
                "model-b",
                crate::proto::Protocol::anthropic(),
                "http://127.0.0.1:1/",
            )
            .provider("prov-y"),
        )
        .pool("mypool", &[(0, 3), (1, 1)])
        .build();
    let router = crate::build_router(app);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    let client = reqwest::Client::new();

    let get = |path: String| {
        let url = format!("http://{addr}{path}");
        let client = client.clone();
        async move {
            client
                .get(url)
                .header("x-admin-token", "admintok")
                .send()
                .await
                .unwrap()
                .json::<serde_json::Value>()
                .await
                .unwrap()
        }
    };

    let pools = get("/api/v1/admin/pools".into()).await;
    let items = pools["items"].as_array().unwrap();
    let mypool = items
        .iter()
        .find(|p| p["name"] == "mypool")
        .expect("mypool present");
    let members = mypool["members"].as_array().unwrap();
    assert_eq!(members.len(), 2, "pool has two members");
    let weight_a = members.iter().find(|m| m["model"] == "model-a").unwrap()["weight"].as_u64();
    assert_eq!(weight_a, Some(3), "model-a weight projected");

    let models = get("/api/v1/admin/models".into()).await;
    let m_items = models["items"].as_array().unwrap();
    assert!(m_items
        .iter()
        .any(|m| m["model"] == "model-a" && m["provider"] == "prov-x"));
    assert!(m_items
        .iter()
        .any(|m| m["model"] == "model-b" && m["provider"] == "prov-y"));

    let providers = get("/api/v1/admin/providers".into()).await;
    let p_items = providers["items"].as_array().unwrap();
    let px = p_items.iter().find(|p| p["provider"] == "prov-x").unwrap();
    assert_eq!(px["model_count"].as_u64(), Some(1));
    assert!(p_items.iter().any(|p| p["provider"] == "prov-y"));

    handle.abort();
}

/// `GET /api/v1/admin/pools/{name}` projects each member's LIVE status (usable/cooldown/concurrency/
/// inflight/tallies) from the store; 404s an unknown pool.
/// Re-audit HIGH-1: EVERY response under the native-API root speaks the frozen envelope —
/// including unmatched paths (404 `not_found`) and wrong methods (405 `method_not_allowed`),
/// which previously fell through to the data plane's vendor-native shaping (`error.type`).
#[tokio::test]
async fn test_api_root_unmatched_paths_speak_the_admin_envelope() {
    crate::metrics::init();
    let store = Arc::new(MemoryStore::new());
    let gov = Arc::new(GovState::new(store, Some("admintok".to_string())).unwrap());
    let app = TestApp::new().governance(gov).build();
    let router = crate::build_router(app);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    let client = reqwest::Client::new();

    // Unmatched path INSIDE the admin nest + an /api path outside any surface: both 404 in the
    // admin envelope (`code`, never a vendor `type`).
    for path in ["/api/v1/admin/nonexistent", "/api/junk"] {
        let r = client
            .get(format!("http://{addr}{path}"))
            .header("x-admin-token", "admintok")
            .send()
            .await
            .unwrap();
        assert_eq!(r.status().as_u16(), 404, "{path}");
        let body: serde_json::Value = r.json().await.unwrap();
        assert_eq!(body["error"]["code"], "not_found", "{path}: {body}");
        assert!(
            body["error"]["type"].is_null(),
            "{path}: never the vendor envelope: {body}"
        );
    }

    // Wrong method on a real endpoint: 405 in the envelope with the frozen code.
    let r = client
        .delete(format!("http://{addr}/api/v1/admin/info"))
        .header("x-admin-token", "admintok")
        .send()
        .await
        .unwrap();
    assert_eq!(r.status().as_u16(), 405);
    assert_eq!(
        r.json::<serde_json::Value>().await.unwrap()["error"]["code"],
        "method_not_allowed"
    );
    handle.abort();
}

/// Re-audit HIGH-2: governance-off semantics are UNAMBIGUOUS — collection reads answer the
/// truthful empty page, single reads a truthful 404, and writes a 409 `conflict` with an
/// actionable message (previously everything was 404, making `not_found` mean two things).
#[tokio::test]
async fn test_keys_surface_governance_disabled_semantics() {
    crate::metrics::init();
    let mut app = TestApp::new().build(); // NO governance
    {
        // Open admin posture (explicit empty chain) — this test probes HANDLER semantics, not
        // auth; with governance off there is no admin token for the default chain to accept.
        let inner = Arc::get_mut(&mut app).expect("sole owner");
        inner.admin_chain = Vec::new();
    }
    let router = crate::build_router(app);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    let client = reqwest::Client::new();

    // Collection read: 200 empty page in the standard envelope.
    let r = client
        .get(format!("http://{addr}/api/v1/admin/keys"))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status().as_u16(), 200, "collection GET is 200-empty");
    let body: serde_json::Value = r.json().await.unwrap();
    assert_eq!(body["items"].as_array().unwrap().len(), 0);
    assert!(body["next_cursor"].is_null());

    // Single-resource read: truthful 404.
    let r = client
        .get(format!("http://{addr}/api/v1/admin/keys/vk_x"))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status().as_u16(), 404);

    // Write: 409 conflict with the actionable message.
    let r = client
        .post(format!("http://{addr}/api/v1/admin/keys"))
        .json(&serde_json::json!({"name": "k"}))
        .send()
        .await
        .unwrap();
    assert_eq!(
        r.status().as_u16(),
        409,
        "writes conflict with server state"
    );
    let body: serde_json::Value = r.json().await.unwrap();
    assert_eq!(body["error"]["code"], "conflict");
    assert!(
        body["error"]["message"]
            .as_str()
            .unwrap()
            .contains("governance"),
        "actionable message: {body}"
    );
    handle.abort();
}

#[tokio::test]
async fn test_admin_v1_pool_detail_live_status() {
    use crate::test_support::LaneSpec;
    crate::metrics::init();
    let store = Arc::new(MemoryStore::new());
    let gov = Arc::new(GovState::new(store, Some("admintok".to_string())).unwrap());
    let app = TestApp::new()
        .governance(gov)
        .lane(
            LaneSpec::new(
                "m1",
                crate::proto::Protocol::anthropic(),
                "http://127.0.0.1:1/",
            )
            .provider("p"),
        )
        .pool("mypool", &[(0, 5)])
        .build();
    let router = crate::build_router(app);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    let client = reqwest::Client::new();

    let ok: serde_json::Value = client
        .get(format!("http://{addr}/api/v1/admin/pools/mypool"))
        .header("x-admin-token", "admintok")
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(ok["name"], "mypool");
    let members = ok["members"].as_array().unwrap();
    assert_eq!(members.len(), 1);
    let m = &members[0];
    assert_eq!(m["model"], "m1");
    assert_eq!(m["weight"], 5);
    // Live-status fields present + typed. A fresh lane is usable with no cooldown.
    assert_eq!(m["usable"], true);
    assert_eq!(m["cooldown_remaining_seconds"], 0);
    assert!(m["available_concurrency"].is_number());
    assert!(m["inflight"].is_number());
    assert!(m["ok"].is_number());
    assert!(m["dead"].is_boolean());
    // Trip observability (audit #5): a MONOTONIC trip counter + last-trip epoch, so a poller
    // detects transient breaker episodes it can never catch live. Fresh lane: 0 / null.
    assert_eq!(m["trip_count"], 0);
    assert!(m["last_trip_at"].is_null());

    // ?detail=true on the COLLECTION returns the same row shape for every pool in ONE call
    // (audit #7 — no more M+1 dashboard fan-out).
    let detailed: serde_json::Value = client
        .get(format!("http://{addr}/api/v1/admin/pools?detail=true"))
        .header("x-admin-token", "admintok")
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let items = detailed["items"].as_array().unwrap();
    assert_eq!(items.len(), 1);
    assert_eq!(items[0]["name"], "mypool");
    assert_eq!(
        items[0]["members"][0]["usable"], true,
        "detail rows carry the live status inline: {detailed}"
    );
    assert_eq!(items[0]["members"][0]["trip_count"], 0);

    // Unknown pool → 404 not_found.
    let missing = client
        .get(format!("http://{addr}/api/v1/admin/pools/nope"))
        .header("x-admin-token", "admintok")
        .send()
        .await
        .unwrap();
    assert_eq!(missing.status().as_u16(), 404);
    assert_eq!(
        missing.json::<serde_json::Value>().await.unwrap()["error"]["code"],
        "not_found"
    );

    handle.abort();
}

/// `GET /api/v1/admin/admin-auth` reports the admin-plane guard: with governance + an admin token it
/// is `configured: true` with the `admin-token` module. Never a secret.
#[tokio::test]
async fn test_admin_v1_admin_auth_read() {
    crate::metrics::init();
    let store = Arc::new(MemoryStore::new());
    let gov = Arc::new(GovState::new(store, Some("admintok".to_string())).unwrap());
    let app = TestApp::new().governance(gov).build();
    let router = crate::build_router(app);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    let client = reqwest::Client::new();

    let body: serde_json::Value = client
        .get(format!("http://{addr}/api/v1/admin/admin-auth"))
        .header("x-admin-token", "admintok")
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(body["configured"], true);
    // modules reports the live admin_auth chain verbatim (the SAME resource PUT admin-auth writes)
    assert!(body["modules"]
        .as_array()
        .unwrap()
        .iter()
        .any(|m| m == "admin-tokens"));

    handle.abort();
}

/// `GET /api/v1/admin/keys/{id}` returns one key's metadata (never the secret/hash); 404 for an
/// unknown id. Fills the single-key read gap on the legacy key surface.
#[tokio::test]
async fn test_admin_v1_get_single_key() {
    use crate::governance::NewKeySpec;
    crate::metrics::init();
    let store = Arc::new(MemoryStore::new());
    let gov = Arc::new(GovState::new(store, Some("admintok".to_string())).unwrap());
    let (minted, minted_secret) = gov
        .create_key(
            NewKeySpec {
                name: "svc".to_string(),
                allowed_pools: vec![],
                max_budget_cents: None,
                budget_period: "total".to_string(),
                rpm_limit: None,
                tpm_limit: None,
                budget_group: None,
                labels: Default::default(),
            },
            crate::store::now(),
        )
        .unwrap();
    let app = TestApp::new().governance(gov).build();
    let router = crate::build_router(app);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    let client = reqwest::Client::new();

    // Found → 200 with metadata, no secret/hash.
    let resp = client
        .get(format!("http://{addr}/api/v1/admin/keys/{}", minted.id))
        .header("x-admin-token", "admintok")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), 200);
    let text = resp.text().await.unwrap();
    let body: serde_json::Value = serde_json::from_str(&text).unwrap();
    assert_eq!(body["id"], minted.id);
    assert_eq!(body["name"], "svc");
    assert!(body.get("key_hash").is_none(), "never expose the hash");
    assert!(
        !text.contains(&minted_secret),
        "never expose the secret on a read"
    );

    // Unknown id → 404.
    let missing = client
        .get(format!("http://{addr}/api/v1/admin/keys/vk_doesnotexist"))
        .header("x-admin-token", "admintok")
        .send()
        .await
        .unwrap();
    assert_eq!(missing.status().as_u16(), 404);

    handle.abort();
}

/// `GET /api/v1/admin/usage` is the METERING read: the current UTC-day bucket aggregated per
/// (model, provider) and per key, each row carrying the raw token SPLIT plus busbar's DERIVED
/// `spend_micros` (from the configured CostModel rate card + flat fee), under a `window`/`as_of`
/// header. Never leaks the secret (id/name only).
#[tokio::test]
async fn test_admin_v1_usage_meters_by_model_and_key() {
    use crate::governance::NewKeySpec;
    crate::metrics::init();
    let store = Arc::new(MemoryStore::new());
    // Prices: 1 cent/request + a rate card of 500 micro-units/token on every tier (the same
    // blended 50 cents/1k tokens the pre-rate-card assertions were derived from). Spend is now
    // DERIVED at read time from ledger x rate card, so the CostModel is the derivation input.
    let gov = Arc::new(GovState::new(store, Some("admintok".to_string())).unwrap());
    let rate = crate::config::RateEntryCfg {
        input_utok: 500.0,
        output_utok: 500.0,
        cache_read_utok: 500.0,
        cache_write_utok: 500.0,
    };
    let gov_cfg = crate::config::GovernanceCfg {
        store: "memory".to_string(),
        db_path: "busbar-governance.db".to_string(),
        price_per_request_cents: 1,
        rate_card: Some(
            [("gpt-x".to_string(), rate), ("claude-z".to_string(), rate)]
                .into_iter()
                .collect(),
        ),
        budget_groups: Default::default(),
        admin_token: Some("admintok".to_string()),
        sqlite_busy_timeout_ms: crate::config::DEFAULT_SQLITE_BUSY_TIMEOUT_MS,
        rate_sweep_interval: crate::config::DEFAULT_RATE_SWEEP_INTERVAL,
        usage_flush_interval_ms: crate::config::DEFAULT_USAGE_FLUSH_INTERVAL_MS,
    };
    let cost =
        crate::cost::CostModel::resolve_parts(&gov_cfg, &Default::default(), &Default::default());
    let now = crate::store::now();
    let (minted, minted_secret) = gov
        .create_key(
            NewKeySpec {
                name: "team-a".to_string(),
                allowed_pools: vec![],
                max_budget_cents: None,
                budget_period: "total".to_string(),
                rpm_limit: None,
                tpm_limit: None,
                budget_group: None,
                labels: Default::default(),
            },
            now,
        )
        .unwrap();
    // Two responses metered against one model (split preserved), one against another model.
    let usage = crate::ir::IrUsage {
        input_tokens: 700,
        output_tokens: 200,
        cache_read_input_tokens: Some(100),
        cache_creation_input_tokens: None,
    };
    // On a runtime `record_metering` offloads (fire-and-forget) — run the setup writes on a
    // plain thread (no tokio context → the write happens inline) and join, so the GET below
    // deterministically sees them.
    {
        let gov = gov.clone();
        let key_id = minted.id.clone();
        std::thread::spawn(move || {
            gov.record_metering(&key_id, "gpt-x", "openai", Some(&usage), now);
            gov.record_metering(&key_id, "gpt-x", "openai", Some(&usage), now);
            gov.record_metering(&key_id, "claude-z", "anthropic", None, now);
        })
        .join()
        .unwrap();
    }
    let app = TestApp::new().governance(gov).cost(cost).build();
    let router = crate::build_router(app);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    let client = reqwest::Client::new();

    let body: serde_json::Value = client
        .get(format!("http://{addr}/api/v1/admin/usage"))
        .header("x-admin-token", "admintok")
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    // Window/freshness header (the audit's #2/#3 findings). No `currency` field anymore: spend
    // is abstract cost units and currency is the consumer's display concern.
    assert!(body.get("currency").is_none(), "currency field is gone");
    assert!(body["as_of"].as_u64().unwrap() >= now);
    let (start, end) = (
        body["window"]["start"].as_u64().unwrap(),
        body["window"]["end"].as_u64().unwrap(),
    );
    assert_eq!(end - start, 86_400, "one UTC-day metering bucket");
    assert!((start..end).contains(&now));

    // Totals: raw split + derived spend. 3 requests; billable = 2x(700+200+100) = 2000 tokens.
    // spend = 3 req x 10_000 micro + 2000 tokens x 500 utok = 30_000 + 1_000_000 = 1_030_000 micro-units.
    assert_eq!(body["total"]["requests"], 3);
    assert_eq!(body["total"]["tokens_input"], 1400);
    assert_eq!(body["total"]["tokens_output"], 400);
    assert_eq!(body["total"]["tokens_cache_read"], 200);
    assert_eq!(body["total"]["tokens_cache_creation"], 0);
    assert_eq!(body["total"]["spend_micros"], 1_030_000);

    // Per-model attribution (the FinOps unit): each row carries the same split shape.
    let by_model = body["by_model"].as_array().unwrap();
    assert_eq!(by_model.len(), 2, "{by_model:?}");
    let x = by_model.iter().find(|m| m["model"] == "gpt-x").unwrap();
    assert_eq!(x["provider"], "openai");
    assert_eq!(x["requests"], 2);
    assert_eq!(x["tokens_input"], 1400);
    // 2 req x 10_000 micro + 2000 tokens x 500 utok = 1_020_000 micro-units
    assert_eq!(x["spend_micros"], 1_020_000);
    let z = by_model.iter().find(|m| m["model"] == "claude-z").unwrap();
    assert_eq!(
        z["requests"], 1,
        "a flat (zero-token) response still counts"
    );
    assert_eq!(
        z["spend_micros"], 10_000,
        "1 req x 1 cent = 10_000 micro-units"
    );

    // Per-key attribution names the key; the secret never appears anywhere in the body.
    let by_key = body["by_key"].as_array().unwrap();
    assert_eq!(by_key.len(), 1);
    assert_eq!(by_key[0]["id"], minted.id);
    assert_eq!(by_key[0]["name"], "team-a");
    assert_eq!(by_key[0]["requests"], 3);
    let text = body.to_string();
    assert!(
        !text.contains(&minted_secret),
        "usage must not leak the key secret"
    );

    handle.abort();
}

/// END-TO-END config apply: `POST /api/v1/admin/hooks` registers a hook at runtime (201), and a
/// subsequent `GET /api/v1/admin/hooks` SEES it — proving the AppHandle swap took effect AND the
/// per-request service reads the CURRENT snapshot. Invalid definitions reject with invalid_request.
/// D2 e2e (unix): PATCH settings pushes `configure` to the running hook and commits ON ACK
/// (the registry shows the new settings); a NACKing hook commits nothing; GET schema proxies
/// the hook's describe reply.
#[cfg(unix)]
#[tokio::test]
async fn test_admin_v1_hook_settings_patch_commit_on_ack_and_schema() {
    crate::metrics::init();
    // A fake hook binary: acks configure (echoing the pushed version), answers describe.
    let dir = std::env::temp_dir().join(format!("busbar-d2-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let sock = dir.join("hook.sock");
    let _ = std::fs::remove_file(&sock);
    let listener = tokio::net::UnixListener::bind(&sock).unwrap();
    let ack_mode = Arc::new(std::sync::atomic::AtomicBool::new(true));
    let hook_ack = ack_mode.clone();
    let hook_task = tokio::spawn(async move {
        use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                return;
            };
            let ack = hook_ack.clone();
            tokio::spawn(async move {
                let (r, mut w) = stream.into_split();
                let mut lines = BufReader::new(r).lines();
                while let Ok(Some(line)) = lines.next_line().await {
                    let v: serde_json::Value = serde_json::from_str(&line).unwrap_or_default();
                    let reply = if let Some(c) = v.get("configure") {
                        if ack.load(std::sync::atomic::Ordering::Relaxed) {
                            serde_json::json!({"ack": {"settings_version": c["settings_version"]}})
                        } else {
                            serde_json::json!({"error": "refused"})
                        }
                    } else if v.get("describe").is_some() {
                        serde_json::json!({"schema": {"type": "object", "properties": {"ratio": {"type": "number"}}}})
                    } else {
                        serde_json::json!({})
                    };
                    if w.write_all(format!("{reply}\n").as_bytes()).await.is_err() {
                        return;
                    }
                }
            });
        }
    });

    let store = Arc::new(MemoryStore::new());
    let gov = Arc::new(GovState::new(store, Some("admintok".to_string())).unwrap());
    let app = TestApp::new().governance(gov).build();
    let router = crate::build_router(app);
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    let serve = tokio::spawn(async move { axum::serve(l, router).await.unwrap() });
    let client = reqwest::Client::new();
    let admin = |req: reqwest::RequestBuilder| {
        req.header("x-admin-token", "admintok")
            .header("content-type", "application/json")
    };

    // Register the hook (overlay), then PATCH its settings — ack mode on: commits.
    let created = admin(client.post(format!("http://{addr}/api/v1/admin/hooks")))
        .body(
            serde_json::json!({
                "name": "cfg-hook",
                "config": {"kind": "gate", "socket": sock.to_str().unwrap()}
            })
            .to_string(),
        )
        .send()
        .await
        .unwrap();
    assert_eq!(created.status().as_u16(), 201);
    let patched = admin(client.patch(format!(
        "http://{addr}/api/v1/admin/hooks/cfg-hook/settings"
    )))
    .body(serde_json::json!({"settings": {"ratio": 0.4}}).to_string())
    .send()
    .await
    .unwrap();
    assert_eq!(patched.status().as_u16(), 200, "{:?}", patched.text().await);
    let got: serde_json::Value =
        admin(client.get(format!("http://{addr}/api/v1/admin/hooks/cfg-hook")))
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
    assert_eq!(
        got["settings"]["ratio"], 0.4,
        "committed settings visible: {got}"
    );

    // NACK mode: the push is refused — nothing commits.
    ack_mode.store(false, std::sync::atomic::Ordering::Relaxed);
    let refused = admin(client.patch(format!(
        "http://{addr}/api/v1/admin/hooks/cfg-hook/settings"
    )))
    .body(serde_json::json!({"settings": {"ratio": 0.9}}).to_string())
    .send()
    .await
    .unwrap();
    assert_eq!(refused.status().as_u16(), 400, "nack = not committed");
    let still: serde_json::Value =
        admin(client.get(format!("http://{addr}/api/v1/admin/hooks/cfg-hook")))
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
    assert_eq!(
        still["settings"]["ratio"], 0.4,
        "old settings intact: {still}"
    );

    // Schema proxy (ack mode back on — the committed settings ride the configure preamble on
    // the fresh describe connection, and a nacking hook refuses connections by design).
    ack_mode.store(true, std::sync::atomic::Ordering::Relaxed);
    let schema: serde_json::Value =
        admin(client.get(format!("http://{addr}/api/v1/admin/hooks/cfg-hook/schema")))
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
    // The describe reply is the {schema, dashboard?} envelope; the engine EXTRACTS the schema
    // member, so the endpoint serves a SINGLE nest (the old double-wrap was audit W-H3).
    assert_eq!(
        schema["schema"]["properties"]["ratio"]["type"], "number",
        "describe schema extracted, single nest: {schema}"
    );

    serve.abort();
    hook_task.abort();
    let _ = std::fs::remove_dir_all(&dir);
}

/// `POST /api/v1/admin/config/apply`: a body-carried full config swaps in atomically — the new
/// topology is live, the surviving identity keeps its tripped health, and a stale
/// If-Match is a 409 that changes nothing.
#[tokio::test]
async fn test_admin_v1_config_apply_body_swaps_and_carries_health() {
    crate::metrics::init();
    let store = Arc::new(MemoryStore::new());
    let gov = Arc::new(GovState::new(store, Some("admintok".to_string())).unwrap());
    let mut app = TestApp::new()
        .lane(crate::test_support::LaneSpec::new(
            "m0",
            crate::proto::Protocol::anthropic(),
            "http://127.0.0.1:1/",
        ))
        .pool("p", &[(0, 1)])
        .governance(gov)
        .build();
    Arc::get_mut(&mut app)
        .expect("sole owner")
        .store
        .record_hard_down(0, "tripped before apply");
    let router = crate::build_router(app);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    let client = reqwest::Client::new();
    let admin = |req: reqwest::RequestBuilder| {
        req.header("x-admin-token", "admintok")
            .header("content-type", "application/json")
    };

    let body = serde_json::json!({
        "providers": {
            "test-provider": {"protocol": "anthropic", "base_url": "http://127.0.0.1:1/", "api_key_env": "BUSBAR_TEST_APPLY_NO_KEY"}
        },
        "config": {
            "listen": "127.0.0.1:0",
            "providers": {"test-provider": {"api_key_env": "BUSBAR_TEST_APPLY_NO_KEY"}},
            "models": {
                "m0": {"provider": "test-provider", "max_concurrent": 4},
                "m-applied": {"provider": "test-provider", "max_concurrent": 4}
            },
            "pools": {"apply-pool": {"members": [{"target": "m0"}, {"target": "m-applied"}]}}
        }
    });
    let resp = admin(client.post(format!("http://{addr}/api/v1/admin/config/apply")))
        .body(body.to_string())
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), 200, "{:?}", resp.text().await);

    let pool: serde_json::Value =
        admin(client.get(format!("http://{addr}/api/v1/admin/pools/apply-pool")))
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
    let members = pool["members"].as_array().unwrap();
    let m0 = members.iter().find(|m| m["model"] == "m0").unwrap();
    let ma = members.iter().find(|m| m["model"] == "m-applied").unwrap();
    assert_eq!(m0["usable"], false, "carried trip: {m0}");
    assert_eq!(ma["usable"], true, "fresh lane: {ma}");

    // Stale If-Match: 409, nothing applied (H3: concurrency rides the header, never the body).
    let stale = admin(client.post(format!("http://{addr}/api/v1/admin/config/apply")))
        .header("if-match", "\"0\"")
        .body(
            serde_json::json!({
                "config": {"listen": "127.0.0.1:0", "providers": {}, "models": {}, "pools": {}},
            })
            .to_string(),
        )
        .send()
        .await
        .unwrap();
    assert_eq!(stale.status().as_u16(), 409);
    // A malformed If-Match is a 400 invalid_request, never a silent unguarded write.
    let malformed = admin(client.post(format!("http://{addr}/api/v1/admin/config/apply")))
        .header("if-match", "\"not-a-version\"")
        .body(
            serde_json::json!({
                "config": {"listen": "127.0.0.1:0", "providers": {}, "models": {}, "pools": {}},
            })
            .to_string(),
        )
        .send()
        .await
        .unwrap();
    assert_eq!(malformed.status().as_u16(), 400);

    handle.abort();
}

/// `POST /api/v1/admin/config/reload`: re-reads disk truth and swaps it in atomically — the new
/// topology is live, surviving lanes keep their learned health BY IDENTITY (a breaker tripped
/// before the reload is still tripped after it), and an invalid disk config rejects with 400
/// changing nothing.
#[tokio::test]
async fn test_admin_v1_config_reload_swaps_disk_truth_and_carries_health() {
    crate::metrics::init();
    let dir = std::env::temp_dir().join(format!("busbar-reload-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let providers_path = dir.join("providers.yaml");
    let config_path = dir.join("config.yaml");
    std::fs::write(
        &providers_path,
        "test-provider:
  protocol: anthropic
  base_url: http://127.0.0.1:1/
  api_key_env: BUSBAR_TEST_RELOAD_NO_SUCH_KEY
",
    )
    .unwrap();
    // Disk truth: the SAME identity as the running lane (m0 @ test-provider) plus a NEW model.
    std::fs::write(
        &config_path,
        "listen: 127.0.0.1:0
providers:
  test-provider:
    api_key_env: BUSBAR_TEST_RELOAD_NO_SUCH_KEY
models:
  m0:
    provider: test-provider
    max_concurrent: 4
  m-new:
    provider: test-provider
    max_concurrent: 4
pools:
  reload-pool:
    members:
      - target: m0
      - target: m-new
",
    )
    .unwrap();

    let store = Arc::new(MemoryStore::new());
    let gov = Arc::new(GovState::new(store, Some("admintok".to_string())).unwrap());
    let mut app = TestApp::new()
        .lane(crate::test_support::LaneSpec::new(
            "m0",
            crate::proto::Protocol::anthropic(),
            "http://127.0.0.1:1/",
        ))
        .pool("p", &[(0, 1)])
        .governance(gov)
        .build();
    {
        let inner = Arc::get_mut(&mut app).expect("sole owner");
        inner.config_path = Some(config_path.clone());
        inner.providers_path = Some(providers_path.clone());
        // Trip m0's default-cell breaker hard so the carried state is unmistakable.
        inner.store.record_hard_down(0, "tripped before reload");
    }
    let router = crate::build_router(app);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    let client = reqwest::Client::new();
    let admin = |req: reqwest::RequestBuilder| req.header("x-admin-token", "admintok");

    // Reload: disk truth replaces the synthetic topology.
    let resp = admin(client.post(format!("http://{addr}/api/v1/admin/config/reload")))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), 200, "{:?}", resp.text().await);
    let models: serde_json::Value = admin(client.get(format!("http://{addr}/api/v1/admin/models")))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let names: Vec<&str> = models["items"]
        .as_array()
        .unwrap()
        .iter()
        .map(|m| m["model"].as_str().unwrap())
        .collect();
    assert!(
        names.contains(&"m-new"),
        "the reloaded topology is live: {names:?}"
    );

    // The surviving identity (m0 @ test-provider) carried its tripped health state.
    let pool: serde_json::Value =
        admin(client.get(format!("http://{addr}/api/v1/admin/pools/reload-pool")))
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
    let members = pool["members"].as_array().unwrap();
    let m0 = members
        .iter()
        .find(|m| m["model"] == "m0")
        .expect("m0 present");
    let m_new = members
        .iter()
        .find(|m| m["model"] == "m-new")
        .expect("m-new present");
    assert_eq!(
        m0["usable"], false,
        "m0's pre-reload trip must survive by identity: {m0}"
    );
    assert_eq!(
        m_new["usable"], true,
        "the new lane starts healthy: {m_new}"
    );

    // Invalid disk config: 400, nothing changes.
    std::fs::write(
        &config_path,
        "listen: 127.0.0.1:0
models:
  broken:
    provider: nope
    max_concurrent: 1
providers: {}
",
    )
    .unwrap();
    let before: serde_json::Value = admin(client.get(format!("http://{addr}/api/v1/admin/info")))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let bad = admin(client.post(format!("http://{addr}/api/v1/admin/config/reload")))
        .send()
        .await
        .unwrap();
    assert_eq!(bad.status().as_u16(), 400, "invalid disk config rejects");
    let after: serde_json::Value = admin(client.get(format!("http://{addr}/api/v1/admin/info")))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(
        before["config_version"], after["config_version"],
        "a rejected reload changes nothing"
    );

    handle.abort();
    let _ = std::fs::remove_dir_all(&dir);
}

/// Per-principal mutation rate limits: the config class (apply/rollback) caps at 10/min per
/// principal — the 11th attempt in the window is a 429 in the frozen envelope, and FAILED
/// attempts count (these are all 404s — anti-enumeration).
#[tokio::test]
async fn test_admin_v1_mutation_rate_limit_config_class() {
    crate::metrics::init();
    let store = Arc::new(MemoryStore::new());
    let gov = Arc::new(GovState::new(store, Some("admintok".to_string())).unwrap());
    let app = TestApp::new().governance(gov).build();
    let router = crate::build_router(app);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    let client = reqwest::Client::new();

    // 10 rollback attempts to a bogus version (all 404 — still spend budget), then the 11th
    // is limited. Tolerate landing exactly on a minute boundary (window refill mid-loop) by
    // accepting the 429 anywhere from attempt 11 to 22, but REQUIRE it eventually.
    let mut limited_at = None;
    for i in 1..=22 {
        let resp = client
            .post(format!("http://{addr}/api/v1/admin/config/rollback"))
            .header("x-admin-token", "admintok")
            .header("content-type", "application/json")
            .body(serde_json::json!({"version": 424242}).to_string())
            .send()
            .await
            .unwrap();
        match resp.status().as_u16() {
            404 => continue,
            429 => {
                assert!(i >= 11, "the budget is 10/min; limited too early at {i}");
                let body: serde_json::Value = resp.json().await.unwrap();
                assert_eq!(body["error"]["code"], "rate_limited");
                limited_at = Some(i);
                break;
            }
            other => panic!("unexpected status {other} at attempt {i}"),
        }
    }
    assert!(
        limited_at.is_some(),
        "the limiter never fired in 22 attempts"
    );

    handle.abort();
}

/// The scope LADDER end-to-end with group-mapped NON-full principals (via the test-only
/// external module): read-only reads but cannot mint (403, audited); hooks-register registers
/// hooks but cannot mint keys; an unmapped group gets nothing at all (403 even on reads);
/// the operator token stays full.
#[tokio::test]
async fn test_admin_v1_scope_ladder_e2e_with_group_mapped_principals() {
    crate::metrics::init();
    let store = Arc::new(MemoryStore::new());
    let gov = Arc::new(GovState::new(store, Some("admintok".to_string())).unwrap());
    let mut app = TestApp::new().governance(gov).build();
    {
        let inner = Arc::get_mut(&mut app).expect("sole owner");
        inner.admin_chain = vec!["test-scope-module".to_string(), "admin-tokens".to_string()];
        inner.group_map.insert(
            "viewers".to_string(),
            crate::config::GroupMapEntry {
                admin_scope: Some("read-only".to_string()),
                ..Default::default()
            },
        );
        inner.group_map.insert(
            "registrars".to_string(),
            crate::config::GroupMapEntry {
                admin_scope: Some("hooks-register".to_string()),
                ..Default::default()
            },
        );
        // For the CAP proofs below: a group MAPPED full — the module ceiling must cut it
        // down — and a group mapped full that the allowlist doesn't authorize at all.
        inner.group_map.insert(
            "admins-capped".to_string(),
            crate::config::GroupMapEntry {
                admin_scope: Some("full".to_string()),
                ..Default::default()
            },
        );
        inner.group_map.insert(
            "sneaky".to_string(),
            crate::config::GroupMapEntry {
                admin_scope: Some("full".to_string()),
                ..Default::default()
            },
        );
        // §2.4 trust-boundary caps on the external module: it may only assert these groups
        // (`sneaky` is deliberately NOT pre-authorized), and nothing through it can exceed
        // hooks-register regardless of group_map.
        inner.auth_modules.insert(
            "test-scope-module".to_string(),
            crate::config::AuthModuleCfg {
                allowed_groups: Some(vec![
                    "viewers".to_string(),
                    "registrars".to_string(),
                    "admins-capped".to_string(),
                    "strangers".to_string(),
                ]),
                max_admin_scope: Some("hooks-register".to_string()),
            },
        );
    }
    let router = crate::build_router(app);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    let client = reqwest::Client::new();
    let with = |tok: &'static str, req: reqwest::RequestBuilder| {
        req.header("x-admin-token", tok)
            .header("content-type", "application/json")
    };
    let hook_body = serde_json::json!({
        "name": "scoped-hook",
        "config": {"kind": "tap", "webhook": "http://127.0.0.1:9969/"}
    })
    .to_string();
    let key_body = serde_json::json!({"name": "k"}).to_string();

    // read-only: GET 200, mutations 403 with the frozen envelope.
    let r = with(
        "grp:viewers",
        client.get(format!("http://{addr}/api/v1/admin/info")),
    )
    .send()
    .await
    .unwrap();
    assert_eq!(r.status().as_u16(), 200, "read-only can read");
    let r = with(
        "grp:viewers",
        client.post(format!("http://{addr}/api/v1/admin/keys")),
    )
    .body(key_body.clone())
    .send()
    .await
    .unwrap();
    assert_eq!(r.status().as_u16(), 403, "read-only cannot mint");
    let body: serde_json::Value = r.json().await.unwrap();
    assert_eq!(body["error"]["code"], "forbidden");
    let r = with(
        "grp:viewers",
        client.post(format!("http://{addr}/api/v1/admin/hooks")),
    )
    .body(hook_body.clone())
    .send()
    .await
    .unwrap();
    assert_eq!(r.status().as_u16(), 403, "read-only cannot register hooks");

    // hooks-register: hook lifecycle yes, keys no (the escalation guard).
    let r = with(
        "grp:registrars",
        client.post(format!("http://{addr}/api/v1/admin/hooks")),
    )
    .body(hook_body.clone())
    .send()
    .await
    .unwrap();
    assert_eq!(r.status().as_u16(), 201, "hooks-register registers hooks");
    let r = with(
        "grp:registrars",
        client.post(format!("http://{addr}/api/v1/admin/keys")),
    )
    .body(key_body.clone())
    .send()
    .await
    .unwrap();
    assert_eq!(r.status().as_u16(), 403, "hooks-register cannot mint keys");

    // Unmapped group: authenticated but zero grants — 403 even on reads.
    let r = with(
        "grp:strangers",
        client.get(format!("http://{addr}/api/v1/admin/info")),
    )
    .send()
    .await
    .unwrap();
    assert_eq!(r.status().as_u16(), 403, "unmapped groups grant nothing");

    // max_admin_scope CEILING: a group MAPPED full through the capped module lands at
    // hooks-register — it registers hooks but still cannot mint keys.
    let capped_hook = serde_json::json!({
        "name": "capped-hook",
        "config": {"kind": "tap", "webhook": "http://127.0.0.1:9969/"}
    })
    .to_string();
    let r = with(
        "grp:admins-capped",
        client.post(format!("http://{addr}/api/v1/admin/hooks")),
    )
    .body(capped_hook)
    .send()
    .await
    .unwrap();
    assert_eq!(
        r.status().as_u16(),
        201,
        "the ceiling still allows what it grants (hooks-register)"
    );
    let r = with(
        "grp:admins-capped",
        client.post(format!("http://{addr}/api/v1/admin/keys")),
    )
    .body(key_body.clone())
    .send()
    .await
    .unwrap();
    assert_eq!(
        r.status().as_u16(),
        403,
        "group_map said full, the module ceiling says hooks-register — the ceiling wins"
    );

    // allowed_groups INTERSECTION: `sneaky` is mapped full in group_map but the module is not
    // authorized to assert it — the group is dropped BEFORE mapping, leaving zero grants.
    let r = with(
        "grp:sneaky",
        client.get(format!("http://{addr}/api/v1/admin/info")),
    )
    .send()
    .await
    .unwrap();
    assert_eq!(
        r.status().as_u16(),
        403,
        "a group outside allowed_groups never reaches group_map"
    );

    // The operator token is still full (admin-tokens is exempt from module ceilings).
    let r = with(
        "admintok",
        client.post(format!("http://{addr}/api/v1/admin/keys")),
    )
    .body(key_body)
    .send()
    .await
    .unwrap();
    assert_eq!(r.status().as_u16(), 201, "operator token stays full");

    handle.abort();
}

/// §6.3 ESCALATION GUARD: a hooks-register principal may register a shape-only, non-global hook
/// but NOT one wired into a security-critical path — a `prompt: rw`/`ro` content-seeing gate, a
/// `user: ro` identity-seeing hook, or an inline `global: true` (chain wiring is full-only). The
/// operator (full) may register all of them.
#[tokio::test]
async fn test_admin_v1_hooks_register_cannot_escalate_via_grants_or_global() {
    crate::metrics::init();
    let store = Arc::new(MemoryStore::new());
    let gov = Arc::new(GovState::new(store, Some("admintok".to_string())).unwrap());
    let mut app = TestApp::new().governance(gov).build();
    {
        let inner = Arc::get_mut(&mut app).expect("sole owner");
        inner.admin_chain = vec!["test-scope-module".to_string(), "admin-tokens".to_string()];
        inner.group_map.insert(
            "registrars".to_string(),
            crate::config::GroupMapEntry {
                admin_scope: Some("hooks-register".to_string()),
                ..Default::default()
            },
        );
        // The module ceiling defaults to read-only; lift it so registrars actually resolves to
        // hooks-register (admin-tokens stays full — it is ceiling-exempt).
        inner.auth_modules.insert(
            "test-scope-module".to_string(),
            crate::config::AuthModuleCfg {
                allowed_groups: None,
                max_admin_scope: Some("full".to_string()),
            },
        );
    }
    let router = crate::build_router(app);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    let client = reqwest::Client::new();
    let post = |tok: &'static str, cfg: serde_json::Value| {
        client
            .post(format!("http://{addr}/api/v1/admin/hooks"))
            .header("x-admin-token", tok)
            .header("content-type", "application/json")
            .body(serde_json::json!({"name": "h", "config": cfg}).to_string())
            .send()
    };
    let base = |extra: serde_json::Value| {
        let mut c = serde_json::json!({"kind": "gate", "webhook": "http://127.0.0.1:9969/"});
        for (k, v) in extra.as_object().unwrap() {
            c[k] = v.clone();
        }
        c
    };

    // hooks-register: each escalating form is 403 (forbidden), naming full.
    for (label, cfg) in [
        ("prompt: rw gate", base(serde_json::json!({"prompt": "rw"}))),
        ("prompt: ro gate", base(serde_json::json!({"prompt": "ro"}))),
        ("user: ro hook", base(serde_json::json!({"user": "ro"}))),
        ("global: true", base(serde_json::json!({"global": true}))),
    ] {
        let r = post("grp:registrars", cfg).await.unwrap();
        assert_eq!(
            r.status().as_u16(),
            403,
            "hooks-register must not register a {label}"
        );
        let body: serde_json::Value = r.json().await.unwrap();
        assert_eq!(body["error"]["code"], "forbidden", "{label}");
    }

    // hooks-register CAN register a shape-only, non-global hook.
    let r = post("grp:registrars", base(serde_json::json!({})))
        .await
        .unwrap();
    assert_eq!(
        r.status().as_u16(),
        201,
        "a shape-only, non-global hook is within hooks-register"
    );

    // The operator (full) can register a prompt: rw global gate (unique name — `h` is taken).
    let r = client
        .post(format!("http://{addr}/api/v1/admin/hooks"))
        .header("x-admin-token", "admintok")
        .header("content-type", "application/json")
        .body(
            serde_json::json!({
                "name": "op-hook",
                "config": base(serde_json::json!({"prompt": "rw", "global": true}))
            })
            .to_string(),
        )
        .send()
        .await
        .unwrap();
    assert_eq!(r.status().as_u16(), 201, "full scope registers anything");

    // REGRESSION (audit c1r6): a hooks-register token may not RETUNE (PATCH settings) a
    // content-seeing / global hook it can neither create nor replace — PATCH must enforce the
    // same §6.3 ceiling, keyed on the EXISTING hook's grants.
    let patch = client
        .patch(format!("http://{addr}/api/v1/admin/hooks/op-hook/settings"))
        .header("x-admin-token", "grp:registrars")
        .header("content-type", "application/json")
        .body(serde_json::json!({"settings": {"k": "v"}}).to_string())
        .send()
        .await
        .unwrap();
    assert_eq!(
        patch.status().as_u16(),
        403,
        "hooks-register must not PATCH settings on a prompt:rw global hook"
    );
    assert_eq!(
        patch.json::<serde_json::Value>().await.unwrap()["error"]["code"],
        "forbidden"
    );

    // REGRESSION (audit c1r13): a hooks-register token may not DELETE a content-seeing / global
    // gate a full admin installed — tearing down that security gate is the same §6.3 escalation
    // register/put/patch forbid.
    let del = client
        .delete(format!("http://{addr}/api/v1/admin/hooks/op-hook"))
        .header("x-admin-token", "grp:registrars")
        .send()
        .await
        .unwrap();
    assert_eq!(
        del.status().as_u16(),
        403,
        "hooks-register must not DELETE a prompt:rw global hook"
    );
    assert_eq!(
        del.json::<serde_json::Value>().await.unwrap()["error"]["code"],
        "forbidden"
    );
    // And the operator's gate is still there — the rejected delete did not remove it.
    let still = client
        .get(format!("http://{addr}/api/v1/admin/hooks/op-hook"))
        .header("x-admin-token", "admintok")
        .send()
        .await
        .unwrap();
    assert_eq!(
        still.status().as_u16(),
        200,
        "the gate survives the rejected delete"
    );

    handle.abort();
}

/// The idempotency cache is SCOPED TO THE PRINCIPAL: a second admin presenting the same
/// Idempotency-Key value must mint its OWN key, never replay the first principal's response
/// (which carries a once-shown secret). Two full principals, same key value, distinct results.
#[tokio::test]
async fn test_admin_v1_idempotency_key_is_principal_scoped() {
    crate::metrics::init();
    let store = Arc::new(MemoryStore::new());
    let gov = Arc::new(GovState::new(store, Some("admintok".to_string())).unwrap());
    let mut app = TestApp::new().governance(gov).build();
    {
        let inner = Arc::get_mut(&mut app).expect("sole owner");
        inner.admin_chain = vec!["test-scope-module".to_string(), "admin-tokens".to_string()];
        // A group mapped FULL so the second principal can also mint keys.
        inner.group_map.insert(
            "admins".to_string(),
            crate::config::GroupMapEntry {
                admin_scope: Some("full".to_string()),
                ..Default::default()
            },
        );
        inner.auth_modules.insert(
            "test-scope-module".to_string(),
            crate::config::AuthModuleCfg {
                allowed_groups: None,
                max_admin_scope: Some("full".to_string()),
            },
        );
    }
    let router = crate::build_router(app);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    let client = reqwest::Client::new();
    let mint = |tok: &'static str| {
        client
            .post(format!("http://{addr}/api/v1/admin/keys"))
            .header("x-admin-token", tok)
            .header("content-type", "application/json")
            .header("idempotency-key", "shared-value")
            .body(serde_json::json!({"name": "k"}).to_string())
            .send()
    };

    // Principal A (operator) mints under the shared key.
    let a: serde_json::Value = mint("admintok").await.unwrap().json().await.unwrap();
    // Principal B (a different full principal) mints under the SAME key value.
    let b: serde_json::Value = mint("grp:admins").await.unwrap().json().await.unwrap();

    assert!(a["id"].is_string() && b["id"].is_string());
    assert_ne!(
        a["id"], b["id"],
        "a second principal's identical Idempotency-Key must mint a NEW key, not replay A's"
    );
    assert_ne!(
        a["secret"], b["secret"],
        "B must never receive A's once-shown secret via a cross-principal replay"
    );
    // And A replaying its OWN key still returns A's response (per-principal idempotency intact).
    let a2: serde_json::Value = mint("admintok").await.unwrap().json().await.unwrap();
    assert_eq!(a2["id"], a["id"], "A's own retry replays A's response");

    handle.abort();
}

/// The credential cache end-to-end (§2.5): an external-module identify is CACHED (the second
/// request is served from the cache — observable via the flush count), `POST
/// /api/v1/admin/auth/cache/flush` drops it (full scope; read-only principals get 403), and the
/// built-in operator token is NEVER cached (flush finds nothing after operator calls).
#[tokio::test]
async fn test_admin_v1_credential_cache_and_flush_endpoint() {
    crate::metrics::init();
    let store = Arc::new(MemoryStore::new());
    let gov = Arc::new(GovState::new(store, Some("admintok".to_string())).unwrap());
    let mut app = TestApp::new().governance(gov).build();
    {
        let inner = Arc::get_mut(&mut app).expect("sole owner");
        inner.admin_chain = vec!["test-scope-module".to_string(), "admin-tokens".to_string()];
        inner.group_map.insert(
            "viewers".to_string(),
            crate::config::GroupMapEntry {
                admin_scope: Some("read-only".to_string()),
                ..Default::default()
            },
        );
    }
    let router = crate::build_router(app);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    let client = reqwest::Client::new();

    // Two reads as a group-mapped principal: the module's Identify lands in the cache.
    for _ in 0..2 {
        let r = client
            .get(format!("http://{addr}/api/v1/admin/info"))
            .header("x-admin-token", "grp:viewers")
            .send()
            .await
            .unwrap();
        assert_eq!(r.status().as_u16(), 200);
    }

    // A read-only principal cannot flush (full-scope mutation).
    let r = client
        .post(format!("http://{addr}/api/v1/admin/auth/cache/flush"))
        .header("x-admin-token", "grp:viewers")
        .send()
        .await
        .unwrap();
    assert_eq!(r.status().as_u16(), 403, "flush is a full-scope mutation");

    // Operator flushes the module partition: exactly ONE entry (the cached viewers identify;
    // operator-token authentications are never cached).
    let r = client
        .post(format!("http://{addr}/api/v1/admin/auth/cache/flush"))
        .header("x-admin-token", "admintok")
        .header("content-type", "application/json")
        .body(serde_json::json!({"module": "test-scope-module"}).to_string())
        .send()
        .await
        .unwrap();
    assert_eq!(r.status().as_u16(), 200);
    let body: serde_json::Value = r.json().await.unwrap();
    // TWO entries in the module's partition: the viewers Identify, plus the PASS the module
    // returned for the operator token (Pass IS cached, short-TTL — §2.5; only the built-in
    // admin-tokens module's own verdicts are exempt). The flushing request's own Pass was
    // inserted by its chain run before the handler flushed.
    assert_eq!(
        body["flushed"], 2,
        "the viewers Identify + the operator credential's cached Pass"
    );

    // Flush-all with an empty body: nothing left.
    let r = client
        .post(format!("http://{addr}/api/v1/admin/auth/cache/flush"))
        .header("x-admin-token", "admintok")
        .send()
        .await
        .unwrap();
    let body: serde_json::Value = r.json().await.unwrap();
    // Exactly ONE: this very request's chain run re-cached a Pass for the operator credential
    // under the external module before the handler flushed. Nothing else survived.
    assert_eq!(
        body["flushed"], 1,
        "only this request's own cached Pass remained"
    );

    // Malformed body: invalid_request.
    let r = client
        .post(format!("http://{addr}/api/v1/admin/auth/cache/flush"))
        .header("x-admin-token", "admintok")
        .header("content-type", "application/json")
        .body("{\"module\": 7}")
        .send()
        .await
        .unwrap();
    assert_eq!(r.status().as_u16(), 400);

    handle.abort();
}

/// `PUT /api/v1/admin/admin-auth` end-to-end with the D4 dry-run guard: a chain that would lock the
/// CALLER out is a 409 and nothing changes; a chain the caller survives applies atomically
/// (the old credential stops working on the very next request, the surviving one carries on);
/// unknown modules and a stale If-Match reject.
#[tokio::test]
async fn test_admin_v1_put_auth_dry_run_guard() {
    crate::metrics::init();
    let store = Arc::new(MemoryStore::new());
    let gov = Arc::new(GovState::new(store, Some("admintok".to_string())).unwrap());
    let mut app = TestApp::new().governance(gov).build();
    {
        let inner = Arc::get_mut(&mut app).expect("sole owner");
        // Chain starts as BOTH modules (so both credentials work); group_map + an explicit
        // full ceiling make `grp:admins` a full principal through the external stand-in.
        inner.admin_chain = vec!["test-scope-module".to_string(), "admin-tokens".to_string()];
        inner.group_map.insert(
            "admins".to_string(),
            crate::config::GroupMapEntry {
                admin_scope: Some("full".to_string()),
                ..Default::default()
            },
        );
        inner.auth_modules.insert(
            "test-scope-module".to_string(),
            crate::config::AuthModuleCfg {
                allowed_groups: None,
                max_admin_scope: Some("full".to_string()),
            },
        );
    }
    let router = crate::build_router(app);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    let client = reqwest::Client::new();
    let put = |tok: &'static str, body: serde_json::Value| {
        client
            .put(format!("http://{addr}/api/v1/admin/admin-auth"))
            .header("x-admin-token", tok)
            .header("content-type", "application/json")
            .body(body.to_string())
            .send()
    };

    // Unknown module: 400, nothing changes.
    let r = put("admintok", serde_json::json!({"admin_auth": ["saml"]}))
        .await
        .unwrap();
    assert_eq!(
        r.status().as_u16(),
        400,
        "unknown module is invalid_request"
    );

    // Stale If-Match: 409 (H3: concurrency rides the header; a body-level twin no longer parses
    // — deny_unknown_fields makes a leftover `expected_version` field a loud 400, not a no-op).
    let r = client
        .put(format!("http://{addr}/api/v1/admin/admin-auth"))
        .header("x-admin-token", "admintok")
        .header("content-type", "application/json")
        .header("if-match", "\"999\"")
        .body(serde_json::json!({"admin_auth": ["admin-tokens"]}).to_string())
        .send()
        .await
        .unwrap();
    assert_eq!(r.status().as_u16(), 409, "stale If-Match conflicts");

    // THE D4 GUARD: the operator token would NOT survive a chain of only the external module
    // (its credential has no grp: shape — all-Pass denies). 409, and the operator still works.
    let r = put(
        "admintok",
        serde_json::json!({"admin_auth": ["test-scope-module"]}),
    )
    .await
    .unwrap();
    assert_eq!(
        r.status().as_u16(),
        409,
        "a chain that locks the caller out is refused"
    );
    let body: serde_json::Value = r.json().await.unwrap();
    assert_eq!(body["error"]["code"], "conflict");
    let r = client
        .get(format!("http://{addr}/api/v1/admin/info"))
        .header("x-admin-token", "admintok")
        .send()
        .await
        .unwrap();
    assert_eq!(r.status().as_u16(), 200, "nothing changed on the refusal");

    // The SAME change made by a caller who survives it (a full group-mapped principal through
    // the external module) applies…
    let r = put(
        "grp:admins",
        serde_json::json!({"admin_auth": ["test-scope-module"]}),
    )
    .await
    .unwrap();
    assert_eq!(
        r.status().as_u16(),
        200,
        "the surviving caller's change applies"
    );
    let body: serde_json::Value = r.json().await.unwrap();
    assert_eq!(body["applied"], true);

    // …after which the operator token no longer authenticates (it is not in the chain)…
    let r = client
        .get(format!("http://{addr}/api/v1/admin/info"))
        .header("x-admin-token", "admintok")
        .send()
        .await
        .unwrap();
    assert_eq!(
        r.status().as_u16(),
        401,
        "the dropped module's credential stops working immediately"
    );

    // …and the surviving credential carries on.
    let r = client
        .get(format!("http://{addr}/api/v1/admin/info"))
        .header("x-admin-token", "grp:admins")
        .send()
        .await
        .unwrap();
    assert_eq!(r.status().as_u16(), 200);

    // READ-AFTER-WRITE (L3): GET /api/v1/admin/admin-auth reflects exactly what the PUT installed —
    // the write and read now name the SAME resource (previously PUT lived on /auth and GET
    // admin-auth reported a hard-coded module, so they could never agree).
    let body: serde_json::Value = client
        .get(format!("http://{addr}/api/v1/admin/admin-auth"))
        .header("x-admin-token", "grp:admins")
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(body["configured"], true);
    assert_eq!(
        body["modules"],
        serde_json::json!(["test-scope-module"]),
        "GET admin-auth mirrors the PUT'd chain verbatim"
    );

    handle.abort();
}

/// Idempotent mint + optimistic concurrency: a retried POST with the same Idempotency-Key
/// returns the FIRST response (same id + secret, no double-create); a PATCH with a stale
/// If-Match is a 409 that changes nothing; a fresh If-Match succeeds.
#[tokio::test]
async fn test_admin_v1_key_idempotent_mint_and_if_match() {
    crate::metrics::init();
    let store = Arc::new(MemoryStore::new());
    let gov = Arc::new(GovState::new(store, Some("admintok".to_string())).unwrap());
    let app = TestApp::new().governance(gov).build();
    let router = crate::build_router(app);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    let client = reqwest::Client::new();
    let admin = |req: reqwest::RequestBuilder| {
        req.header("x-admin-token", "admintok")
            .header("content-type", "application/json")
    };

    // Same Idempotency-Key twice → identical response, ONE key.
    let mint = |k: &'static str| {
        admin(client.post(format!("http://{addr}/api/v1/admin/keys")))
            .header("idempotency-key", k)
            .body(serde_json::json!({"name": "idem"}).to_string())
            .send()
    };
    let a: serde_json::Value = mint("abc").await.unwrap().json().await.unwrap();
    let b: serde_json::Value = mint("abc").await.unwrap().json().await.unwrap();
    assert_eq!(a["id"], b["id"], "replay returns the same key");
    assert_eq!(
        a["secret"], b["secret"],
        "replay returns the FIRST response verbatim"
    );
    let listed: serde_json::Value = admin(client.get(format!(
        "http://{addr}/api/v1/admin/keys?prefix={}",
        a["id"].as_str().unwrap()
    )))
    .send()
    .await
    .unwrap()
    .json()
    .await
    .unwrap();
    assert_eq!(
        listed["items"].as_array().unwrap().len(),
        1,
        "no double-create: {listed}"
    );

    // If-Match: stale = 409 untouched; current etag = applied.
    let id = a["id"].as_str().unwrap();
    let got = admin(client.get(format!("http://{addr}/api/v1/admin/keys/{id}")))
        .send()
        .await
        .unwrap();
    // ETag is header-only now (H4) — strip the surrounding quotes to feed back as If-Match.
    let etag = got
        .headers()
        .get(axum::http::header::ETAG)
        .and_then(|v| v.to_str().ok())
        .unwrap()
        .trim_matches('"')
        .to_string();
    let stale = admin(client.patch(format!("http://{addr}/api/v1/admin/keys/{id}")))
        .header("if-match", "\"deadbeefdeadbeef\"")
        .body(serde_json::json!({"rpm_limit": 5}).to_string())
        .send()
        .await
        .unwrap();
    assert_eq!(stale.status().as_u16(), 409, "stale If-Match conflicts");
    let fresh = admin(client.patch(format!("http://{addr}/api/v1/admin/keys/{id}")))
        .header("if-match", format!("\"{etag}\""))
        .body(serde_json::json!({"rpm_limit": 5}).to_string())
        .send()
        .await
        .unwrap();
    assert_eq!(fresh.status().as_u16(), 200, "current If-Match applies");

    handle.abort();
}

/// The idempotency RESERVATION frees itself on a FAILED mint: a POST that reserves an
/// Idempotency-Key then fails validation must NOT leave a stuck in-flight sentinel — a
/// subsequent valid retry under the SAME key mints normally (not a spurious 409/replay).
#[tokio::test]
async fn test_admin_v1_idempotency_reservation_frees_on_failure() {
    crate::metrics::init();
    let store = Arc::new(MemoryStore::new());
    let gov = Arc::new(GovState::new(store, Some("admintok".to_string())).unwrap());
    let app = TestApp::new().governance(gov).build();
    let router = crate::build_router(app);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    let client = reqwest::Client::new();
    let post = |body: &'static str| {
        client
            .post(format!("http://{addr}/api/v1/admin/keys"))
            .header("x-admin-token", "admintok")
            .header("content-type", "application/json")
            .header("idempotency-key", "reuse-key")
            .body(body)
            .send()
    };

    // Reserve the key, then fail validation (unknown budget_period).
    let bad = post(r#"{"name": "x", "budget_period": "fortnightly"}"#)
        .await
        .unwrap();
    assert_eq!(bad.status().as_u16(), 400, "invalid body is a 400");

    // The SAME key now mints normally — the reservation was cleared, not stuck in-flight.
    let good = post(r#"{"name": "x"}"#).await.unwrap();
    assert_eq!(
        good.status().as_u16(),
        201,
        "a valid retry under the same key mints (reservation freed on the prior failure)"
    );

    handle.abort();
}

/// Key ROTATION: the new secret works, the old stops resolving, the id + settings are
/// unchanged; unknown ids 404. And keys pagination: limit/offset over the id-sorted set with a
/// stable total.
#[tokio::test]
async fn test_admin_v1_key_rotate_and_pagination() {
    crate::metrics::init();
    let store = Arc::new(MemoryStore::new());
    let gov = Arc::new(GovState::new(store, Some("admintok".to_string())).unwrap());
    let app = TestApp::new().governance(gov.clone()).build();
    let router = crate::build_router(app);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    let client = reqwest::Client::new();
    let admin = |req: reqwest::RequestBuilder| {
        req.header("x-admin-token", "admintok")
            .header("content-type", "application/json")
    };

    // Mint three keys.
    let mut ids = Vec::new();
    for n in ["ka", "kb", "kc"] {
        let created: serde_json::Value =
            admin(client.post(format!("http://{addr}/api/v1/admin/keys")))
                .body(serde_json::json!({"name": n}).to_string())
                .send()
                .await
                .unwrap()
                .json()
                .await
                .unwrap();
        ids.push((
            created["id"].as_str().unwrap().to_string(),
            created["secret"].as_str().unwrap().to_string(),
        ));
    }

    // Pagination (cursor envelope): page 1 with ?limit=2 yields 2 items + a next_cursor; feeding
    // that opaque cursor back yields the final item with next_cursor=null. Covers all three once.
    let p1: serde_json::Value =
        admin(client.get(format!("http://{addr}/api/v1/admin/keys?limit=2")))
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
    assert_eq!(p1["items"].as_array().unwrap().len(), 2);
    let cursor = p1["next_cursor"]
        .as_str()
        .expect("more rows remain -> a next_cursor is present");
    let p2: serde_json::Value = admin(client.get(format!(
        "http://{addr}/api/v1/admin/keys?limit=2&cursor={cursor}"
    )))
    .send()
    .await
    .unwrap()
    .json()
    .await
    .unwrap();
    assert_eq!(p2["items"].as_array().unwrap().len(), 1);
    assert!(
        p2["next_cursor"].is_null(),
        "last page has no next_cursor: {p2}"
    );
    let mut seen: Vec<String> = p1["items"]
        .as_array()
        .unwrap()
        .iter()
        .chain(p2["items"].as_array().unwrap())
        .map(|k| k["id"].as_str().unwrap().to_string())
        .collect();
    seen.sort();
    seen.dedup();
    assert_eq!(seen.len(), 3, "pages cover every key exactly once");

    // A malformed/foreign cursor is a 400 invalid_request (never a silent skip).
    let bad = admin(client.get(format!("http://{addr}/api/v1/admin/keys?cursor=notacursor")))
        .send()
        .await
        .unwrap();
    assert_eq!(
        bad.status().as_u16(),
        400,
        "foreign cursor is invalid_request"
    );
    assert_eq!(
        bad.json::<serde_json::Value>().await.unwrap()["error"]["code"],
        "invalid_request"
    );

    // Rotate the first key: same id, new secret; old secret dead, new secret resolves.
    let (id, old_secret) = ids[0].clone();
    let rotated: serde_json::Value =
        admin(client.post(format!("http://{addr}/api/v1/admin/keys/{id}/rotate")))
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
    assert_eq!(rotated["id"], id.as_str(), "id is stable across rotation");
    let new_secret = rotated["secret"].as_str().unwrap().to_string();
    assert_ne!(new_secret, old_secret);
    assert!(gov.lookup(&new_secret).is_some(), "new secret resolves");
    assert!(
        gov.lookup(&old_secret).is_none(),
        "old secret stops resolving immediately"
    );

    // Unknown id → 404.
    let missing = admin(client.post(format!("http://{addr}/api/v1/admin/keys/vk_nope/rotate")))
        .send()
        .await
        .unwrap();
    assert_eq!(missing.status().as_u16(), 404);

    handle.abort();
}

/// `PUT /api/v1/admin/hooks/{name}`: replaces an overlay hook live; 404 for an unknown name;
/// 409 for a grant change (immutability) and for a stale If-Match.
#[tokio::test]
async fn test_admin_v1_put_hook_replaces_live_with_guards() {
    crate::metrics::init();
    let store = Arc::new(MemoryStore::new());
    let gov = Arc::new(GovState::new(store, Some("admintok".to_string())).unwrap());
    let app = TestApp::new().governance(gov).build();
    let router = crate::build_router(app);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    let client = reqwest::Client::new();
    let admin = |req: reqwest::RequestBuilder| {
        req.header("x-admin-token", "admintok")
            .header("content-type", "application/json")
    };

    // PUT on an unknown name is 404 (PUT replaces; POST creates).
    let missing = admin(client.put(format!("http://{addr}/api/v1/admin/hooks/nope")))
        .body(
            serde_json::json!({"config": {"kind": "tap", "webhook": "http://127.0.0.1:1/"}})
                .to_string(),
        )
        .send()
        .await
        .unwrap();
    assert_eq!(missing.status().as_u16(), 404);

    // Create, then replace with a new transport target (same grants) — 200, live.
    let created = admin(client.post(format!("http://{addr}/api/v1/admin/hooks")))
        .body(
            serde_json::json!({
                "name": "rep",
                "config": {"kind": "tap", "webhook": "http://127.0.0.1:9971/"}
            })
            .to_string(),
        )
        .send()
        .await
        .unwrap();
    assert_eq!(created.status().as_u16(), 201);
    let replaced = admin(client.put(format!("http://{addr}/api/v1/admin/hooks/rep")))
        .body(
            serde_json::json!({"config": {"kind": "tap", "webhook": "http://127.0.0.1:9972/"}})
                .to_string(),
        )
        .send()
        .await
        .unwrap();
    assert_eq!(replaced.status().as_u16(), 200);
    let got: serde_json::Value = admin(client.get(format!("http://{addr}/api/v1/admin/hooks/rep")))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert!(
        got["transport"].to_string().contains("9972"),
        "the replacement is live: {got}"
    );

    // Grant change via PUT is a 409 (immutability holds on the replace path too).
    let escalate = admin(client.put(format!("http://{addr}/api/v1/admin/hooks/rep")))
            .body(serde_json::json!({"config": {"kind": "gate", "webhook": "http://127.0.0.1:9972/", "prompt": "rw"}}).to_string())
            .send()
            .await
            .unwrap();
    assert_eq!(escalate.status().as_u16(), 409, "grants are immutable");

    // Stale If-Match is a 409 conflict (H3: concurrency rides the header).
    let stale = admin(client.put(format!("http://{addr}/api/v1/admin/hooks/rep")))
        .header("if-match", "\"0\"")
        .body(
            serde_json::json!({
                "config": {"kind": "tap", "webhook": "http://127.0.0.1:9973/"},
            })
            .to_string(),
        )
        .send()
        .await
        .unwrap();
    assert_eq!(stale.status().as_u16(), 409, "stale If-Match conflicts");

    // The current ETag (from the GET above / the PUT response) applies cleanly: read it live.
    let live = admin(client.get(format!("http://{addr}/api/v1/admin/hooks/rep")))
        .send()
        .await
        .unwrap();
    let etag = live
        .headers()
        .get(reqwest::header::ETAG)
        .and_then(|v| v.to_str().ok())
        .expect("config-plane reads emit the ETag")
        .to_string();
    let fresh = admin(client.put(format!("http://{addr}/api/v1/admin/hooks/rep")))
        .header("if-match", etag)
        .body(
            serde_json::json!({
                "config": {"kind": "tap", "webhook": "http://127.0.0.1:9973/"},
            })
            .to_string(),
        )
        .send()
        .await
        .unwrap();
    assert_eq!(fresh.status().as_u16(), 200, "current If-Match applies");
    assert!(
        fresh.headers().get(reqwest::header::ETAG).is_some(),
        "the mutation response carries the NEW ETag for chaining"
    );

    handle.abort();
}

/// The config version-history cycle: mutations record attributed versions; diff explains a
/// change; rollback restores a prior hook surface LIVE as a NEW version; unknown targets 404
/// and a stale If-Match conflicts.
#[tokio::test]
async fn test_admin_v1_config_versions_rollback_and_diff() {
    crate::metrics::init();
    let store = Arc::new(MemoryStore::new());
    let gov = Arc::new(GovState::new(store, Some("admintok".to_string())).unwrap());
    let app = TestApp::new().governance(gov).build();
    let router = crate::build_router(app);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    let client = reqwest::Client::new();
    let admin = |req: reqwest::RequestBuilder| req.header("x-admin-token", "admintok");

    // v1: register a hook. v2: delete it. (Boot floor is v0.)
    let body = serde_json::json!({
        "name": "rbk",
        "config": {"kind": "tap", "webhook": "http://127.0.0.1:9979/"}
    });
    let created = admin(client.post(format!("http://{addr}/api/v1/admin/hooks")))
        .header("content-type", "application/json")
        .body(body.to_string())
        .send()
        .await
        .unwrap();
    assert_eq!(created.status().as_u16(), 201);
    let deleted = admin(client.delete(format!("http://{addr}/api/v1/admin/hooks/rbk")))
        .send()
        .await
        .unwrap();
    assert_eq!(deleted.status().as_u16(), 204);

    // The history lists boot + register + delete, newest first, attributed.
    let versions: serde_json::Value =
        admin(client.get(format!("http://{addr}/api/v1/admin/config/versions")))
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
    let list = versions["items"].as_array().unwrap();
    assert_eq!(list.len(), 3, "boot + register + delete: {versions}");
    assert_eq!(list[0]["version"], 2);
    assert!(list[0]["summary"]
        .as_str()
        .unwrap()
        .contains("hook.delete hook:rbk"));
    assert_eq!(list[0]["principal"], "admin");

    // Diff v1 -> v2: the hook was removed.
    let diff: serde_json::Value = admin(client.get(format!(
        "http://{addr}/api/v1/admin/config/diff?from=1&to=2"
    )))
    .send()
    .await
    .unwrap()
    .json()
    .await
    .unwrap();
    assert_eq!(diff["hooks"]["removed"][0], "rbk", "{diff}");

    // Rollback to v1 restores the hook, LIVE, as a NEW version (append-only history).
    let rb = admin(client.post(format!("http://{addr}/api/v1/admin/config/rollback")))
        .header("content-type", "application/json")
        .body(serde_json::json!({"version": 1}).to_string())
        .send()
        .await
        .unwrap();
    assert_eq!(rb.status().as_u16(), 200);
    let rb_body: serde_json::Value = rb.json().await.unwrap();
    assert_eq!(rb_body["restored_version"], 1);
    assert_eq!(rb_body["config_version"], 3); // the post-rollback version, under the uniform name
    let restored = admin(client.get(format!("http://{addr}/api/v1/admin/hooks/rbk")))
        .send()
        .await
        .unwrap();
    assert_eq!(
        restored.status().as_u16(),
        200,
        "the rolled-back hook is live again"
    );

    // Guard rails: unknown target = 404; stale If-Match = 409 (H3).
    let missing = admin(client.post(format!("http://{addr}/api/v1/admin/config/rollback")))
        .header("content-type", "application/json")
        .body(serde_json::json!({"version": 999}).to_string())
        .send()
        .await
        .unwrap();
    assert_eq!(missing.status().as_u16(), 404);
    let stale = admin(client.post(format!("http://{addr}/api/v1/admin/config/rollback")))
        .header("content-type", "application/json")
        .header("if-match", "\"0\"")
        .body(serde_json::json!({"version": 1}).to_string())
        .send()
        .await
        .unwrap();
    assert_eq!(stale.status().as_u16(), 409);

    handle.abort();
}

#[tokio::test]
async fn test_admin_v1_register_hook_takes_effect_live() {
    crate::metrics::init();
    let store = Arc::new(MemoryStore::new());
    let gov = Arc::new(GovState::new(store, Some("admintok".to_string())).unwrap());
    let app = TestApp::new().governance(gov).build();
    let router = crate::build_router(app);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    let client = reqwest::Client::new();

    // Before: no hooks.
    let before: serde_json::Value = client
        .get(format!("http://{addr}/api/v1/admin/hooks"))
        .header("x-admin-token", "admintok")
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(before["items"].as_array().unwrap().len(), 0);

    // Register a global gate at runtime.
    let body = serde_json::json!({
        "name": "compress",
        "config": {
            "kind": "gate",
            "webhook": "http://127.0.0.1:9977/",
            "prompt": "rw",
            "global": true
        }
    });
    let created = client
        .post(format!("http://{addr}/api/v1/admin/hooks"))
        .header("x-admin-token", "admintok")
        .header("content-type", "application/json")
        .body(body.to_string())
        .send()
        .await
        .unwrap();
    assert_eq!(created.status().as_u16(), 201, "hook registered");
    let created_body: serde_json::Value = created.json().await.unwrap();
    assert_eq!(created_body["name"], "compress");
    assert_eq!(created_body["kind"], "gate");
    assert_eq!(created_body["global"], true);

    // After: the hook is LIVE — a fresh read sees it (swap took effect + reads-current).
    let after: serde_json::Value = client
        .get(format!("http://{addr}/api/v1/admin/hooks"))
        .header("x-admin-token", "admintok")
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let items = after["items"].as_array().unwrap();
    assert_eq!(
        items.len(),
        1,
        "the registered hook is now in the live config"
    );
    assert_eq!(items[0]["name"], "compress");

    // The config version bumped from 0 → 1 on the apply (drift-detection primitive).
    let info: serde_json::Value = client
        .get(format!("http://{addr}/api/v1/admin/info"))
        .header("x-admin-token", "admintok")
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(
        info["config_version"], 1,
        "one apply bumped the config version"
    );

    // GET one by name also sees it.
    let one = client
        .get(format!("http://{addr}/api/v1/admin/hooks/compress"))
        .header("x-admin-token", "admintok")
        .send()
        .await
        .unwrap();
    assert_eq!(one.status().as_u16(), 200);

    // A RESERVED name (an on_error terminal / built-in) rejects on the register path too —
    // previously only boot validation checked this, so a runtime hook named `reject` could
    // shadow the terminal and make every consumer's on_error parse ambiguous (audit #8).
    for reserved in ["reject", "weighted", "nothing", "cheapest", "admin-tokens"] {
        let shadow = client
            .post(format!("http://{addr}/api/v1/admin/hooks"))
            .header("x-admin-token", "admintok")
            .header("content-type", "application/json")
            .body(
                serde_json::json!({
                    "name": reserved,
                    "config": {"kind": "gate", "webhook": "http://127.0.0.1:9977/"}
                })
                .to_string(),
            )
            .send()
            .await
            .unwrap();
        assert_eq!(
            shadow.status().as_u16(),
            400,
            "hook name `{reserved}` is reserved and must reject"
        );
        assert_eq!(
            shadow.json::<serde_json::Value>().await.unwrap()["error"]["code"],
            "invalid_request"
        );
    }

    // Invalid definition (prompt:rw on a tap) → 400 invalid_request, no mutation.
    let bad = client
        .post(format!("http://{addr}/api/v1/admin/hooks"))
        .header("x-admin-token", "admintok")
        .header("content-type", "application/json")
        .body(
            serde_json::json!({
                "name": "bad",
                "config": {"kind": "tap", "webhook": "http://127.0.0.1:9977/", "prompt": "rw"}
            })
            .to_string(),
        )
        .send()
        .await
        .unwrap();
    assert_eq!(bad.status().as_u16(), 400);
    assert_eq!(
        bad.json::<serde_json::Value>().await.unwrap()["error"]["code"],
        "invalid_request"
    );

    // Grant immutability over the wire (§6.4): re-registering "compress" (a prompt:rw gate) with a
    // DIFFERENT grant (prompt:ro) → 409 conflict, no mutation. Same grants would be idempotent.
    let escalate = client
        .post(format!("http://{addr}/api/v1/admin/hooks"))
        .header("x-admin-token", "admintok")
        .header("content-type", "application/json")
        .body(
            serde_json::json!({
                "name": "compress",
                "config": {"kind": "gate", "webhook": "http://127.0.0.1:9977/", "prompt": "ro"}
            })
            .to_string(),
        )
        .send()
        .await
        .unwrap();
    assert_eq!(
        escalate.status().as_u16(),
        409,
        "grant change must conflict"
    );
    assert_eq!(
        escalate.json::<serde_json::Value>().await.unwrap()["error"]["code"],
        "conflict"
    );

    handle.abort();
}

/// `GET /api/v1/admin/audit` records admin mutations: registering a hook appears in the audit log as
/// `hook.register` / `applied`, with the resource named. (The audit ring is process-global, so
/// other concurrent tests may add entries — assert the specific action appears, not an exact count.)
#[tokio::test]
async fn test_admin_v1_audit_records_mutations() {
    crate::metrics::init();
    let store = Arc::new(MemoryStore::new());
    let gov = Arc::new(GovState::new(store, Some("admintok".to_string())).unwrap());
    let app = TestApp::new().governance(gov).build();
    let router = crate::build_router(app);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    let client = reqwest::Client::new();

    // A uniquely-named hook so the audit assertion can't collide with a concurrent test.
    let name = "audit_probe_hook_x7";
    client
        .post(format!("http://{addr}/api/v1/admin/hooks"))
        .header("x-admin-token", "admintok")
        .header("content-type", "application/json")
        .body(
            serde_json::json!({
                "name": name,
                "config": {"kind": "tap", "webhook": "http://127.0.0.1:9979/", "global": true}
            })
            .to_string(),
        )
        .send()
        .await
        .unwrap();

    let audit: serde_json::Value = client
        .get(format!("http://{addr}/api/v1/admin/audit"))
        .header("x-admin-token", "admintok")
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let entries = audit["items"].as_array().unwrap();
    let mine = entries
        .iter()
        .find(|e| e["resource"] == format!("hook:{name}"))
        .expect("the registration is recorded in the audit log");
    assert_eq!(mine["action"], "hook.register");
    assert_eq!(mine["outcome"], "applied");
    assert!(mine["seq"].is_number() && mine["ts"].is_number());

    // Filter by resource (§2.5): only this hook's entries come back.
    let filtered: serde_json::Value = client
        .get(format!(
            "http://{addr}/api/v1/admin/audit?resource=hook:{name}"
        ))
        .header("x-admin-token", "admintok")
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let f = filtered["items"].as_array().unwrap();
    assert!(!f.is_empty());
    assert!(
        f.iter().all(|e| e["resource"] == format!("hook:{name}")),
        "the resource filter returns only matching entries"
    );

    // Filter by a non-matching action → empty.
    let none: serde_json::Value = client
        .get(format!(
            "http://{addr}/api/v1/admin/audit?resource=hook:{name}&action=key.create"
        ))
        .header("x-admin-token", "admintok")
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(none["items"].as_array().unwrap().len(), 0);

    handle.abort();
}

/// REGRESSION (audit c1r9): the UNKNOWN-NAME 404 on `PUT /hooks/{name}` and
/// `PATCH /hooks/{name}/settings` must be AUDITED (like DELETE's 404) — an unaudited 404 lets a
/// principal probe which hook names exist by response code alone, with no trail.
#[tokio::test]
async fn test_admin_v1_hook_mutation_404_is_audited() {
    crate::metrics::init();
    let store = Arc::new(MemoryStore::new());
    let gov = Arc::new(GovState::new(store, Some("admintok".to_string())).unwrap());
    let app = TestApp::new().governance(gov).build();
    let router = crate::build_router(app);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    let client = reqwest::Client::new();

    // Two uniquely-named, NEVER-registered hooks so the audit assertions can't collide.
    let put_name = "ghost_put_hook_q3";
    let patch_name = "ghost_patch_hook_q3";

    let put_resp = client
        .put(format!("http://{addr}/api/v1/admin/hooks/{put_name}"))
        .header("x-admin-token", "admintok")
        .header("content-type", "application/json")
        .body(
            serde_json::json!({"config": {"kind": "tap", "webhook": "http://127.0.0.1:9978/"}})
                .to_string(),
        )
        .send()
        .await
        .unwrap();
    assert_eq!(put_resp.status(), 404, "PUT on an unknown hook is a 404");

    let patch_resp = client
        .patch(format!(
            "http://{addr}/api/v1/admin/hooks/{patch_name}/settings"
        ))
        .header("x-admin-token", "admintok")
        .header("content-type", "application/json")
        .body(serde_json::json!({"settings": {"k": "v"}}).to_string())
        .send()
        .await
        .unwrap();
    assert_eq!(
        patch_resp.status(),
        404,
        "PATCH on an unknown hook is a 404"
    );

    // Both 404s must appear in the audit log as REJECTED, resource-named.
    for (name, action) in [(put_name, "hook.replace"), (patch_name, "hook.settings")] {
        let filtered: serde_json::Value = client
            .get(format!(
                "http://{addr}/api/v1/admin/audit?resource=hook:{name}"
            ))
            .header("x-admin-token", "admintok")
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        let entry = filtered["items"]
            .as_array()
            .unwrap()
            .iter()
            .find(|e| e["resource"] == format!("hook:{name}"))
            .unwrap_or_else(|| panic!("the {action} 404 must be recorded in the audit log"));
        assert_eq!(entry["action"], action);
        assert_eq!(
            entry["outcome"], "rejected",
            "the unknown-name 404 is a rejected mutation, audited"
        );
    }

    handle.abort();
}

/// `GET /api/v1/admin/keys` supports `?prefix=` and `?enabled=` filters (§2.1): a full-id prefix
/// returns just that key; a non-matching prefix returns none; `?enabled=true` includes a fresh key.
#[tokio::test]
async fn test_admin_v1_list_keys_filters() {
    use crate::governance::NewKeySpec;
    crate::metrics::init();
    let store = Arc::new(MemoryStore::new());
    let gov = Arc::new(GovState::new(store, Some("admintok".to_string())).unwrap());
    let (minted, _secret) = gov
        .create_key(
            NewKeySpec {
                name: "filter-probe".to_string(),
                allowed_pools: vec![],
                max_budget_cents: None,
                budget_period: "total".to_string(),
                rpm_limit: None,
                tpm_limit: None,
                budget_group: None,
                labels: Default::default(),
            },
            crate::store::now(),
        )
        .unwrap();
    let app = TestApp::new().governance(gov).build();
    let router = crate::build_router(app);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    let client = reqwest::Client::new();
    let get = |query: String| {
        let url = format!("http://{addr}/api/v1/admin/keys{query}");
        let client = client.clone();
        async move {
            client
                .get(url)
                .header("x-admin-token", "admintok")
                .send()
                .await
                .unwrap()
                .json::<serde_json::Value>()
                .await
                .unwrap()
        }
    };

    // Prefix = the full id → exactly this key.
    let by_prefix = get(format!("?prefix={}", minted.id)).await;
    let keys = by_prefix["items"].as_array().unwrap();
    assert_eq!(keys.len(), 1);
    assert_eq!(keys[0]["id"], minted.id);

    // Non-matching prefix → none.
    let none = get("?prefix=vk_does_not_exist".into()).await;
    assert_eq!(none["items"].as_array().unwrap().len(), 0);

    // enabled=true includes the fresh (enabled) key.
    let enabled = get("?enabled=true".into()).await;
    assert!(enabled["items"]
        .as_array()
        .unwrap()
        .iter()
        .any(|k| k["id"] == minted.id));

    handle.abort();
}

/// GOLDEN PATH: the whole config plane working together in one flow — register → live + version
/// bump + audit + persist → delete → gone + version bump + audit. A coherent-flow regression anchor
/// for the marquee feature (catches integration breaks the per-feature tests miss).
#[tokio::test]
async fn test_admin_v1_config_plane_golden_path() {
    crate::metrics::init();
    let store = Arc::new(MemoryStore::new());
    let gov = Arc::new(GovState::new(store, Some("t".to_string())).unwrap());
    let overlay = std::env::temp_dir().join(format!(
        "busbar-golden-{}-{}.json",
        std::process::id(),
        crate::store::now()
    ));
    let _ = std::fs::remove_file(&overlay);
    let app = TestApp::new()
        .governance(gov)
        .overlay_path(overlay.clone())
        .build();
    let router = crate::build_router(app);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    let c = reqwest::Client::new();
    let base = format!("http://{addr}");
    let get = |p: String| {
        let (c, url) = (c.clone(), format!("{base}{p}"));
        async move {
            c.get(url)
                .header("x-admin-token", "t")
                .send()
                .await
                .unwrap()
                .json::<serde_json::Value>()
                .await
                .unwrap()
        }
    };
    let name = "golden_gate";

    // Baseline: no hooks, version 0, persistence on.
    assert_eq!(
        get("/api/v1/admin/hooks".into()).await["items"]
            .as_array()
            .unwrap()
            .len(),
        0
    );
    let info0 = get("/api/v1/admin/info".into()).await;
    assert_eq!(info0["config_version"], 0);
    assert_eq!(info0["config_persistence"], true);

    // Register.
    let created = c
        .post(format!("{base}/api/v1/admin/hooks"))
        .header("x-admin-token", "t")
        .header("content-type", "application/json")
        .body(
            serde_json::json!({"name": name, "config":
                    {"kind": "gate", "webhook": "http://127.0.0.1:9982/", "global": true}})
            .to_string(),
        )
        .send()
        .await
        .unwrap();
    assert_eq!(created.status().as_u16(), 201);

    // Live (read sees it), version bumped, persisted to disk.
    assert!(get("/api/v1/admin/hooks".into()).await["items"]
        .as_array()
        .unwrap()
        .iter()
        .any(|h| h["name"] == name));
    assert_eq!(get("/api/v1/admin/info".into()).await["config_version"], 1);
    assert_eq!(get("/api/v1/admin/config".into()).await["version"], 1);
    assert!(crate::config::overlay::read(&overlay)
        .unwrap()
        .hooks
        .contains_key(name));
    // Audit records it.
    assert!(
        get(format!("/api/v1/admin/audit?resource=hook:{name}")).await["items"]
            .as_array()
            .unwrap()
            .iter()
            .any(|e| e["action"] == "hook.register" && e["outcome"] == "applied")
    );

    // Delete.
    let deleted = c
        .delete(format!("{base}/api/v1/admin/hooks/{name}"))
        .header("x-admin-token", "t")
        .send()
        .await
        .unwrap();
    assert_eq!(deleted.status().as_u16(), 204);

    // Gone, version bumped again, persisted removal.
    assert_eq!(
        get("/api/v1/admin/hooks".into()).await["items"]
            .as_array()
            .unwrap()
            .len(),
        0
    );
    assert_eq!(get("/api/v1/admin/info".into()).await["config_version"], 2);
    assert!(!crate::config::overlay::read(&overlay)
        .unwrap()
        .hooks
        .contains_key(name));

    let _ = std::fs::remove_file(&overlay);
    handle.abort();
}

/// Config-overlay PERSISTENCE: with an overlay path set, registering a hook over the API writes it
/// to the overlay file, and merging that overlay onto a fresh base config (a "restart") restores
/// the hook — so a runtime-registered hook survives a restart.
#[tokio::test]
async fn test_admin_v1_hook_register_persists_to_overlay() {
    crate::metrics::init();
    let store = Arc::new(MemoryStore::new());
    let gov = Arc::new(GovState::new(store, Some("admintok".to_string())).unwrap());
    let overlay = std::env::temp_dir().join(format!(
        "busbar-persist-test-{}-{}.json",
        std::process::id(),
        crate::store::now()
    ));
    let _ = std::fs::remove_file(&overlay);
    let app = TestApp::new()
        .governance(gov)
        .overlay_path(overlay.clone())
        .build();
    let router = crate::build_router(app);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    let client = reqwest::Client::new();

    // Register a global gate — the handler persists it to the overlay file.
    let created = client
        .post(format!("http://{addr}/api/v1/admin/hooks"))
        .header("x-admin-token", "admintok")
        .header("content-type", "application/json")
        .body(
            serde_json::json!({
                "name": "persisted_gate",
                "config": {"kind": "gate", "webhook": "http://127.0.0.1:9981/", "global": true}
            })
            .to_string(),
        )
        .send()
        .await
        .unwrap();
    assert_eq!(created.status().as_u16(), 201);

    // The overlay file now holds the hook.
    let doc = crate::config::overlay::read(&overlay).expect("overlay written");
    assert!(doc.hooks.contains_key("persisted_gate"));
    assert!(doc.global_hooks.iter().any(|g| g == "persisted_gate"));

    // "Restart": merge the overlay onto a fresh base config → the hook is restored.
    let mut fresh: crate::config::DeployCfg =
        serde_json::from_value(serde_json::json!({"providers": {}, "models": {}})).unwrap();
    crate::config::overlay::merge_into(&mut fresh, doc);
    assert!(
        fresh.hooks.contains_key("persisted_gate"),
        "the runtime-registered hook survives a restart via the overlay"
    );

    let _ = std::fs::remove_file(&overlay);
    handle.abort();
}

/// Key mutations are audited too (§6.7 — EVERY admin mutation): minting a key records
/// `key.create` / `applied` with the new key's id.
#[tokio::test]
async fn test_admin_v1_audit_records_key_mutations() {
    crate::metrics::init();
    let store = Arc::new(MemoryStore::new());
    let gov = Arc::new(GovState::new(store, Some("admintok".to_string())).unwrap());
    let app = TestApp::new().governance(gov).build();
    let router = crate::build_router(app);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    let client = reqwest::Client::new();

    // Mint a uniquely-named key.
    let minted: serde_json::Value = client
        .post(format!("http://{addr}/api/v1/admin/keys"))
        .header("x-admin-token", "admintok")
        .header("content-type", "application/json")
        .body(serde_json::json!({"name": "audit_key_probe_z3"}).to_string())
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let id = minted["id"].as_str().unwrap().to_string();

    let audit: serde_json::Value = client
        .get(format!("http://{addr}/api/v1/admin/audit"))
        .header("x-admin-token", "admintok")
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let mine = audit["items"]
        .as_array()
        .unwrap()
        .iter()
        .find(|e| e["resource"] == format!("key:{id}"))
        .expect("the key creation is recorded in the audit log");
    assert_eq!(mine["action"], "key.create");
    assert_eq!(mine["outcome"], "applied");

    handle.abort();
}

/// REGRESSION (audit c1r5): base-config hooks are READ-ONLY across every mutation verb — a
/// narrow hooks-register token must not be able to shadow/redirect (POST) or remove (DELETE) an
/// operator's file-defined hook (e.g. a `pii-guard` gate). PUT/PATCH already guarded; this pins
/// POST + DELETE to the same 409, matching the guard other verbs enforce.
#[tokio::test]
async fn test_admin_v1_base_hook_is_read_only_via_api() {
    crate::metrics::init();
    let store = Arc::new(MemoryStore::new());
    let gov = Arc::new(GovState::new(store, Some("admintok".to_string())).unwrap());
    let base: crate::config::HookCfg = serde_json::from_value(serde_json::json!({
        "kind": "gate", "webhook": "http://127.0.0.1:9990/", "prompt": "no", "global": true
    }))
    .unwrap();
    let app = TestApp::new()
        .governance(gov)
        .base_hook("pii-guard", base)
        .build();
    let router = crate::build_router(app);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let _handle = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    let client = reqwest::Client::new();

    // POST a same-shape definition over the base hook's name → 409 (no silent transport redirect).
    let shadow = client
            .post(format!("http://{addr}/api/v1/admin/hooks"))
            .header("x-admin-token", "admintok")
            .header("content-type", "application/json")
            .body(
                serde_json::json!({
                    "name": "pii-guard",
                    "config": {"kind": "gate", "webhook": "http://127.0.0.1:6666/", "prompt": "no", "global": true}
                })
                .to_string(),
            )
            .send()
            .await
            .unwrap();
    assert_eq!(
        shadow.status().as_u16(),
        409,
        "POST cannot shadow a base hook"
    );

    // DELETE the base hook → 409 (cannot remove an operator's base security gate via the API).
    let del = client
        .delete(format!("http://{addr}/api/v1/admin/hooks/pii-guard"))
        .header("x-admin-token", "admintok")
        .send()
        .await
        .unwrap();
    assert_eq!(
        del.status().as_u16(),
        409,
        "DELETE cannot remove a base hook"
    );

    // It is still present and unchanged.
    let got: serde_json::Value = client
        .get(format!("http://{addr}/api/v1/admin/hooks/pii-guard"))
        .header("x-admin-token", "admintok")
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert!(
        got["transport"].to_string().contains("9990"),
        "base hook untouched: {got}"
    );
}

/// `DELETE /api/v1/admin/hooks/{name}` removes a hook at runtime (live): register → delete (204) →
/// GET /hooks/{name} 404. Deleting an unregistered hook is 404.
#[tokio::test]
async fn test_admin_v1_delete_hook_takes_effect_live() {
    crate::metrics::init();
    let store = Arc::new(MemoryStore::new());
    let gov = Arc::new(GovState::new(store, Some("admintok".to_string())).unwrap());
    let app = TestApp::new().governance(gov).build();
    let router = crate::build_router(app);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    let client = reqwest::Client::new();
    let tok = ("x-admin-token", "admintok");

    // Register a global tap.
    let created = client
        .post(format!("http://{addr}/api/v1/admin/hooks"))
        .header(tok.0, tok.1)
        .header("content-type", "application/json")
        .body(
            serde_json::json!({
                "name": "logger",
                "config": {"kind": "tap", "webhook": "http://127.0.0.1:9978/", "global": true}
            })
            .to_string(),
        )
        .send()
        .await
        .unwrap();
    assert_eq!(created.status().as_u16(), 201);

    // Delete an absent hook → 404.
    let absent = client
        .delete(format!("http://{addr}/api/v1/admin/hooks/nope"))
        .header(tok.0, tok.1)
        .send()
        .await
        .unwrap();
    assert_eq!(absent.status().as_u16(), 404);

    // Delete the registered hook → 204, and it's gone live.
    let deleted = client
        .delete(format!("http://{addr}/api/v1/admin/hooks/logger"))
        .header(tok.0, tok.1)
        .send()
        .await
        .unwrap();
    assert_eq!(deleted.status().as_u16(), 204);

    let after = client
        .get(format!("http://{addr}/api/v1/admin/hooks/logger"))
        .header(tok.0, tok.1)
        .send()
        .await
        .unwrap();
    assert_eq!(
        after.status().as_u16(),
        404,
        "the hook is gone from the live config"
    );

    handle.abort();
}

/// The hooks read surface (`GET /api/v1/admin/hooks`, `GET /api/v1/admin/hooks/{name}`) projects the
/// registry definitions (kind/transport/grants/global), 404s an unknown name, and never leaks a
/// secret. Built on a fixture with one global gate.
#[tokio::test]
async fn test_admin_v1_hooks_read_surface() {
    crate::metrics::init();
    let store = Arc::new(MemoryStore::new());
    let gov = Arc::new(GovState::new(store, Some("admintok".to_string())).unwrap());

    let gate = crate::config::HookCfg {
        kind: crate::config::HookKind::Gate,
        socket: None,
        webhook: Some("http://127.0.0.1:9990/".to_string()),
        timeout_ms: 25,
        on_error: "reject".to_string(),
        prompt: crate::config::PromptAccess::Rw,
        user: crate::config::UserAccess::Ro,
        priority: 7,
        at: None,
        settings: serde_json::Map::new(),
        on_empty: None,
        global: false,
        default: false,
    };
    let app = TestApp::new()
        .governance(gov)
        .hook("compress", gate)
        .global_hook("compress")
        .build();
    let router = crate::build_router(app);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    let client = reqwest::Client::new();

    // List: the one hook, projected.
    let list = client
        .get(format!("http://{addr}/api/v1/admin/hooks"))
        .header("x-admin-token", "admintok")
        .send()
        .await
        .unwrap()
        .json::<serde_json::Value>()
        .await
        .unwrap();
    let items = list["items"].as_array().unwrap();
    assert_eq!(items.len(), 1);
    let h = &items[0];
    assert_eq!(h["name"], "compress");
    assert_eq!(h["kind"], "gate");
    assert_eq!(h["prompt"], "rw");
    assert_eq!(h["user"], "ro");
    assert_eq!(h["priority"], 7);
    assert_eq!(h["on_error"], "reject");
    assert_eq!(h["transport"]["kind"], "webhook");
    assert_eq!(h["transport"]["target"], "http://127.0.0.1:9990/");
    assert_eq!(
        h["global"], true,
        "named in global_hooks → reported as globally wired"
    );

    // Get one by name.
    let one = client
        .get(format!("http://{addr}/api/v1/admin/hooks/compress"))
        .header("x-admin-token", "admintok")
        .send()
        .await
        .unwrap();
    assert_eq!(one.status().as_u16(), 200);

    // Unknown name → 404 with the stable v1 `not_found` code.
    let missing = client
        .get(format!("http://{addr}/api/v1/admin/hooks/nope"))
        .header("x-admin-token", "admintok")
        .send()
        .await
        .unwrap();
    assert_eq!(missing.status().as_u16(), 404);
    let body: serde_json::Value = missing.json().await.unwrap();
    assert_eq!(body["error"]["code"], "not_found");

    handle.abort();
}

/// `GET /api/v1/admin/hooks/{name}/health` best-effort probes a hook's transport: 404 for an unknown
/// name; a webhook hook reports `reachable: null` (probed on demand); a socket hook pointing at a
/// nonexistent path reports `reachable: false`. Never fires the hook.
#[tokio::test]
async fn test_admin_v1_hook_health_best_effort() {
    crate::metrics::init();
    let store = Arc::new(MemoryStore::new());
    let gov = Arc::new(GovState::new(store, Some("admintok".to_string())).unwrap());
    let mk = |socket: Option<&str>, webhook: Option<&str>| crate::config::HookCfg {
        kind: crate::config::HookKind::Gate,
        socket: socket.map(str::to_string),
        webhook: webhook.map(str::to_string),
        timeout_ms: 5,
        on_error: "weighted".to_string(),
        prompt: crate::config::PromptAccess::No,
        user: crate::config::UserAccess::No,
        priority: 0,
        at: None,
        settings: serde_json::Map::new(),
        on_empty: None,
        global: false,
        default: false,
    };
    let app = TestApp::new()
        .governance(gov)
        .hook("web", mk(None, Some("http://127.0.0.1:9980/")))
        .hook("sock", mk(Some("/nonexistent/busbar-hook.sock"), None))
        .build();
    let router = crate::build_router(app);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    let client = reqwest::Client::new();
    let get = |name: &str| {
        let url = format!("http://{addr}/api/v1/admin/hooks/{name}/health");
        let client = client.clone();
        async move {
            client
                .get(url)
                .header("x-admin-token", "admintok")
                .send()
                .await
                .unwrap()
        }
    };

    // Unknown → 404 not_found.
    let missing = get("nope").await;
    assert_eq!(missing.status().as_u16(), 404);
    assert_eq!(
        missing.json::<serde_json::Value>().await.unwrap()["error"]["code"],
        "not_found"
    );

    // Webhook → reachable null (not probed here).
    let web: serde_json::Value = get("web").await.json().await.unwrap();
    assert_eq!(web["name"], "web");
    assert_eq!(web["transport"]["kind"], "webhook");
    assert!(web["reachable"].is_null(), "webhook is not probed here");

    // Socket to a nonexistent path → reachable false (best-effort connect failed).
    let sock: serde_json::Value = get("sock").await.json().await.unwrap();
    assert_eq!(sock["transport"]["kind"], "socket");
    // On unix the connect fails → Some(false); on non-unix sockets aren't probed → null. Accept both.
    assert!(
        sock["reachable"] == serde_json::json!(false) || sock["reachable"].is_null(),
        "socket to a dead path is unreachable (unix) or unprobed (non-unix): {}",
        sock["reachable"]
    );

    handle.abort();
}

/// The plugin catalog (`GET /api/v1/admin/plugins?type=`) lists compiled-in plugins per type (the
/// same feature-gated source as `info`) plus external hooks from the registry, and rejects an
/// unknown/absent type with the stable `invalid_request` code.
#[tokio::test]
async fn test_admin_v1_plugins_catalog_by_type() {
    crate::metrics::init();
    let store = Arc::new(MemoryStore::new());
    let gov = Arc::new(GovState::new(store, Some("admintok".to_string())).unwrap());
    let gate = crate::config::HookCfg {
        kind: crate::config::HookKind::Gate,
        socket: Some("/run/busbar/h.sock".to_string()),
        webhook: None,
        timeout_ms: 5,
        on_error: "weighted".to_string(),
        prompt: crate::config::PromptAccess::No,
        user: crate::config::UserAccess::No,
        priority: 0,
        at: None,
        settings: serde_json::Map::new(),
        on_empty: None,
        global: false,
        default: false,
    };
    let app = TestApp::new().governance(gov).hook("myhook", gate).build();
    let router = crate::build_router(app);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    let client = reqwest::Client::new();

    let get = |q: &str| {
        let url = format!("http://{addr}/api/v1/admin/plugins?type={q}");
        let client = client.clone();
        async move {
            client
                .get(url)
                .header("x-admin-token", "admintok")
                .send()
                .await
                .unwrap()
        }
    };

    // auth: the compiled-in tokens module — present iff the auth-tokens feature is compiled in.
    let auth: serde_json::Value = get("auth").await.json().await.unwrap();
    let a_items = auth["items"].as_array().unwrap();
    let tokens = a_items.iter().find(|p| p["name"] == "tokens");
    assert_eq!(
        tokens.is_some(),
        cfg!(feature = "auth-tokens"),
        "tokens listed iff compiled in"
    );
    if let Some(tokens) = tokens {
        assert_eq!(tokens["loader"], "compiled-in");
        assert_eq!(tokens["type"], "auth");
    }

    // hooks: the weighted floor is ALWAYS compiled-in; ranking iff the feature is on; plus the
    // external myhook.
    let hooks: serde_json::Value = get("hooks").await.json().await.unwrap();
    let h_items = hooks["items"].as_array().unwrap();
    assert!(h_items
        .iter()
        .any(|p| p["name"] == "weighted" && p["loader"] == "compiled-in"));
    assert_eq!(
        h_items.iter().any(|p| p["name"] == "ranking"),
        cfg!(feature = "hooks-ranking"),
        "ranking listed iff compiled in"
    );
    let ext = h_items
        .iter()
        .find(|p| p["name"] == "myhook")
        .expect("external hook listed");
    assert_eq!(ext["loader"], "external");
    assert_eq!(ext["active"], true);
    assert_eq!(ext["target"], "/run/busbar/h.sock");

    // Unknown type → 400 invalid_request.
    let bad = get("nope").await;
    assert_eq!(bad.status().as_u16(), 400);
    let body: serde_json::Value = bad.json().await.unwrap();
    assert_eq!(body["error"]["code"], "invalid_request");

    handle.abort();
}

/// `GET /api/v1/admin/auth` reports the ingress chain + upstream-credential mode, never a secret. A
/// governance-only fixture (no explicit auth chain) is the open front door.
#[tokio::test]
async fn test_admin_v1_auth_read() {
    crate::metrics::init();
    let store = Arc::new(MemoryStore::new());
    let gov = Arc::new(GovState::new(store, Some("admintok".to_string())).unwrap());
    let app = TestApp::new().governance(gov).build();
    let router = crate::build_router(app);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    let client = reqwest::Client::new();

    let body: serde_json::Value = client
        .get(format!("http://{addr}/api/v1/admin/auth"))
        .header("x-admin-token", "admintok")
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert!(body["chain"].is_array());
    assert_eq!(body["open"], true, "no explicit chain → open front door");
    assert_eq!(body["upstream_credentials"], "own");
    // Sanity: no secret-looking field leaked.
    assert!(body.get("client_tokens").is_none());

    handle.abort();
}

/// `POST /api/v1/admin/config/validate` dry-runs a proposed config: a malformed body is a 400
/// `invalid_request`; a well-formed body describing an INVALID config (here a provider reference
/// absent from the defs) returns 200 with `ok:false` and the resolution errors — never mutating.
#[tokio::test]
async fn test_admin_v1_config_validate_dry_run() {
    crate::metrics::init();
    let store = Arc::new(MemoryStore::new());
    let gov = Arc::new(GovState::new(store, Some("admintok".to_string())).unwrap());
    let app = TestApp::new().governance(gov).build();
    let router = crate::build_router(app);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    let client = reqwest::Client::new();
    let url = format!("http://{addr}/api/v1/admin/config/validate");

    // Malformed body → 400 invalid_request (the REQUEST is broken, not the config).
    let bad = client
        .post(&url)
        .header("x-admin-token", "admintok")
        .header("content-type", "application/json")
        .body("{\"config\": \"not-an-object\"}")
        .send()
        .await
        .unwrap();
    assert_eq!(bad.status().as_u16(), 400);
    let body: serde_json::Value = bad.json().await.unwrap();
    assert_eq!(body["error"]["code"], "invalid_request");

    // Well-formed body, invalid config: deploy references provider "openai" but the defs are empty
    // → resolve fails with a dangling-provider error → 200 ok:false.
    let proposed = serde_json::json!({
        "config": {
            "providers": { "openai": { "api_key_env": "OPENAI_KEY" } },
            "models": {}
        },
        "providers": {}
    });
    let resp = client
        .post(&url)
        .header("x-admin-token", "admintok")
        .header("content-type", "application/json")
        .body(proposed.to_string())
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), 200);
    let v: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(v["ok"], false, "config with a dangling provider is invalid");
    let errors = v["errors"].as_array().unwrap();
    assert!(!errors.is_empty(), "invalid config must report errors");
    assert!(
        errors
            .iter()
            .any(|e| e.as_str().unwrap_or("").contains("openai")),
        "the dangling provider is named in an error: {errors:?}"
    );

    handle.abort();
}

/// `GET /api/v1/admin/config` composes the effective-config snapshot (auth + pools/models/providers +
/// hooks + global_hooks) from the redacted reads. Asserts the shape and that no secret-bearing
/// field (client tokens, provider keys) appears anywhere in the serialized body.
#[tokio::test]
async fn test_admin_v1_config_effective_snapshot_no_secrets() {
    use crate::test_support::LaneSpec;
    crate::metrics::init();
    let store = Arc::new(MemoryStore::new());
    let gov = Arc::new(GovState::new(store, Some("admintok".to_string())).unwrap());
    let gate = crate::config::HookCfg {
        kind: crate::config::HookKind::Gate,
        socket: None,
        webhook: Some("http://127.0.0.1:9970/".to_string()),
        timeout_ms: 5,
        on_error: "weighted".to_string(),
        prompt: crate::config::PromptAccess::No,
        user: crate::config::UserAccess::No,
        priority: 0,
        at: None,
        settings: serde_json::Map::new(),
        on_empty: None,
        global: false,
        default: false,
    };
    let app = TestApp::new()
        .governance(gov)
        .lane(
            LaneSpec::new(
                "m",
                crate::proto::Protocol::anthropic(),
                "http://127.0.0.1:1/",
            )
            .provider("prov"),
        )
        .pool("p", &[(0, 1)])
        .hook("g", gate)
        .global_hook("g")
        .build();
    let router = crate::build_router(app);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    let client = reqwest::Client::new();

    let resp = client
        .get(format!("http://{addr}/api/v1/admin/config"))
        .header("x-admin-token", "admintok")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), 200);
    let text = resp.text().await.unwrap();
    let body: serde_json::Value = serde_json::from_str(&text).unwrap();
    // Composed sections present.
    assert_eq!(body["version"], 0, "fresh config is version 0");
    assert!(body["auth"]["chain"].is_array());
    assert!(body["pools"]
        .as_array()
        .unwrap()
        .iter()
        .any(|p| p["name"] == "p"));
    assert!(body["models"]
        .as_array()
        .unwrap()
        .iter()
        .any(|m| m["model"] == "m"));
    assert!(body["providers"]
        .as_array()
        .unwrap()
        .iter()
        .any(|p| p["provider"] == "prov"));
    assert!(body["hooks"]
        .as_array()
        .unwrap()
        .iter()
        .any(|h| h["name"] == "g"));
    assert!(body["global_hooks"]
        .as_array()
        .unwrap()
        .iter()
        .any(|n| n == "g"));
    // No secret-bearing key names anywhere in the snapshot.
    for needle in ["admintok", "client_tokens", "api_key", "secret"] {
        assert!(
            !text.contains(needle),
            "effective config must not leak `{needle}`: {text}"
        );
    }

    handle.abort();
}

/// `GET /api/v1/admin/openapi.json` returns a valid OpenAPI 3.1 doc, and — the DRIFT GUARD — every GET
/// path it documents (from V1_GET_PATHS) actually resolves on the live router (never a phantom
/// endpoint in the discovery contract). Also asserts the stable error `code` enum is present.
#[tokio::test]
async fn test_admin_v1_openapi_paths_all_resolve() {
    crate::metrics::init();
    let store = Arc::new(MemoryStore::new());
    let gov = Arc::new(GovState::new(store, Some("admintok".to_string())).unwrap());
    let app = TestApp::new().governance(gov).build();
    let router = crate::build_router(app);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    let client = reqwest::Client::new();

    let doc: serde_json::Value = client
        .get(format!("http://{addr}/api/v1/admin/openapi.json"))
        .header("x-admin-token", "admintok")
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(doc["openapi"], "3.1.0");
    assert_eq!(doc["info"]["title"], "Busbar Admin API");
    // The stable error code enum is documented.
    let codes = doc["components"]["schemas"]["Error"]["properties"]["error"]["properties"]["code"]
        ["enum"]
        .as_array()
        .unwrap();
    assert!(codes.iter().any(|c| c == "not_found"));

    // The runtime hook mutation methods are documented in the discovery contract.
    assert!(
        doc["paths"]["/api/v1/admin/hooks"]["post"].is_object(),
        "POST /api/v1/admin/hooks (register) must be in the openapi doc"
    );
    assert!(
        doc["paths"]["/api/v1/admin/hooks/{name}"]["delete"].is_object(),
        "DELETE /api/v1/admin/hooks/{{name}} (remove) must be in the openapi doc"
    );

    // DRIFT GUARD: every documented GET path is both listed in the doc AND actually mounted.
    // V1_GET_PATHS entries are RELATIVE; the wire path derives from the contract prefix (whose
    // literal value is pinned by its own golden test in contract.rs).
    for (rel, _) in crate::admin::v1::json::V1_GET_PATHS {
        let path = format!("{}{rel}", crate::admin::v1::contract::ADMIN_PREFIX);
        assert!(
            doc["paths"][&path]["get"].is_object(),
            "documented path {path} missing from openapi doc"
        );
        let status = client
            .get(format!("http://{addr}{path}"))
            .header("x-admin-token", "admintok")
            .send()
            .await
            .unwrap()
            .status();
        assert_ne!(
            status.as_u16(),
            404,
            "openapi documents {path} but the router does not mount it (phantom endpoint)"
        );
    }

    handle.abort();
}

/// SECURITY CONTRACT: every documented `/api/v1/admin` GET endpoint rejects a MISSING token and a
/// WRONG token with 401 — the whole surface is admin-guarded, no read leaks without the credential.
/// Iterates the same V1_GET_PATHS the openapi doc + drift guard use, so a newly-added endpoint is
/// automatically covered.
#[tokio::test]
async fn test_admin_v1_all_reads_require_admin_token() {
    crate::metrics::init();
    let store = Arc::new(MemoryStore::new());
    let gov = Arc::new(GovState::new(store, Some("admintok".to_string())).unwrap());
    let app = TestApp::new().governance(gov).build();
    let router = crate::build_router(app);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    let client = reqwest::Client::new();

    for (rel, _) in crate::admin::v1::json::V1_GET_PATHS {
        let path = format!("{}{rel}", crate::admin::v1::contract::ADMIN_PREFIX);
        // No token → 401, in the FROZEN v1 envelope (code `unauthorized`) — the most frequent
        // error a tooling consumer hits must branch on the same code seam as every other
        // (3rd-party audit #9; previously a protocol-shaped body).
        let none = client
            .get(format!("http://{addr}{path}"))
            .send()
            .await
            .unwrap();
        assert_eq!(
            none.status().as_u16(),
            401,
            "{path} must reject a request with NO admin token"
        );
        let body: serde_json::Value = none.json().await.unwrap();
        assert_eq!(
            body["error"]["code"], "unauthorized",
            "{path}: the admin 401 speaks the v1 envelope: {body}"
        );
        // Wrong token → 401.
        let wrong = client
            .get(format!("http://{addr}{path}"))
            .header("x-admin-token", "not-the-token")
            .send()
            .await
            .unwrap();
        assert_eq!(
            wrong.status().as_u16(),
            401,
            "{path} must reject a request with the WRONG admin token"
        );
    }

    handle.abort();
}

#[tokio::test]
async fn test_create_key_with_aws_credential_returns_secret_once_and_hides_on_reads() {
    // Minting with `issue_aws_credential: true` returns the AccessKeyId AND the secret access key
    // ONCE at creation; neither the AWS secret nor the key_hash is ever returned by a later read.
    crate::metrics::init();
    let store = Arc::new(MemoryStore::new());
    let gov = Arc::new(GovState::new(store, Some("admintok".to_string())).unwrap());
    let (addr, handle) = serve_with_gov(gov).await;
    let client = reqwest::Client::new();

    let created = client
        .post(format!("http://{addr}/api/v1/admin/keys"))
        .header("x-admin-token", "admintok")
        .json(&serde_json::json!({"name": "bedrock-key", "issue_aws_credential": true}))
        .send()
        .await
        .unwrap();
    assert_eq!(created.status().as_u16(), 201);
    let body: serde_json::Value = created.json().await.unwrap();
    let akid = body["aws_access_key_id"].as_str().unwrap().to_string();
    let aws_secret = body["aws_secret_access_key"].as_str().unwrap().to_string();
    assert!(akid.starts_with("AKIA"), "akid shape: {akid}");
    assert_eq!(aws_secret.len(), 40, "aws secret is 40 chars");
    assert!(
        body["secret"].is_string(),
        "bearer secret returned once too"
    );

    // A plain mint (no flag) carries NO AWS fields.
    let plain: serde_json::Value = client
        .post(format!("http://{addr}/api/v1/admin/keys"))
        .header("x-admin-token", "admintok")
        .json(&serde_json::json!({"name": "plain"}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert!(
        plain["aws_secret_access_key"].is_null() && plain["aws_access_key_id"].is_null(),
        "a bearer-only key must not carry AWS fields: {plain}"
    );

    // The list endpoint must NEVER expose the AWS secret (nor key_hash).
    let listed: serde_json::Value = client
        .get(format!("http://{addr}/api/v1/admin/keys"))
        .header("x-admin-token", "admintok")
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let listed_str = listed.to_string();
    assert!(
        !listed_str.contains(&aws_secret),
        "the AWS secret access key must NEVER appear in a read response: {listed_str}"
    );
    for k in listed["items"].as_array().unwrap() {
        assert!(
            k["aws_secret_access_key"].is_null(),
            "list must not leak the AWS secret"
        );
        assert!(k["key_hash"].is_null(), "list must not leak key_hash");
    }

    handle.abort();
}

#[tokio::test]
async fn test_create_list_usage_roundtrip_through_spawn_blocking() {
    // Exercises the create_key / list_keys / key_usage handlers end-to-end after they were moved
    // onto spawn_blocking: a slow store call must not block a Tokio worker, and the offloaded
    // handlers must still return the same responses (no secret/hash leak; usage resolves).
    crate::metrics::init();
    let store = Arc::new(MemoryStore::new());
    let gov = Arc::new(GovState::new(store, Some("admintok".to_string())).unwrap());
    let (addr, handle) = serve_with_gov(gov).await;
    let client = reqwest::Client::new();

    // create
    let created = client
        .post(format!("http://{addr}/api/v1/admin/keys"))
        .header("x-admin-token", "admintok")
        .json(&serde_json::json!({"name": "k1"}))
        .send()
        .await
        .unwrap();
    assert_eq!(created.status().as_u16(), 201);
    let body: serde_json::Value = created.json().await.unwrap();
    let id = body["id"].as_str().unwrap().to_string();
    assert!(body["secret"].is_string(), "secret returned once on create");
    assert!(body["key_hash"].is_null(), "key_hash must never be exposed");

    // list
    let listed = client
        .get(format!("http://{addr}/api/v1/admin/keys"))
        .header("x-admin-token", "admintok")
        .send()
        .await
        .unwrap();
    assert_eq!(listed.status().as_u16(), 200);
    let lb: serde_json::Value = listed.json().await.unwrap();
    assert_eq!(lb["items"].as_array().unwrap().len(), 1);
    assert!(
        lb["items"][0]["secret"].is_null(),
        "list must not leak secrets"
    );

    // usage — an UNCAPPED key reports `rate_headroom: null` (nothing to be near).
    let usage = client
        .get(format!("http://{addr}/api/v1/admin/keys/{id}/usage"))
        .header("x-admin-token", "admintok")
        .send()
        .await
        .unwrap();
    assert_eq!(usage.status().as_u16(), 200);
    let ub: serde_json::Value = usage.json().await.unwrap();
    assert_eq!(ub["id"], id);
    assert!(
        ub["rate_headroom"].is_null(),
        "uncapped key has no headroom signal: {ub}"
    );

    // A rate-CAPPED key reports its headroom fraction (a fresh window = fully available, 1.0),
    // so a client can back off BEFORE tripping a 429 (key-06).
    let capped: serde_json::Value = client
        .post(format!("http://{addr}/api/v1/admin/keys"))
        .header("x-admin-token", "admintok")
        .json(&serde_json::json!({"name": "k-capped", "rpm_limit": 10}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let capped_id = capped["id"].as_str().unwrap();
    let ub: serde_json::Value = client
        .get(format!("http://{addr}/api/v1/admin/keys/{capped_id}/usage"))
        .header("x-admin-token", "admintok")
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(
        ub["rate_headroom"], 1.0,
        "fresh capped key is fully available: {ub}"
    );
    handle.abort();
}

#[tokio::test]
async fn test_create_key_rejects_unknown_budget_period() {
    // Regression (MEDIUM/correctness): an unrecognized budget_period (a typo) must be rejected
    // with 400, NOT accepted at 201 and silently enforced as the all-time `"total"` window. A
    // valid period (and the default when omitted) must still create the key.
    crate::metrics::init();
    let store = Arc::new(MemoryStore::new());
    let gov = Arc::new(GovState::new(store, Some("admintok".to_string())).unwrap());
    let (addr, handle) = serve_with_gov(gov).await;
    let client = reqwest::Client::new();
    let url = format!("http://{addr}/api/v1/admin/keys");

    // Typo'd period → 400, no key minted.
    for bad in ["weekly", "monthlly", "", "TOTAL"] {
        let resp = client
            .post(&url)
            .header("x-admin-token", "admintok")
            .json(&serde_json::json!({"name": "k", "budget_period": bad}))
            .send()
            .await
            .unwrap();
        assert_eq!(
            resp.status().as_u16(),
            400,
            "budget_period '{bad}' must be rejected with 400"
        );
        let body: serde_json::Value = resp.json().await.unwrap();
        assert!(
            body["error"]["message"]
                .as_str()
                .unwrap_or("")
                .contains("budget_period"),
            "400 body must name budget_period: {body}"
        );
        assert_eq!(
            body["error"]["code"],
            "invalid_request", // frozen v1 envelope: keys speak the SAME code enum (H1)
            "400 error code must be invalid_request: {body}"
        );
    }

    // Each valid period (and the omitted-default) creates the key with that exact period.
    for &good in super::VALID_BUDGET_PERIODS {
        let resp = client
            .post(&url)
            .header("x-admin-token", "admintok")
            .json(&serde_json::json!({"name": "k", "budget_period": good}))
            .send()
            .await
            .unwrap();
        assert_eq!(
            resp.status().as_u16(),
            201,
            "valid budget_period '{good}' must create the key"
        );
        let body: serde_json::Value = resp.json().await.unwrap();
        assert_eq!(
            body["budget_period"], good,
            "stored period must match request"
        );
    }

    // Omitted budget_period defaults to "total".
    let resp = client
        .post(&url)
        .header("x-admin-token", "admintok")
        .json(&serde_json::json!({"name": "k"}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), 201, "omitted period must default");
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(
        body["budget_period"],
        "total", // golden wire-contract literal (kept bare on purpose)
        "omitted period defaults to total"
    );

    handle.abort();
}

/// MED (no-raw-parse-error / secret-leak): a malformed admin create/update body must produce a
/// GENERIC 400 whose body contains NEITHER serde error prose NOR any fragment of the offending
/// input. The create-key body carries SECRETS (an AWS secret_access_key, the bearer being minted),
/// so axum's stock `Json<T>` rejection — which echoes the raw serde `Display` — must NOT be used.
#[tokio::test]
async fn test_admin_malformed_body_returns_generic_400_no_input_fragment() {
    crate::metrics::init();
    let store = Arc::new(MemoryStore::new());
    let gov = Arc::new(GovState::new(store, Some("admintok".to_string())).unwrap());
    let (addr, handle) = serve_with_gov(gov).await;
    let client = reqwest::Client::new();

    // A SECRET-bearing fragment that must NEVER be echoed back in the error body.
    let secret_fragment = "SUPER_SECRET_AWS_KEY_abc123";
    let malformed = format!(r#"{{"name": "k", "secret_access_key": "{secret_fragment}" "#);

    for path in ["/api/v1/admin/keys", "/api/v1/admin/keys/some-id"] {
        let req = if path == "/api/v1/admin/keys" {
            client.post(format!("http://{addr}{path}"))
        } else {
            client.patch(format!("http://{addr}{path}"))
        };
        let resp = req
            .header("x-admin-token", "admintok")
            .header("content-type", crate::proxy::APPLICATION_JSON)
            .body(malformed.clone())
            .send()
            .await
            .unwrap();
        assert_eq!(
            resp.status().as_u16(),
            400,
            "malformed body on {path} must be 400"
        );
        let text = resp.text().await.unwrap();
        assert!(
            !text.contains(secret_fragment),
            "the 400 body on {path} must NOT echo any input fragment; got {text}"
        );
        // The generic envelope only — no serde prose (e.g. "expected", "column", "EOF").
        assert!(
            !text.contains("expected")
                && !text.contains("column")
                && !text.contains("EOF")
                && !text.contains("line"),
            "the 400 body on {path} must NOT contain serde error text; got {text}"
        );
        let body: serde_json::Value = serde_json::from_str(&text).unwrap();
        assert_eq!(
            body["error"]["message"], "invalid JSON",
            "the 400 body on {path} must be the generic envelope; got {text}"
        );
        assert_eq!(
            body["error"]["code"],
            "invalid_request", // frozen v1 envelope: keys speak the SAME code enum (H1)
            "the 400 error code must be invalid_request; got {text}"
        );
    }

    handle.abort();
}

#[tokio::test]
async fn test_create_key_rejects_negative_max_budget_cents() {
    // Regression (HIGH/correctness): a negative `max_budget_cents` is a signed-i64 value serde
    // does NOT auto-reject (unlike the unsigned rpm/tpm limits). A negative cap makes governance
    // read a brand-new key (spend 0) as over budget from request one — a silent DoS. It must be
    // rejected with 400 and no key minted; `0` (a hard no-spend cap) and a positive value, and an
    // omitted field (unlimited), must all still create the key.
    crate::metrics::init();
    let store = Arc::new(MemoryStore::new());
    let gov = Arc::new(GovState::new(store, Some("admintok".to_string())).unwrap());
    let (addr, handle) = serve_with_gov(gov).await;
    let client = reqwest::Client::new();
    let url = format!("http://{addr}/api/v1/admin/keys");

    for bad in [-1_i64, -100, i64::MIN] {
        let resp = client
            .post(&url)
            .header("x-admin-token", "admintok")
            .json(&serde_json::json!({"name": "k", "max_budget_cents": bad}))
            .send()
            .await
            .unwrap();
        assert_eq!(
            resp.status().as_u16(),
            400,
            "negative max_budget_cents {bad} must be rejected with 400"
        );
        let body: serde_json::Value = resp.json().await.unwrap();
        assert!(
            body["error"]["message"]
                .as_str()
                .unwrap_or("")
                .contains("max_budget_cents"),
            "400 body must name max_budget_cents: {body}"
        );
    }

    // Zero (hard no-spend cap) and a positive value both create the key with that exact cap.
    for good in [0_i64, 1, 100_000] {
        let resp = client
            .post(&url)
            .header("x-admin-token", "admintok")
            .json(&serde_json::json!({"name": "k", "max_budget_cents": good}))
            .send()
            .await
            .unwrap();
        assert_eq!(
            resp.status().as_u16(),
            201,
            "non-negative max_budget_cents {good} must create the key"
        );
        let body: serde_json::Value = resp.json().await.unwrap();
        assert_eq!(
            body["max_budget_cents"], good,
            "stored cap must match request"
        );
    }

    // Omitted field → unlimited (null), still 201.
    let resp = client
        .post(&url)
        .header("x-admin-token", "admintok")
        .json(&serde_json::json!({"name": "k"}))
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp.status().as_u16(),
        201,
        "omitted budget must create key"
    );
    let body: serde_json::Value = resp.json().await.unwrap();
    assert!(
        body["max_budget_cents"].is_null(),
        "omitted budget is unlimited (null)"
    );

    handle.abort();
}

#[tokio::test]
async fn test_patch_key_enables_disables_and_validates_at_create_parity() {
    // #28: PATCH /admin/keys/:id can disable a key (without DELETE destroying its history) and
    // adjust caps; it is admin-gated and rejects the same invalid values create() does.
    crate::metrics::init();
    let store = Arc::new(MemoryStore::new());
    let gov = Arc::new(GovState::new(store, Some("admintok".to_string())).unwrap());
    let (addr, handle) = serve_with_gov(gov).await;
    let client = reqwest::Client::new();
    let base = format!("http://{addr}/api/v1/admin/keys");

    // Create a key to operate on.
    let created: serde_json::Value = client
        .post(&base)
        .header("x-admin-token", "admintok")
        .json(&serde_json::json!({"name": "k"}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let id = created["id"].as_str().unwrap().to_string();
    let key_url = format!("{base}/{id}");

    // Admin gate: PATCH without the admin token is rejected by the middleware (not 200).
    let no_tok = client
        .patch(&key_url)
        .json(&serde_json::json!({"enabled": false}))
        .send()
        .await
        .unwrap();
    assert_ne!(no_tok.status().as_u16(), 200, "PATCH must be admin-gated");

    // Disable the key → 200, enabled=false.
    let disabled = client
        .patch(&key_url)
        .header("x-admin-token", "admintok")
        .json(&serde_json::json!({"enabled": false}))
        .send()
        .await
        .unwrap();
    assert_eq!(disabled.status().as_u16(), 200);
    let body: serde_json::Value = disabled.json().await.unwrap();
    assert_eq!(body["enabled"], false, "key is disabled: {body}");

    // Create-parity validation: negative budget and zero rate caps are 400 via PATCH too.
    for bad in [
        serde_json::json!({"max_budget_cents": -1}),
        serde_json::json!({"rpm_limit": 0}),
        serde_json::json!({"tpm_limit": 0}),
    ] {
        let r = client
            .patch(&key_url)
            .header("x-admin-token", "admintok")
            .json(&bad)
            .send()
            .await
            .unwrap();
        assert_eq!(r.status().as_u16(), 400, "PATCH must reject {bad} with 400");
    }

    // PATCH a non-existent key → 404.
    let missing = client
        .patch(format!("{base}/vk_nope"))
        .header("x-admin-token", "admintok")
        .json(&serde_json::json!({"enabled": true}))
        .send()
        .await
        .unwrap();
    assert_eq!(missing.status().as_u16(), 404);

    handle.abort();
}

#[tokio::test]
async fn test_create_key_rejects_zero_rate_limits() {
    // Regression (LOW/bug): `rpm_limit`/`tpm_limit` are unsigned, so serde rejects a negative but
    // accepts `0`. A zero limit is NOT "unlimited" (that is the omitted/None case): governance
    // checks `requests >= rpm` / `tokens >= tpm` against a window starting at 0, so `0` makes the
    // key reject every request from creation — a permanently-dead key minted with 201 and no
    // diagnostic. Both fields must 400; a positive value, and omission (unlimited), must create it.
    crate::metrics::init();
    let store = Arc::new(MemoryStore::new());
    let gov = Arc::new(GovState::new(store, Some("admintok".to_string())).unwrap());
    let (addr, handle) = serve_with_gov(gov).await;
    let client = reqwest::Client::new();
    let url = format!("http://{addr}/api/v1/admin/keys");

    for field in ["rpm_limit", "tpm_limit"] {
        let resp = client
            .post(&url)
            .header("x-admin-token", "admintok")
            .json(&serde_json::json!({"name": "k", field: 0}))
            .send()
            .await
            .unwrap();
        assert_eq!(
            resp.status().as_u16(),
            400,
            "{field}: 0 must be rejected with 400"
        );
        let body: serde_json::Value = resp.json().await.unwrap();
        assert!(
            body["error"]["message"]
                .as_str()
                .unwrap_or("")
                .contains(field),
            "400 body must name {field}: {body}"
        );
    }

    // A positive limit on either field still creates the key.
    for field in ["rpm_limit", "tpm_limit"] {
        let resp = client
            .post(&url)
            .header("x-admin-token", "admintok")
            .json(&serde_json::json!({"name": "k", field: 5}))
            .send()
            .await
            .unwrap();
        assert_eq!(
            resp.status().as_u16(),
            201,
            "{field}: 5 must create the key"
        );
        let body: serde_json::Value = resp.json().await.unwrap();
        assert_eq!(body[field], 5, "stored {field} must match request");
    }

    // Omitted limits → unlimited (null), still 201.
    let resp = client
        .post(&url)
        .header("x-admin-token", "admintok")
        .json(&serde_json::json!({"name": "k"}))
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp.status().as_u16(),
        201,
        "omitted limits must create key"
    );
    let body: serde_json::Value = resp.json().await.unwrap();
    assert!(
        body["rpm_limit"].is_null() && body["tpm_limit"].is_null(),
        "omitted limits are unlimited (null): {body}"
    );

    handle.abort();
}

#[tokio::test]
async fn test_patch_key_clears_caps_to_unlimited_via_null() {
    // LOW #16/#19 (three-state): PATCH must distinguish absent (leave unchanged), JSON null
    // (clear to unlimited), and a value (set). A single Option<T> conflated absent with null, so a
    // cap could never be cleared once set. Verify the full matrix end-to-end through the handler.
    crate::metrics::init();
    let store = Arc::new(MemoryStore::new());
    let gov = Arc::new(GovState::new(store, Some("admintok".to_string())).unwrap());
    let (addr, handle) = serve_with_gov(gov).await;
    let client = reqwest::Client::new();
    let base = format!("http://{addr}/api/v1/admin/keys");

    // Create a key that HAS all three caps set.
    let created: serde_json::Value = client
        .post(&base)
        .header("x-admin-token", "admintok")
        .json(&serde_json::json!({
            "name": "k",
            "rpm_limit": 10,
            "tpm_limit": 2000,
            "max_budget_cents": 5000
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let id = created["id"].as_str().unwrap().to_string();
    assert_eq!(created["rpm_limit"], 10);
    assert_eq!(created["tpm_limit"], 2000);
    assert_eq!(created["max_budget_cents"], 5000);
    let key_url = format!("{base}/{id}");

    // Present null CLEARS each cap to unlimited (null in the response).
    let cleared: serde_json::Value = client
        .patch(&key_url)
        .header("x-admin-token", "admintok")
        .json(&serde_json::json!({
            "rpm_limit": null,
            "tpm_limit": null,
            "max_budget_cents": null
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert!(
        cleared["rpm_limit"].is_null(),
        "rpm cleared to unlimited: {cleared}"
    );
    assert!(cleared["tpm_limit"].is_null(), "tpm cleared to unlimited");
    assert!(
        cleared["max_budget_cents"].is_null(),
        "budget cleared to unlimited"
    );

    // Re-set them with values.
    let reset: serde_json::Value = client
        .patch(&key_url)
        .header("x-admin-token", "admintok")
        .json(&serde_json::json!({
            "rpm_limit": 7,
            "tpm_limit": 99,
            "max_budget_cents": 123
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(reset["rpm_limit"], 7);
    assert_eq!(reset["tpm_limit"], 99);
    assert_eq!(reset["max_budget_cents"], 123);

    // Absent fields LEAVE the caps unchanged (only `enabled` present here).
    let unchanged: serde_json::Value = client
        .patch(&key_url)
        .header("x-admin-token", "admintok")
        .json(&serde_json::json!({"enabled": false}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(unchanged["enabled"], false);
    assert_eq!(unchanged["rpm_limit"], 7, "absent leaves rpm unchanged");
    assert_eq!(unchanged["tpm_limit"], 99, "absent leaves tpm unchanged");
    assert_eq!(
        unchanged["max_budget_cents"], 123,
        "absent leaves budget unchanged"
    );

    // Clearing to unlimited (null) must NOT trip the create-parity guards (those reject a present
    // 0/negative VALUE, not a clear). null on rpm/tpm/budget all return 200.
    let cleared2 = client
        .patch(&key_url)
        .header("x-admin-token", "admintok")
        .json(&serde_json::json!({"rpm_limit": null, "max_budget_cents": null}))
        .send()
        .await
        .unwrap();
    assert_eq!(
        cleared2.status().as_u16(),
        200,
        "null (clear) must not be rejected by the create-parity guards"
    );

    handle.abort();
}

#[test]
fn test_create_key_warns_on_unconfigured_allowed_pool() {
    // Regression (LOW #13, completeness): create_key accepted `allowed_pools` with NO ingress
    // diagnostic, unlike its sibling validations. An entry naming no configured pool must NOT be
    // a 400 (minting a key before its pool exists is a supported forward-reference workflow), but
    // it MUST surface a NON-FATAL `tracing::warn!` so a typo (`"smrt"` for `"smart"`) is visible.
    // Against the old code (no warn) the unknown-pool assertion FAILS; it passes once the
    // diagnostic is emitted. We also assert the key is still created (201) and that a configured
    // pool produces NO warning (no false positive on the legitimate path).
    //
    // The diagnostic fires synchronously in the handler BEFORE the `spawn_blocking().await`, so a
    // thread-local subscriber (`with_default`) on a current-thread runtime captures it — we call
    // the handler directly rather than through the HTTP server (whose task would run on a
    // different thread, out of the subscriber's reach).
    use tracing_subscriber::layer::SubscriberExt as _;

    crate::metrics::init();
    let store = Arc::new(MemoryStore::new());
    let gov = Arc::new(GovState::new(store, Some("admintok".to_string())).unwrap());
    // App has exactly one configured pool, "smart" (lane 0). "smrt" is the typo'd sibling.
    let app = TestApp::new()
        .lane(crate::test_support::LaneSpec::new(
            "m",
            crate::proto::Protocol::anthropic(),
            "http://127.0.0.1:0",
        ))
        .pool("smart", &[(0, 1)])
        .governance(gov)
        .build();

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let cap = WarnCapture::default();
    let subscriber = tracing_subscriber::registry().with(cap.clone());

    let (unknown_status, known_status) = tracing::subscriber::with_default(subscriber, || {
        rt.block_on(async {
            // Request 1: references "smart" (configured, OK) AND "smrt" (typo, no such pool).
            let body1 = axum::body::Bytes::from(
                serde_json::json!({
                    "name": "k-typo",
                    "allowed_pools": ["smart", "smrt"]
                })
                .to_string(),
            );
            let r1 = super::create_key(
                crate::state::CurrentApp(app.clone()),
                axum::Extension(crate::auth::AuthPrincipal(None)),
                axum::http::HeaderMap::new(),
                body1,
            )
            .await;
            let s1 = r1.status().as_u16();

            // Request 2: references ONLY the configured pool — no warning expected.
            let body2 = axum::body::Bytes::from(
                serde_json::json!({
                    "name": "k-ok",
                    "allowed_pools": ["smart"]
                })
                .to_string(),
            );
            let r2 = super::create_key(
                crate::state::CurrentApp(app),
                axum::Extension(crate::auth::AuthPrincipal(None)),
                axum::http::HeaderMap::new(),
                body2,
            )
            .await;
            let s2 = r2.status().as_u16();
            (s1, s2)
        })
    });

    // Both keys are still created — the diagnostic is non-fatal (forward-reference preserved).
    assert_eq!(
        unknown_status, 201,
        "an unconfigured allowed_pool must NOT 400 — the key is still minted"
    );
    assert_eq!(
        known_status, 201,
        "a configured allowed_pool creates the key"
    );

    let msgs = cap.0.lock().unwrap();
    // Exactly one warning, naming the typo'd pool — "smart" (configured) must NOT warn.
    let pool_warns: Vec<&String> = msgs
        .iter()
        .filter(|m| m.contains("allowed_pools entry names no configured pool"))
        .collect();
    assert_eq!(
        pool_warns.len(),
        1,
        "exactly one allowed_pools diagnostic expected (only the typo'd entry): {msgs:?}"
    );
    assert!(
        pool_warns[0].contains("smrt"),
        "the warning must name the typo'd pool 'smrt': {:?}",
        pool_warns[0]
    );
    assert!(
        !pool_warns[0].contains("smart\""),
        "the configured pool 'smart' must NOT be reported as unconfigured: {:?}",
        pool_warns[0]
    );
}

#[tokio::test]
async fn test_delete_existing_key_returns_200() {
    crate::metrics::init();
    let store = Arc::new(MemoryStore::new());
    let gov = Arc::new(GovState::new(store, Some("admintok".to_string())).unwrap());
    let (key, _secret) = gov
        .create_key(
            NewKeySpec {
                name: "k".to_string(),
                allowed_pools: vec![],
                max_budget_cents: None,
                budget_period: super::VALID_BUDGET_PERIODS[0].to_string(),
                rpm_limit: None,
                tpm_limit: None,
                budget_group: None,
                labels: Default::default(),
            },
            0,
        )
        .unwrap();

    let (addr, handle) = serve_with_gov(gov).await;
    let client = reqwest::Client::new();
    let resp = client
        .delete(format!("http://{addr}/api/v1/admin/keys/{}", key.id))
        .header("x-admin-token", "admintok")
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp.status().as_u16(),
        204,
        "existing key deletes with 204 No Content (H4)"
    );
    handle.abort();
}

#[tokio::test]
async fn test_delete_missing_key_returns_404() {
    crate::metrics::init();
    let store = Arc::new(MemoryStore::new());
    let gov = Arc::new(GovState::new(store, Some("admintok".to_string())).unwrap());

    let (addr, handle) = serve_with_gov(gov).await;
    let client = reqwest::Client::new();
    let resp = client
        .delete(format!("http://{addr}/api/v1/admin/keys/vk_does_not_exist"))
        .header("x-admin-token", "admintok")
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp.status().as_u16(),
        404,
        "deleting a non-existent key must 404, not a spurious 200"
    );
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["error"]["message"], "key not found");
    assert_eq!(body["error"]["code"], "not_found"); // frozen v1 envelope: keys speak the SAME code enum (H1)
    handle.abort();
}

#[tokio::test]
async fn test_delete_key_is_not_idempotent_204() {
    // After a successful delete, a second delete of the same id must 404 (proves the 204 was a
    // real revocation, not a no-op masquerading as success).
    crate::metrics::init();
    let store = Arc::new(MemoryStore::new());
    let gov = Arc::new(GovState::new(store, Some("admintok".to_string())).unwrap());
    let (key, _secret) = gov
        .create_key(
            NewKeySpec {
                name: "k".to_string(),
                allowed_pools: vec![],
                max_budget_cents: None,
                budget_period: super::VALID_BUDGET_PERIODS[0].to_string(),
                rpm_limit: None,
                tpm_limit: None,
                budget_group: None,
                labels: Default::default(),
            },
            0,
        )
        .unwrap();
    let (addr, handle) = serve_with_gov(gov).await;
    let client = reqwest::Client::new();
    let url = format!("http://{addr}/api/v1/admin/keys/{}", key.id);
    let first = client
        .delete(&url)
        .header("x-admin-token", "admintok")
        .send()
        .await
        .unwrap();
    assert_eq!(first.status().as_u16(), 204);
    let second = client
        .delete(&url)
        .header("x-admin-token", "admintok")
        .send()
        .await
        .unwrap();
    assert_eq!(second.status().as_u16(), 404, "second delete must 404");
    handle.abort();
}

#[tokio::test]
async fn test_concurrent_delete_returns_exactly_one_204() {
    // Regression (MEDIUM/correctness, TOCTOU): two concurrent DELETEs of the SAME id must not
    // both observe the key and both return 204 (which would imply two revocations of one row in
    // an audit trail). The delete handler serializes its lookup→delete critical section, so the
    // winner returns 204 and every loser returns 404. Fire a burst and assert exactly one 204.
    crate::metrics::init();
    let store = Arc::new(MemoryStore::new());
    let gov = Arc::new(GovState::new(store, Some("admintok".to_string())).unwrap());
    let (key, _secret) = gov
        .create_key(
            NewKeySpec {
                name: "k".to_string(),
                allowed_pools: vec![],
                max_budget_cents: None,
                budget_period: super::VALID_BUDGET_PERIODS[0].to_string(),
                rpm_limit: None,
                tpm_limit: None,
                budget_group: None,
                labels: Default::default(),
            },
            0,
        )
        .unwrap();
    let (addr, handle) = serve_with_gov(gov).await;
    let url = format!("http://{addr}/api/v1/admin/keys/{}", key.id);

    // Launch several DELETEs concurrently against the single freshly-created key.
    let mut tasks = Vec::new();
    for _ in 0..8 {
        let url = url.clone();
        tasks.push(tokio::spawn(async move {
            let client = reqwest::Client::new();
            client
                .delete(&url)
                .header("x-admin-token", "admintok")
                .send()
                .await
                .unwrap()
                .status()
                .as_u16()
        }));
    }
    let mut ok = 0;
    let mut not_found = 0;
    for t in tasks {
        match t.await.unwrap() {
            204 => ok += 1,
            404 => not_found += 1,
            other => panic!("unexpected status {other} from concurrent delete"),
        }
    }
    assert_eq!(
        ok, 1,
        "exactly one concurrent delete must report a 204 revocation"
    );
    assert_eq!(
        not_found, 7,
        "every losing concurrent delete must report 404"
    );
    handle.abort();
}

#[tokio::test]
async fn test_patch_after_delete_404s_and_does_not_recreate_key() {
    // Regression (MEDIUM #7, SECURITY): a PATCH must never RESURRECT a key a DELETE removed. The
    // store's `update_key` is a check-then-act (`get_key` → `put_key`, where `put_key` UPSERTs and
    // so re-INSERTs a missing row). Serializing `update_key`'s lookup→put behind the same gate as
    // DELETE closes the window. This sequential case (DELETE fully precedes PATCH) proves the base
    // contract: PATCH on a deleted key 404s and leaves it deleted (a later GET/usage stays 404).
    crate::metrics::init();
    let store = Arc::new(MemoryStore::new());
    let gov = Arc::new(GovState::new(store, Some("admintok".to_string())).unwrap());
    let (key, _secret) = gov
        .create_key(
            NewKeySpec {
                name: "k".to_string(),
                allowed_pools: vec![],
                max_budget_cents: None,
                budget_period: super::VALID_BUDGET_PERIODS[0].to_string(),
                rpm_limit: None,
                tpm_limit: None,
                budget_group: None,
                labels: Default::default(),
            },
            0,
        )
        .unwrap();
    let (addr, handle) = serve_with_gov(gov).await;
    let client = reqwest::Client::new();
    let key_url = format!("http://{addr}/api/v1/admin/keys/{}", key.id);

    // Revoke the key.
    let del = client
        .delete(&key_url)
        .header("x-admin-token", "admintok")
        .send()
        .await
        .unwrap();
    assert_eq!(del.status().as_u16(), 204, "the key is revoked");

    // PATCH the now-deleted key → 404, and it must NOT recreate the row.
    let patched = client
        .patch(&key_url)
        .header("x-admin-token", "admintok")
        .json(&serde_json::json!({"enabled": true}))
        .send()
        .await
        .unwrap();
    assert_eq!(
        patched.status().as_u16(),
        404,
        "PATCH on a deleted key must 404, not resurrect it"
    );

    // The key must still be gone: usage 404s and the list is empty.
    let usage = client
        .get(format!("{key_url}/usage"))
        .header("x-admin-token", "admintok")
        .send()
        .await
        .unwrap();
    assert_eq!(
        usage.status().as_u16(),
        404,
        "the revoked key must remain absent after the PATCH"
    );
    let listed: serde_json::Value = client
        .get(format!("http://{addr}/api/v1/admin/keys"))
        .header("x-admin-token", "admintok")
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(
        listed["items"].as_array().unwrap().len(),
        0,
        "PATCH must not have re-inserted the deleted key: {listed}"
    );
    handle.abort();
}

/// A `Store` decorator that can pause inside `put_key` to force the exact PATCH/DELETE
/// interleaving the resurrection race needs — something a black-box HTTP burst cannot do
/// deterministically (the window between `update_key`'s `get_key` and `put_key` is microscopic).
/// All methods delegate to an inner `MemoryStore`; only `put_key` is instrumented, and only once
/// armed (so the create-time `put_key` during setup is unaffected).
///
/// When armed, the FIRST subsequent `put_key` (the PATCH's) signals `entered` and then BLOCKS on
/// `release` until the test lets it proceed. This pins the PATCH between its existence check and
/// its write, so the test can run a DELETE in that gap and observe whether the gate prevents the
/// PATCH from re-inserting (resurrecting) the just-revoked row.
struct BarrierStore {
    inner: MemoryStore,
    armed: std::sync::atomic::AtomicBool,
    entered: std::sync::mpsc::SyncSender<()>,
    release: std::sync::Mutex<std::sync::mpsc::Receiver<()>>,
}

impl crate::governance::Store for BarrierStore {
    fn put_key(&self, key: &crate::governance::VirtualKey) -> crate::governance::StoreResult<()> {
        // Disarm atomically so only the first put after arming pauses (and never the setup put).
        if self.armed.swap(false, std::sync::atomic::Ordering::SeqCst) {
            let _ = self.entered.send(());
            // Block this blocking-pool thread until the test releases us, AFTER it has run a DELETE.
            let _ = self.release.lock().unwrap().recv();
        }
        self.inner.put_key(key)
    }
    fn get_key(
        &self,
        id: &str,
    ) -> crate::governance::StoreResult<Option<crate::governance::VirtualKey>> {
        self.inner.get_key(id)
    }
    fn list_keys(&self) -> crate::governance::StoreResult<Vec<crate::governance::VirtualKey>> {
        self.inner.list_keys()
    }
    fn delete_key(&self, id: &str) -> crate::governance::StoreResult<()> {
        self.inner.delete_key(id)
    }
    fn get_usage(
        &self,
        bucket_id: &str,
        window_start: u64,
    ) -> crate::governance::StoreResult<busbar_api::UsageLedger> {
        self.inner.get_usage(bucket_id, window_start)
    }
    fn put_usage(
        &self,
        bucket_id: &str,
        window_start: u64,
        ledger: &busbar_api::UsageLedger,
    ) -> crate::governance::StoreResult<()> {
        self.inner.put_usage(bucket_id, window_start, ledger)
    }
    fn add_metering(
        &self,
        delta: &crate::governance::MeteringDelta,
    ) -> crate::governance::StoreResult<()> {
        self.inner.add_metering(delta)
    }
    fn list_metering(
        &self,
        bucket: u64,
    ) -> crate::governance::StoreResult<Vec<crate::governance::MeteringRow>> {
        self.inner.list_metering(bucket)
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_patch_interleaved_with_delete_never_resurrects_key() {
    // Regression (MEDIUM #7, SECURITY — the precise interleaving the gate exists to stop): a PATCH
    // that has already read an extant key, then is overtaken by a DELETE that revokes it, must NOT
    // have its `put_key` re-INSERT (resurrect) the row. We force the interleaving deterministically
    // with `BarrierStore`: the PATCH's `put_key` pauses between the existence check and the write
    // while the DELETE runs.
    //
    // Old code (PATCH not under the gate): the DELETE proceeds while the PATCH is paused, removes
    // the row, returns 200; then the PATCH's UPSERT re-inserts it -> key PRESENT -> this test's
    // final "key absent" assertion FAILS.
    //
    // Fixed code (PATCH holds the same `EXISTENCE_GATE` across lookup→put): the DELETE blocks on
    // the gate until the PATCH releases it, so it runs strictly AFTER the PATCH's put -> the row is
    // removed last -> key ABSENT -> this test PASSES.
    crate::metrics::init();
    let (entered_tx, entered_rx) = std::sync::mpsc::sync_channel::<()>(1);
    let (release_tx, release_rx) = std::sync::mpsc::channel::<()>();
    let store = Arc::new(BarrierStore {
        inner: MemoryStore::new(),
        armed: std::sync::atomic::AtomicBool::new(false),
        entered: entered_tx,
        release: std::sync::Mutex::new(release_rx),
    });
    let gov = Arc::new(GovState::new(store.clone(), Some("admintok".to_string())).unwrap());
    let (key, _secret) = gov
        .create_key(
            NewKeySpec {
                name: "k".to_string(),
                allowed_pools: vec![],
                max_budget_cents: None,
                budget_period: super::VALID_BUDGET_PERIODS[0].to_string(),
                rpm_limit: None,
                tpm_limit: None,
                budget_group: None,
                labels: Default::default(),
            },
            0,
        )
        .unwrap();
    let (addr, handle) = serve_with_gov(gov).await;
    let key_url = format!("http://{addr}/api/v1/admin/keys/{}", key.id);

    // Arm the barrier so the PATCH's put_key (the next put) pauses mid-update.
    store.armed.store(true, std::sync::atomic::Ordering::SeqCst);

    // PATCH in the background — it will read the key, then block inside put_key.
    let patch_url = key_url.clone();
    let patch_task = tokio::spawn(async move {
        reqwest::Client::new()
            .patch(&patch_url)
            .header("x-admin-token", "admintok")
            .json(&serde_json::json!({"enabled": false}))
            .send()
            .await
            .unwrap()
            .status()
            .as_u16()
    });

    // Wait until the PATCH is parked inside put_key (between its check and its write).
    tokio::task::spawn_blocking(move || entered_rx.recv())
        .await
        .unwrap()
        .expect("PATCH must reach the instrumented put_key");

    // DELETE in the background. Old code: it completes now. Fixed code: it blocks on EXISTENCE_GATE.
    let delete_url = key_url.clone();
    let delete_task = tokio::spawn(async move {
        reqwest::Client::new()
            .delete(&delete_url)
            .header("x-admin-token", "admintok")
            .send()
            .await
            .unwrap()
            .status()
            .as_u16()
    });

    // Give the DELETE a moment to either complete (old) or wedge on the gate (fixed), then release
    // the paused PATCH so both can finish.
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    release_tx.send(()).unwrap();
    let _ = patch_task.await.unwrap();
    let _ = delete_task.await.unwrap();

    // DECISIVE: regardless of the order the two requests reported, the revoked key must be GONE.
    // A resurrecting PATCH (old code) leaves it PRESENT here.
    let listed: serde_json::Value = reqwest::Client::new()
        .get(format!("http://{addr}/api/v1/admin/keys"))
        .header("x-admin-token", "admintok")
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(
        listed["items"].as_array().unwrap().len(),
        0,
        "a PATCH must never resurrect a key a concurrent DELETE revoked: {listed}"
    );
    handle.abort();
}

/// REGRESSION (audit c1r6, SECURITY): `rotate_key` is a check-then-act (get_key → mint →
/// put_key over the UPSERT), so — exactly like update_key/delete_key — it must hold
/// EXISTENCE_GATE across lookup→write. Without it a DELETE that revokes the key between rotate's
/// read and its `put_key` is clobbered by the put, RESURRECTING the revoked key with a fresh
/// (attacker-usable) secret. Same deterministic `BarrierStore` interleaving as the PATCH test.
#[tokio::test]
async fn test_rotate_interleaved_with_delete_never_resurrects_key() {
    crate::metrics::init();
    let (entered_tx, entered_rx) = std::sync::mpsc::sync_channel::<()>(1);
    let (release_tx, release_rx) = std::sync::mpsc::channel::<()>();
    let store = Arc::new(BarrierStore {
        inner: MemoryStore::new(),
        armed: std::sync::atomic::AtomicBool::new(false),
        entered: entered_tx,
        release: std::sync::Mutex::new(release_rx),
    });
    let gov = Arc::new(GovState::new(store.clone(), Some("admintok".to_string())).unwrap());
    let (key, _secret) = gov
        .create_key(
            NewKeySpec {
                name: "k".to_string(),
                allowed_pools: vec![],
                max_budget_cents: None,
                budget_period: super::VALID_BUDGET_PERIODS[0].to_string(),
                rpm_limit: None,
                tpm_limit: None,
                budget_group: None,
                labels: Default::default(),
            },
            0,
        )
        .unwrap();
    let (addr, handle) = serve_with_gov(gov).await;

    // Arm the barrier so rotate's put_key (the next put) pauses between its check and its write.
    store.armed.store(true, std::sync::atomic::Ordering::SeqCst);

    let rotate_url = format!("http://{addr}/api/v1/admin/keys/{}/rotate", key.id);
    let rotate_task = tokio::spawn(async move {
        reqwest::Client::new()
            .post(&rotate_url)
            .header("x-admin-token", "admintok")
            .send()
            .await
            .unwrap()
            .status()
            .as_u16()
    });

    // Wait until rotate is parked inside put_key.
    tokio::task::spawn_blocking(move || entered_rx.recv())
        .await
        .unwrap()
        .expect("ROTATE must reach the instrumented put_key");

    let delete_url = format!("http://{addr}/api/v1/admin/keys/{}", key.id);
    let delete_task = tokio::spawn(async move {
        reqwest::Client::new()
            .delete(&delete_url)
            .header("x-admin-token", "admintok")
            .send()
            .await
            .unwrap()
            .status()
            .as_u16()
    });

    tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    release_tx.send(()).unwrap();
    let _ = rotate_task.await.unwrap();
    let _ = delete_task.await.unwrap();

    // DECISIVE: the revoked key must be GONE. A resurrecting rotate (ungated) leaves it PRESENT.
    let listed: serde_json::Value = reqwest::Client::new()
        .get(format!("http://{addr}/api/v1/admin/keys"))
        .header("x-admin-token", "admintok")
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(
        listed["items"].as_array().unwrap().len(),
        0,
        "rotate must never resurrect a key a concurrent DELETE revoked: {listed}"
    );
    handle.abort();
}

#[test]
fn test_existence_gate_is_std_sync_mutex_lockable_without_runtime() {
    // Regression (MEDIUM #6, R26 — CONTINUES the R25 existence-race fix): the gate MUST be a
    // `std::sync::Mutex<()>`, not a `tokio::sync::Mutex<()>`. The fix binds the gate's lifetime to
    // the SYNCHRONOUS store mutation by locking it INSIDE the `spawn_blocking` closure (which has no
    // async runtime in scope); a `tokio::sync::Mutex` cannot be locked there — its `.lock()` returns
    // a future. This test locks the gate from a PLAIN (non-async) thread with no Tokio runtime
    // present: that only compiles/runs for a `std::sync::Mutex`. Against the old `tokio::sync::Mutex`
    // this call would not typecheck as a blocking lock (and `into_inner` on poison is std-only), so
    // the gate-type regression is pinned. We assert the guarded unit value round-trips.
    let guard = super::EXISTENCE_GATE
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    // The guarded data is the unit type; dereferencing proves we hold a std MutexGuard<()>.
    let () = *guard;
    drop(guard);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_cancelled_patch_keeps_gate_held_for_full_store_mutation() {
    // Regression (MEDIUM #6, R26 — request-cancellation voids the existence gate): the R25 fix held
    // the gate across the cancellable outer `.await`. If the client dropped the request, the async
    // guard dropped — but the already-scheduled (uncancellable) `spawn_blocking` closure kept
    // running its lookup→write with the gate NO LONGER held, re-opening the resurrection /
    // double-revoke races. The R26 fix locks the gate INSIDE the blocking closure, so the gate is
    // held for the entire lookup→write regardless of any outer-future drop.
    //
    // We force the exact condition with `BarrierStore`: a PATCH parks inside `put_key` (between its
    // existence check and its write). We then DROP (cancel) the PATCH's driving future while it is
    // parked, and fire a DELETE. The DELETE must NOT be able to complete while the PATCH's blocking
    // mutation is still in flight:
    //   - Old code (async guard owned by the dropped PATCH future): cancelling releases the gate, so
    //     the DELETE acquires it and COMPLETES within the window -> this test's "DELETE still
    //     pending" assertion FAILS.
    //   - Fixed code (gate locked inside the still-running blocking closure): the DELETE blocks on
    //     the gate until the PATCH's `put_key` finishes -> the DELETE is STILL PENDING in the
    //     window -> this test PASSES. Releasing the barrier then lets both drain.
    crate::metrics::init();
    let (entered_tx, entered_rx) = std::sync::mpsc::sync_channel::<()>(1);
    let (release_tx, release_rx) = std::sync::mpsc::channel::<()>();
    let store = Arc::new(BarrierStore {
        inner: MemoryStore::new(),
        armed: std::sync::atomic::AtomicBool::new(false),
        entered: entered_tx,
        release: std::sync::Mutex::new(release_rx),
    });
    let gov = Arc::new(GovState::new(store.clone(), Some("admintok".to_string())).unwrap());
    let (key, _secret) = gov
        .create_key(
            NewKeySpec {
                name: "k".to_string(),
                allowed_pools: vec![],
                max_budget_cents: None,
                budget_period: super::VALID_BUDGET_PERIODS[0].to_string(),
                rpm_limit: None,
                tpm_limit: None,
                budget_group: None,
                labels: Default::default(),
            },
            0,
        )
        .unwrap();
    let (addr, handle) = serve_with_gov(gov).await;
    let key_url = format!("http://{addr}/api/v1/admin/keys/{}", key.id);

    // Arm the barrier so the PATCH's put_key (the next put) pauses mid-update.
    store.armed.store(true, std::sync::atomic::Ordering::SeqCst);

    // PATCH in the background — it will read the key, acquire the gate inside the blocking closure,
    // then block inside put_key. We keep the JoinHandle so we can ABORT (cancel) it.
    let patch_url = key_url.clone();
    let patch_task = tokio::spawn(async move {
        let _ = reqwest::Client::new()
            .patch(&patch_url)
            .header("x-admin-token", "admintok")
            .json(&serde_json::json!({"enabled": false}))
            .send()
            .await;
    });

    // Wait until the PATCH is parked inside put_key (gate held by the blocking closure).
    tokio::task::spawn_blocking(move || entered_rx.recv())
        .await
        .unwrap()
        .expect("PATCH must reach the instrumented put_key");

    // CANCEL the PATCH: abort its driving future. The Tokio JoinHandle abort drops the async task;
    // in the old design this dropped the async existence guard. The blocking closure keeps running.
    patch_task.abort();
    let _ = patch_task.await; // joins the cancellation

    // Fire a DELETE. Old code: gate is free -> DELETE completes quickly. Fixed code: gate is still
    // held by the parked blocking closure -> DELETE blocks.
    let delete_url = key_url.clone();
    let delete_task = tokio::spawn(async move {
        reqwest::Client::new()
            .delete(&delete_url)
            .header("x-admin-token", "admintok")
            .send()
            .await
            .unwrap()
            .status()
            .as_u16()
    });

    // Give the DELETE time to either complete (old) or wedge on the gate (fixed).
    tokio::time::sleep(std::time::Duration::from_millis(300)).await;
    assert!(
        !delete_task.is_finished(),
        "a cancelled PATCH must keep the EXISTENCE_GATE held for its full blocking mutation; the \
             DELETE must remain blocked on the gate (old async-guard code releases it on cancel)"
    );

    // Release the parked PATCH put_key so the gate frees and the DELETE can finish — proves no
    // deadlock and lets the task drain cleanly.
    release_tx.send(()).unwrap();
    let del_status = delete_task.await.unwrap();
    // The PATCH's put_key resurrected/updated the row (it ran to completion despite cancellation),
    // so the DELETE that follows under the gate observes it and revokes it: 204. (The point of this
    // test is the BLOCKING, not the final status — but it must be a coherent 204, not a 404.)
    assert_eq!(
        del_status, 204,
        "the DELETE runs after the gate frees and revokes the (now-present) key"
    );
    handle.abort();
}

// ── plugin admin endpoints (#13), end-to-end over the live router ─────────────────────────────────

/// Serve a router whose App points its plugin surface at `dir` (allow_unsigned posture, no
/// publishers), with a known admin token — for the install/list/remove/reload plugin endpoints.
async fn serve_with_plugins_dir(
    dir: std::path::PathBuf,
) -> (std::net::SocketAddr, tokio::task::JoinHandle<()>) {
    let store = Arc::new(MemoryStore::new());
    let gov = Arc::new(GovState::new(store, Some("admintok".to_string())).unwrap());
    // The lifecycle test installs an UNSIGNED plugin tarball, so opt in to unsigned plugins (the
    // trust DEFAULT rejects unsigned artifacts). The trust-default behavior itself is covered by
    // the dedicated trust tests; this test is about the install/list/reload/remove lifecycle.
    let mut plugins_cfg = crate::config::PluginsCfg::default();
    plugins_cfg.trust.allow_unsigned = true;
    let app = TestApp::new()
        .governance(gov)
        .plugins_dir(dir)
        .plugins_cfg(plugins_cfg)
        .build();
    let (router, _handle) = crate::build_router_with_limits(
        app,
        256 * 1024 * 1024,
        0,
        crate::config::DEFAULT_EMIT_SERVER_TIMING,
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    (addr, handle)
}

/// Build an UNSIGNED (structurally valid) plugin tarball in memory for the HTTP lifecycle tests.
fn admin_test_tarball(name: &str, alias: &str) -> Vec<u8> {
    let lib = b"junk library bytes (never dlopened by the admin surface)";
    let m = busbar_plugin_sign::Manifest {
        name: name.into(),
        alias: alias.into(),
        kind: "store".into(),
        version: "1.0.0".into(),
        publisher: "acme".into(),
        abi_version: *busbar_plugin_loader::supported_abi("store")
            .iter()
            .max()
            .expect("store abi"),
        sha256: busbar_plugin_sign::sha256_hex(lib),
        signature: String::new(),
        description: String::new(),
        homepage: String::new(),
        license: String::new(),
    };
    busbar_plugin_loader::tarball::package(&m, "lib.so", lib).unwrap()
}

/// FULL LIFECYCLE over the wire: `POST /plugins` installs an (unsigned, allow_unsigned-posture)
/// plugin tarball → `GET /plugins?type=store` lists it as a dynamic-library row → `POST
/// /plugins/reload` reports it → `DELETE /plugins/{file}` removes it (204) → a second DELETE is
/// 404. Every mutation is admin-token guarded and audited; the uploaded code is never executed.
#[tokio::test]
async fn test_admin_v1_plugin_install_list_reload_remove() {
    use base64::Engine as _;
    crate::metrics::init();
    let tarball = admin_test_tarball("acme-store-junk", "junkstore");
    let file = "acme-store-junk.tar.gz";
    let dir =
        std::env::temp_dir().join(format!("busbar-admin-plugins-http-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let (addr, handle) = serve_with_plugins_dir(dir.clone()).await;
    let client = reqwest::Client::new();

    // INSTALL — 201 with a trust verdict of "unverified" (unsigned under allow_unsigned).
    let body = serde_json::json!({
        "file": file,
        "tarball_b64": base64::engine::general_purpose::STANDARD.encode(&tarball),
    });
    let resp = client
        .post(format!("http://{addr}/api/v1/admin/plugins"))
        .header("x-admin-token", "admintok")
        .json(&body)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), 201, "install returns 201 Created");
    let v: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(v["file"], file);
    assert_eq!(v["trust"], "unverified");
    assert_eq!(
        v["name"], "acme-store-junk",
        "identity from the signed manifest"
    );
    assert!(dir.join(file).exists(), "tarball published to disk");

    // A mutation WITHOUT the admin token is rejected (401) — the whole surface is guarded.
    let unauth = client
        .post(format!("http://{addr}/api/v1/admin/plugins"))
        .json(&body)
        .send()
        .await
        .unwrap();
    assert_eq!(unauth.status().as_u16(), 401);

    // LIST — the store catalog reports the memory head + our dynamic plugin (ready).
    let list: serde_json::Value = client
        .get(format!("http://{addr}/api/v1/admin/plugins?type=store"))
        .header("x-admin-token", "admintok")
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let items = list["items"].as_array().unwrap();
    assert_eq!(items[0]["name"], "memory");
    let dyn_row = items
        .iter()
        .find(|p| p["loader"] == "dynamic-library")
        .expect("dynamic-library row present");
    assert_eq!(dyn_row["valid"], true);
    assert_eq!(dyn_row["target"], file);
    assert_eq!(dyn_row["name"], "acme-store-junk");

    // RELOAD — reports the reconciled dynamic set (no memory head).
    let reload: serde_json::Value = client
        .post(format!("http://{addr}/api/v1/admin/plugins/reload"))
        .header("x-admin-token", "admintok")
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(reload["plugins"].as_array().unwrap().len(), 1);

    // REMOVE — 204, then a second remove is 404 in the frozen envelope.
    let del = client
        .delete(format!("http://{addr}/api/v1/admin/plugins/{file}"))
        .header("x-admin-token", "admintok")
        .send()
        .await
        .unwrap();
    assert_eq!(del.status().as_u16(), 204);
    assert!(!dir.join(file).exists(), "tarball removed from disk");

    let del2 = client
        .delete(format!("http://{addr}/api/v1/admin/plugins/{file}"))
        .header("x-admin-token", "admintok")
        .send()
        .await
        .unwrap();
    assert_eq!(del2.status().as_u16(), 404);
    let b: serde_json::Value = del2.json().await.unwrap();
    assert_eq!(b["error"]["code"], "not_found");

    // The install + remove both left audit rows (every mutation is audited).
    let audit: serde_json::Value = client
        .get(format!("http://{addr}/api/v1/admin/audit"))
        .header("x-admin-token", "admintok")
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let actions: Vec<&str> = audit["items"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|e| e["action"].as_str())
        .collect();
    assert!(
        actions.contains(&"plugin.install"),
        "install audited: {actions:?}"
    );
    assert!(
        actions.contains(&"plugin.remove"),
        "remove audited: {actions:?}"
    );

    let _ = std::fs::remove_dir_all(&dir);
    handle.abort();
}

/// A malformed install body (bad base64) is a `400 invalid_request` in the frozen envelope, a
/// non-tarball upload is a `400`, and an UNSIGNED upload under the STRICT default posture is a
/// `409 conflict` (the trust gate cannot be bypassed by pushing over the API) — nothing is
/// published in any case, and the rejects are audited.
#[tokio::test]
async fn test_admin_v1_plugin_install_rejections() {
    use base64::Engine as _;
    crate::metrics::init();
    let dir = std::env::temp_dir().join(format!("busbar-admin-plugins-rej-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let (addr, handle) = serve_with_plugins_dir(dir.clone()).await;
    let client = reqwest::Client::new();

    // Bad base64.
    let bad = client
        .post(format!("http://{addr}/api/v1/admin/plugins"))
        .header("x-admin-token", "admintok")
        .json(&serde_json::json!({"file": "x.tar.gz", "tarball_b64": "!!!not base64!!!"}))
        .send()
        .await
        .unwrap();
    assert_eq!(bad.status().as_u16(), 400);
    let b: serde_json::Value = bad.json().await.unwrap();
    assert_eq!(b["error"]["code"], "invalid_request");

    // Valid base64 but not a plugin tarball → structural validation fails (400).
    let notplugin = client
        .post(format!("http://{addr}/api/v1/admin/plugins"))
        .header("x-admin-token", "admintok")
        .json(&serde_json::json!({
            "file": "nope.tar.gz",
            "tarball_b64": base64::engine::general_purpose::STANDARD.encode(b"not a tarball"),
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(notplugin.status().as_u16(), 400);
    assert_eq!(
        std::fs::read_dir(&dir).unwrap().count(),
        0,
        "nothing published"
    );

    // TRUST NO-BYPASS: a STRICT-posture server rejects an unsigned upload as 409 conflict.
    {
        let store = Arc::new(MemoryStore::new());
        let gov = Arc::new(GovState::new(store, Some("admintok".to_string())).unwrap());
        let strict_dir = std::env::temp_dir().join(format!(
            "busbar-admin-plugins-strict-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&strict_dir);
        std::fs::create_dir_all(&strict_dir).unwrap();
        let app = TestApp::new()
            .governance(gov)
            .plugins_dir(strict_dir.clone())
            .plugins_cfg(crate::config::PluginsCfg::default())
            .build();
        let (router, _h) = crate::build_router_with_limits(
            app,
            256 * 1024 * 1024,
            0,
            crate::config::DEFAULT_EMIT_SERVER_TIMING,
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let strict_addr = listener.local_addr().unwrap();
        let strict_handle =
            tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
        let tarball = admin_test_tarball("acme-store-x", "acmex");
        let resp = client
            .post(format!("http://{strict_addr}/api/v1/admin/plugins"))
            .header("x-admin-token", "admintok")
            .json(&serde_json::json!({
                "file": "x.tar.gz",
                "tarball_b64": base64::engine::general_purpose::STANDARD.encode(&tarball),
            }))
            .send()
            .await
            .unwrap();
        assert_eq!(
            resp.status().as_u16(),
            409,
            "the strict default posture rejects an unsigned upload over the API"
        );
        let b: serde_json::Value = resp.json().await.unwrap();
        assert_eq!(b["error"]["code"], "conflict");
        assert_eq!(
            std::fs::read_dir(&strict_dir).unwrap().count(),
            0,
            "nothing published on a trust rejection"
        );
        let _ = std::fs::remove_dir_all(&strict_dir);
        strict_handle.abort();
    }

    let _ = std::fs::remove_dir_all(&dir);
    handle.abort();
}

/// The 1.5.0 mint surface: `budget_group` + `labels` round-trip through create/list, a mint naming
/// a MISSING budget_group is a 400 that names the offender (fail-closed at the mint boundary), and
/// the key-usage read derives spend at the current cost model.
#[tokio::test]
#[allow(clippy::field_reassign_with_default)]
async fn test_create_key_budget_group_and_labels_roundtrip_and_missing_group_400() {
    crate::metrics::init();
    let store = Arc::new(MemoryStore::new());
    let gov = Arc::new(GovState::new(store, Some("admintok".to_string())).unwrap());
    // An App whose cost model KNOWS the "growth" group; "ghost" stays unconfigured.
    let cost = {
        #[allow(clippy::field_reassign_with_default)]
        let mut gcfg = crate::config::GovernanceCfg::default();
        gcfg.budget_groups = std::collections::BTreeMap::from([(
            "growth".to_string(),
            crate::config::BudgetGroupCfg {
                max_budget_cents: 1_000_000,
                budget_period: "monthly".to_string(),
                parent: None,
            },
        )]);
        crate::cost::CostModel::resolve_parts(&gcfg, &Default::default(), &Default::default())
    };
    let app = TestApp::new().governance(gov).cost(cost).build();
    let router = crate::build_router(app);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    let client = reqwest::Client::new();
    let url = format!("http://{addr}/api/v1/admin/keys");

    // A mint naming a MISSING group is a 400 naming the offender.
    let resp = client
        .post(&url)
        .header("x-admin-token", "admintok")
        .json(&serde_json::json!({"name": "k", "budget_group": "ghost"}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), 400);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert!(
        body["error"]["message"]
            .as_str()
            .unwrap_or("")
            .contains("budget_group 'ghost' does not exist"),
        "the 400 names the missing group: {body}"
    );

    // A mint binding a CONFIGURED group with labels succeeds and echoes both.
    let resp = client
        .post(&url)
        .header("x-admin-token", "admintok")
        .json(&serde_json::json!({
            "name": "grouped",
            "budget_group": "growth",
            "labels": {"team": "growth", "env": "prod"}
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), 201, "configured group mints");
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["budget_group"], "growth");
    assert_eq!(body["labels"]["env"], "prod");
    let id = body["id"].as_str().unwrap().to_string();

    // The list surface carries both fields too (metadata round-trip, never the secret).
    let list: serde_json::Value = client
        .get(&url)
        .header("x-admin-token", "admintok")
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let row = list["items"]
        .as_array()
        .unwrap()
        .iter()
        .find(|k| k["id"] == id.as_str())
        .expect("minted key listed");
    assert_eq!(row["budget_group"], "growth");
    assert_eq!(row["labels"]["team"], "growth");

    handle.abort();
}
