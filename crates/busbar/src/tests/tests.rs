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
                    let _ =
                        tokio::time::timeout(std::time::Duration::from_millis(300), barrier.wait())
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
        gates: Vec::new(),
        base_named: false,
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
    let resolved = resolve_model_context_max(&pools).expect("identical values must not conflict");
    assert_eq!(resolved.get("m"), Some(&Some(64_000)));
}

#[test]
fn test_resolve_model_context_max_conflict_is_loud() {
    // Two DIFFERENT explicit limits for the same model is an operator contradiction: fail loud
    // (deterministic error) rather than silently pick whichever pool iterated last.
    let mut pools = HashMap::new();
    pools.insert("a".to_string(), pool(vec![member("m", Some(128_000))]));
    pools.insert("b".to_string(), pool(vec![member("m", Some(32_000))]));
    let err =
        resolve_model_context_max(&pools).expect_err("conflicting context_max must be rejected");
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

/// INERT-KEYS BOOT GUARD (bypass-edge): a DURABLE store carrying keys with NO admin token is the
/// one state where a prior run's keys become silently unenforced (governance goes inert). The
/// banner fires EXACTLY there and nowhere else.
#[test]
fn test_inert_durable_keys_banner_fires_only_for_durable_keyed_no_token() {
    // The dangerous edge: durable store, keys present, no admin token → LOUD banner.
    let b = inert_durable_keys_banner(true, 3, false).expect("durable+keys+no-token must banner");
    assert!(
        b.contains("INERT") && b.contains("3 key") && b.contains("admin_token"),
        "banner must name the count and the fix; got: {b}"
    );

    // An admin token IS set → keys are enforced, no banner.
    assert!(
        inert_durable_keys_banner(true, 3, true).is_none(),
        "an admin token makes governance active — no inert-keys banner"
    );

    // Durable store but EMPTY (fresh durable deploy, no keys yet) → nothing to bypass, no banner.
    assert!(
        inert_durable_keys_banner(true, 0, false).is_none(),
        "an empty durable store has no keys to leave unenforced"
    );

    // A RAM (non-durable) store never persists keys across the admin-token removal that creates
    // this edge — even if it somehow reported keys, the banner is scoped to durable stores.
    assert!(
        inert_durable_keys_banner(false, 5, false).is_none(),
        "the inert-keys banner is scoped to durable stores"
    );
}

/// A MEMORY store can never REACH the inert-with-keys state in practice: keys are only minted
/// through the admin API, which is gated by the admin token — so a keyed engine implies an admin
/// token, and a RAM store starts empty every boot. This pins that invariant end-to-end: a fresh
/// `MemoryStore` reports zero keys, and its `admin_token_hash()` gate matches the token it was
/// constructed with. (The durable-store analogue is exercised by the router-level bypass test.)
#[test]
fn test_memory_store_cannot_reach_inert_with_keys() {
    use crate::governance::{GovState, MemoryStore};
    use std::sync::Arc;

    // No admin token → engine inert AND the store is empty (RAM starts fresh each boot). There is
    // no keyed-but-inert state to warn about: key_count is 0, so the banner is None regardless.
    let store = Arc::new(MemoryStore::new());
    let gov = GovState::new(store, 0, 0, None).unwrap();
    assert!(gov.admin_token_hash().is_none(), "no admin token → inert");
    let key_count = gov.all_keys().map(|k| k.len()).unwrap_or(0);
    assert_eq!(key_count, 0, "a fresh RAM store holds no keys");
    // store_is_durable = false for memory → banner is None even if key_count were nonzero.
    assert!(inert_durable_keys_banner(false, key_count, false).is_none());

    // With an admin token the same engine is active — the state a real minted-keys deploy is in.
    let store2 = Arc::new(MemoryStore::new());
    let gov2 = GovState::new(store2, 0, 0, Some("admintok".to_string())).unwrap();
    assert!(gov2.admin_token_hash().is_some(), "admin token → active");
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

/// SPLIT-LISTENER NO-DOUBLE-EXPOSURE: with a separate admin listener the admin surface must live
/// ONLY on the admin router. `build_split_routers_with_limits` must yield an admin router that
/// serves `/api/v1/admin/*` and a data router that does NOT — even for a request carrying a VALID
/// admin token (the route is ABSENT, not merely auth-guarded), so the public data bind can never
/// reach the management plane. Both planes keep an open, unauthenticated `/healthz`.
// Exercises the admin-token auth link, so it only applies when that feature is compiled in.
#[cfg(feature = "auth-admin-tokens")]
#[tokio::test]
async fn split_admin_listener_no_double_exposure() {
    use crate::governance::{GovState, MemoryStore};
    use crate::test_support::{LaneSpec, TestApp};
    use std::sync::Arc;
    crate::metrics::init();

    let store = Arc::new(MemoryStore::new());
    let gov = Arc::new(GovState::new(store, 0, 0, Some("admintok".to_string())).unwrap());
    // One configured lane so `/healthz` reports ready (200) rather than "no usable lanes" (503) —
    // the probe URL is never actually dialed here; the test only exercises routing/auth.
    let app = TestApp::new()
        .lane(LaneSpec::new(
            "test-model",
            crate::proto::Protocol::anthropic(),
            "http://127.0.0.1:1",
        ))
        .pool("pa", &[(0, 1)])
        .governance(gov)
        .build();
    let (data_router, admin_router, _handle) = build_split_routers_with_limits(
        app,
        limits::translate_body_max_bytes(),
        crate::config::DEFAULT_MAX_INBOUND_CONCURRENT,
        crate::config::DEFAULT_EMIT_SERVER_TIMING,
    );

    async fn get(router: Router, path: &str, token: Option<&str>) -> u16 {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
        let mut req = reqwest::Client::new().get(format!("http://{addr}{path}"));
        if let Some(t) = token {
            req = req.bearer_auth(t);
        }
        let code = req.send().await.unwrap().status().as_u16();
        server.abort();
        code
    }

    let admin_path = format!("{}/keys", crate::admin::v1::contract::ADMIN_PREFIX);
    // Admin surface SERVED on the admin plane (valid token ⇒ 200).
    assert_eq!(
        get(admin_router.clone(), &admin_path, Some("admintok")).await,
        200,
        "admin router must serve the admin surface"
    );
    // Admin surface ABSENT on the data plane — even WITH a valid admin token it is a hard 404,
    // proving the route is not mounted here (no double-exposure), not merely auth-blocked.
    assert_eq!(
        get(data_router.clone(), &admin_path, Some("admintok")).await,
        404,
        "data router must NOT serve the admin surface even for an authenticated admin request"
    );
    // Both planes keep an open, unauthenticated liveness probe.
    assert_eq!(get(admin_router, "/healthz", None).await, 200);
    assert_eq!(get(data_router, "/healthz", None).await, 200);
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

/// The fast integer header writer must be BYTE-IDENTICAL to the original float path
/// (`format!("busbar;dur={:.3}", internal_us as f64 / 1000.0)`) for every internal-µs value —
/// same sentinel handling, same saturation, same 3-digit fractional rendering.
#[test]
fn test_write_server_timing_value_matches_float_format() {
    let cases: &[(u64, u64)] = &[
        (1090, 1000),            // normal: 90µs internal → "0.090"
        (57, NO_UPSTREAM_RTT),   // no upstream → full time "0.057"
        (500, 800),              // skew saturates → "0.000"
        (0, NO_UPSTREAM_RTT),    // zero
        (999, NO_UPSTREAM_RTT),  // frac only, needs all 3 digits
        (1000, NO_UPSTREAM_RTT), // exactly 1 ms
        (1001, NO_UPSTREAM_RTT), // 1.001
        (123_456_789, 456),      // large whole part
        // (the float path stays print-identical while its half-ulp error is under the 0.0005 ms
        // print threshold — comfortably true for any reachable duration; the integer writer is
        // exact everywhere)
        (1_000_000_000_000_000, NO_UPSTREAM_RTT), // 1e15 µs ≈ 31.7 years
        (25_000_033, 25_000_000),                 // benchmark shape: 20ms upstream + 33µs internal
    ];
    for &(total, upstream) in cases {
        let expected = format!("busbar;dur={:.3}", server_timing_dur_ms(total, upstream));
        let internal = server_timing_internal_us(total, upstream);
        let mut buf = [0u8; 40];
        let n = write_server_timing_value(&mut buf, internal);
        assert_eq!(
            std::str::from_utf8(&buf[..n]).unwrap(),
            expected,
            "mismatch for total={total} upstream={upstream}"
        );
    }
    // Sweep every µs in the first 2ms plus a coarse sweep beyond — the fractional rendering is
    // the risky part and this covers every frac value twice.
    for us in (0..2000u64).chain((0..1_000_000).step_by(7919)) {
        let expected = format!("busbar;dur={:.3}", us as f64 / 1000.0);
        let mut buf = [0u8; 40];
        let n = write_server_timing_value(&mut buf, us);
        assert_eq!(std::str::from_utf8(&buf[..n]).unwrap(), expected, "us={us}");
    }
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
            axum::http::HeaderValue::from_static(crate::proxy::APPLICATION_JSON),
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
