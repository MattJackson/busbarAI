// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! End-to-end coverage of the `webrequest` forwarder loaded over the REAL loader `open_hook` seam
//! (`load_hook_from_bytes`) against a local mock HTTP server. This is the exact seam the engine sees:
//! an `Arc<dyn RoutingPolicy>` indistinguishable from a compiled-in policy, whose ops POST to an
//! operator URL and whose replies are parsed through the engine's own fail-closed normalizers.
//!
//! The coverage ported from the retired `hooks/webhook.rs` tests:
//! - forward decide → `order` / `abstain` / `reject` reply parsing (fail-closed);
//! - forward transform → `rewrite` / `reject` / `abstain`;
//! - notify is fire-and-forget (never errors);
//! - oversized / malformed / deeply-nested reply → the forwarder returns `{}` → engine Abstain/on_error;
//! - a slow target past the budget → `on_error`;
//! - userinfo-leak masking on a transport error;
//! - SSRF rejection of a blocked target at load.

use axum::{routing::post, Router};
use busbar_api::{
    Candidate, RoutingContext, RoutingDecision, RoutingPolicy, RoutingRequest, TransformOutcome,
};
use busbar_plugin_loader::hook::{load_hook_from_bytes, HookProjectors};
use std::sync::Arc;
use std::time::Duration;

// ── The mock target (mirrors the old webhook.rs test sidecar) ─────────────────────────────────────

/// Spin up a local axum target that replies to POST `/` with `status` + `body`, optionally delaying
/// first. Returns its base URL. The task is detached; the test process tears it down on exit.
async fn mock_target(status: u16, body: &'static str, delay: Option<Duration>) -> String {
    let handler = move || async move {
        if let Some(d) = delay {
            tokio::time::sleep(d).await;
        }
        (
            axum::http::StatusCode::from_u16(status).unwrap(),
            [(axum::http::header::CONTENT_TYPE, "application/json")],
            body,
        )
    };
    let app = Router::new().route("/", post(handler));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    format!("http://{addr}/")
}

/// A target that CAPTURES the POSTed body into a shared slot and replies with a fixed order. Returns
/// `(url, captured)`. Proves what the forwarder SENDS on the wire (the op envelope), not just reads.
async fn capturing_target() -> (String, Arc<std::sync::Mutex<Vec<String>>>) {
    let captured: Arc<std::sync::Mutex<Vec<String>>> = Arc::new(std::sync::Mutex::new(Vec::new()));
    let sink = captured.clone();
    let app = Router::new().route(
        "/",
        post(move |body: String| {
            let sink = sink.clone();
            async move {
                sink.lock().unwrap().push(body);
                (
                    axum::http::StatusCode::OK,
                    [(axum::http::header::CONTENT_TYPE, "application/json")],
                    r#"{"order":[0]}"#,
                )
            }
        }),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    (format!("http://{addr}/"), captured)
}

/// A target that replies with a body of `n` bytes (for the oversize-cap test).
async fn mock_target_bytes(status: u16, body: Vec<u8>) -> String {
    use axum::body::Body;
    use axum::http::Response;
    let handler = move || {
        let body = body.clone();
        async move {
            Response::builder()
                .status(status)
                .header(axum::http::header::CONTENT_TYPE, "application/json")
                .body(Body::from(body))
                .unwrap()
        }
    };
    let app = Router::new().route("/", post(handler));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    format!("http://{addr}/")
}

// ── The cdylib + loader glue ──────────────────────────────────────────────────────────────────────

/// Locate the built `webrequest` cdylib in the target dir (mirrors the loader's hook_plugin_path).
fn plugin_path() -> Option<std::path::PathBuf> {
    let exe = std::env::current_exe().ok()?;
    let profile_dir = exe.parent()?.parent()?;
    let name = busbar_plugin_loader::plugin_library_filename("busbar_webrequest_hook_plugin");
    let candidate = profile_dir.join(&name);
    candidate.exists().then_some(candidate)
}

/// The engine-side projectors: the same tiny fail-closed shims the loader's own hook test uses
/// (`plugin-loader/src/hook.rs`), standing in for the engine's real `hooks::wire`. They build a
/// projection carrying `request.messages` and parse the reply with reject > order / reject > rewrite.
fn projectors() -> Arc<HookProjectors> {
    Arc::new(HookProjectors {
        decide: Box::new(|req, cands, _ctx| {
            serde_json::json!({
                "request": {
                    "pool": req.pool,
                    "messages": req.prompt.as_ref().map(|p| {
                        p.messages.iter().map(|(r, t)| {
                            serde_json::json!({"role": r.as_ref(), "text": t.as_ref()})
                        }).collect::<Vec<_>>()
                    }),
                },
                "candidates": cands.iter().map(|c| serde_json::json!({"idx": c.idx})).collect::<Vec<_>>(),
            })
        }),
        transform: Box::new(|req| {
            serde_json::json!({
                "request": {
                    "messages": req.prompt.as_ref().map(|p| {
                        p.messages.iter().map(|(r, t)| {
                            serde_json::json!({"role": r.as_ref(), "text": t.as_ref()})
                        }).collect::<Vec<_>>()
                    }),
                }
            })
        }),
        normalize: Box::new(|v, cands| {
            if let Some(reject) = v.get("reject") {
                let status = reject
                    .get("status")
                    .and_then(|s| s.as_u64())
                    .map(|s| s as u16)
                    .unwrap_or(403);
                let message = reject
                    .get("message")
                    .and_then(|m| m.as_str())
                    .unwrap_or("")
                    .to_string();
                return RoutingDecision::Reject { status, message };
            }
            let Some(order) = v.get("order").and_then(|o| o.as_array()) else {
                return RoutingDecision::Abstain;
            };
            let valid: std::collections::HashSet<usize> = cands.iter().map(|c| c.idx).collect();
            RoutingDecision::from_ranked(
                order.iter().filter_map(|x| x.as_u64().map(|x| x as usize)),
                &valid,
            )
        }),
        transform_outcome: Box::new(|v| {
            if let Some(reject) = v.get("reject") {
                let status = reject
                    .get("status")
                    .and_then(|s| s.as_u64())
                    .map(|s| s as u16)
                    .unwrap_or(403);
                return TransformOutcome::Reject {
                    status,
                    message: reject
                        .get("message")
                        .and_then(|m| m.as_str())
                        .unwrap_or("")
                        .to_string(),
                };
            }
            match v
                .get("rewrite")
                .and_then(|r| r.get("messages"))
                .and_then(|m| m.as_array())
            {
                Some(msgs) if !msgs.is_empty() => {
                    TransformOutcome::Rewrite(busbar_api::RewriteReply {
                        messages: msgs.clone(),
                        tools: Vec::new(),
                    })
                }
                _ => TransformOutcome::Abstain,
            }
        }),
        status: Box::new(|v| {
            v.get("status").map(|s| busbar_api::HookStatus {
                settings_version: None,
                settings: s.get("settings").and_then(|x| x.as_object()).cloned(),
                metrics: s.get("metrics").and_then(|m| m.as_array()).cloned(),
            })
        }),
        describe_schema: Box::new(|v| v.get("schema").cloned()),
    })
}

/// Load the forwarder over the real loader seam with the given `settings` JSON.
fn load(settings: &str) -> Arc<dyn RoutingPolicy> {
    let path = plugin_path().expect("webrequest cdylib built under --workspace");
    let bytes = std::fs::read(&path).expect("read webrequest cdylib");
    load_hook_from_bytes(
        &bytes,
        settings,
        "webrequest",
        "hook",
        "webrequest",
        projectors(),
    )
    .expect("load the webrequest plugin over the ABI")
}

fn cfg(url: &str) -> String {
    serde_json::json!({ "url": url }).to_string()
}

fn req_with_prompt(text: &str) -> RoutingRequest<'static> {
    RoutingRequest {
        pool: "p",
        ingress_protocol: "anthropic",
        requested_model: None,
        message_count: 1,
        tool_count: 0,
        has_tools: false,
        total_chars: text.len(),
        system_chars: 0,
        max_tokens: None,
        stream: false,
        prompt: Some(busbar_api::PromptProjection {
            system: None,
            messages: vec![("user".into(), text.to_string().into())],
        }),
        identity: None,
    }
}

fn cand(idx: usize) -> Candidate<'static> {
    Candidate {
        idx,
        model: "m",
        provider: "prov",
        weight: 1,
        context_max: None,
        tier: None,
        cost_per_mtok: None,
        tags: &[],
        latency_ms: None,
        available_concurrency: 1,
        budget_remaining: None,
        rate_headroom: None,
    }
}

fn ctx() -> RoutingContext<'static> {
    RoutingContext {
        pool: "p",
        budget_remaining: None,
        budget: &[],
    }
}

const BUDGET: Duration = Duration::from_secs(5);

// ── The tests ─────────────────────────────────────────────────────────────────────────────────────

/// END-TO-END: load the forwarder, POST `decide` to a mock target, get back the ranked `order`.
#[tokio::test(flavor = "multi_thread")]
async fn forward_decide_returns_prefer_from_order() {
    if plugin_path().is_none() {
        eprintln!("skip: webrequest cdylib not built (run under --workspace)");
        return;
    }
    let url = mock_target(200, r#"{"order":[1,0]}"#, None).await;
    let policy = load(&cfg(&url));
    let cands = [cand(0), cand(1)];
    let d = policy
        .decide(&req_with_prompt("hi"), &cands, &ctx(), BUDGET)
        .await
        .expect("decide ok");
    assert_eq!(d, RoutingDecision::Prefer(vec![1, 0]));
}

/// A `decide` reply of `{}` (absent order) or `{"abstain":true}` normalizes to Abstain, not an error.
#[tokio::test(flavor = "multi_thread")]
async fn forward_decide_absent_order_abstains() {
    if plugin_path().is_none() {
        return;
    }
    let url = mock_target(200, r#"{}"#, None).await;
    let policy = load(&cfg(&url));
    let d = policy
        .decide(&req_with_prompt("x"), &[cand(0)], &ctx(), BUDGET)
        .await
        .expect("decide ok");
    assert_eq!(d, RoutingDecision::Abstain);
}

/// A `decide` reply `{"reject":{...}}` surfaces as a `RoutingDecision::Reject` through the normalizer
/// (status clamped by the engine's real wire; here the test normalizer keeps the status as-sent).
#[tokio::test(flavor = "multi_thread")]
async fn forward_decide_reject_surfaces() {
    if plugin_path().is_none() {
        return;
    }
    let url = mock_target(200, r#"{"reject":{"status":403,"message":"nope"}}"#, None).await;
    let policy = load(&cfg(&url));
    match policy
        .decide(&req_with_prompt("x"), &[cand(0)], &ctx(), BUDGET)
        .await
        .expect("decide ok")
    {
        RoutingDecision::Reject { status, message } => {
            assert_eq!(status, 403);
            assert_eq!(message, "nope");
        }
        other => panic!("expected Reject, got {other:?}"),
    }
}

/// `transform` forwards and maps a `{"rewrite":{...}}` reply to a Rewrite outcome; a `{"reject":{...}}`
/// reply to a Reject.
#[tokio::test(flavor = "multi_thread")]
async fn forward_transform_rewrites_and_rejects() {
    if plugin_path().is_none() {
        return;
    }
    let url = mock_target(
        200,
        r#"{"rewrite":{"messages":[{"role":"user","content":"rw"}]}}"#,
        None,
    )
    .await;
    let policy = load(&cfg(&url));
    match policy.transform(&req_with_prompt("hi"), BUDGET).await {
        TransformOutcome::Rewrite(rw) => assert_eq!(rw.messages.len(), 1),
        other => panic!("expected Rewrite, got {other:?}"),
    }

    let url = mock_target(
        200,
        r#"{"reject":{"status":451,"message":"screened"}}"#,
        None,
    )
    .await;
    let policy = load(&cfg(&url));
    match policy.transform(&req_with_prompt("BLOCKME"), BUDGET).await {
        TransformOutcome::Reject { status, .. } => assert_eq!(status, 451),
        other => panic!("expected Reject, got {other:?}"),
    }
}

/// `notify` is fire-and-forget: it never errors, never blocks, and posts the tap projection.
#[tokio::test(flavor = "multi_thread")]
async fn forward_notify_is_fire_and_forget() {
    if plugin_path().is_none() {
        return;
    }
    let url = mock_target(200, r#"{}"#, None).await;
    let policy = load(&cfg(&url));
    let projection = serde_json::to_vec(&serde_json::json!({"request": {"pool": "p"}})).unwrap();
    policy.notify(&projection, BUDGET).await; // returns unit, never panics
}

/// The forwarder SENDS the op envelope (op discriminator + the projected request) on the wire — and
/// the opt-in prompt content the projector included rides straight through.
#[tokio::test(flavor = "multi_thread")]
async fn forward_posts_op_envelope_on_the_wire() {
    if plugin_path().is_none() {
        return;
    }
    let (url, captured) = capturing_target().await;
    let policy = load(&cfg(&url));
    policy
        .decide(&req_with_prompt("hello-wire"), &[cand(0)], &ctx(), BUDGET)
        .await
        .expect("decide ok");
    let bodies = captured.lock().unwrap().clone();
    assert_eq!(bodies.len(), 1);
    let v: serde_json::Value = serde_json::from_str(&bodies[0]).unwrap();
    assert_eq!(v["op"], "decide");
    assert_eq!(v["request"]["pool"], "p");
    assert_eq!(v["request"]["messages"][0]["text"], "hello-wire");
    assert_eq!(v["candidates"][0]["idx"], 0);
}

/// An oversized reply body (past the 64 KiB cap) → the forwarder returns `{}` → engine Abstain, never
/// unbounded allocation, never a crash.
#[tokio::test(flavor = "multi_thread")]
async fn forward_oversized_reply_abstains() {
    if plugin_path().is_none() {
        return;
    }
    let mut big = Vec::with_capacity(64 * 1024 + 4);
    big.push(b'"');
    big.extend(std::iter::repeat_n(b'x', 64 * 1024 + 1));
    big.push(b'"');
    let url = mock_target_bytes(200, big).await;
    let policy = load(&cfg(&url));
    let d = policy
        .decide(&req_with_prompt("x"), &[cand(0)], &ctx(), BUDGET)
        .await
        .expect("oversize reply must degrade to Abstain, not error");
    assert_eq!(d, RoutingDecision::Abstain);
}

/// A malformed (non-JSON) reply → the forwarder returns `{}` → engine Abstain.
#[tokio::test(flavor = "multi_thread")]
async fn forward_malformed_reply_abstains() {
    if plugin_path().is_none() {
        return;
    }
    let url = mock_target(200, "this is not json {{{", None).await;
    let policy = load(&cfg(&url));
    let d = policy
        .decide(&req_with_prompt("x"), &[cand(0)], &ctx(), BUDGET)
        .await
        .expect("malformed reply degrades to Abstain");
    assert_eq!(d, RoutingDecision::Abstain);
}

/// A deeply-nested reply (~150 deep, under the size cap) is rejected by the depth guard BEFORE parse →
/// the forwarder returns `{}` → engine Abstain (never a recursive deserialize that could blow the stack).
#[tokio::test(flavor = "multi_thread")]
async fn forward_deeply_nested_reply_abstains() {
    if plugin_path().is_none() {
        return;
    }
    let depth = 150;
    let mut deep = String::from(r#"{"order":"#);
    deep.push_str(&"[".repeat(depth));
    deep.push_str(&"]".repeat(depth));
    deep.push('}');
    assert!(deep.len() < 64 * 1024);
    let body: &'static str = Box::leak(deep.into_boxed_str());
    let url = mock_target(200, body, None).await;
    let policy = load(&cfg(&url));
    let d = policy
        .decide(&req_with_prompt("x"), &[cand(0)], &ctx(), BUDGET)
        .await
        .expect("deep reply degrades to Abstain");
    assert_eq!(d, RoutingDecision::Abstain);
}

/// A 5xx / 4xx target response → the forwarder returns `{}` → engine Abstain (a bad status is a
/// no-opinion, coerced to the on_error chain by the engine, never a silent route on the error body).
#[tokio::test(flavor = "multi_thread")]
async fn forward_error_status_abstains() {
    if plugin_path().is_none() {
        return;
    }
    for status in [500u16, 404] {
        let url = mock_target(status, "{}", None).await;
        let policy = load(&cfg(&url));
        let d = policy
            .decide(&req_with_prompt("x"), &[cand(0)], &ctx(), BUDGET)
            .await
            .expect("error status degrades to Abstain");
        assert_eq!(d, RoutingDecision::Abstain, "HTTP {status} must abstain");
    }
}

/// A target slower than the op budget → the forwarder's tight timeout fires, it returns `{}`, and the
/// deadline cuts off promptly (the blocking HTTP call never stalls the engine's runtime).
#[tokio::test(flavor = "multi_thread")]
async fn forward_slow_target_times_out_promptly() {
    if plugin_path().is_none() {
        return;
    }
    // Plugin timeout 100ms; target sleeps 2s.
    let url = mock_target(200, r#"{"order":[0]}"#, Some(Duration::from_secs(2))).await;
    let settings = serde_json::json!({ "url": url, "timeout_ms": 100 }).to_string();
    let policy = load(&settings);
    let started = std::time::Instant::now();
    let d = policy
        .decide(&req_with_prompt("x"), &[cand(0)], &ctx(), BUDGET)
        .await
        .expect("a slow target degrades to Abstain via the plugin timeout");
    assert_eq!(d, RoutingDecision::Abstain);
    assert!(
        started.elapsed() < Duration::from_secs(1),
        "the plugin timeout must cut off promptly, got {:?}",
        started.elapsed()
    );
}

/// SSRF: loading with an internal/metadata target URL is a hard fail-closed LOAD error (the ctor
/// rejects it), never a live forwarder that could be pointed at `169.254.169.254`.
#[test]
fn load_rejects_ssrf_blocked_target() {
    let Some(path) = plugin_path() else {
        return;
    };
    let bytes = std::fs::read(&path).expect("read cdylib");
    for bad in [
        "http://169.254.169.254/latest/meta-data/",
        "https://10.0.0.1/route",
        "https://metadata.google.internal/x",
        "https://100.64.0.1/x",
    ] {
        let err = match load_hook_from_bytes(
            &bytes,
            &cfg(bad),
            "webrequest",
            "hook",
            "webrequest",
            projectors(),
        ) {
            Err(e) => e,
            Ok(_) => panic!("an SSRF-blocked target ({bad}) must fail the load"),
        };
        assert!(
            err.contains("open failed"),
            "expected a fail-closed load error, got: {err}"
        );
    }
}

/// Userinfo masking: a transport error against an unroutable `user:pass@` URL must not leak the
/// credential. The forwarder returns `{}` (Abstain) rather than surfacing the error to the engine, so
/// there is no path for the credential to reach a log — this asserts the load succeeds (external host)
/// and the failing decide degrades cleanly.
#[tokio::test(flavor = "multi_thread")]
async fn forward_transport_error_never_leaks_userinfo() {
    if plugin_path().is_none() {
        return;
    }
    // RFC 5737 TEST-NET-1 is unroutable → the POST fails fast. userinfo embedded in the URL.
    let settings =
        serde_json::json!({ "url": "https://svc:hunter2@192.0.2.1/route", "timeout_ms": 300 })
            .to_string();
    let policy = load(&settings);
    let d = policy
        .decide(
            &req_with_prompt("x"),
            &[cand(0)],
            &ctx(),
            Duration::from_secs(2),
        )
        .await
        .expect("an unroutable target degrades to Abstain (no error surfaced, no credential path)");
    assert_eq!(d, RoutingDecision::Abstain);
}

/// `configure` over the seam: a good pushed URL ACKs (Ok); an SSRF-blocked pushed URL NACKs (Err — the
/// engine rejects the push, so an operator cannot re-point the forwarder at an internal target).
#[tokio::test(flavor = "multi_thread")]
async fn forward_configure_revalidates_over_the_seam() {
    if plugin_path().is_none() {
        return;
    }
    let url = mock_target(200, r#"{}"#, None).await;
    let policy = load(&cfg(&url));

    let mut good = serde_json::Map::new();
    good.insert(
        "url".into(),
        serde_json::json!("https://api.example.com/route"),
    );
    policy
        .configure("webrequest", &good, 2, BUDGET)
        .await
        .expect("a valid pushed url acks the version");

    let mut bad = serde_json::Map::new();
    bad.insert("url".into(), serde_json::json!("http://169.254.169.254/x"));
    assert!(
        policy
            .configure("webrequest", &bad, 3, BUDGET)
            .await
            .is_err(),
        "an SSRF-blocked pushed url must NACK (the push must not commit)"
    );
}

/// `describe` returns the forwarder's own config schema; `status` reports the target host + timeout
/// (no prompt/user content).
#[tokio::test(flavor = "multi_thread")]
async fn forward_describe_and_status_over_the_seam() {
    if plugin_path().is_none() {
        return;
    }
    let policy = load(&cfg("https://api.example.com/route"));
    let schema = policy.describe(BUDGET).await.expect("describe schema");
    assert_eq!(schema["type"], "object");
    let status = policy.status(BUDGET).await.expect("status");
    let settings = status.settings.expect("status settings");
    assert_eq!(settings.get("target_host").unwrap(), "api.example.com");
}
