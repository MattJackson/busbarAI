// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Matthew Jackson

//! The `webhook` routing transport — an operator-run HTTP sidecar that ranks pool members.
//!
//! A `route: webhook` pool POSTs a stable projection of the request + candidates + context to an
//! operator-configured URL and reads back a ranked `{ "order": [<idx>, ...] }`. The sidecar is a
//! policy brain Busbar does not embed (an LLM classifier, a cost optimizer, a bespoke heuristic);
//! Busbar only marshals the projection and consumes the ranked order through the same failover loop
//! the natives feed.
//!
//! SAFETY STANCE (mirrors the module contract): the seam treats a timeout / transport error /
//! malformed response as "no opinion" — it is coerced to the pool's `on_error` (default `weighted`)
//! by the caller and NEVER blocks or fails the client request. So `decide` returns `Ok(Abstain)` for
//! an absent/empty order or `{"abstain": true}`, and surfaces transport/timeout failures as `Err`
//! (which the caller coerces identically). Unknown idxs in the returned order are dropped defensively
//! via `RoutingDecision::from_ranked`.
//!
//! SSRF: the sidecar URL is operator-configured and TYPICALLY a loopback sidecar, so — unlike a
//! provider `base_url` — loopback is ALLOWED. The URL is validated at config load by
//! `observability::validate_routing_webhook_url`, which reuses the OTLP carve-out
//! (`otlp_host_is_blocked` / `otlp_host_is_loopback`): link-local/IMDS/RFC1918/CGNAT/cloud-metadata
//! are blocked, loopback/`localhost` are allowed, and plaintext `http://` is permitted only for a
//! loopback host. The shared upstream `reqwest::Client` is reused (no new client, no new dependency);
//! it is built with `redirect::Policy::none()`, so a sidecar cannot 30x-redirect Busbar to an
//! internal target at runtime.
//!
//! This transport is live: `resolve_policy`'s webhook arm constructs a `WebhookPolicy` over the
//! validated sidecar URL + the shared client at config load, and `forward::decide_policy_order`
//! invokes it per request through the same failover loop the natives feed.

use super::{Candidate, PolicyResult, RoutingContext, RoutingPolicy, RoutingRequest};
use std::time::Duration;

/// A `WebhookPolicy` POSTs the request projection to an operator sidecar and returns the ranked
/// order. Holds a clone of the SHARED upstream `reqwest::Client` (reused, not freshly built) so the
/// connection pool and the `redirect::none` SSRF posture are inherited. The URL is validated at
/// config load; this struct assumes it.
pub(crate) struct WebhookPolicy {
    /// The validated sidecar URL (loopback allowed; see `validate_routing_webhook_url`).
    url: String,
    /// The shared upstream client (built once in `main`, `redirect::none`).
    client: reqwest::Client,
}

impl WebhookPolicy {
    /// Construct a webhook policy over a pre-validated `url` and the shared `client`. The URL must
    /// already have passed `observability::validate_routing_webhook_url` at config load.
    pub(crate) fn new(url: String, client: reqwest::Client) -> Self {
        Self { url, client }
    }
}

#[async_trait::async_trait]
impl RoutingPolicy for WebhookPolicy {
    async fn decide(
        &self,
        req: &RoutingRequest<'_>,
        candidates: &[Candidate<'_>],
        ctx: &RoutingContext<'_>,
        budget: Duration,
    ) -> PolicyResult {
        // Build the ONE shared hook wire projection (`routing::wire`) — identical for every
        // out-of-process transport, so a hook moves between webhook and socket without changes.
        let body = super::wire::build(req, candidates, ctx);

        // Serialize the projection with `serde_json` and POST it as a raw body. We do NOT use
        // reqwest's `.json()` helper because the request-path build does not enable reqwest's `json`
        // feature (only the in-crate test harness does); marshaling by hand keeps the runtime
        // dependency set unchanged — mirrors the `observability::fire_request_log` pattern.
        let payload = serde_json::to_vec(&body)?;

        // Hard per-decision timeout from policy config: the request `.timeout(budget)` gives up at the
        // wall-clock deadline. The caller ALSO wraps `decide` in its own `tokio::time::timeout`; a
        // reqwest timeout surfaces here as an `Err`, which the caller coerces to `on_error`. Either
        // way a slow sidecar never blocks the served request.
        let resp = self
            .client
            .post(&self.url)
            .header(
                reqwest::header::CONTENT_TYPE,
                crate::forward::APPLICATION_JSON,
            )
            .body(payload)
            .timeout(budget)
            .send()
            .await?;

        // A non-2xx sidecar response is an error → coerced to `on_error` by the caller. We do not try
        // to parse an error body as an order.
        let mut resp = resp.error_for_status()?;

        // A malformed/non-JSON body surfaces as `Err` → `on_error`. A well-formed body with an absent/
        // empty `order` (or `abstain: true`) is the clean Abstain path. Read the body under a TIGHT cap
        // — a routing decision is a short list of indices, so a hostile/buggy sidecar returning a huge
        // body must not drive unbounded allocation (mirrors the forwarding path's capped reads). Stream
        // chunks and abort past the cap → Err → coerced to `on_error`. Parse with `serde_json` (the
        // request-path build has no reqwest `json` feature).
        const MAX_WEBHOOK_RESP_BYTES: usize = 64 * 1024;
        let mut buf: Vec<u8> = Vec::new();
        while let Some(chunk) = resp.chunk().await? {
            if buf.len() + chunk.len() > MAX_WEBHOOK_RESP_BYTES {
                return Err(
                    format!("webhook response exceeded {MAX_WEBHOOK_RESP_BYTES} byte cap").into(),
                );
            }
            buf.extend_from_slice(&chunk);
        }
        // Parse through the `crate::json` depth-guard seam (MAX_JSON_DEPTH=128) so a hostile/buggy
        // sidecar returning a pathologically nested body is rejected as `Err` (→ `on_error`) BEFORE a
        // recursive deserialize can blow the stack — same guard the forwarding path uses. The 64 KiB
        // cap above bounds size; this bounds nesting depth. Normalization (abstain / drop unknown
        // idxs / dedup / empty → Abstain) is the shared `wire::normalize`, same as every transport.
        let parsed: super::wire::HookResponse = crate::json::parse(&buf)?;
        Ok(super::wire::normalize(parsed, candidates))
    }

    fn name(&self) -> &'static str {
        "webhook"
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::routing::RoutingDecision;
    use axum::{routing::post, Router};
    use std::time::Duration as StdDuration;

    /// Spin up a local axum sidecar that responds to POST `/` with the given status + raw body, and
    /// optionally delays first. Returns its base URL. Mirrors the in-crate mock-server pattern in
    /// `test_support`. The server task is detached; the test process tears it down on exit.
    async fn mock_sidecar(status: u16, body: &'static str, delay: Option<StdDuration>) -> String {
        let handler = move || async move {
            if let Some(d) = delay {
                tokio::time::sleep(d).await;
            }
            (
                axum::http::StatusCode::from_u16(status).unwrap(),
                [(
                    axum::http::header::CONTENT_TYPE,
                    crate::forward::APPLICATION_JSON,
                )],
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

    fn cand(idx: usize) -> Candidate<'static> {
        Candidate {
            idx,
            model: "m",
            provider: "p",
            weight: 1,
            context_max: None,
            tier: Some("large"),
            cost_per_mtok: Some(3.0),
            tags: &[],
            latency_ms: Some(42.0),
            available_concurrency: 4,
            budget_remaining: Some(1000),
            rate_headroom: Some(0.75),
        }
    }

    fn req() -> RoutingRequest<'static> {
        RoutingRequest {
            pool: "p",
            ingress_protocol: "anthropic",
            requested_model: None,
            message_count: 2,
            tool_count: 1,
            has_tools: true,
            total_chars: 1234,
            system_chars: 50,
            max_tokens: Some(256),
            stream: true,
        }
    }

    fn ctx() -> RoutingContext<'static> {
        RoutingContext {
            pool: "p",
            budget_remaining: Some(500),
        }
    }

    fn client() -> reqwest::Client {
        reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .expect("build test client")
    }

    /// Hit a local mock that returns an order; assert the decision is the ranked Prefer.
    #[tokio::test]
    async fn returns_prefer_from_order() {
        let url = mock_sidecar(200, r#"{"order":[2,0,1]}"#, None).await;
        let policy = WebhookPolicy::new(url, client());
        let cands = [cand(0), cand(1), cand(2)];
        let d = policy
            .decide(&req(), &cands, &ctx(), Duration::from_secs(2))
            .await
            .expect("ok decision");
        assert_eq!(d, RoutingDecision::Prefer(vec![2, 0, 1]));
    }

    /// Unknown idxs in the returned order are dropped defensively; dups deduped.
    #[tokio::test]
    async fn drops_unknown_idxs() {
        let url = mock_sidecar(200, r#"{"order":[9,1,1,0]}"#, None).await;
        let policy = WebhookPolicy::new(url, client());
        let cands = [cand(0), cand(1)];
        let d = policy
            .decide(&req(), &cands, &ctx(), Duration::from_secs(2))
            .await
            .unwrap();
        assert_eq!(d, RoutingDecision::Prefer(vec![1, 0]));
    }

    /// An explicit `{"abstain": true}` is the clean no-opinion path.
    #[tokio::test]
    async fn explicit_abstain() {
        let url = mock_sidecar(200, r#"{"abstain":true}"#, None).await;
        let policy = WebhookPolicy::new(url, client());
        let cands = [cand(0)];
        let d = policy
            .decide(&req(), &cands, &ctx(), Duration::from_secs(2))
            .await
            .unwrap();
        assert_eq!(d, RoutingDecision::Abstain);
    }

    /// An empty body `{}` (absent order) is Abstain, not an error.
    #[tokio::test]
    async fn absent_order_abstains() {
        let url = mock_sidecar(200, r#"{}"#, None).await;
        let policy = WebhookPolicy::new(url, client());
        let cands = [cand(0)];
        let d = policy
            .decide(&req(), &cands, &ctx(), Duration::from_secs(2))
            .await
            .unwrap();
        assert_eq!(d, RoutingDecision::Abstain);
    }

    /// A slow sidecar past the budget yields `Err` → the caller coerces to `on_error` (fallback).
    #[tokio::test]
    async fn timeout_is_error_fallback() {
        let url = mock_sidecar(200, r#"{"order":[0]}"#, Some(StdDuration::from_secs(2))).await;
        let policy = WebhookPolicy::new(url, client());
        let cands = [cand(0)];
        let res = policy
            .decide(&req(), &cands, &ctx(), Duration::from_millis(50))
            .await;
        assert!(
            res.is_err(),
            "a sidecar slower than the budget must surface as Err (→ on_error fallback)"
        );
    }

    /// A malformed (non-JSON) body yields `Err` → fallback.
    #[tokio::test]
    async fn malformed_body_is_error_fallback() {
        let url = mock_sidecar(200, "this is not json {{{", None).await;
        let policy = WebhookPolicy::new(url, client());
        let cands = [cand(0)];
        let res = policy
            .decide(&req(), &cands, &ctx(), Duration::from_secs(2))
            .await;
        assert!(
            res.is_err(),
            "a malformed sidecar body must surface as Err (→ on_error fallback)"
        );
    }

    /// The sidecar response body is parsed through the `crate::json` depth-guard seam
    /// (MAX_JSON_DEPTH=128). A pathologically nested response (~150 deep) must be rejected as `Err`
    /// (→ `on_error` fallback) BEFORE a recursive deserialize can blow the stack — not parsed. The
    /// body stays well under the 64 KiB cap, so depth (not size) is what rejects it.
    #[tokio::test]
    async fn deeply_nested_response_body_is_rejected() {
        // 150 levels of nested arrays: `{"order":[[[...]]]}` — past MAX_JSON_DEPTH=128, well under 64 KiB.
        let depth = 150;
        let mut deep = String::from(r#"{"order":"#);
        deep.push_str(&"[".repeat(depth));
        deep.push_str(&"]".repeat(depth));
        deep.push('}');
        assert!(
            deep.len() < 64 * 1024,
            "the deep body must stay under the size cap"
        );
        let body: &'static str = Box::leak(deep.into_boxed_str());
        let url = mock_sidecar(200, body, None).await;
        let policy = WebhookPolicy::new(url, client());
        let cands = [cand(0)];
        let res = policy
            .decide(&req(), &cands, &ctx(), Duration::from_secs(2))
            .await;
        assert!(
            res.is_err(),
            "a ~150-deep sidecar response must be rejected by the depth guard (→ on_error fallback)"
        );
    }

    /// A 5xx sidecar response yields `Err` → fallback. Beyond `is_err()`, assert the error IDENTITY:
    /// it is the `error_for_status` status error carrying the 500, NOT a transport/parse error — so a
    /// regression that (e.g.) started parsing error bodies as an order would be caught.
    #[tokio::test]
    async fn server_error_is_error_fallback() {
        let url = mock_sidecar(500, "{}", None).await;
        let policy = WebhookPolicy::new(url, client());
        let cands = [cand(0)];
        let err = policy
            .decide(&req(), &cands, &ctx(), Duration::from_secs(2))
            .await
            .expect_err("a 5xx sidecar response must surface as Err (→ on_error fallback)");
        // The boxed error is the reqwest status error from `error_for_status()`; its source is a
        // reqwest::Error that is_status() and carries the 500.
        let re = err
            .downcast_ref::<reqwest::Error>()
            .expect("a 5xx must surface as the reqwest status error, not a transport/parse error");
        assert!(re.is_status(), "must be a status error, got: {re}");
        assert_eq!(
            re.status(),
            Some(reqwest::StatusCode::INTERNAL_SERVER_ERROR),
            "the status error must carry the 500"
        );
    }

    /// A 4xx sidecar response (here 404) likewise yields `Err` → fallback, carrying the 404 status —
    /// a misconfigured sidecar path is a transport error, not a silent Abstain.
    #[tokio::test]
    async fn client_error_404_is_error_fallback() {
        let url = mock_sidecar(404, "{}", None).await;
        let policy = WebhookPolicy::new(url, client());
        let cands = [cand(0)];
        let err = policy
            .decide(&req(), &cands, &ctx(), Duration::from_secs(2))
            .await
            .expect_err("a 404 sidecar response must surface as Err (→ on_error fallback)");
        let re = err
            .downcast_ref::<reqwest::Error>()
            .expect("a 4xx must surface as the reqwest status error");
        assert!(re.is_status(), "must be a status error, got: {re}");
        assert_eq!(
            re.status(),
            Some(reqwest::StatusCode::NOT_FOUND),
            "the status error must carry the 404"
        );
    }

    /// Spin up a local axum sidecar that returns a 2xx with a dynamically-built body (owned `Vec<u8>`).
    /// Unlike `mock_sidecar`, this variant takes ownership of the body bytes so callers can pass large
    /// buffers without needing a `'static` lifetime.
    async fn mock_sidecar_bytes(status: u16, body: Vec<u8>) -> String {
        use axum::body::Body;
        use axum::http::Response;
        let handler = move || {
            let body = body.clone();
            async move {
                Response::builder()
                    .status(status)
                    .header(
                        axum::http::header::CONTENT_TYPE,
                        crate::forward::APPLICATION_JSON,
                    )
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

    /// Spin up a local axum sidecar that CAPTURES the raw POSTed request body into a shared slot and
    /// replies with a fixed 2xx order. Returns `(base_url, captured)`; after a `decide` call the test
    /// reads the captured bytes (the exact JSON Busbar serialized onto the wire) and asserts the
    /// contracted fields. Unlike `mock_sidecar`, this asserts what Busbar SENDS, not just what it reads.
    async fn capturing_sidecar() -> (String, std::sync::Arc<std::sync::Mutex<Option<Vec<u8>>>>) {
        use axum::body::Bytes;
        let captured = std::sync::Arc::new(std::sync::Mutex::new(None::<Vec<u8>>));
        let sink = captured.clone();
        let handler = move |body: Bytes| {
            let sink = sink.clone();
            async move {
                *sink.lock().unwrap() = Some(body.to_vec());
                (
                    axum::http::StatusCode::OK,
                    [(
                        axum::http::header::CONTENT_TYPE,
                        crate::forward::APPLICATION_JSON,
                    )],
                    r#"{"order":[0]}"#,
                )
            }
        };
        let app = Router::new().route("/", post(handler));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        (format!("http://{addr}/"), captured)
    }

    /// Payload CONTRACT: the existing webhook tests use a mock that ignores the request body, so none
    /// of them assert what Busbar actually serializes onto the wire. This captures the POSTed JSON and
    /// asserts the contracted projection — in particular that `context.budget_remaining` is present and
    /// carries the `RoutingContext`'s value (500), plus the per-candidate `budget_remaining` and the
    /// request projection. Pins the shared `wire::HookContext`/`HookReqProjection`/`HookCandidate` wire shape.
    #[tokio::test]
    async fn posts_budget_remaining_in_payload() {
        let (url, captured) = capturing_sidecar().await;
        let policy = WebhookPolicy::new(url, client());
        let cands = [cand(0), cand(1)];
        let d = policy
            .decide(&req(), &cands, &ctx(), Duration::from_secs(2))
            .await
            .expect("ok decision");
        assert_eq!(d, RoutingDecision::Prefer(vec![0]));

        let body = captured
            .lock()
            .unwrap()
            .clone()
            .expect("sidecar must have captured the POSTed body");
        let v: serde_json::Value =
            serde_json::from_slice(&body).expect("POSTed body must be valid JSON");

        // context.budget_remaining is the field this test exists to pin: it must serialize and carry
        // the RoutingContext's value (ctx() sets 500).
        assert_eq!(
            v["context"]["budget_remaining"], 500,
            "context.budget_remaining must be serialized with the RoutingContext value"
        );
        assert_eq!(
            v["context"]["pool"], "p",
            "context.pool must carry the pool name"
        );

        // The request projection must reflect the live RoutingRequest (req()).
        assert_eq!(v["request"]["pool"], "p");
        assert_eq!(v["request"]["ingress_protocol"], "anthropic");
        assert_eq!(v["request"]["message_count"], 2);
        assert_eq!(v["request"]["has_tools"], true);
        assert_eq!(v["request"]["total_chars"], 1234);
        assert_eq!(v["request"]["max_tokens"], 256);
        assert_eq!(v["request"]["stream"], true);

        // Each candidate carries its own budget_remaining + idx (cand() sets 1000).
        let arr = v["candidates"]
            .as_array()
            .expect("candidates must be an array");
        assert_eq!(arr.len(), 2, "both candidates must be projected");
        assert_eq!(arr[0]["idx"], 0);
        assert_eq!(arr[0]["budget_remaining"], 1000);
        assert_eq!(arr[0]["rate_headroom"], 0.75);
        assert_eq!(arr[1]["idx"], 1);
        assert_eq!(arr[1]["budget_remaining"], 1000);
    }

    /// A 2xx sidecar response whose body exceeds MAX_WEBHOOK_RESP_BYTES (64 KiB) must yield `Err`
    /// (→ coerced to `on_error` fallback by the seam). This guards against a hostile/buggy sidecar
    /// driving unbounded allocation by streaming a huge body.
    #[tokio::test]
    async fn oversized_body_is_error_fallback() {
        // Build a body just over the 64 KiB cap. Fill it with spaces so it is valid UTF-8 but not
        // valid JSON — that doesn't matter since the cap fires before parse. We wrap in a JSON-looking
        // prefix so it looks superficially like a real response.
        const OVER_CAP: usize = 64 * 1024 + 1;
        let mut big_body = Vec::with_capacity(OVER_CAP + 2);
        big_body.push(b'"');
        big_body.extend(std::iter::repeat_n(b'x', OVER_CAP));
        big_body.push(b'"');

        let url = mock_sidecar_bytes(200, big_body).await;
        let policy = WebhookPolicy::new(url, client());
        let cands = [cand(0)];
        let res = policy
            .decide(&req(), &cands, &ctx(), Duration::from_secs(5))
            .await;
        assert!(
            res.is_err(),
            "a sidecar body exceeding MAX_WEBHOOK_RESP_BYTES must surface as Err (→ on_error fallback)"
        );
    }
}
