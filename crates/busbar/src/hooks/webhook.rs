// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

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
//! validated sidecar URL + the shared client at config load, and `proxy::decide_policy_order`
//! invokes it per request through the same failover loop the natives feed.

use super::{Candidate, PolicyResult, RoutingContext, RoutingPolicy, RoutingRequest};
use std::time::Duration;

/// Read a webhook response body with the 64 KiB cap, aborting (rather than allocating) past it.
async fn read_capped(mut resp: reqwest::Response) -> Result<Vec<u8>, super::PolicyError> {
    let mut buf: Vec<u8> = Vec::new();
    // `without_url()`: a reqwest body-read error carries the request URL (WITH any operator-embedded
    // `user:pass@` userinfo) in its own `Display`. This error is boxed into `PolicyError` and later
    // logged verbatim (`error = %e`) by the seam's on_error fallback, so strip the URL before boxing
    // The credential must never reach the log. Parity with the `send()` decide-path hardening.
    while let Some(chunk) = resp.chunk().await.map_err(|e| -> super::PolicyError {
        format!("webhook response read failed: {}", e.without_url()).into()
    })? {
        if buf.len() + chunk.len() > super::wire::MAX_HOOK_REPLY_BYTES {
            return Err(format!(
                "webhook response exceeded {} byte cap",
                super::wire::MAX_HOOK_REPLY_BYTES
            )
            .into());
        }
        buf.extend_from_slice(&chunk);
    }
    Ok(buf)
}

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

    /// POST the request projection to the sidecar and parse the reply into a `HookResponse` (shared
    /// by `decide` and `transform`). Bounded by `budget`; a non-2xx / oversize / malformed / timed-out
    /// response surfaces as `Err`. Read under a TIGHT cap (a hostile sidecar must not drive unbounded
    /// allocation) and depth-guarded parse (MAX_JSON_DEPTH). Parse errors are length-only (a sidecar
    /// echoing prompt content into a malformed reply must not splash it into operator logs).
    async fn send(
        &self,
        op: &'static str,
        req: &RoutingRequest<'_>,
        candidates: &[Candidate<'_>],
        ctx: &RoutingContext<'_>,
        budget: Duration,
    ) -> Result<super::wire::HookResponse, super::PolicyError> {
        let payload = serde_json::to_vec(&super::wire::build(op, req, candidates, ctx))?;
        // A reqwest error carries the request URL (WITH any operator-embedded `user:pass@` userinfo)
        // in its own `Display`. This error is boxed into `PolicyError` and later logged verbatim
        // (`error = %e`) by the seam's on_error fallback, so strip the URL from the error with
        // `without_url()` before boxing - the credential must never reach the log. Parity with the
        // request-log/OTLP userinfo hardening.
        let resp = self
            .client
            .post(&self.url)
            .header(
                reqwest::header::CONTENT_TYPE,
                crate::proxy::APPLICATION_JSON,
            )
            .body(payload)
            .timeout(budget)
            .send()
            .await
            .map_err(|e| -> super::PolicyError { Box::new(e.without_url()) })?;
        let resp = resp
            .error_for_status()
            .map_err(|e| -> super::PolicyError { Box::new(e.without_url()) })?;
        let buf = read_capped(resp).await?;
        crate::json::parse(&buf)
            .map_err(|_| -> super::PolicyError { crate::json::parse_err_log(buf.len()).into() })
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
        // POST the shared wire projection via the `send` helper (identical for every out-of-process
        // transport), then apply the shared normalizer (abstain / drop unknown idxs / dedup / empty →
        // Abstain). A slow/errored/malformed sidecar surfaces as `Err` → the caller's `on_error`.
        let parsed = self
            .send(super::wire::OP_DECIDE, req, candidates, ctx, budget)
            .await?;
        Ok(super::wire::normalize(parsed, candidates))
    }

    fn name(&self) -> &'static str {
        "webhook"
    }

    /// REWRITE transform: POST the request projection; reject > rewrite > abstain (shared
    /// normalizer — see `wire::transform_outcome`). Transport/parse failures abstain (proceed with
    /// the ORIGINAL body); a parsed reject is HONORED (audit W-H1).
    async fn transform(
        &self,
        req: &RoutingRequest<'_>,
        budget: Duration,
    ) -> busbar_api::TransformOutcome {
        let empty: [Candidate<'_>; 0] = [];
        let ctx = RoutingContext {
            pool: req.pool,
            budget_remaining: None,
        };
        match self
            .send(super::wire::OP_TRANSFORM, req, &empty, &ctx, budget)
            .await
        {
            Ok(parsed) => super::wire::transform_outcome(parsed),
            Err(_) => busbar_api::TransformOutcome::Abstain,
        }
    }

    /// TAP: fire-and-forget POST of the pre-serialized projection. The response is NOT read (a tap is
    /// write-only). Bounded by `budget`; any error is swallowed — a tap never affects the request.
    async fn configure(
        &self,
        hook_name: &str,
        settings: &serde_json::Map<String, serde_json::Value>,
        settings_version: u64,
        budget: Duration,
    ) -> Result<(), super::PolicyError> {
        // HTTP is stateless — configure is a plain POST of the same body the socket wire frames;
        // 2xx with an ack body = committed. (No per-connection preamble exists for webhooks; the
        // PATCH push is the delivery, documented.)
        let msg = super::wire::ConfigureMsg {
            configure: super::wire::ConfigureBody {
                hook: hook_name,
                settings,
                settings_version,
                busbar_version: env!("CARGO_PKG_VERSION"),
            },
        };
        let body = serde_json::to_vec(&msg)
            .map_err(|e| -> super::PolicyError { format!("serialize configure: {e}").into() })?;
        // `.timeout(budget)` on the builder (not an outer `tokio::time::timeout` around only
        // `send()`) so the deadline also covers the BODY-read phase — a slow/dribbling ack body must
        // not stall `configure` for the client-level total timeout (default 300s). (found: audit c2r2.)
        let resp = self
            .client
            .post(self.url.clone())
            .header("content-type", "application/json")
            .body(body)
            .timeout(budget)
            .send()
            .await
            // `without_url()`: the reqwest send error carries the sidecar URL (with any
            // operator-embedded `user:pass@` userinfo) in its `Display`; this error is boxed into
            // `PolicyError` and can reach operator logs, so strip the URL before boxing. Parity with
            // the `send()` decide-path hardening.
            .map_err(|e| -> super::PolicyError {
                format!("configure POST failed: {}", e.without_url()).into()
            })?;
        if !resp.status().is_success() {
            return Err(format!("configure rejected: HTTP {}", resp.status()).into());
        }
        let bytes = read_capped(resp).await?;
        let ack: super::wire::ConfigureAck =
            serde_json::from_slice(&bytes).map_err(|e| -> super::PolicyError {
                format!("configure reply unparsable: {e}").into()
            })?;
        match ack.ack {
            Some(body) if body.settings_version == settings_version => Ok(()),
            _ => Err("hook did not ack the configure push".into()),
        }
    }

    async fn describe(&self, budget: Duration) -> Option<serde_json::Value> {
        let body = serde_json::to_vec(&super::wire::DescribeMsg { describe: true }).ok()?;
        // `.timeout(budget)` on the builder so the deadline covers the body-read too (see
        // `configure`) — not just the header exchange. (found: audit c2r2.)
        let resp = self
            .client
            .post(self.url.clone())
            .header("content-type", "application/json")
            .body(body)
            .timeout(budget)
            .send()
            .await
            .ok()?;
        if !resp.status().is_success() {
            return None;
        }
        let bytes = read_capped(resp).await.ok()?;
        serde_json::from_slice(&bytes).ok()
    }

    async fn status(&self, budget: Duration) -> Option<busbar_api::HookStatus> {
        let body = serde_json::to_vec(&super::wire::StatusMsg { status: true }).ok()?;
        let resp = self
            .client
            .post(self.url.clone())
            .header("content-type", "application/json")
            .body(body)
            .timeout(budget)
            .send()
            .await
            .ok()?;
        if !resp.status().is_success() {
            return None;
        }
        let bytes = read_capped(resp).await.ok()?;
        // `{}` (no `status` key) = unsupported — fail open (None), per the unknown-op rule.
        let parsed: super::wire::StatusEnvelope = crate::json::parse(&bytes).ok()?;
        parsed.status.map(Into::into)
    }

    async fn notify(&self, projection: &[u8], budget: Duration) {
        let _ = self
            .client
            .post(&self.url)
            .header(
                reqwest::header::CONTENT_TYPE,
                crate::proxy::APPLICATION_JSON,
            )
            .body(projection.to_vec())
            .timeout(budget)
            .send()
            .await; // response intentionally dropped — a tap does not read a reply
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hooks::RoutingDecision;
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
                    crate::proxy::APPLICATION_JSON,
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
            prompt: None,
            identity: None,
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

    /// TEMP timing probe (not an assertion) — measures the REAL per-decision cost of the webhook
    /// transport through `WebhookPolicy::decide()` (serialize + HTTP POST + parse + normalize).
    /// Defaults to an in-process mock; set BUSBAR_WEBHOOK_PROBE_URL to a real external sidecar
    /// process for the honest cross-process number. Run:
    ///   cargo test --release --bin busbar webhook_decide_timing -- --nocapture --ignored
    #[tokio::test]
    #[ignore]
    async fn webhook_decide_timing() {
        let url = match std::env::var("BUSBAR_WEBHOOK_PROBE_URL") {
            Ok(u) if !u.is_empty() => u,
            _ => mock_sidecar(200, r#"{"order":[2,0,1]}"#, None).await,
        };
        let policy = WebhookPolicy::new(url, client());
        let cands = [cand(0), cand(1), cand(2)];
        let r = req();
        let c = ctx();
        let budget = StdDuration::from_millis(150);
        for _ in 0..2000 {
            policy.decide(&r, &cands, &c, budget).await.unwrap();
        }
        let mut xs = Vec::with_capacity(20_000);
        for _ in 0..20_000 {
            let t = std::time::Instant::now();
            policy.decide(&r, &cands, &c, budget).await.unwrap();
            xs.push(t.elapsed().as_nanos() as f64 / 1e3); // microseconds
        }
        xs.sort_by(|a, b| a.partial_cmp(b).unwrap());
        let pc = |q: f64| xs[((q * xs.len() as f64) as usize).min(xs.len() - 1)];
        println!(
            "WEBHOOK decide() via busbar transport (3 cands, N=20000): median {:.2} us  p95 {:.2} us  p99 {:.2} us  min {:.2} us",
            xs[xs.len() / 2],
            pc(0.95),
            pc(0.99),
            xs[0]
        );
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

    /// REGRESSION (P2 finding 4, routing-webhook radius): a transport error from `decide()` is boxed
    /// into `PolicyError` and later logged verbatim (`error = %e`) by the seam's on_error fallback. If
    /// the operator embedded `user:pass@` userinfo in the sidecar URL, the reqwest error's own Display
    /// would carry it - so the boxed error must have its URL stripped (`without_url`) before it can
    /// reach a log. Point the policy at an unroutable userinfo URL, force a transport error, and assert
    /// the resulting PolicyError's Display contains no credential.
    #[tokio::test]
    async fn decide_transport_error_does_not_leak_url_userinfo() {
        // RFC 5737 TEST-NET-1 host is unroutable, so the POST fails fast with a transport error.
        let url = "https://svc:hunter2@192.0.2.1/route".to_string();
        let policy = WebhookPolicy::new(url, client());
        let cands = [cand(0), cand(1)];
        let err = policy
            .decide(&req(), &cands, &ctx(), Duration::from_millis(200))
            .await
            .expect_err("unroutable sidecar must error");
        let shown = err.to_string();
        assert!(
            !shown.contains("hunter2") && !shown.contains("svc:hunter2"),
            "routing-webhook PolicyError leaked embedded userinfo: {shown}"
        );
    }

    /// FIX F [P2, security] REGRESSION: the round-1 userinfo-mask fix hardened only the `decide()`
    /// (`send()`) path. The `configure()` path still `format!`ed a raw reqwest send error, which
    /// carries the sidecar URL WITH any operator-embedded `user:pass@` userinfo in its `Display`,
    /// into a `PolicyError` that can reach operator logs. Point `configure` at an unroutable userinfo
    /// URL, force a transport error, and assert the resulting error carries no credential.
    #[tokio::test]
    async fn configure_transport_error_does_not_leak_url_userinfo() {
        // RFC 5737 TEST-NET-1 host is unroutable, so the POST fails fast with a transport error.
        let url = "https://svc:hunter2@192.0.2.1/route".to_string();
        let policy = WebhookPolicy::new(url, client());
        let settings = serde_json::Map::new();
        let err = policy
            .configure("myhook", &settings, 1, Duration::from_millis(200))
            .await
            .expect_err("unroutable sidecar must error");
        let shown = err.to_string();
        assert!(
            !shown.contains("hunter2") && !shown.contains("svc:hunter2"),
            "configure() PolicyError leaked embedded userinfo: {shown}"
        );
    }

    /// FIX F [P2, security] REGRESSION: the response-body read path (`read_capped`, via `resp.chunk()`)
    /// also `format!`ed a raw reqwest error that carries the request URL (with any embedded userinfo).
    /// Drive a body-read error by advertising a `Content-Length` larger than the bytes actually sent,
    /// then closing the connection, so `chunk()` surfaces an incomplete-body error whose Display carries
    /// the URL. Assert the resulting `PolicyError` masks the credential.
    #[tokio::test]
    async fn response_body_read_error_does_not_leak_url_userinfo() {
        use tokio::io::AsyncWriteExt;
        // Raw TCP mock: send valid response headers claiming a 100-byte body, then only 3 bytes and
        // close. reqwest's body reader errors mid-stream (incomplete message).
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            if let Ok((mut sock, _)) = listener.accept().await {
                // Read and discard the request (best-effort) so the client finishes sending.
                let mut throwaway = [0u8; 1024];
                let _ = tokio::io::AsyncReadExt::read(&mut sock, &mut throwaway).await;
                let _ = sock
                    .write_all(
                        b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 100\r\n\r\nabc",
                    )
                    .await;
                let _ = sock.flush().await;
                // Drop the socket -> connection closes with the body short of Content-Length.
            }
        });
        // Embed userinfo in the URL so a leaked reqwest error Display would expose it.
        let url = format!("http://svc:hunter2@{addr}/route");
        let policy = WebhookPolicy::new(url, client());
        let cands = [cand(0)];
        let err = policy
            .decide(&req(), &cands, &ctx(), Duration::from_secs(2))
            .await
            .expect_err("a truncated response body must surface as Err");
        let shown = err.to_string();
        assert!(
            !shown.contains("hunter2") && !shown.contains("svc:hunter2"),
            "response-body read PolicyError leaked embedded userinfo: {shown}"
        );
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
                        crate::proxy::APPLICATION_JSON,
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
                        crate::proxy::APPLICATION_JSON,
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
        // context.pool was REMOVED (wire audit L12): request.pool is the one carrier.
        assert!(
            v["context"].get("pool").is_none(),
            "context must not duplicate the pool name"
        );
        assert_eq!(v["request"]["pool"], "p");
        // Per-request payloads carry the explicit op discriminator (wire audit #5).
        assert_eq!(v["op"], "decide");

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

    /// A 2xx sidecar response whose body exceeds MAX_HOOK_REPLY_BYTES (64 KiB) must yield `Err`
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
            "a sidecar body exceeding MAX_HOOK_REPLY_BYTES must surface as Err (→ on_error fallback)"
        );
    }

    /// End-to-end opt-in payload over the REAL HTTP wire: a capturing sidecar proves the POST body
    /// actually carries the opt-in keys when populated — and that a default request carries none.
    #[tokio::test]
    async fn opt_in_payload_rides_the_webhook_wire() {
        use std::sync::Mutex as StdMutex;
        let seen: std::sync::Arc<StdMutex<Vec<String>>> =
            std::sync::Arc::new(StdMutex::new(Vec::new()));
        let seen_h = seen.clone();
        let app = Router::new().route(
            "/",
            post(move |body: String| {
                let seen = seen_h.clone();
                async move {
                    seen.lock().unwrap().push(body);
                    (
                        axum::http::StatusCode::OK,
                        [(
                            axum::http::header::CONTENT_TYPE,
                            crate::proxy::APPLICATION_JSON,
                        )],
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
        let policy = WebhookPolicy::new(format!("http://{addr}/"), client());
        let cands = [cand(0)];

        // Default request: no opt-in keys on the wire.
        policy
            .decide(&req(), &cands, &ctx(), Duration::from_secs(5))
            .await
            .unwrap();
        // Opt-in request: prompt + identity present.
        let mut r = req();
        r.prompt = Some(crate::hooks::PromptProjection {
            system: Some("be brief".into()),
            messages: vec![("user".into(), "hello".into())],
        });
        r.identity = Some(crate::hooks::CallerIdentity {
            key_id: None,
            key_name: Some("sales-team".into()),
            user: Some("alice".into()),
        });
        policy
            .decide(&r, &cands, &ctx(), Duration::from_secs(5))
            .await
            .unwrap();

        let bodies = seen.lock().unwrap().clone();
        assert_eq!(bodies.len(), 2);
        let default: serde_json::Value = serde_json::from_str(&bodies[0]).unwrap();
        for key in ["system", "messages", "user"] {
            assert!(
                default["request"].get(key).is_none(),
                "default POST body leaked {key}: {}",
                bodies[0]
            );
        }
        let opted: serde_json::Value = serde_json::from_str(&bodies[1]).unwrap();
        assert_eq!(opted["request"]["system"], "be brief");
        assert_eq!(opted["request"]["messages"][0]["text"], "hello");
        assert_eq!(opted["request"]["user"]["key_name"], "sales-team");
        assert_eq!(opted["request"]["user"]["user"], "alice");
    }

    /// A malformed sidecar reply must surface as a LENGTH-ONLY parse error: the raw parser Display
    /// embeds reply bytes, and a sidecar that echoes prompt content into a broken reply must not
    /// splash it into operator logs via the seam's `error = %e` warn.
    #[tokio::test]
    async fn malformed_reply_error_never_echoes_reply_bytes() {
        let url = mock_sidecar(200, r#"{"order":[0,, "echo":"SENTINEL-PROMPT-TEXT"}"#, None).await;
        let policy = WebhookPolicy::new(url, client());
        let err = policy
            .decide(&req(), &[cand(0)], &ctx(), Duration::from_secs(5))
            .await
            .expect_err("malformed reply must be an Err");
        let msg = err.to_string();
        assert!(
            !msg.contains("SENTINEL-PROMPT-TEXT"),
            "parse error must not echo reply bytes: {msg}"
        );
        assert!(
            msg.contains("invalid JSON"),
            "length-only parse_err_log message expected: {msg}"
        );
    }

    /// The reject verb over the webhook transport: same wire contract as the socket, so the
    /// sidecar's `{"reject":{...}}` surfaces as a `RoutingDecision::Reject` (status pre-clamped,
    /// message pre-sanitized by the shared `wire::normalize`).
    #[tokio::test]
    async fn reject_reply_surfaces_as_reject_decision() {
        let url = mock_sidecar(200, r#"{"reject":{"status":500,"message":"nope"}}"#, None).await;
        let policy = WebhookPolicy::new(url, client());
        let d = policy
            .decide(&req(), &[cand(0)], &ctx(), Duration::from_secs(5))
            .await
            .unwrap();
        // 500 is OUT of the hook-speakable range → clamped to 403 by the shared normalizer.
        assert_eq!(
            d,
            RoutingDecision::Reject {
                status: 403,
                message: "nope".to_string()
            }
        );
    }
}
