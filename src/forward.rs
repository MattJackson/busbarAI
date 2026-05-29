// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Matthew Jackson

use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::task::{Context, Poll};

use axum::{body::Body, http::header::CONTENT_TYPE, response::IntoResponse, response::Response};
use bytes::Bytes;
use futures::Stream;
use reqwest::StatusCode;
use serde_json::Value;
use tokio::sync::OwnedSemaphorePermit;

use crate::proto::{convert_headers, CanonicalSignal};
use crate::state::{now, App};

/// Body wrapper that implements the before-first-byte failover boundary (B-202).
/// Tracks when the first byte is sent and handles mid-stream errors by emitting
/// SSE error events instead of allowing failover. Also holds the permit until stream ends.
struct FirstByteBody<S, P> {
    inner: S,
    first_byte_sent: Arc<AtomicBool>,
    is_sse: bool,
    permit: Option<P>,
    app: Option<Arc<App>>,
    lane_idx: usize,
}

impl<S, P> FirstByteBody<S, P>
where
    S: Stream<Item = Result<Bytes, reqwest::Error>> + Send + 'static,
{
    fn new(inner: S, is_sse: bool, permit: P, app: Arc<App>, lane_idx: usize) -> Self {
        Self {
            inner,
            first_byte_sent: Arc::new(AtomicBool::new(false)),
            is_sse,
            permit: Some(permit),
            app: Some(app),
            lane_idx,
        }
    }
}

impl<S, P> Stream for FirstByteBody<S, P>
where
    S: Stream<Item = Result<Bytes, reqwest::Error>> + Unpin + Send + 'static,
    P: Send + Unpin + 'static,
{
    type Item = Result<Bytes, std::io::Error>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = self.get_mut();
        match Pin::new(&mut this.inner).poll_next(cx) {
            Poll::Ready(Some(Ok(chunk))) => {
                if !this.first_byte_sent.load(Ordering::Relaxed) {
                    this.first_byte_sent.store(true, Ordering::Relaxed);
                }
                Poll::Ready(Some(Ok(chunk)))
            }
            Poll::Ready(Some(Err(e))) => {
                let had_first = this.first_byte_sent.load(Ordering::Relaxed);
                if had_first && this.is_sse {
                    // Mid-stream failure after first byte in SSE mode: record breaker failure then emit SSE error event
                    if let Some(ref app) = this.app {
                        app.lanes[this.lane_idx].cooldown_transient("mid-stream");
                    }
                    let err_json = serde_json::json!({
                        "type": "error",
                        "error": {
                            "message": e.to_string(),
                            "source": "upstream"
                        }
                    });
                    let sse_error = format!("event: error\ndata: {}\n\n", err_json);
                    Poll::Ready(Some(Ok(Bytes::from(sse_error))))
                } else {
                    // Before first byte or non-SSE: propagate error (allows failover at caller level)
                    Poll::Ready(Some(Err(std::io::Error::new(
                        std::io::ErrorKind::Other,
                        e.to_string(),
                    ))))
                }
            }

            Poll::Ready(None) => {
                // Stream ended - for SSE streams that sent at least one byte, record the failure
                if this.is_sse && this.first_byte_sent.load(Ordering::Relaxed) {
                    if let Some(ref app) = this.app {
                        app.lanes[this.lane_idx].cooldown_transient("mid-stream-end");
                    }
                }
                drop(this.permit.take());
                Poll::Ready(None)
            }
            Poll::Pending => Poll::Pending,
        }
    }
}

impl<S, P> FirstByteBody<S, P> {
    fn into_body(self) -> Body
    where
        S: Stream<Item = Result<Bytes, reqwest::Error>> + Unpin + Send + 'static,
        P: Send + Unpin + 'static,
    {
        Body::from_stream(self)
    }
}

async fn pick_among(app: &Arc<App>, cands: &[usize]) -> Option<(usize, OwnedSemaphorePermit)> {
    let t = now();
    let usable: Vec<usize> = cands
        .iter()
        .copied()
        .filter(|&i| app.lanes[i].usable(t))
        .collect();
    if usable.is_empty() {
        return None;
    }
    let start = app.rr.fetch_add(1, Ordering::Relaxed);
    let order: Vec<usize> = (0..usable.len())
        .map(|k| usable[(start + k) % usable.len()])
        .collect();
    for &i in &order {
        if let Ok(p) = app.lanes[i].sem.clone().try_acquire_owned() {
            return Some((i, p));
        }
    }
    let futs: Vec<_> = order
        .iter()
        .map(|&i| {
            let sem = app.lanes[i].sem.clone();
            Box::pin(async move { (i, sem.acquire_owned().await.unwrap()) })
        })
        .collect();
    let ((i, p), _, _) = futures::future::select_all(futs).await;
    Some((i, p))
}

pub(crate) async fn forward(app: Arc<App>, cands: Vec<usize>, body: Bytes) -> Response {
    let mut v: Value = match serde_json::from_slice(&body) {
        Ok(v) => v,
        Err(e) => {
            return (StatusCode::BAD_REQUEST, format!("router: bad json: {e}")).into_response()
        }
    };

    // Before-first-byte failover boundary (B-202):
    // Failover is allowed ONLY until the first upstream byte reaches the client.
    // After that point, an upstream failure must NOT trigger failover because
    // the client already has a partial response. Instead:
    // - For SSE streams: emit an SSE `error` event and terminate the stream
    // - Record the breaker failure for that lane (the member tripped)
    // The client must restart the request itself after receiving the error event.

    let attempts = cands.len() + 2;
    for _attempt in 0..attempts {
        let (i, permit) = match pick_among(&app, &cands).await {
            Some(x) => x,
            None => {
                return (StatusCode::SERVICE_UNAVAILABLE, "router: no usable lane").into_response()
            }
        };

        let proto = app.lanes[i].protocol.as_ref();
        proto.rewrite_model(&mut v, &app.lanes[i].model);
        let payload = serde_json::to_vec(&v).unwrap();
        let base = &app.lanes[i].base_url;
        let key = &app.lanes[i].api_key;
        app.lanes[i].inflight.fetch_add(1, Ordering::Relaxed);

        let res = app
            .client
            .post(format!("{base}{}", proto.upstream_path()))
            .headers(convert_headers(proto.auth_headers(key)))
            .header(CONTENT_TYPE, "application/json")
            .body(payload)
            .send()
            .await;

        app.lanes[i].inflight.fetch_sub(1, Ordering::Relaxed);

        match res {
            Err(e) => {
                // Pre-response error: classify and potentially failover
                let err_type = if e.is_timeout() { "timeout" } else { "connect" };
                app.lanes[i].cooldown_transient(err_type);
                drop(permit);
                continue;
            }
            Ok(r) => {
                let status = r.status();

                // For non-2xx responses, read the body to classify (failover allowed)
                if !status.is_success() {
                    let bytes = r.bytes().await.unwrap_or_default();
                    match proto.classify(status, &bytes) {
                        CanonicalSignal {
                            class: "billing", ..
                        } => {
                            app.lanes[i].kill("billing / insufficient balance (1113)");
                            drop(permit);
                            continue;
                        }
                        CanonicalSignal { class: "auth", .. } => {
                            app.lanes[i].kill(&format!("auth rejected (HTTP {})", status.as_u16()));
                            drop(permit);
                            continue;
                        }
                        CanonicalSignal {
                            class: "rate_limit",
                            ..
                        } => {
                            app.lanes[i].cooldown_rate_limit();
                            drop(permit);
                            continue;
                        }
                        CanonicalSignal {
                            class: "transient", ..
                        } => {
                            app.lanes[i].cooldown_transient("5xx");
                            drop(permit);
                            continue;
                        }
                        CanonicalSignal { class, .. } => {
                            app.lanes[i].cooldown_transient(&format!("unknown-{class}"));
                            drop(permit);
                            continue;
                        }
                    }
                }

                // SUCCESS case: stream the response body incrementally with first-byte boundary tracking (B-202)
                let ct = r.headers().get(CONTENT_TYPE).cloned();
                let is_sse = ct
                    .as_ref()
                    .map(|h| h.to_str().unwrap_or("").starts_with("text/event-stream"))
                    .unwrap_or(false);

                // B-202: Use FirstByteBody wrapper to track first byte and emit SSE error events on mid-stream failures
                let upstream_stream = r.bytes_stream();
                let guarded_body =
                    FirstByteBody::new(upstream_stream, is_sse, permit, app.clone(), i);
                let axum_body = guarded_body.into_body();

                let mut rb = Response::builder().status(status);
                if let Some(ct) = ct {
                    rb = rb.header(CONTENT_TYPE, ct);
                }
                return rb.body(axum_body).unwrap();
            }
        }
    }

    (
        StatusCode::SERVICE_UNAVAILABLE,
        "router: all lanes exhausted",
    )
        .into_response()
}
