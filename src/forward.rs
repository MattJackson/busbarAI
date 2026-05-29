// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Matthew Jackson

use std::sync::atomic::Ordering;
use std::sync::Arc;

use axum::{body::Body, http::header::CONTENT_TYPE, response::IntoResponse, response::Response};
use futures::StreamExt;
use reqwest::StatusCode;
use serde_json::Value;
use tokio::sync::OwnedSemaphorePermit;

use crate::proto::{convert_headers, CanonicalSignal};
use crate::state::{now, App};

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

use axum::body::Bytes;

pub(crate) async fn forward(app: Arc<App>, cands: Vec<usize>, body: Bytes) -> Response {
    let mut v: Value = match serde_json::from_slice(&body) {
        Ok(v) => v,
        Err(e) => {
            return (StatusCode::BAD_REQUEST, format!("router: bad json: {e}")).into_response()
        }
    };
    let attempts = cands.len() + 2;
    for _ in 0..attempts {
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
                app.lanes[i].cooldown_transient(if e.is_timeout() { "timeout" } else { "connect" });
                drop(permit);
                continue;
            }
            Ok(r) => {
                let status = r.status();

                // For non-2xx responses, read the body to classify (as before)
                if !status.is_success() {
                    let bytes = r.bytes().await.unwrap_or_default();
                    match proto.classify(status, &bytes) {
                        CanonicalSignal {
                            class: "billing", ..
                        } => {
                            app.lanes[i].kill("billing / insufficient balance (1113)");
                            continue;
                        }
                        CanonicalSignal { class: "auth", .. } => {
                            app.lanes[i].kill(&format!("auth rejected (HTTP {})", status.as_u16()));
                            continue;
                        }
                        CanonicalSignal {
                            class: "rate_limit",
                            ..
                        } => {
                            app.lanes[i].cooldown_rate_limit();
                            continue;
                        }
                        CanonicalSignal {
                            class: "transient", ..
                        } => {
                            app.lanes[i].cooldown_transient("5xx");
                            continue;
                        }
                        CanonicalSignal { class: _, .. } => {
                            app.lanes[i].cooldown_transient("unknown");
                            continue;
                        }
                    }
                } else {
                    // SUCCESS case: stream the response body incrementally
                    let ct = r.headers().get(CONTENT_TYPE).cloned();

                    let upstream_stream = r.bytes_stream();
                    let guarded = futures::stream::unfold(
                        (upstream_stream, Some(permit)),
                        |(mut s, permit)| async move {
                            match s.next().await {
                                Some(Ok(chunk)) => Some((Ok(chunk), (s, permit))),
                                Some(Err(e)) => Some((
                                    Err(std::io::Error::new(
                                        std::io::ErrorKind::Other,
                                        e.to_string(),
                                    )),
                                    (s, permit),
                                )),
                                None => {
                                    drop(permit);
                                    None
                                }
                            }
                        },
                    );

                    let axum_body = Body::from_stream(guarded);

                    let mut rb = Response::builder().status(status);
                    if let Some(ct) = ct {
                        rb = rb.header(CONTENT_TYPE, ct);
                    }
                    return rb.body(axum_body).unwrap();
                }
            }
        }
    }
    (
        StatusCode::SERVICE_UNAVAILABLE,
        "router: all lanes exhausted",
    )
        .into_response()
}
