// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Matthew Jackson

use axum::{
    body::Body,
    extract::State,
    http::{Request, Response, StatusCode},
    routing::any,
    Router,
};
use serde_json::Value;
use std::net::SocketAddr;
use std::sync::Mutex;
use tokio::task::JoinHandle;

#[derive(Debug, Clone)]
pub enum MockResponse {
    Ok {
        status: StatusCode,
        body: Value,
    },
    RateLimit {
        status: StatusCode,
        provider_signal: Option<&'static str>,
    },
    Billing {
        status: StatusCode,
        code: &'static str,
        message: &'static str,
    },
    Auth {
        status: StatusCode,
    },
    ClientError {
        status: StatusCode,
        body: Value,
    },
    ServerError {
        status: StatusCode,
        body: Value,
    },
}

impl Default for MockResponse {
    fn default() -> Self {
        MockResponse::Ok {
            status: StatusCode::OK,
            body: serde_json::json!({ "ok": true }),
        }
    }
}

#[derive(Debug)]
pub struct MockServerState {
    responses: Mutex<Vec<MockResponse>>,
}

impl MockServerState {
    pub fn new() -> Self {
        Self {
            responses: Mutex::new(Vec::new()),
        }
    }

    pub fn push(&self, response: MockResponse) {
        self.responses.lock().unwrap().push(response);
    }

    pub fn next_response(&self) -> Option<MockResponse> {
        self.responses.lock().unwrap().pop()
    }
}

impl Default for MockServerState {
    fn default() -> Self {
        Self::new()
    }
}

pub struct MockServer {
    addr: SocketAddr,
    state: std::sync::Arc<MockServerState>,
    handle: Option<JoinHandle<()>>,
}

impl MockServer {
    pub async fn new(state: std::sync::Arc<MockServerState>) -> Self {
        let app = Router::new()
            .route("/v1/messages", any(mock_handler))
            .with_state(state.clone());

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let handle = tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });

        Self {
            addr,
            state,
            handle: Some(handle),
        }
    }

    pub fn address(&self) -> SocketAddr {
        self.addr
    }

    pub fn base_url(&self) -> String {
        format!("http://{}", self.addr)
    }

    pub async fn shutdown(self) {
        if let Some(handle) = self.handle {
            handle.abort();
        }
    }
}

async fn mock_handler(
    State(state): State<std::sync::Arc<MockServerState>>,
    _request: Request<Body>,
) -> Response<Body> {
    use axum::http::header;

    let response = state
        .next_response()
        .unwrap_or_else(|| MockResponse::default());

    match response {
        MockResponse::Ok { status, body } => Response::builder()
            .status(status)
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(body.to_string()))
            .unwrap(),

        MockResponse::RateLimit {
            status,
            provider_signal,
        } => {
            let body = serde_json::json!({
                "error": {
                    "message": if provider_signal == Some("1302") {
                        "rate_limit"
                    } else {
                        "Rate limit exceeded"
                    },
                    "code": provider_signal.unwrap_or("429"),
                }
            });
            Response::builder()
                .status(status)
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(body.to_string()))
                .unwrap()
        }

        MockResponse::Billing {
            status,
            code,
            message,
        } => {
            let body = serde_json::json!({
                "error": {
                    "message": message,
                    "code": code,
                }
            });
            Response::builder()
                .status(status)
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(body.to_string()))
                .unwrap()
        }

        MockResponse::Auth { status } => {
            let body = serde_json::json!({
                "error": "Unauthorized"
            });
            Response::builder()
                .status(status)
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(body.to_string()))
                .unwrap()
        }

        MockResponse::ClientError { status, body } => Response::builder()
            .status(status)
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(body.to_string()))
            .unwrap(),

        MockResponse::ServerError { status, body } => Response::builder()
            .status(status)
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(body.to_string()))
            .unwrap(),
    }
}
