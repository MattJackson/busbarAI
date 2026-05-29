// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Matthew Jackson

//! ADR-0006 protocol seam: agnostic core vs. protocol-specific edges.
//! This module defines the `Protocol` trait and the `AnthropicProtocol` implementation.
//! The agnostic core never names a wire format; protocol specifics live behind this trait.

use axum::http::{header::HeaderValue, HeaderName, StatusCode};

/// Canonical signal emitted by a protocol when classifying an error response.
#[derive(Debug, Clone)]
#[allow(dead_code)] // Fields used for future extensibility (B-301, ADR-0005)
pub(crate) struct CanonicalSignal {
    /// Class of the signal (e.g., "billing", "auth", "rate_limit", "transient").
    pub(crate) class: &'static str,
    /// Provider-specific signal code or description.
    pub(crate) provider_signal: Option<&'static str>,
    /// Optional retry-after seconds for rate-limiting scenarios.
    pub(crate) retry_after: Option<u64>,
}

/// Protocol abstraction for upstream LLM providers (Anthropic, OpenAI, etc.).
/// Per ADR-0006, the agnostic core calls this trait instead of naming wire-format literals.
#[allow(dead_code)] // name() reserved for future extensibility
pub(crate) trait Protocol: Send + Sync {
    /// Returns the protocol name ("anthropic", "openai", etc.).
    fn name(&self) -> &str;

    /// Returns the upstream path suffix (e.g., "/v1/messages").
    fn upstream_path(&self) -> &str;

    /// Returns auth headers given an API key.
    fn auth_headers(&self, key: &str) -> Vec<(HeaderName, HeaderValue)>;

    /// Rewrites the model field in the request body.
    fn rewrite_model(&self, body: &mut serde_json::Value, model: &str);

    /// Classifies a response into a canonical signal.
    /// Per A3 (ADR-0006): prefer HTTP status + structured error type first;
    /// body substrings are fallback for known provider codes.
    fn classify(&self, status: StatusCode, body: &[u8]) -> CanonicalSignal;
}

/// Anthropic protocol implementation.
/// Reproduces TODAY's exact behavior: path `/v1/messages`, auth headers, model rewrite,
/// and classification logic per A3 (status + structured error type first).
#[derive(Clone)]
pub(crate) struct AnthropicProtocol;

impl AnthropicProtocol {
    pub(crate) fn new() -> Self {
        Self
    }
}

impl Default for AnthropicProtocol {
    fn default() -> Self {
        Self::new()
    }
}

impl Protocol for AnthropicProtocol {
    fn name(&self) -> &str {
        "anthropic"
    }

    fn upstream_path(&self) -> &str {
        "/v1/messages"
    }

    fn auth_headers(&self, key: &str) -> Vec<(HeaderName, HeaderValue)> {
        vec![
            (
                HeaderName::from_static("x-api-key"),
                HeaderValue::from_str(key).expect("api key is valid"),
            ),
            (
                HeaderName::from_static("authorization"),
                HeaderValue::from_str(&format!("Bearer {}", key)).expect("bearer token is valid"),
            ),
            (
                HeaderName::from_static("anthropic-version"),
                HeaderValue::from_static("2023-06-01"),
            ),
        ]
    }

    fn rewrite_model(&self, body: &mut serde_json::Value, model: &str) {
        if let Some(obj) = body.as_object_mut() {
            obj.insert("model".to_string(), serde_json::json!(model));
        }
    }

    fn classify(&self, status: StatusCode, body: &[u8]) -> CanonicalSignal {
        let text = String::from_utf8_lossy(body);

        // A3: prefer HTTP status first, then structured error codes, then substrings as fallback.

        // Billing (1113 / insufficient balance) — provider-specific code takes precedence
        if body.windows(4).any(|w| w == b"1113") || text.contains("nsufficient balance") {
            return CanonicalSignal {
                class: "billing",
                provider_signal: Some("1113"),
                retry_after: None,
            };
        }

        // Auth (401/403)
        if status.as_u16() == 401 || status.as_u16() == 403 {
            return CanonicalSignal {
                class: "auth",
                provider_signal: None,
                retry_after: None,
            };
        }

        // Rate limit (429 / z.ai 1302 / rate_limit strings)
        if status.as_u16() == 429
            || body.windows(4).any(|w| w == b"1302")
            || text.contains("rate_limit")
            || text.contains("Rate limit")
        {
            return CanonicalSignal {
                class: "rate_limit",
                provider_signal: None,
                retry_after: None,
            };
        }

        // 5xx transient
        if status.as_u16() >= 500 {
            return CanonicalSignal {
                class: "transient",
                provider_signal: Some("5xx"),
                retry_after: None,
            };
        }

        // Default: relay (2xx, 4xx non-problematic)
        CanonicalSignal {
            class: "relay",
            provider_signal: None,
            retry_after: None,
        }
    }
}

pub(crate) fn convert_headers(
    headers: Vec<(HeaderName, HeaderValue)>,
) -> reqwest::header::HeaderMap {
    let mut map = reqwest::header::HeaderMap::new();
    for (name, value) in headers {
        map.insert(name, value);
    }
    map
}
