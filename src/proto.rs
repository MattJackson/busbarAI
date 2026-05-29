// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Matthew Jackson

//! ADR-0006 protocol seam: agnostic core vs. protocol-specific edges.
//! This module defines the `Protocol` trait and the `AnthropicProtocol` implementation.
//! The agnostic core never names a wire format; protocol specifics live behind this trait.

use axum::http::{header::HeaderValue, HeaderName, StatusCode};

// StatusClass and CanonicalSignal are defined in breaker.rs and re-exported here for compatibility
pub(crate) use crate::breaker::CanonicalSignal;
pub(crate) use crate::breaker::StatusClass;

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

    /// Extracts raw error information from HTTP response (Stage 1a).
    /// Returns structured data without classifying — classification is provider-specific via error_map.
    fn extract_error(&self, status: StatusCode, body: &[u8]) -> crate::breaker::RawUpstreamError;

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

    fn extract_error(&self, status: StatusCode, body: &[u8]) -> crate::breaker::RawUpstreamError {
        // Stage 1a: Extract raw error info without classifying (classification is per-provider via error_map)
        let provider_code = if let Ok(json) = serde_json::from_slice::<serde_json::Value>(body) {
            json.get("error")
                .and_then(|e| e.get("code"))
                .and_then(|c| c.as_str())
                .map(String::from)
        } else {
            None
        };

        let structured_type = if let Ok(json) = serde_json::from_slice::<serde_json::Value>(body) {
            json.get("error")
                .and_then(|e| e.get("type"))
                .and_then(|t| t.as_str())
                .map(String::from)
        } else {
            None
        };

        crate::breaker::RawUpstreamError {
            http_status: status.as_u16(),
            provider_code,
            structured_type,
        }
    }

    fn classify(&self, status: StatusCode, body: &[u8]) -> CanonicalSignal {
        let text = String::from_utf8_lossy(body);

        // A3: prefer HTTP status first, then structured error codes, then substrings as fallback.
        if let Ok(json) = serde_json::from_slice::<serde_json::Value>(body) {
            if let Some(code_val) = json.get("error").and_then(|e| e.get("code")) {
                if code_val.as_str() == Some("400") || code_val.as_str() == Some("422") {
                    return CanonicalSignal {
                        class: StatusClass::ClientError,
                        provider_signal: Some("client_error".to_string()),
                        retry_after: None,
                    };
                }

                if let Some(msg_val) = json.get("error").and_then(|e| e.get("message")) {
                    if let Some(msg_str) = msg_val.as_str() {
                        if msg_str.contains("nsufficient balance") {
                            return CanonicalSignal {
                                class: StatusClass::Billing,
                                provider_signal: Some("billing".to_string()),
                                retry_after: None,
                            };
                        }
                        if msg_str.contains("unauthorized") || msg_str.contains("invalid token") {
                            return CanonicalSignal {
                                class: StatusClass::Auth,
                                provider_signal: Some("auth".to_string()),
                                retry_after: None,
                            };
                        }
                    }
                }
            }
        }

        if status.as_u16() == 401 || status.as_u16() == 403 {
            return CanonicalSignal {
                class: StatusClass::Auth,
                provider_signal: None,
                retry_after: None,
            };
        }

        if status.as_u16() == 429 {
            let text_lower = text.to_lowercase();
            if text_lower.contains("quota") && text_lower.contains("exhausted") {
                return CanonicalSignal {
                    class: StatusClass::Billing,
                    provider_signal: Some("429-quota-exhausted".to_string()),
                    retry_after: None,
                };
            }
            return CanonicalSignal {
                class: StatusClass::RateLimit,
                provider_signal: Some("429-slowdown".to_string()),
                retry_after: None,
            };
        }

        if status.as_u16() >= 500 {
            return CanonicalSignal {
                class: StatusClass::ServerError,
                provider_signal: Some("5xx".to_string()),
                retry_after: None,
            };
        }

        if status.is_client_error() {
            return CanonicalSignal {
                class: StatusClass::ClientError,
                provider_signal: None,
                retry_after: None,
            };
        }

        CanonicalSignal {
            class: StatusClass::ClientError,
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
