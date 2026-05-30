// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Matthew Jackson

//! ADR-0006 protocol seam: agnostic core vs. protocol-specific edges.
//! Per B-500: split the flat `Protocol` trait into Reader (wire→signal) + Writer (intent→wire),
//! bundle them in `Protocol`, and add a string-keyed registry for provider lookup.

use axum::http::{header::HeaderValue, HeaderName, StatusCode};
use std::sync::Arc;

// StatusClass and CanonicalSignal are defined in breaker.rs and re-exported here for compatibility
pub(crate) use crate::breaker::CanonicalSignal;
pub(crate) use crate::breaker::StatusClass;

/// IrError is an alias for CanonicalSignal (B-500 scaffolding).
/// Per ADR-0007: keep it compatible with CanonicalSignal; B-502 may promote to a richer struct.
#[allow(dead_code)] // Used by B-501/B-502 for IR bridge
pub(crate) type IrError = crate::breaker::CanonicalSignal;

/// ProtocolReader extracts signals from wire responses (Stage 1a + 1b).
/// Methods are provider-specific normalizers that feed the breaker's Stage 2 classifier.
pub(crate) trait ProtocolReader: Send + Sync {
    /// Extract raw error info from HTTP response without classifying.
    fn extract_error(&self, status: StatusCode, body: &[u8]) -> crate::breaker::RawUpstreamError;

    /// Classify a response into a canonical signal (two-stage pipeline).
    fn classify(&self, status: StatusCode, body: &[u8]) -> CanonicalSignal;
}

/// ProtocolWriter rewrites intents for the upstream wire format.
pub(crate) trait ProtocolWriter: Send + Sync {
    /// Returns the upstream path suffix (e.g., "/v1/messages").
    fn upstream_path(&self) -> &str;

    /// Returns auth headers given an API key.
    fn auth_headers(&self, key: &str) -> Vec<(HeaderName, HeaderValue)>;

    /// Rewrites the model field in the request body.
    fn rewrite_model(&self, body: &mut serde_json::Value, model: &str);
}

/// Bundled Protocol with name + reader + writer.
pub(crate) struct Protocol {
    name: &'static str,
    reader: Box<dyn ProtocolReader>,
    writer: Box<dyn ProtocolWriter>,
}

impl Clone for Protocol {
    fn clone(&self) -> Self {
        // Reconstruct using the same constructor - Anthropic types implement Clone
        if self.name == "anthropic" {
            Protocol::anthropic()
        } else {
            panic!("only anthropic protocol is cloneable")
        }
    }
}

impl Protocol {
    pub(crate) fn new<R, W>(name: &'static str, reader: R, writer: W) -> Self
    where
        R: ProtocolReader + 'static,
        W: ProtocolWriter + 'static,
    {
        Self {
            name,
            reader: Box::new(reader),
            writer: Box::new(writer),
        }
    }

    /// Returns the protocol name ("anthropic", "openai", etc.).
    #[allow(dead_code)] // Reserved for future extensibility (B-501)
    pub(crate) fn name(&self) -> &str {
        self.name
    }

    /// Returns the reader for this protocol.
    pub(crate) fn reader(&self) -> &dyn ProtocolReader {
        self.reader.as_ref()
    }

    /// Returns the writer for this protocol.
    pub(crate) fn writer(&self) -> &dyn ProtocolWriter {
        self.writer.as_ref()
    }

    /// Construct an Anthropic protocol instance.
    pub(crate) fn anthropic() -> Self {
        Self::new("anthropic", AnthropicReader, AnthropicWriter)
    }
}

/// Anthropic reader implementation (migrated from `Protocol::extract_error` and `classify`).
#[derive(Clone)]
pub(crate) struct AnthropicReader;

impl ProtocolReader for AnthropicReader {
    fn extract_error(&self, status: StatusCode, body: &[u8]) -> crate::breaker::RawUpstreamError {
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

/// Anthropic writer implementation (migrated from `Protocol::upstream_path`, `auth_headers`, `rewrite_model`).
#[derive(Clone)]
pub(crate) struct AnthropicWriter;

impl ProtocolWriter for AnthropicWriter {
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
}

/// String-keyed registry for protocol lookup (ADR-0008).
#[derive(Default)]
#[allow(dead_code)] // Scaffolding: not wired into App/Lane yet (B-501)
pub(crate) struct ProtocolRegistry {
    map: std::collections::HashMap<String, Arc<Protocol>>,
}

impl ProtocolRegistry {
    /// Create a new registry with built-in protocols.
    #[allow(dead_code)] // Used by B-501 for provider resolution
    pub(crate) fn with_builtins() -> Self {
        let mut map = std::collections::HashMap::new();
        map.insert("anthropic".to_string(), Arc::new(Protocol::anthropic()));
        Self { map }
    }

    /// Get a protocol by name.
    #[allow(dead_code)] // Used by B-501 for provider resolution
    pub(crate) fn get(&self, name: &str) -> Option<Arc<Protocol>> {
        self.map.get(name).cloned()
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

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::StatusCode;

    #[test]
    fn test_registry_resolves_anthropic() {
        let registry = ProtocolRegistry::with_builtins();

        // Anthropic should be present
        let protocol = registry.get("anthropic").expect("anthropic should exist");
        assert_eq!(protocol.name(), "anthropic");
        assert_eq!(protocol.writer().upstream_path(), "/v1/messages");

        // Non-existent should return None
        assert!(registry.get("nonexistent").is_none());
    }

    #[test]
    fn test_reader_classify_behavior() {
        let registry = ProtocolRegistry::with_builtins();
        let protocol = registry.get("anthropic").expect("anthropic should exist");
        let reader = protocol.reader();

        // Test 429 → RateLimit
        let signal = reader.classify(StatusCode::TOO_MANY_REQUESTS, b"{}");
        assert_eq!(signal.class, StatusClass::RateLimit);

        // Test 401 → Auth
        let signal = reader.classify(StatusCode::UNAUTHORIZED, b"{}");
        assert_eq!(signal.class, StatusClass::Auth);

        // Test 503 → ServerError
        let signal = reader.classify(StatusCode::SERVICE_UNAVAILABLE, b"{}");
        assert_eq!(signal.class, StatusClass::ServerError);
    }

    #[test]
    fn test_writer_auth_headers() {
        let registry = ProtocolRegistry::with_builtins();
        let protocol = registry.get("anthropic").expect("anthropic should exist");
        let writer = protocol.writer();

        let headers = writer.auth_headers("k");
        let header_names: Vec<&str> = headers.iter().map(|(name, _)| name.as_str()).collect();

        assert!(header_names.contains(&"x-api-key"));
        assert!(header_names.contains(&"anthropic-version"));
    }

    #[test]
    fn test_irerror_bridge() {
        // IrError IS CanonicalSignal - construct and verify
        let ir_error: IrError = IrError {
            class: StatusClass::Billing,
            provider_signal: Some("test".to_string()),
            retry_after: None,
        };

        assert_eq!(ir_error.class, StatusClass::Billing);
    }
}
