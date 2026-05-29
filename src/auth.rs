// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Matthew Jackson

#![allow(dead_code, private_interfaces)]

use std::sync::Arc;

use axum::{
    body::Body,
    extract::State,
    http::{header::AUTHORIZATION, Request, StatusCode},
    middleware::Next,
    response::Response,
};

use crate::config::AuthCfg;
use crate::state::App;

/// AuthMode is an exhaustive enum for runtime authentication behavior.
#[derive(Debug, Clone, Copy, PartialEq)]
pub(crate) enum AuthMode {
    /// Require a client token matching the allowlist in Authorization: Bearer <token>.
    Token,
    /// Forward caller's key to upstream (passthrough); 401/403 attributed to caller.
    Passthrough,
    /// Open relay; no auth required.
    None,
}

/// AuthMiddleware holds the resolved auth mode and token allowlist.
#[allow(dead_code)]
#[derive(Debug)]
pub struct AuthMiddleware {
    pub mode: AuthMode,
    pub client_tokens: Vec<String>,
}

impl AuthMiddleware {
    pub fn new(cfg: &AuthCfg) -> Self {
        let mode = match cfg.mode.as_str() {
            "token" => AuthMode::Token,
            "passthrough" => AuthMode::Passthrough,
            "none" => AuthMode::None,
            other => {
                panic!("invalid auth mode '{other}': must be 'token', 'passthrough', or 'none'")
            }
        };

        // Expand env vars in client_tokens (B-102 interpolation pass)
        let tokens: Vec<String> = cfg
            .client_tokens
            .iter()
            .map(|t| {
                crate::config::interpolate_env(t).expect("env var expansion in auth.client_tokens")
            })
            .collect();

        if mode == AuthMode::None && tokens.is_empty() {
            eprintln!(
                "[warn] auth.mode=none (open relay) — only acceptable for dev; reject in production"
            );
        }

        Self {
            mode,
            client_tokens: tokens,
        }
    }

    /// Constant-time comparison to prevent timing attacks.
    fn constant_time_eq(a: &str, b: &str) -> bool {
        let a_bytes = a.as_bytes();
        let b_bytes = b.as_bytes();

        if a_bytes.len() != b_bytes.len() {
            return false;
        }

        // XOR all bytes and OR the results together. If any bit differs, result > 0.
        let mut result: u8 = 0;
        for (x, y) in a_bytes.iter().zip(b_bytes.iter()) {
            result |= x ^ y;
        }

        result == 0
    }

    /// Extract Bearer token from Authorization header if present.
    fn extract_bearer_token(auth_header: Option<&str>) -> Option<String> {
        auth_header.and_then(|h| {
            if h.len() > 7 && h[..7].eq_ignore_ascii_case("Bearer ") {
                Some(h[7..].to_string())
            } else {
                None
            }
        })
    }

    /// Validate the request's token against the allowlist.
    pub(crate) fn validate_token(&self, auth_header: Option<&str>) -> bool {
        match self.mode {
            AuthMode::Token => {
                let Some(token) = Self::extract_bearer_token(auth_header) else {
                    return false;
                };

                // Constant-time compare against each allowed token.
                self.client_tokens
                    .iter()
                    .any(|allowed| Self::constant_time_eq(&token, allowed))
            }
            AuthMode::Passthrough | AuthMode::None => true,
        }
    }
}

/// Axum middleware layer that validates auth before routing.
#[allow(dead_code)] // used at runtime, not in tests
pub(crate) async fn auth_middleware(
    State(app): State<Arc<App>>,
    req: Request<Body>,
    next: Next,
) -> Result<Response, (StatusCode, &'static str)> {
    let auth_header = req
        .headers()
        .get(AUTHORIZATION)
        .and_then(|v| v.to_str().ok());

    // /healthz is always open (per spec decision).
    let path = req.uri().path();
    if path == "/healthz" {
        return Ok(next.run(req).await);
    }

    // /stats requires auth by default (per spec decision).
    if !app.auth.validate_token(auth_header) {
        return Err((StatusCode::UNAUTHORIZED, "unauthorized"));
    }

    Ok(next.run(req).await)
}

#[cfg(test)]
#[allow(deprecated)] // allow deprecated field access in tests
mod tests {
    use super::*;

    #[test]
    fn test_constant_time_eq_same() {
        assert!(AuthMiddleware::constant_time_eq("secret", "secret"));
    }

    #[test]
    fn test_constant_time_eq_different_length() {
        assert!(!AuthMiddleware::constant_time_eq("short", "longer"));
    }

    #[test]
    fn test_constant_time_eq_one_char_diff() {
        assert!(!AuthMiddleware::constant_time_eq("secret1", "secret2"));
    }

    #[test]
    fn test_extract_bearer_token_valid() {
        let token = AuthMiddleware::extract_bearer_token(Some("Bearer mytoken123"));
        assert_eq!(token, Some("mytoken123".to_string()));
    }

    #[test]
    fn test_extract_bearer_token_case_insensitive() {
        let token = AuthMiddleware::extract_bearer_token(Some("BEARER mytoken123"));
        assert_eq!(token, Some("mytoken123".to_string()));
    }

    #[test]
    fn test_extract_bearer_token_no_bearer() {
        let token = AuthMiddleware::extract_bearer_token(Some("mytoken123"));
        assert_eq!(token, None);
    }

    #[test]
    fn test_extract_bearer_token_none() {
        let token = AuthMiddleware::extract_bearer_token(None);
        assert_eq!(token, None);
    }

    #[test]
    fn test_auth_mode_token_valid() {
        let cfg = AuthCfg {
            mode: "token".to_string(),
            client_tokens: vec!["tok1".to_string(), "tok2".to_string()],
            _legacy_token: None, // deprecated but needed for tests
        };
        let mw = AuthMiddleware::new(&cfg);

        assert!(mw.validate_token(Some("Bearer tok1")));
        assert!(mw.validate_token(Some("Bearer tok2")));
        assert!(!mw.validate_token(Some("Bearer tok3")));
        assert!(!mw.validate_token(None));
    }

    #[test]
    fn test_auth_mode_passthrough() {
        let cfg = AuthCfg {
            mode: "passthrough".to_string(),
            client_tokens: vec![],
            _legacy_token: None, // deprecated but needed for tests
        };
        let mw = AuthMiddleware::new(&cfg);

        // Passthrough allows all (auth is upstream's responsibility)
        assert!(mw.validate_token(None));
        assert!(mw.validate_token(Some("Bearer anything")));
    }

    #[test]
    fn test_auth_mode_none() {
        let cfg = AuthCfg {
            mode: "none".to_string(),
            client_tokens: vec![],
            _legacy_token: None, // deprecated but needed for tests
        };
        let mw = AuthMiddleware::new(&cfg);

        // None allows all (open relay)
        assert!(mw.validate_token(None));
        assert!(mw.validate_token(Some("Bearer anything")));
    }

    #[test]
    fn test_auth_mode_invalid() {
        let cfg = AuthCfg {
            mode: "invalid".to_string(),
            client_tokens: vec![],
            _legacy_token: None, // deprecated but needed for tests
        };

        // Should panic on invalid mode
        assert!(std::panic::catch_unwind(|| AuthMiddleware::new(&cfg)).is_err());
    }
}
