// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Matthew Jackson

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

impl AuthMode {
    /// The wire/config spellings of each mode — the single source of truth for the `auth.mode`
    /// strings (used by parsing, validation, and the config default), so no comparison site
    /// hardcodes them.
    pub(crate) const TOKEN: &'static str = "token";
    pub(crate) const PASSTHROUGH: &'static str = "passthrough";
    pub(crate) const NONE: &'static str = "none";

    /// Parse the config `auth.mode` value (case-insensitive, trimmed). `None` if unrecognized.
    pub(crate) fn from_config_str(s: &str) -> Option<AuthMode> {
        match s.trim().to_ascii_lowercase().as_str() {
            Self::TOKEN => Some(AuthMode::Token),
            Self::PASSTHROUGH => Some(AuthMode::Passthrough),
            Self::NONE => Some(AuthMode::None),
            _ => None,
        }
    }
}

/// The caller's bearer token, threaded into request extensions by `auth_middleware` so handlers can
/// forward it upstream in passthrough mode. `None` when no usable bearer token was presented.
#[derive(Clone, Default)]
pub(crate) struct CallerToken(pub(crate) Option<String>);

/// AuthMiddleware holds the resolved auth mode and token allowlist.
#[derive(Debug)]
pub(crate) struct AuthMiddleware {
    pub(crate) mode: AuthMode,
    pub(crate) client_tokens: Vec<String>,
}

impl AuthMiddleware {
    pub(crate) fn new(cfg: &AuthCfg) -> Self {
        // Config is validated before this point (see config_validate), so an unknown mode here is a
        // programming error rather than user error.
        let mode = AuthMode::from_config_str(&cfg.mode).unwrap_or_else(|| {
            panic!(
                "invalid auth mode '{}': must be '{}', '{}', or '{}'",
                cfg.mode,
                AuthMode::TOKEN,
                AuthMode::PASSTHROUGH,
                AuthMode::NONE
            )
        });

        // client_tokens are already env-interpolated: `interpolate_env` runs over the WHOLE
        // config.yaml text once at load (main.rs), before deserialization. A second per-token pass
        // here would double-interpolate — a token that legitimately contains the literal `${...}`
        // (legal in opaque API keys) would be re-expanded or abort startup via `.expect`. Interpolate
        // exactly once; just clone the resolved values.
        let tokens: Vec<String> = cfg.client_tokens.clone();

        if mode == AuthMode::None && tokens.is_empty() {
            tracing::warn!(
                "auth.mode=none (open relay) — only acceptable for dev; reject in production"
            );
        }

        Self {
            mode,
            client_tokens: tokens,
        }
    }

    /// Constant-time string comparison to avoid leaking how much of a token matches via timing.
    /// `#[inline(never)]` + `black_box` keep the optimizer from turning the accumulation loop into
    /// an early-exit branch (which would reintroduce a timing signal). The length check is a
    /// deliberate fast-path: token *length* is not treated as secret.
    #[inline(never)]
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

        std::hint::black_box(result) == 0
    }

    /// Extract the token from an `Authorization: Bearer <token>` header (scheme match is
    /// case-insensitive). Splits on the first space rather than byte-slicing, so a malformed header
    /// with a multibyte character in the scheme position can't panic on a UTF-8 boundary.
    fn extract_bearer_token(auth_header: Option<&str>) -> Option<String> {
        let (scheme, token) = auth_header?.split_once(' ')?;
        if scheme.eq_ignore_ascii_case("bearer") && !token.is_empty() {
            Some(token.to_string())
        } else {
            None
        }
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
pub(crate) async fn auth_middleware(
    State(app): State<Arc<App>>,
    mut req: Request<Body>,
    next: Next,
) -> Result<Response, (StatusCode, &'static str)> {
    let auth_header = req
        .headers()
        .get(AUTHORIZATION)
        .and_then(|v| v.to_str().ok());

    // /healthz and /metrics are always open: liveness and Prometheus scraping must not require a
    // caller token (operators protect /metrics at the network layer if needed).
    let path = req.uri().path();
    if path == "/healthz" || path == "/metrics" {
        return Ok(next.run(req).await);
    }

    // Derive owned values up front so no immutable borrow of `req` is live when we mutate its
    // extensions below.
    let is_admin = path.starts_with("/admin");
    let admin_header_token = req
        .headers()
        .get("x-admin-token")
        .and_then(|v| v.to_str().ok())
        .map(String::from);
    let token_valid = app.auth.validate_token(auth_header);
    // Use the same case-insensitive, panic-safe extraction as the client-token path.
    let bearer_token: Option<String> = AuthMiddleware::extract_bearer_token(auth_header);

    // the /admin management API is guarded by the configured admin token (Bearer or
    // X-Admin-Token) — NOT a virtual key. Disabled (401) when no admin token is configured.
    if is_admin {
        let configured = app.governance.as_ref().and_then(|g| g.admin_token());
        let authorized = match configured {
            // Constant-time compare so the admin token can't be recovered byte-by-byte via a timing
            // side channel (matches the client-token path).
            Some(t) => {
                bearer_token
                    .as_deref()
                    .is_some_and(|b| AuthMiddleware::constant_time_eq(b, t))
                    || admin_header_token
                        .as_deref()
                        .is_some_and(|h| AuthMiddleware::constant_time_eq(h, t))
            }
            None => false,
        };
        if !authorized {
            return Err((StatusCode::UNAUTHORIZED, "admin unauthorized"));
        }
        req.extensions_mut()
            .insert(crate::governance::GovCtx::default());
        return Ok(next.run(req).await);
    }

    // when governance is enabled, the caller's Bearer token MUST resolve to an enabled
    // virtual key; the resolved key is attached for downstream allowed-pools enforcement. This
    // supersedes the static AuthMode token check. When governance is disabled, the existing
    // AuthMode (None/Token/Passthrough) applies unchanged.
    if let Some(gov) = &app.governance {
        match gov.lookup(bearer_token.as_deref().unwrap_or("")) {
            Some(key) if key.enabled => {
                req.extensions_mut()
                    .insert(crate::governance::GovCtx { key: Some(key) });
            }
            _ => return Err((StatusCode::UNAUTHORIZED, "invalid or disabled virtual key")),
        }
    } else {
        // /stats requires auth by default (per spec decision).
        if !token_valid {
            return Err((StatusCode::UNAUTHORIZED, "unauthorized"));
        }
        req.extensions_mut()
            .insert(crate::governance::GovCtx::default());
    }

    // Thread the caller's Bearer token into request extensions for passthrough forwarding. Always
    // inserted (even when None) so the `Extension<CallerToken>` extractor in handlers never fails.
    req.extensions_mut().insert(CallerToken(bearer_token));

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
    fn test_extract_bearer_token_malformed_no_panic() {
        // A multibyte char in the scheme position must not panic (was a `h[..7]` UTF-8 boundary bug).
        assert_eq!(AuthMiddleware::extract_bearer_token(Some("Béarer x")), None);
        assert_eq!(AuthMiddleware::extract_bearer_token(Some("🔑🔑🔑")), None);
        assert_eq!(AuthMiddleware::extract_bearer_token(Some("Bearer ")), None); // empty token
        assert_eq!(
            AuthMiddleware::extract_bearer_token(Some("Basic abc")),
            None
        );
    }

    #[test]
    fn test_auth_mode_from_config_str() {
        assert_eq!(AuthMode::from_config_str("token"), Some(AuthMode::Token));
        assert_eq!(
            AuthMode::from_config_str("  PassThrough "),
            Some(AuthMode::Passthrough)
        );
        assert_eq!(AuthMode::from_config_str("NONE"), Some(AuthMode::None));
        assert_eq!(AuthMode::from_config_str("bogus"), None);
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

    #[test]
    fn test_client_tokens_not_double_interpolated() {
        // A client token that legitimately contains the literal `${...}` (legal in opaque API keys)
        // must be passed through verbatim — the whole config file is already env-interpolated once
        // at load, so AuthMiddleware::new must NOT interpolate again (which would re-expand or panic
        // on an unset var). Regression for the dropped second interpolation pass.
        let raw = "sk-${NOT_A_REAL_ENV_VAR}-suffix";
        let cfg = AuthCfg {
            mode: "token".to_string(),
            client_tokens: vec![raw.to_string()],
            _legacy_token: None,
        };
        // Must not panic even though NOT_A_REAL_ENV_VAR is unset.
        let mw = AuthMiddleware::new(&cfg);
        assert_eq!(mw.client_tokens, vec![raw.to_string()]);
        // And the verbatim token authenticates (it was not mangled by a second expansion pass).
        assert!(mw.validate_token(Some(&format!("Bearer {raw}"))));
    }

    /// End-to-end through the real router + `auth_middleware`: a virtual key with `enabled: false`
    /// must be rejected with 401, while the same secret on an enabled key is admitted. Guards the
    /// `Some(key) if key.enabled => ... else 401` authz path, which had no test (a regression that
    /// dropped the `if key.enabled` guard would otherwise pass CI — an authz bypass).
    #[tokio::test]
    async fn test_disabled_virtual_key_is_rejected_401() {
        use crate::governance::{GovState, SqliteStore, Store, VirtualKey};
        use crate::test_support::{LaneSpec, MockResponse, MockServer, MockServerState, TestApp};
        use serde_json::json;
        use std::sync::Arc;

        crate::metrics::init();

        // Mock upstream that returns a valid Anthropic-shaped body, so an ADMITTED request reaches
        // 200 rather than failing for an unrelated reason.
        let state = Arc::new(MockServerState::new());
        state.push(MockResponse::Ok {
            status: axum::http::StatusCode::OK,
            body: json!({
                "model": "glm-4.5",
                "choices": [{"index": 0, "message": {"role": "assistant", "content": "hi"}, "finish_reason": "stop"}],
                "usage": {"prompt_tokens": 1, "completion_tokens": 1}
            }),
        });
        let server = MockServer::new(state).await;

        let disabled_secret = "sk-vk-disabled";
        let enabled_secret = "sk-vk-enabled";
        let store = Arc::new(SqliteStore::open_in_memory().unwrap());
        let mk = |id: &str, secret: &str, enabled: bool| VirtualKey {
            id: id.to_string(),
            key_hash: crate::sigv4::sha256_hex(secret.as_bytes()),
            name: id.to_string(),
            allowed_pools: vec!["pa".to_string()],
            max_budget_cents: None,
            budget_period: "total".to_string(),
            rpm_limit: None,
            tpm_limit: None,
            enabled,
            created_at: 0,
        };
        store.put_key(&mk("kdis", disabled_secret, false)).unwrap();
        store.put_key(&mk("kena", enabled_secret, true)).unwrap();
        let gov = Arc::new(GovState::new(store, 0, 0, None).unwrap());

        let app = TestApp::new()
            .lane(
                LaneSpec::new(
                    "glm-4.5",
                    crate::proto::Protocol::openai(),
                    &server.base_url(),
                )
                .provider("zai"),
            )
            .pool("pa", &[(0, 1)])
            .governance(gov)
            .build();

        let router = crate::build_router(app);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let handle = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
        let client = reqwest::Client::new();
        let url = format!("http://{addr}/pa/v1/messages");
        let req =
            json!({"model": "pa", "messages": [{"role": "user", "content": "hi"}], "max_tokens": 16})
                .to_string();

        // Disabled key → 401.
        let r_dis = client
            .post(&url)
            .bearer_auth(disabled_secret)
            .body(req.clone())
            .send()
            .await
            .unwrap();
        assert_eq!(
            r_dis.status().as_u16(),
            401,
            "a disabled virtual key must be rejected"
        );

        // Unknown secret → 401 (control: lookup miss is the same 401 path).
        let r_bogus = client
            .post(&url)
            .bearer_auth("sk-vk-nope")
            .body(req.clone())
            .send()
            .await
            .unwrap();
        assert_eq!(
            r_bogus.status().as_u16(),
            401,
            "unknown key must be rejected"
        );

        // Enabled key with the same shape → NOT 401 (admitted past auth).
        let r_ena = client
            .post(&url)
            .bearer_auth(enabled_secret)
            .body(req)
            .send()
            .await
            .unwrap();
        assert_ne!(
            r_ena.status().as_u16(),
            401,
            "an enabled virtual key must pass auth (got {})",
            r_ena.status()
        );

        handle.abort();
        server.shutdown().await;
    }
}
