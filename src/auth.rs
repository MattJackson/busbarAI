// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Matthew Jackson

use std::sync::Arc;

use axum::{
    body::Body,
    extract::State,
    http::{header::AUTHORIZATION, header::CONTENT_TYPE, HeaderValue, Request, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
};

use crate::config::AuthCfg;
use crate::state::App;

/// The two non-`Authorization` headers that native vendor SDKs use to carry their API key:
/// the Anthropic SDK sends `x-api-key`, the Gemini SDK sends `x-goog-api-key`. busbar accepts
/// either as a carrier of the SAME busbar client token / virtual key (validated identically,
/// in constant time, against the same allowlist / governance lookup). Checked AFTER
/// `Authorization: Bearer` (see `extract_client_token`).
const X_API_KEY: &str = "x-api-key";
const X_GOOG_API_KEY: &str = "x-goog-api-key";

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
    fn extract_bearer_token(auth_header: &str) -> Option<String> {
        let (scheme, token) = auth_header.split_once(' ')?;
        if scheme.eq_ignore_ascii_case("bearer") && !token.is_empty() {
            Some(token.to_string())
        } else {
            None
        }
    }

    /// Extract the busbar client token from whichever scheme the caller used, in a FIXED
    /// precedence order: `Authorization: Bearer <t>` first, then `x-api-key: <t>` (Anthropic SDK),
    /// then `x-goog-api-key: <t>` (Gemini SDK). The `x-api-key`/`x-goog-api-key` values are the raw
    /// token (no scheme prefix); an empty value is treated as absent so a present-but-blank header
    /// does not mask a token in a lower-precedence carrier. The returned token is validated
    /// identically and in constant time regardless of which header carried it.
    ///
    /// Bedrock SDKs authenticate with inbound AWS SigV4, NOT a bearer-style token. busbar does NOT
    /// verify inbound SigV4 (no inbound verifier exists; `src/sigv4.rs` is sign-only). Bedrock
    /// ingress under `token` mode is therefore UNSUPPORTED and must run under `passthrough`, where
    /// `validate_token` returns `true` unconditionally and the caller's SigV4 creds are forwarded
    /// upstream. We deliberately do not read any `x-amz-*` / SigV4 `Authorization` header here.
    fn extract_client_token(req: &Request<Body>) -> Option<String> {
        let header_str = |name: &str| {
            req.headers()
                .get(name)
                .and_then(|v| v.to_str().ok())
                .map(str::to_owned)
        };

        if let Some(t) = req
            .headers()
            .get(AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .and_then(Self::extract_bearer_token)
        {
            return Some(t);
        }
        if let Some(t) = header_str(X_API_KEY).filter(|t| !t.is_empty()) {
            return Some(t);
        }
        if let Some(t) = header_str(X_GOOG_API_KEY).filter(|t| !t.is_empty()) {
            return Some(t);
        }
        None
    }

    /// Validate the request's token against the allowlist. `token` accepts a token extracted from
    /// ANY supported carrier (see `extract_client_token`); the comparison is identical and
    /// constant-time regardless of which header carried it.
    pub(crate) fn validate_token(&self, token: Option<&str>) -> bool {
        match self.mode {
            AuthMode::Token => {
                let Some(token) = token else {
                    return false;
                };
                if token.is_empty() {
                    return false;
                }

                // Constant-time compare against EVERY allowed token. `.any()` would short-circuit
                // on the first match, making the number of `constant_time_eq` calls depend on the
                // matched token's position in the allowlist (a match at index 0 returns after one
                // comparison; a miss scans all N) — a list-level timing oracle that lets an
                // adversary distinguish "matched early" from "matched late" / "not found". Fold
                // with bitwise-OR (`|`, NOT `||`) so all N comparisons always run regardless of
                // where (or whether) a match occurs; `black_box` keeps the optimizer from
                // reintroducing an early exit.
                let found = self.client_tokens.iter().fold(0u8, |acc, allowed| {
                    acc | u8::from(Self::constant_time_eq(token, allowed))
                });
                std::hint::black_box(found) != 0
            }
            AuthMode::Passthrough | AuthMode::None => true,
        }
    }
}

/// The ingress wire protocol a request targets, inferred from its path prefix. Auth runs BEFORE
/// routing, so the path is the only signal available for shaping a native 401 envelope. Order of
/// checks is significant: the more specific anthropic adhoc/named `/<seg>/v1/messages` shape is
/// covered by the generic `/v1/messages` suffix test.
fn proto_for_path(path: &str) -> &'static str {
    if path.starts_with("/v1beta/models") {
        "gemini"
    } else if path.starts_with("/model/")
        && (path.ends_with("/converse") || path.ends_with("/converse-stream"))
    {
        // Bedrock's Converse API is `/model/<id>/converse[-stream]`. Require that suffix so a pool
        // or model literally named "model" hitting `/model/v1/messages` is NOT misclassified as
        // bedrock (which would hand it a Bedrock-shaped 401 envelope — a protocol tell). Such a
        // path falls through to the `/v1/messages` (anthropic) arm below.
        "bedrock"
    } else if path == "/v1/messages" || path.ends_with("/v1/messages") {
        "anthropic"
    } else if path == "/v1/chat/completions" {
        "openai"
    } else if path == "/v2/chat" {
        "cohere"
    } else if path == "/v1/responses" {
        "responses"
    } else {
        // Unknown ingress: fall back to the generic `ProtocolWriter::write_error` envelope.
        "openai"
    }
}

/// Build a 401 response carrying the inferred ingress protocol's NATIVE error envelope (design
/// §8 BLOCKER #1). Auth runs before routing, so the protocol is inferred from the request path.
/// A native vendor SDK hitting busbar in `token`/governance mode with a bad credential then gets
/// the vendor's JSON 401 shape (`application/json`) instead of a bare `text/plain` 401 — removing
/// a deterministic proxy tell. Falls back to the generic envelope for an unknown path. No unwrap /
/// expect / panic on this request path: a serialization failure degrades to an empty JSON object.
fn unauthorized_response(path: &str, message: &str) -> Response {
    let proto = proto_for_path(path);
    // `protocol_for` knows every name `proto_for_path` can return, so this is `Some` in practice;
    // the `?`-style fallback keeps the request path panic-free if that ever changes.
    let body = match crate::proto::protocol_for(proto) {
        Some(p) => p.writer().write_error(401, "authentication_error", message),
        None => serde_json::json!({"error": {"message": message, "type": "authentication_error"}}),
    };
    let bytes = serde_json::to_vec(&body).unwrap_or_else(|_| b"{}".to_vec());
    let mut resp = (StatusCode::UNAUTHORIZED, bytes).into_response();
    resp.headers_mut()
        .insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
    resp
}

/// Axum middleware layer that validates auth before routing.
pub(crate) async fn auth_middleware(
    State(app): State<Arc<App>>,
    mut req: Request<Body>,
    next: Next,
) -> Result<Response, Response> {
    // /healthz is always open: liveness probes must not require a caller token. /metrics is NOT
    // exempted — Prometheus telemetry (lane/pool topology, per-protocol counters, error rates) is a
    // fingerprinting / information-disclosure surface, so it goes through the same auth check as any
    // other route. Operators scraping from a localhost sidecar use a configured token (or run under
    // `none`/`passthrough` mode, where `validate_token` admits unconditionally). Clone the path so
    // no immutable borrow of `req` is held while we later mutate its extensions.
    let path = req.uri().path().to_owned();
    if path == "/healthz" {
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
    // The busbar client token, taken from whichever carrier the SDK used (Authorization: Bearer,
    // then x-api-key, then x-goog-api-key). This single value drives BOTH the static-allowlist
    // check and the governance virtual-key lookup, so every scheme is validated identically and in
    // constant time. Replaces the previous Bearer-only `bearer_token`.
    let client_token: Option<String> = AuthMiddleware::extract_client_token(&req);
    let token_valid = app.auth.validate_token(client_token.as_deref());

    // the /admin management API is guarded by the configured admin token (Bearer or
    // X-Admin-Token) — NOT a virtual key, and NOT the vendor-SDK carriers (admin is a busbar
    // operator surface, not a native SDK ingress). Disabled (401) when no admin token is
    // configured. Extract the admin Bearer separately so the multi-scheme client-token carriers
    // can't present an operator token via `x-api-key`/`x-goog-api-key`.
    if is_admin {
        let admin_bearer = req
            .headers()
            .get(AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .and_then(AuthMiddleware::extract_bearer_token);
        let configured = app.governance.as_ref().and_then(|g| g.admin_token());
        let authorized = match configured {
            // Constant-time compare so the admin token can't be recovered byte-by-byte via a timing
            // side channel (matches the client-token path).
            Some(t) => {
                admin_bearer
                    .as_deref()
                    .is_some_and(|b| AuthMiddleware::constant_time_eq(b, t))
                    || admin_header_token
                        .as_deref()
                        .is_some_and(|h| AuthMiddleware::constant_time_eq(h, t))
            }
            None => false,
        };
        if !authorized {
            return Err(unauthorized_response(&path, "admin unauthorized"));
        }
        req.extensions_mut()
            .insert(crate::governance::GovCtx::default());
        return Ok(next.run(req).await);
    }

    // when governance is enabled, the caller's token MUST resolve to an enabled virtual key; the
    // resolved key is attached for downstream allowed-pools enforcement. This supersedes the static
    // AuthMode token check. The token may arrive via any supported carrier (Bearer / x-api-key /
    // x-goog-api-key) — `client_token` already encodes that precedence. When governance is
    // disabled, the existing AuthMode (None/Token/Passthrough) applies unchanged.
    if let Some(gov) = &app.governance {
        match gov.lookup(client_token.as_deref().unwrap_or("")) {
            Some(key) if key.enabled => {
                req.extensions_mut()
                    .insert(crate::governance::GovCtx { key: Some(key) });
            }
            _ => {
                return Err(unauthorized_response(
                    &path,
                    "invalid or disabled virtual key",
                ))
            }
        }
    } else {
        // /stats requires auth by default (per spec decision).
        if !token_valid {
            return Err(unauthorized_response(&path, "unauthorized"));
        }
        req.extensions_mut()
            .insert(crate::governance::GovCtx::default());
    }

    // Thread the caller's token into request extensions for passthrough forwarding. Uses the same
    // multi-scheme carrier precedence as auth (Bearer / x-api-key / x-goog-api-key), so a native
    // SDK's key is forwarded upstream regardless of which header carried it. Always inserted (even
    // when None) so the `Extension<CallerToken>` extractor in handlers never fails.
    req.extensions_mut().insert(CallerToken(client_token));

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
        let token = AuthMiddleware::extract_bearer_token("Bearer mytoken123");
        assert_eq!(token, Some("mytoken123".to_string()));
    }

    #[test]
    fn test_extract_bearer_token_case_insensitive() {
        let token = AuthMiddleware::extract_bearer_token("BEARER mytoken123");
        assert_eq!(token, Some("mytoken123".to_string()));
    }

    #[test]
    fn test_extract_bearer_token_no_bearer() {
        let token = AuthMiddleware::extract_bearer_token("mytoken123");
        assert_eq!(token, None);
    }

    #[test]
    fn test_extract_bearer_token_malformed_no_panic() {
        // A multibyte char in the scheme position must not panic (was a `h[..7]` UTF-8 boundary bug).
        assert_eq!(AuthMiddleware::extract_bearer_token("Béarer x"), None);
        assert_eq!(AuthMiddleware::extract_bearer_token("🔑🔑🔑"), None);
        assert_eq!(AuthMiddleware::extract_bearer_token("Bearer "), None); // empty token
        assert_eq!(AuthMiddleware::extract_bearer_token("Basic abc"), None);
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

        assert!(mw.validate_token(Some("tok1")));
        assert!(mw.validate_token(Some("tok2")));
        assert!(!mw.validate_token(Some("tok3")));
        assert!(!mw.validate_token(None));
        assert!(!mw.validate_token(Some(""))); // empty token never matches
    }

    #[test]
    fn test_validate_token_matches_any_allowlist_position() {
        // Regression for the list-level timing oracle: validation must compare against EVERY
        // configured token (bitwise-OR fold, no `.any()` short-circuit). Behaviorally this means a
        // match is found regardless of the token's ordinal position — first, middle, or last.
        let cfg = AuthCfg {
            mode: "token".to_string(),
            client_tokens: vec![
                "first-token".to_string(),
                "middle-token".to_string(),
                "last-token".to_string(),
            ],
            _legacy_token: None,
        };
        let mw = AuthMiddleware::new(&cfg);
        assert!(mw.validate_token(Some("first-token")), "match at index 0");
        assert!(mw.validate_token(Some("middle-token")), "match at index 1");
        assert!(mw.validate_token(Some("last-token")), "match at last index");
        assert!(!mw.validate_token(Some("absent-token")), "no match");
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
        assert!(mw.validate_token(Some("anything")));
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
        assert!(mw.validate_token(Some("anything")));
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
        assert!(mw.validate_token(Some(raw)));
    }

    /// Helper: build a request with a single header set, for `extract_client_token` unit tests.
    fn req_with(name: &str, value: &str) -> Request<Body> {
        Request::builder()
            .uri("/v1/messages")
            .header(name, value)
            .body(Body::empty())
            .expect("test request must build")
    }

    #[test]
    fn test_extract_client_token_authorization_bearer() {
        let req = req_with("authorization", "Bearer tok-abc");
        assert_eq!(
            AuthMiddleware::extract_client_token(&req),
            Some("tok-abc".to_string())
        );
    }

    #[test]
    fn test_extract_client_token_x_api_key() {
        // Anthropic SDK carrier: raw token, no scheme prefix.
        let req = req_with("x-api-key", "tok-anthropic");
        assert_eq!(
            AuthMiddleware::extract_client_token(&req),
            Some("tok-anthropic".to_string())
        );
    }

    #[test]
    fn test_extract_client_token_x_goog_api_key() {
        // Gemini SDK carrier: raw token, no scheme prefix.
        let req = req_with("x-goog-api-key", "tok-gemini");
        assert_eq!(
            AuthMiddleware::extract_client_token(&req),
            Some("tok-gemini".to_string())
        );
    }

    #[test]
    fn test_extract_client_token_precedence_is_authorization_first() {
        // Authorization wins over x-api-key, which wins over x-goog-api-key.
        let req = Request::builder()
            .uri("/v1/messages")
            .header("authorization", "Bearer from-auth")
            .header("x-api-key", "from-x-api-key")
            .header("x-goog-api-key", "from-goog")
            .body(Body::empty())
            .unwrap();
        assert_eq!(
            AuthMiddleware::extract_client_token(&req),
            Some("from-auth".to_string())
        );

        // Without Authorization, x-api-key wins over x-goog-api-key.
        let req = Request::builder()
            .uri("/v1/messages")
            .header("x-api-key", "from-x-api-key")
            .header("x-goog-api-key", "from-goog")
            .body(Body::empty())
            .unwrap();
        assert_eq!(
            AuthMiddleware::extract_client_token(&req),
            Some("from-x-api-key".to_string())
        );
    }

    #[test]
    fn test_extract_client_token_empty_carrier_falls_through() {
        // A present-but-blank x-api-key must not mask a token in x-goog-api-key.
        let req = Request::builder()
            .uri("/v1/messages")
            .header("x-api-key", "")
            .header("x-goog-api-key", "tok-gemini")
            .body(Body::empty())
            .unwrap();
        assert_eq!(
            AuthMiddleware::extract_client_token(&req),
            Some("tok-gemini".to_string())
        );
    }

    #[test]
    fn test_extract_client_token_none_when_no_carrier() {
        let req = Request::builder()
            .uri("/v1/messages")
            .body(Body::empty())
            .unwrap();
        assert_eq!(AuthMiddleware::extract_client_token(&req), None);
    }

    #[test]
    fn test_proto_for_path_inference() {
        assert_eq!(
            proto_for_path("/v1beta/models/gemini-1.5:generateContent"),
            "gemini"
        );
        assert_eq!(
            proto_for_path("/model/anthropic.claude/converse"),
            "bedrock"
        );
        assert_eq!(
            proto_for_path("/model/anthropic.claude/converse-stream"),
            "bedrock"
        );
        // A pool/model literally named "model" hitting `/model/v1/messages` must NOT be classified
        // as bedrock (no `/converse[-stream]` suffix) — it falls through to anthropic.
        assert_eq!(proto_for_path("/model/v1/messages"), "anthropic");
        // `/model/` prefix without a Converse suffix and without `/v1/messages` is unknown → openai.
        assert_eq!(proto_for_path("/model/foo/bar"), "openai");
        assert_eq!(proto_for_path("/v1/messages"), "anthropic");
        assert_eq!(proto_for_path("/pa/v1/messages"), "anthropic");
        assert_eq!(proto_for_path("/anthropic/claude/v1/messages"), "anthropic");
        assert_eq!(proto_for_path("/v1/chat/completions"), "openai");
        assert_eq!(proto_for_path("/v2/chat"), "cohere");
        assert_eq!(proto_for_path("/v1/responses"), "responses");
        // Unknown → generic (openai-shaped) envelope.
        assert_eq!(proto_for_path("/stats"), "openai");
    }

    #[test]
    fn test_unauthorized_response_is_json_with_native_envelope() {
        // Gemini path → native Gemini error envelope, application/json.
        let resp = unauthorized_response("/v1beta/models/x:generateContent", "unauthorized");
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(
            resp.headers()
                .get(CONTENT_TYPE)
                .and_then(|v| v.to_str().ok()),
            Some("application/json")
        );

        // Anthropic path → native Anthropic error envelope.
        let resp = unauthorized_response("/pa/v1/messages", "unauthorized");
        assert_eq!(
            resp.headers()
                .get(CONTENT_TYPE)
                .and_then(|v| v.to_str().ok()),
            Some("application/json")
        );
    }

    /// End-to-end through the real router + `auth_middleware` in TOKEN mode: the busbar client
    /// token authenticates via `x-goog-api-key` (Gemini SDK), via `x-api-key` (Anthropic SDK), and
    /// via `Authorization: Bearer`. A missing/wrong token is rejected 401 with the native error
    /// envelope shaped for the inferred ingress protocol (`application/json`, not `text/plain`).
    #[tokio::test]
    async fn test_token_mode_accepts_all_carriers_and_native_401() {
        use crate::test_support::{LaneSpec, MockResponse, MockServer, MockServerState, TestApp};
        use serde_json::json;
        use std::sync::Arc;

        crate::metrics::init();

        let token = "busbar-client-token";

        let state = Arc::new(MockServerState::new());
        // Three admitted requests reach the upstream; queue three OK bodies.
        for _ in 0..3 {
            state.push(MockResponse::Ok {
                status: axum::http::StatusCode::OK,
                body: json!({
                    "id": "msg_1",
                    "type": "message",
                    "role": "assistant",
                    "model": "test-model",
                    "content": [{"type": "text", "text": "hi"}],
                    "stop_reason": "end_turn",
                    "usage": {"input_tokens": 1, "output_tokens": 1}
                }),
            });
        }
        let server = MockServer::new(state).await;

        let auth_cfg = crate::config::AuthCfg {
            mode: "token".to_string(),
            client_tokens: vec![token.to_string()],
            _legacy_token: None,
        };
        let app = TestApp::new()
            .lane(
                LaneSpec::new(
                    "test-model",
                    crate::proto::Protocol::anthropic(),
                    &server.base_url(),
                )
                .api_key("busbar-upstream-key"),
            )
            .pool("pa", &[(0, 1)])
            .auth(Arc::new(AuthMiddleware::new(&auth_cfg)))
            .auth_mode(AuthMode::Token)
            .build();

        let router = crate::build_router(app);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let handle = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
        let client = reqwest::Client::new();
        let url = format!("http://{addr}/pa/v1/messages");
        let body = json!({"model": "pa", "messages": [{"role": "user", "content": "hi"}], "max_tokens": 16})
            .to_string();

        // Bearer still works.
        let r_bearer = client
            .post(&url)
            .bearer_auth(token)
            .body(body.clone())
            .send()
            .await
            .unwrap();
        assert_ne!(
            r_bearer.status().as_u16(),
            401,
            "valid token via Authorization: Bearer must pass (got {})",
            r_bearer.status()
        );

        // x-api-key (Anthropic SDK carrier) works.
        let r_xapi = client
            .post(&url)
            .header("x-api-key", token)
            .body(body.clone())
            .send()
            .await
            .unwrap();
        assert_ne!(
            r_xapi.status().as_u16(),
            401,
            "valid token via x-api-key must pass (got {})",
            r_xapi.status()
        );

        // x-goog-api-key (Gemini SDK carrier) works.
        let r_goog = client
            .post(&url)
            .header("x-goog-api-key", token)
            .body(body.clone())
            .send()
            .await
            .unwrap();
        assert_ne!(
            r_goog.status().as_u16(),
            401,
            "valid token via x-goog-api-key must pass (got {})",
            r_goog.status()
        );

        // Wrong token via x-api-key → 401 with native (anthropic, inferred from /v1/messages) envelope.
        let r_wrong = client
            .post(&url)
            .header("x-api-key", "not-the-token")
            .body(body.clone())
            .send()
            .await
            .unwrap();
        assert_eq!(r_wrong.status().as_u16(), 401, "wrong token must be 401");
        assert_eq!(
            r_wrong
                .headers()
                .get(reqwest::header::CONTENT_TYPE)
                .and_then(|v| v.to_str().ok()),
            Some("application/json"),
            "401 must carry application/json native envelope, not text/plain"
        );
        let env: serde_json::Value = r_wrong.json().await.unwrap();
        // Anthropic native error envelope: {"type":"error","error":{...}}.
        assert!(
            env.get("error").is_some(),
            "native error envelope must contain an `error` object: {env}"
        );

        // Missing credential entirely → 401 (still JSON).
        let r_missing = client.post(&url).body(body).send().await.unwrap();
        assert_eq!(
            r_missing.status().as_u16(),
            401,
            "missing token must be 401"
        );
        assert_eq!(
            r_missing
                .headers()
                .get(reqwest::header::CONTENT_TYPE)
                .and_then(|v| v.to_str().ok()),
            Some("application/json"),
        );

        handle.abort();
        server.shutdown().await;
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

    /// End-to-end through the real router + `auth_middleware` in GOVERNANCE mode, exercising the
    /// non-`Authorization` carriers (`x-goog-api-key`, `x-api-key`) into the virtual-key lookup.
    /// The existing governance test only uses `Authorization: Bearer`, and the multi-carrier test
    /// runs under static-token mode (`governance=None`) — so the intersection (a virtual key
    /// presented via a vendor-SDK carrier resolving the governance lookup) was untested. A
    /// regression that stopped threading those carriers into `gov.lookup` would otherwise pass CI.
    #[tokio::test]
    async fn test_governance_accepts_vendor_carriers_and_native_401() {
        use crate::governance::{GovState, SqliteStore, Store, VirtualKey};
        use crate::test_support::{LaneSpec, MockResponse, MockServer, MockServerState, TestApp};
        use serde_json::json;
        use std::sync::Arc;

        crate::metrics::init();

        let state = Arc::new(MockServerState::new());
        // Two admitted requests (x-goog-api-key, x-api-key) reach the upstream; queue two bodies.
        for _ in 0..2 {
            state.push(MockResponse::Ok {
                status: axum::http::StatusCode::OK,
                body: json!({
                    "id": "msg_1",
                    "type": "message",
                    "role": "assistant",
                    "model": "test-model",
                    "content": [{"type": "text", "text": "hi"}],
                    "stop_reason": "end_turn",
                    "usage": {"input_tokens": 1, "output_tokens": 1}
                }),
            });
        }
        let server = MockServer::new(state).await;

        let secret = "sk-vk-carrier";
        let store = Arc::new(SqliteStore::open_in_memory().unwrap());
        store
            .put_key(&VirtualKey {
                id: "kc".to_string(),
                key_hash: crate::sigv4::sha256_hex(secret.as_bytes()),
                name: "kc".to_string(),
                allowed_pools: vec!["pa".to_string()],
                max_budget_cents: None,
                budget_period: "total".to_string(),
                rpm_limit: None,
                tpm_limit: None,
                enabled: true,
                created_at: 0,
            })
            .unwrap();
        let gov = Arc::new(GovState::new(store, 0, 0, None).unwrap());

        let app = TestApp::new()
            .lane(
                LaneSpec::new(
                    "test-model",
                    crate::proto::Protocol::anthropic(),
                    &server.base_url(),
                )
                .api_key("busbar-upstream-key"),
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
        let body = json!({"model": "pa", "messages": [{"role": "user", "content": "hi"}], "max_tokens": 16})
            .to_string();

        // Valid virtual key via x-goog-api-key (Gemini SDK carrier) → admitted past governance auth.
        let r_goog = client
            .post(&url)
            .header("x-goog-api-key", secret)
            .body(body.clone())
            .send()
            .await
            .unwrap();
        assert_ne!(
            r_goog.status().as_u16(),
            401,
            "valid virtual key via x-goog-api-key must pass governance (got {})",
            r_goog.status()
        );

        // Valid virtual key via x-api-key (Anthropic SDK carrier) → admitted past governance auth.
        let r_xapi = client
            .post(&url)
            .header("x-api-key", secret)
            .body(body.clone())
            .send()
            .await
            .unwrap();
        assert_ne!(
            r_xapi.status().as_u16(),
            401,
            "valid virtual key via x-api-key must pass governance (got {})",
            r_xapi.status()
        );

        // Bad secret via x-goog-api-key → native JSON 401 (governance lookup miss).
        let r_bad = client
            .post(&url)
            .header("x-goog-api-key", "sk-vk-nope")
            .body(body)
            .send()
            .await
            .unwrap();
        assert_eq!(
            r_bad.status().as_u16(),
            401,
            "an unknown virtual key via x-goog-api-key must be 401"
        );
        assert_eq!(
            r_bad
                .headers()
                .get(reqwest::header::CONTENT_TYPE)
                .and_then(|v| v.to_str().ok()),
            Some("application/json"),
            "401 must carry the native application/json envelope, not text/plain"
        );

        handle.abort();
        server.shutdown().await;
    }
}
