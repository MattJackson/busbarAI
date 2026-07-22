/// `admin_scope_for`: the operator principal is full; group-carrying principals resolve
/// through group_map (most permissive wins, unmapped grants nothing); a groupless non-operator
/// principal gets nothing; the open posture (no principal) is full.
#[test]
fn admin_scope_resolution() {
    use crate::admin::v1::contract::Scope;
    let mut gm = std::collections::HashMap::new();
    gm.insert(
        "viewers".to_string(),
        crate::config::GroupMapEntry {
            admin_scope: Some("read-only".to_string()),
            ..Default::default()
        },
    );
    gm.insert(
        "admins".to_string(),
        crate::config::GroupMapEntry {
            admin_scope: Some("full".to_string()),
            ..Default::default()
        },
    );
    gm.insert(
        "no-admin".to_string(),
        crate::config::GroupMapEntry {
            admin_scope: None,
            ..Default::default()
        },
    );

    // Open posture: full.
    assert_eq!(admin_scope_for(None, &gm), Some(Scope::Full));
    // The operator principal (admin-tokens): full.
    #[cfg(feature = "auth-admin-tokens")]
    assert_eq!(
        admin_scope_for(Some(&Principal::from_id("admin")), &gm),
        Some(Scope::Full)
    );
    // Group-mapped: most permissive of the mapped groups wins.
    let mut p = Principal::from_id("ad:alice");
    p.groups = vec!["viewers".to_string(), "admins".to_string()];
    assert_eq!(admin_scope_for(Some(&p), &gm), Some(Scope::Full));
    p.groups = vec!["viewers".to_string()];
    assert_eq!(admin_scope_for(Some(&p), &gm), Some(Scope::ReadOnly));
    // Unmapped groups grant nothing (fail closed).
    p.groups = vec!["strangers".to_string()];
    assert_eq!(admin_scope_for(Some(&p), &gm), None);
    // A group mapped WITHOUT admin_scope grants nothing.
    p.groups = vec!["no-admin".to_string()];
    assert_eq!(admin_scope_for(Some(&p), &gm), None);
    // A groupless NON-operator principal gets nothing (an external module cannot mint the
    // operator identity by returning a bare id).
    let stranger = Principal::from_id("ad:bob");
    assert_eq!(admin_scope_for(Some(&stranger), &gm), None);
}
use super::*;
use axum::http::header::CONTENT_TYPE;

/// Assert a string is canonical UUID-v4 shaped: five dash-separated lowercase-hex groups of
/// lengths 8-4-4-4-12, with the version nibble == '4' and the variant nibble in {8,9,a,b}.
fn assert_uuid_v4_shaped(id: &str) {
    let segs: Vec<&str> = id.split('-').collect();
    assert_eq!(
        segs.iter().map(|s| s.len()).collect::<Vec<_>>(),
        vec![8, 4, 4, 4, 12],
        "x-amzn-requestid must be UUID-v4 shaped (8-4-4-4-12), got '{id}'"
    );
    assert!(
        id.chars()
            .all(|c| c == '-' || c.is_ascii_hexdigit() && !c.is_ascii_uppercase()),
        "UUID must be lowercase hex with dashes only, got '{id}'"
    );
    // Version nibble: first char of the third group.
    assert_eq!(
        segs[2].chars().next(),
        Some('4'),
        "UUID version nibble must be 4, got '{id}'"
    );
    // Variant nibble: first char of the fourth group must be one of 8,9,a,b.
    assert!(
        matches!(segs[3].chars().next(), Some('8' | '9' | 'a' | 'b')),
        "UUID variant nibble must be 8/9/a/b, got '{id}'"
    );
}

#[test]
fn test_synth_amzn_request_id_is_uuid_v4() {
    // Regression for the flat-32-hex-no-dashes format: a Bedrock x-amzn-RequestId must be a
    // CSPRNG UUID-v4, matching real AWS. The auth path now mints this id through the CANONICAL
    // `crate::proto::bedrock::synth_amzn_request_id` (via `proxy::ingress_error` →
    // `attach_bedrock_error_headers`), not a private copy — assert the canonical fn's shape so the
    // bedrock auth-failure header contract stays covered. Two consecutive ids must differ
    // (entropy-sourced, not a predictable timestamp||counter).
    let a = crate::proto::bedrock::synth_amzn_request_id()
        .expect("entropy must be available under test");
    let b = crate::proto::bedrock::synth_amzn_request_id()
        .expect("entropy must be available under test");
    assert_uuid_v4_shaped(&a);
    assert_uuid_v4_shaped(&b);
    assert_ne!(a, b, "consecutive synthetic request ids must differ");
}

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

#[cfg(feature = "auth-tokens")]
#[test]
fn test_auth_mode_token_valid() {
    let cfg = AuthCfg {
        chain: vec!["tokens".to_string()],
        upstream_credentials: crate::auth::UpstreamCreds::Own,
        client_tokens: vec!["tok1".to_string(), "tok2".to_string()],
        modules: std::collections::HashMap::new(),
    };
    let mw = AuthMiddleware::new(&cfg);

    assert!(mw.validate_token(Some("tok1")));
    assert!(mw.validate_token(Some("tok2")));
    assert!(!mw.validate_token(Some("tok3")));
    assert!(!mw.validate_token(None));
    assert!(!mw.validate_token(Some(""))); // empty token never matches
}

#[cfg(feature = "auth-tokens")]
#[test]
fn test_validate_token_matches_any_allowlist_position() {
    // Regression for the list-level timing oracle: validation must compare against EVERY
    // configured token (bitwise-OR fold, no `.any()` short-circuit). Behaviorally this means a
    // match is found regardless of the token's ordinal position — first, middle, or last.
    let cfg = AuthCfg {
        chain: vec!["tokens".to_string()],
        upstream_credentials: crate::auth::UpstreamCreds::Own,
        client_tokens: vec![
            "first-token".to_string(),
            "middle-token".to_string(),
            "last-token".to_string(),
        ],
        modules: std::collections::HashMap::new(),
    };
    let mw = AuthMiddleware::new(&cfg);
    assert!(mw.validate_token(Some("first-token")), "match at index 0");
    assert!(mw.validate_token(Some("middle-token")), "match at index 1");
    assert!(mw.validate_token(Some("last-token")), "match at last index");
    assert!(!mw.validate_token(Some("absent-token")), "no match");
}

#[cfg(feature = "auth-tokens")]
#[test]
fn test_validate_token_length_independent_compare() {
    // Regression for the client-token timing-LENGTH leak: the configured token's length must not
    // be observable via `constant_time_eq`'s early length-mismatch return. Both sides are now
    // SHA-256-hashed to a fixed 64-hex-char digest before the constant-time compare, so a
    // wrong-length candidate runs the same work as a right-length one AND still fails.
    let cfg = AuthCfg {
        chain: vec!["tokens".to_string()],
        upstream_credentials: crate::auth::UpstreamCreds::Own,
        client_tokens: vec!["the-real-token".to_string()],
        modules: std::collections::HashMap::new(),
    };
    let mw = AuthMiddleware::new(&cfg);

    // Correctness preserved: the valid token still authenticates.
    assert!(
        mw.validate_token(Some("the-real-token")),
        "valid token must authenticate"
    );

    // Wrong tokens are rejected regardless of length — shorter, longer, and equal-length.
    assert!(
        !mw.validate_token(Some("x")),
        "much shorter wrong token rejected"
    );
    assert!(
        !mw.validate_token(Some("a-very-much-longer-wrong-token-value")),
        "much longer wrong token rejected"
    );
    assert!(
        !mw.validate_token(Some("the-real-tokeX")),
        "equal-length wrong token rejected"
    );

    // Structural guarantee: both the candidate and the stored token are hashed to equal length
    // (32 bytes / 64 hex chars) before the compare, so the compare's runtime no longer depends
    // on the relationship between the candidate length and the stored-token length.
    let stored_hash = crate::sigv4::sha256_hex(mw.client_tokens[0].as_bytes());
    let cand_short = crate::sigv4::sha256_hex(b"x");
    let cand_long = crate::sigv4::sha256_hex(b"a-very-much-longer-wrong-token-value");
    assert_eq!(stored_hash.len(), 64);
    assert_eq!(cand_short.len(), 64);
    assert_eq!(cand_long.len(), 64);
}

#[test]
fn test_auth_mode_passthrough() {
    let cfg = AuthCfg {
        chain: vec![],
        upstream_credentials: crate::auth::UpstreamCreds::Passthrough,
        client_tokens: vec![],
        modules: std::collections::HashMap::new(),
    };
    let mw = AuthMiddleware::new(&cfg);

    // Passthrough allows all (auth is upstream's responsibility)
    assert!(mw.validate_token(None));
    assert!(mw.validate_token(Some("anything")));
}

#[test]
fn test_auth_mode_none() {
    let cfg = AuthCfg {
        chain: vec![],
        upstream_credentials: crate::auth::UpstreamCreds::Own,
        client_tokens: vec![],
        modules: std::collections::HashMap::new(),
    };
    let mw = AuthMiddleware::new(&cfg);

    // None allows all (open relay)
    assert!(mw.validate_token(None));
    assert!(mw.validate_token(Some("anything")));
}

#[test]
fn test_auth_mode_none_with_client_tokens_is_inert_open_relay() {
    // Regression (MEDIUM/correctness): `mode: none` together with a non-empty client_tokens list
    // is an open relay — the listed tokens have ZERO enforcement effect. The constructor must not
    // panic, must preserve the configured tokens, and `validate_token` must still admit EVERY
    // request (including a token NOT in the list, and no token at all), proving the allowlist is
    // inert. (A startup warning is emitted but is not asserted here — behaviour is the contract.)
    let cfg = AuthCfg {
        chain: vec![],
        upstream_credentials: crate::auth::UpstreamCreds::Own,
        client_tokens: vec!["listed-but-ignored".to_string()],
        modules: std::collections::HashMap::new(),
    };
    let mw = AuthMiddleware::new(&cfg);
    assert_eq!(mw.client_tokens, vec!["listed-but-ignored".to_string()]);
    // Open relay: a token NOT on the list is admitted (the list does not constrain access).
    assert!(mw.validate_token(Some("some-other-token")));
    // And so is no token at all.
    assert!(mw.validate_token(None));
}

#[test]
fn test_upstream_credentials_deserialize() {
    // `upstream_credentials` deserializes snake_case; an unknown value is rejected at config LOAD.
    assert!(
        serde_yaml::from_str::<crate::auth::UpstreamCreds>("invalid").is_err(),
        "an unrecognized upstream_credentials value must fail to deserialize"
    );
    assert_eq!(
        serde_yaml::from_str::<crate::auth::UpstreamCreds>("passthrough").unwrap(),
        crate::auth::UpstreamCreds::Passthrough
    );
    assert_eq!(
        serde_yaml::from_str::<crate::auth::UpstreamCreds>("own").unwrap(),
        crate::auth::UpstreamCreds::Own
    );
}

#[test]
fn test_client_tokens_not_double_interpolated() {
    // A client token that legitimately contains the literal `${...}` (legal in opaque API keys)
    // must be passed through verbatim — the whole config file is already env-interpolated once
    // at load, so AuthMiddleware::new must NOT interpolate again (which would re-expand or panic
    // on an unset var). Regression for the dropped second interpolation pass.
    let raw = "sk-${NOT_A_REAL_ENV_VAR}-suffix";
    let cfg = AuthCfg {
        chain: vec!["tokens".to_string()],
        upstream_credentials: crate::auth::UpstreamCreds::Own,
        client_tokens: vec![raw.to_string()],
        modules: std::collections::HashMap::new(),
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
fn test_extract_client_token_non_bearer_authorization_falls_through_to_x_api_key() {
    // A PRESENT but non-Bearer Authorization header (AWS SigV4, or Basic) must NOT short-circuit
    // extract_client_token to None: extract_bearer_token returns None for these schemes, so the
    // code must FALL THROUGH to x-api-key. This is the bedrock-SigV4-plus-vendor-key shape the
    // multi-scheme design targets (a client signs the upstream request with SigV4 in
    // Authorization while carrying the busbar token in x-api-key). A regression that made any
    // present Authorization header short-circuit would silently break those clients yet pass
    // every bearer-only / carrier-only test.
    for non_bearer in [
        "AWS4-HMAC-SHA256 Credential=AKIA.../20240101/us-east-1/bedrock/aws4_request, \
             SignedHeaders=host;x-amz-date, Signature=deadbeef",
        "Basic dXNlcjpwYXNz",
    ] {
        let req = Request::builder()
            .uri("/v1/messages")
            .header("authorization", non_bearer)
            .header("x-api-key", "tok")
            .body(Body::empty())
            .expect("test request must build");
        assert_eq!(
            AuthMiddleware::extract_client_token(&req),
            Some("tok".to_string()),
            "a non-bearer Authorization ('{non_bearer}') must fall through to x-api-key"
        );
    }
}

#[test]
fn test_extract_client_token_non_bearer_authorization_falls_through_to_x_goog_api_key() {
    // Symmetric to the x-api-key case: a present-but-non-bearer Authorization must fall through
    // PAST the (empty/absent) x-api-key carrier all the way to x-goog-api-key, locking the full
    // multi-scheme chain. A regression short-circuiting on the non-bearer Authorization, or one
    // that stopped after x-api-key, would be caught here.
    let req = Request::builder()
        .uri("/v1/messages")
        .header(
            "authorization",
            "AWS4-HMAC-SHA256 Credential=AKIA.../bedrock/aws4_request",
        )
        .header("x-goog-api-key", "goog-tok")
        .body(Body::empty())
        .expect("test request must build");
    assert_eq!(
        AuthMiddleware::extract_client_token(&req),
        Some("goog-tok".to_string()),
        "a non-bearer Authorization must fall through to x-goog-api-key"
    );
}

#[test]
fn test_proto_for_path_inference() {
    assert_eq!(
        proto_for_path("/v1beta/models/gemini-1.5:generateContent"),
        "gemini"
    );
    // The stable `v1` Gemini alias the router also registers (`/v1/models/*rest`). A colon
    // `:<action>` in the final segment is the Gemini generateContent/streamGenerateContent shape
    // → gemini (mirrors main.rs::proto_for_path so the two classifiers cannot drift).
    assert_eq!(
        proto_for_path("/v1/models/gemini-pro:generateContent"),
        "gemini"
    );
    assert_eq!(
        proto_for_path("/v1/models/gemini-1.5-pro:streamGenerateContent"),
        "gemini"
    );
    // `/v1/models/...` WITHOUT a colon action is the OpenAI `model.retrieve` shape (`GET
    // /v1/models/{id}`) — shape the auth error as OpenAI so an OpenAI SDK gets a decodable body.
    assert_eq!(proto_for_path("/v1/models/gpt-4o"), "openai");
    // `/v1beta/models/...` is Gemini-only even without a colon (OpenAI has no v1beta surface).
    assert_eq!(proto_for_path("/v1beta/models/gemini-pro"), "gemini");
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

/// Decode the JSON body of an `unauthorized_response` for shape assertions. Synchronously
/// drains the (in-memory, already-complete) body — no network, no runtime needed.
fn decode_body(resp: Response) -> serde_json::Value {
    let bytes = futures::executor::block_on(async {
        axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .expect("test body must collect")
    });
    serde_json::from_slice(&bytes).expect("auth-failure body must be valid JSON")
}

#[test]
fn test_unauthorized_response_is_json_with_native_envelope() {
    // Every supported ingress protocol must get its DISTINCTIVE native error SHAPE, not just
    // `application/json` — a wrong-shaped 401 is a deterministic proxy tell a native SDK
    // would choke on. One assertion per `proto_for_path` arm.

    // Gemini → {"error":{"code":400,"message":..,"status":"INVALID_ARGUMENT"}}, HTTP 400. The
    // genuine Generative Language API does NOT return 401/UNAUTHENTICATED for a bad API key; it
    // returns HTTP 400 INVALID_ARGUMENT. A 401/UNAUTHENTICATED body is a tell the google-genai
    // SDK never sees from real Google on the bad-key path.
    let resp = unauthorized_response("/v1beta/models/x:generateContent");
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        resp.headers()
            .get(CONTENT_TYPE)
            .and_then(|v| v.to_str().ok()),
        Some("application/json")
    );
    let body = decode_body(resp);
    assert_eq!(body["error"]["code"], 400, "gemini body: {body}");
    assert_eq!(
        body["error"]["status"], "INVALID_ARGUMENT",
        "gemini body: {body}"
    );

    // Gemini stable-v1 alias (`/v1/models/<m>:generateContent`) must shape IDENTICALLY to the
    // v1beta surface — the bug this round fixed mis-shaped it as an OpenAI 401.
    let resp = unauthorized_response("/v1/models/gemini-pro:generateContent");
    assert_eq!(
        resp.status(),
        StatusCode::BAD_REQUEST,
        "stable-v1 gemini status"
    );
    let body = decode_body(resp);
    assert_eq!(body["error"]["code"], 400, "stable-v1 gemini body: {body}");
    assert_eq!(
        body["error"]["status"], "INVALID_ARGUMENT",
        "stable-v1 gemini body: {body}"
    );

    // Anthropic → top-level {"type":"error","error":{"type":"authentication_error",..}}.
    let resp = unauthorized_response("/pa/v1/messages");
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    let body = decode_body(resp);
    assert_eq!(body["type"], "error", "anthropic top-level type: {body}");
    assert_eq!(
        body["error"]["type"], "authentication_error",
        "anthropic error.type: {body}"
    );

    // OpenAI → {"error":{"type":"authentication_error","code":"invalid_api_key",..}} (no
    // top-level type=error). The genuine OpenAI bad-key 401 body carries
    // `error.code: "invalid_api_key"`, which the official SDK surfaces as
    // `AuthenticationError.code`; emitting `code: null` is a deterministic proxy tell. The
    // writers pair that code ONLY with `error.type: "authentication_error"`, so the envelope
    // must carry that pairing on the most common failure path.
    let resp = unauthorized_response("/v1/chat/completions");
    assert_eq!(
        resp.status(),
        StatusCode::UNAUTHORIZED,
        "openai auth status"
    );
    let body = decode_body(resp);
    assert!(
        body.get("type").is_none(),
        "openai must NOT carry a top-level type: {body}"
    );
    assert_eq!(
        body["error"]["type"], "authentication_error",
        "openai error.type must match the real bad-key body: {body}"
    );
    assert_eq!(
            body["error"]["code"], "invalid_api_key",
            "openai bad-key body must carry code=invalid_api_key (not null), the SDK-visible tell: {body}"
        );

    // Responses → {"error":{"type":"authentication_error","code":"invalid_api_key","param":null,..}}
    // (same OpenAI-family bad-key shape, with the SDK-visible code populated).
    let resp = unauthorized_response("/v1/responses");
    let body = decode_body(resp);
    assert_eq!(
        body["error"]["type"], "authentication_error",
        "responses error.type must match the real bad-key body: {body}"
    );
    assert_eq!(
        body["error"]["code"], "invalid_api_key",
        "responses bad-key body must carry code=invalid_api_key (not null): {body}"
    );
    assert!(
        body["error"].get("param").is_some(),
        "responses envelope carries a param field: {body}"
    );

    // Cohere → bare {"message":..} with NO `error` and NO `type`.
    let resp = unauthorized_response("/v2/chat");
    let body = decode_body(resp);
    assert!(
        body.get("message").is_some(),
        "cohere body has a top-level message: {body}"
    );
    assert!(
        body.get("error").is_none() && body.get("type").is_none(),
        "cohere body must be bare (no error/type): {body}"
    );

    // Bedrock → {"__type":"AccessDeniedException","message":..}, HTTP 403, x-amzn-* headers.
    let resp = unauthorized_response("/model/anthropic.claude/converse");
    assert_eq!(
        resp.status(),
        StatusCode::FORBIDDEN,
        "a Bedrock SigV4 auth failure is 403, not 401"
    );
    assert_eq!(
        resp.headers()
            .get("x-amzn-errortype")
            .and_then(|v| v.to_str().ok()),
        Some("AccessDeniedException"),
        "Bedrock auth failure must carry x-amzn-errortype the AWS SDK types off"
    );
    let req_id = resp
        .headers()
        .get("x-amzn-requestid")
        .and_then(|v| v.to_str().ok())
        .expect("Bedrock auth failure must carry a synthetic x-amzn-requestid")
        .to_string();
    // Real Bedrock x-amzn-RequestId is UUID-v4 shaped (8-4-4-4-12 lowercase hex). A flat
    // 32-hex-no-dashes value is a protocol tell — assert the canonical shape, not just presence.
    assert_uuid_v4_shaped(&req_id);
    let body = decode_body(resp);
    assert_eq!(
        body["__type"], "AccessDeniedException",
        "bedrock __type: {body}"
    );
    assert!(
        body.get("error").is_none(),
        "bedrock body uses __type, not an error object: {body}"
    );
}

/// Recursively collect every JSON string value reachable in `v` (object values, array elements,
/// and the leaf string itself), so a leak-vocabulary scan covers the message regardless of the
/// field the per-protocol writer placed it on (`error.message` / top-level `message` / `__type`).
fn collect_strings(v: &serde_json::Value, out: &mut Vec<String>) {
    match v {
        serde_json::Value::String(s) => out.push(s.clone()),
        serde_json::Value::Array(a) => a.iter().for_each(|e| collect_strings(e, out)),
        serde_json::Value::Object(o) => o.values().for_each(|e| collect_strings(e, out)),
        _ => {}
    }
}

#[test]
fn test_unauthorized_body_carries_no_busbar_vocabulary() {
    // Regression for the auth-model leak: the auth-failure wire body must NOT name busbar's
    // internal auth concepts. Previously the literal "invalid or disabled virtual key" (and
    // "unauthorized" / "admin unauthorized") were reflected verbatim into the native error body
    // — a deterministic proxy tell that also discloses the per-virtual-key enable/disable model.
    // Sweep EVERY supported ingress path (incl. the unknown-path fallback) and assert no leaked
    // token appears anywhere in the JSON. The invalid-vs-disabled distinction must also be gone.
    const FORBIDDEN: &[&str] = &[
        "virtual key",
        "client token",
        "client_token",
        "allowlist",
        "disabled",
        "passthrough",
        "busbar",
        "unauthorized", // busbar-internal reason wording, not vendor copy
        "admin",
    ];
    let paths = [
        "/v1beta/models/x:generateContent", // gemini
        "/pa/v1/messages",                  // anthropic
        "/v1/chat/completions",             // openai
        "/v1/responses",                    // responses
        "/v2/chat",                         // cohere
        "/model/anthropic.claude/converse", // bedrock
        "/api/v1/admin/keys",               // admin path → inferred-proto fallback (openai)
        "/totally/unknown/path",            // unknown → openai fallback
    ];
    for path in paths {
        let body = decode_body(unauthorized_response(path));
        let mut strings = Vec::new();
        collect_strings(&body, &mut strings);
        for s in &strings {
            let lc = s.to_ascii_lowercase();
            for bad in FORBIDDEN {
                assert!(
                    !lc.contains(bad),
                    "auth-failure body for '{path}' leaked busbar vocabulary '{bad}': {body}"
                );
            }
        }
    }
}

#[test]
fn test_vendor_auth_failure_message_is_plausible_per_proto() {
    // The wire message is keyed PURELY off the inferred protocol (independent of the failure
    // reason) and reads like genuine vendor copy. Lock the exact strings so a regression that
    // reintroduces busbar wording — or distinguishes invalid-vs-disabled — is caught.
    assert_eq!(
        vendor_auth_failure_message("anthropic"),
        "invalid x-api-key"
    );
    assert_eq!(
        vendor_auth_failure_message("openai"),
        "Incorrect API key provided."
    );
    assert_eq!(
        vendor_auth_failure_message("responses"),
        "Incorrect API key provided."
    );
    assert_eq!(
        vendor_auth_failure_message("gemini"),
        crate::proto::gemini::GEMINI_BAD_KEY_MESSAGE
    );
    assert_eq!(vendor_auth_failure_message("cohere"), "invalid api token");
    // AWS conveys AccessDenied via __type / x-amzn-errortype, not a message string.
    assert_eq!(vendor_auth_failure_message("bedrock"), "");
    // Any unknown future proto: a neutral credential message, never busbar vocabulary.
    assert_eq!(
        vendor_auth_failure_message("some-future-proto"),
        "authentication failed"
    );
}

#[test]
fn test_every_router_ingress_path_maps_to_non_fallback_proto() {
    // Coupling guard (finding: router route table ↔ proto_for_path ↔ protocol_for). Each real
    // ingress path the router registers must resolve to a SPECIFIC proto, not the unknown-path
    // `openai` fallback applied via the final `else`. If a future route is added without
    // updating proto_for_path, callers on that protocol would silently get an OpenAI-shaped 401
    // — a partial defeat of the indistinguishability promise. We assert the expected mapping
    // explicitly (a sample path per registered ingress family), so a regression is caught.
    let cases = [
        ("/v1/messages", "anthropic"),
        ("/somepool/v1/messages", "anthropic"),
        ("/v1/chat/completions", "openai"),
        ("/v2/chat", "cohere"),
        ("/v1/responses", "responses"),
        ("/v1beta/models/gemini-1.5:generateContent", "gemini"),
        // BOTH Gemini ingress prefixes the router registers (main.rs) must resolve to a
        // non-fallback proto. The stable `v1` alias was previously omitted here, masking the
        // missing `/v1/models/` arm in proto_for_path (a `:`-action path mis-shaped as openai).
        ("/v1/models/gemini-pro:generateContent", "gemini"),
        ("/model/anthropic.claude/converse", "bedrock"),
        ("/model/anthropic.claude/converse-stream", "bedrock"),
    ];
    for (path, expected) in cases {
        assert_eq!(
            proto_for_path(path),
            expected,
            "router ingress path '{path}' must map to '{expected}', not the fallback"
        );
        // And the resolved proto must be a real protocol (never the dead `None` arm).
        assert!(
            crate::proto::protocol_for(proto_for_path(path)).is_some(),
            "proto for '{path}' must resolve to a known protocol"
        );
    }
}

/// End-to-end through the real router + `auth_middleware` in TOKEN mode: the busbar client
/// token authenticates via `x-goog-api-key` (Gemini SDK), via `x-api-key` (Anthropic SDK), and
/// via `Authorization: Bearer`. A missing/wrong token is rejected 401 with the native error
/// envelope shaped for the inferred ingress protocol (`application/json`, not `text/plain`).
#[cfg(feature = "auth-tokens")]
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
        chain: vec!["tokens".to_string()],
        upstream_credentials: crate::auth::UpstreamCreds::Own,
        client_tokens: vec![token.to_string()],
        modules: std::collections::HashMap::new(),
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
        .build();

    let router = crate::build_router(app);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    let client = reqwest::Client::new();
    let url = format!("http://{addr}/pa/v1/messages");
    let body =
        json!({"model": "pa", "messages": [{"role": "user", "content": "hi"}], "max_tokens": 16})
            .to_string();

    // Bearer still works.
    let r_bearer = client
        .post(&url)
        .bearer_auth(token)
        .body(body.clone())
        .send()
        .await
        .unwrap();
    assert_eq!(
        r_bearer.status().as_u16(),
        200,
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
    assert_eq!(
        r_xapi.status().as_u16(),
        200,
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
    assert_eq!(
        r_goog.status().as_u16(),
        200,
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

/// End-to-end through the real router + `auth_middleware` in TOKEN mode: an unauthenticated
/// POST to `/v2/chat` (Cohere) and `/v1/responses` (Responses) must be rejected 401 with the
/// RESPECTIVE protocol's native error envelope — not an Anthropic/OpenAI-shaped body. The
/// existing multi-carrier test only covers the Anthropic path, leaving these two protocol
/// envelopes untested on the auth boundary (an indistinguishability failure if regressed).
#[cfg(feature = "auth-tokens")]
#[tokio::test]
async fn test_cohere_and_responses_ingress_token_mode_native_401() {
    use crate::test_support::{LaneSpec, MockServer, MockServerState, TestApp};
    use serde_json::json;
    use std::sync::Arc;

    crate::metrics::init();

    // No upstream call is made — auth rejects before routing — but TestApp needs a lane/pool.
    let state = Arc::new(MockServerState::new());
    let server = MockServer::new(state).await;

    let auth_cfg = crate::config::AuthCfg {
        chain: vec!["tokens".to_string()],
        upstream_credentials: crate::auth::UpstreamCreds::Own,
        client_tokens: vec!["the-real-token".to_string()],
        modules: std::collections::HashMap::new(),
    };
    let app = TestApp::new()
        .lane(
            LaneSpec::new(
                "test-model",
                crate::proto::Protocol::openai(),
                &server.base_url(),
            )
            .api_key("busbar-upstream-key"),
        )
        .pool("pa", &[(0, 1)])
        .auth(Arc::new(AuthMiddleware::new(&auth_cfg)))
        .build();

    let router = crate::build_router(app);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    let client = reqwest::Client::new();
    let body = json!({"model": "pa", "messages": [{"role": "user", "content": "hi"}]}).to_string();

    // Cohere `/v2/chat` → bare {"message":..}, no `error`, no `type`.
    let r_cohere = client
        .post(format!("http://{addr}/v2/chat"))
        .header("x-api-key", "wrong-token")
        .body(body.clone())
        .send()
        .await
        .unwrap();
    assert_eq!(r_cohere.status().as_u16(), 401, "cohere wrong token → 401");
    assert_eq!(
        r_cohere
            .headers()
            .get(reqwest::header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok()),
        Some("application/json"),
    );
    let env: serde_json::Value = r_cohere.json().await.unwrap();
    assert!(
        env.get("message").is_some(),
        "cohere 401 must carry a bare message: {env}"
    );
    assert!(
        env.get("error").is_none() && env.get("type").is_none(),
        "cohere 401 must be the bare envelope (no error/type): {env}"
    );

    // Responses `/v1/responses` → {"error":{"type":"authentication_error","code":"invalid_api_key",..}}
    // (the genuine OpenAI-family bad-key 401 carries the SDK-visible code=invalid_api_key, which
    // the writers pair with type=authentication_error).
    let r_resp = client
        .post(format!("http://{addr}/v1/responses"))
        .header("x-api-key", "wrong-token")
        .body(body)
        .send()
        .await
        .unwrap();
    assert_eq!(r_resp.status().as_u16(), 401, "responses wrong token → 401");
    assert_eq!(
        r_resp
            .headers()
            .get(reqwest::header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok()),
        Some("application/json"),
    );
    let env: serde_json::Value = r_resp.json().await.unwrap();
    assert_eq!(
        env["error"]["type"], "authentication_error",
        "responses 401 must carry error.type=authentication_error: {env}"
    );
    assert_eq!(
        env["error"]["code"], "invalid_api_key",
        "responses 401 must carry the SDK-visible code=invalid_api_key (not null): {env}"
    );

    handle.abort();
    server.shutdown().await;
}

/// End-to-end through the real router + `auth_middleware` in TOKEN mode: a wrong token on the
/// Bedrock ingress path (`/model/<id>/converse`) must be rejected with HTTP 403 (NOT 401 —
/// a native SigV4 auth failure is 403) carrying `x-amzn-errortype: AccessDeniedException`, a
/// UUID-v4-shaped `x-amzn-requestid`, and a body whose `__type` is `AccessDeniedException`. The
/// existing end-to-end auth tests only cover anthropic/cohere/responses; the bedrock-specific
/// status + typing headers were exercised only by a direct `unauthorized_response` call that
/// bypasses the middleware → router stack, so a regression dropping the 403/headers in the full
/// pipeline would be uncaught.
#[cfg(feature = "auth-tokens")]
#[tokio::test]
async fn test_bedrock_ingress_wrong_token_is_403_native_envelope() {
    use crate::test_support::{LaneSpec, MockServer, MockServerState, TestApp};
    use serde_json::json;
    use std::sync::Arc;

    crate::metrics::init();

    // Auth rejects before routing, so no upstream call is made; TestApp still needs a lane/pool.
    let state = Arc::new(MockServerState::new());
    let server = MockServer::new(state).await;

    let auth_cfg = crate::config::AuthCfg {
        chain: vec!["tokens".to_string()],
        upstream_credentials: crate::auth::UpstreamCreds::Own,
        client_tokens: vec!["the-real-token".to_string()],
        modules: std::collections::HashMap::new(),
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
        .build();

    let router = crate::build_router(app);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    let client = reqwest::Client::new();
    let body = json!({"messages": [{"role": "user", "content": [{"text": "hi"}]}]}).to_string();

    let r = client
        .post(format!("http://{addr}/model/anthropic.claude/converse"))
        .header("authorization", "Bearer wrong-token")
        .body(body)
        .send()
        .await
        .unwrap();

    assert_eq!(
        r.status().as_u16(),
        403,
        "a Bedrock SigV4 auth failure must be 403, not 401 (got {})",
        r.status()
    );
    assert_eq!(
        r.headers()
            .get("x-amzn-errortype")
            .and_then(|v| v.to_str().ok()),
        Some("AccessDeniedException"),
        "Bedrock auth failure must carry x-amzn-errortype the AWS SDK types off"
    );
    let req_id = r
        .headers()
        .get("x-amzn-requestid")
        .and_then(|v| v.to_str().ok())
        .expect("Bedrock auth failure must carry x-amzn-requestid")
        .to_string();
    assert_uuid_v4_shaped(&req_id);
    assert_eq!(
        r.headers()
            .get(reqwest::header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok()),
        Some("application/json"),
    );
    let env: serde_json::Value = r.json().await.unwrap();
    assert_eq!(
        env["__type"], "AccessDeniedException",
        "bedrock body must use __type=AccessDeniedException: {env}"
    );

    handle.abort();
    server.shutdown().await;
}

/// End-to-end through the real router + `auth_middleware` in TOKEN mode: a wrong token on EITHER
/// registered Gemini ingress prefix — the `v1beta` surface (`/v1beta/models/<id>:generateContent`)
/// AND the stable `v1` alias (`/v1/models/<id>:generateContent`) — must be rejected with the
/// Gemini-native bad-key envelope: HTTP 400, `error.code == 400`, `error.status ==
/// "INVALID_ARGUMENT"` (a real Generative Language API bad key is 400 INVALID_ARGUMENT, NOT
/// 401/UNAUTHENTICATED). The stable-v1 path was previously mis-shaped as an OpenAI 401 because
/// `proto_for_path` had no `/v1/models/` arm — this exercises both prefixes through the full stack.
#[cfg(feature = "auth-tokens")]
#[tokio::test]
async fn test_gemini_ingress_wrong_token_is_native_bad_key_envelope() {
    use crate::test_support::{LaneSpec, MockServer, MockServerState, TestApp};
    use serde_json::json;
    use std::sync::Arc;

    crate::metrics::init();

    let state = Arc::new(MockServerState::new());
    let server = MockServer::new(state).await;

    let auth_cfg = crate::config::AuthCfg {
        chain: vec!["tokens".to_string()],
        upstream_credentials: crate::auth::UpstreamCreds::Own,
        client_tokens: vec!["the-real-token".to_string()],
        modules: std::collections::HashMap::new(),
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
        .build();

    let router = crate::build_router(app);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    let client = reqwest::Client::new();
    let body = json!({"contents": [{"role": "user", "parts": [{"text": "hi"}]}]}).to_string();

    // Both registered Gemini ingress prefixes must produce the identical native bad-key envelope.
    for path in [
        "/v1beta/models/gemini-1.5:generateContent",
        "/v1/models/gemini-1.5:generateContent",
    ] {
        let r = client
            .post(format!("http://{addr}{path}"))
            .header("x-goog-api-key", "wrong-token")
            .body(body.clone())
            .send()
            .await
            .unwrap();

        assert_eq!(
            r.status().as_u16(),
            400,
            "a Gemini bad-key auth failure on '{path}' must be 400 INVALID_ARGUMENT (got {})",
            r.status()
        );
        assert_eq!(
            r.headers()
                .get(reqwest::header::CONTENT_TYPE)
                .and_then(|v| v.to_str().ok()),
            Some("application/json"),
        );
        let env: serde_json::Value = r.json().await.unwrap();
        assert_eq!(
            env["error"]["code"], 400,
            "gemini error.code on '{path}': {env}"
        );
        assert_eq!(
            env["error"]["status"], "INVALID_ARGUMENT",
            "gemini error.status on '{path}' must be INVALID_ARGUMENT: {env}"
        );
    }

    handle.abort();
    server.shutdown().await;
}

/// Regression for the over-broad admin-prefix detection: a path that merely STARTS WITH the
/// bytes `/api` but is not a registered `/api/...` route (e.g. `/apix/...`) must NOT be
/// classified as admin. Under TOKEN mode with a wrong token it should be rejected by the normal
/// auth branch with the inferred-protocol native 401 envelope — never routed down the admin
/// branch (which would early-return without the `CallerToken` extension and 500 in a non-admin
/// handler). `/apix/v1/messages` infers the anthropic protocol via the `/v1/messages` suffix.
#[cfg(feature = "auth-tokens")]
#[tokio::test]
async fn test_admin_prefix_is_boundary_safe() {
    use crate::test_support::{LaneSpec, MockServer, MockServerState, TestApp};
    use serde_json::json;
    use std::sync::Arc;

    crate::metrics::init();

    let state = Arc::new(MockServerState::new());
    let server = MockServer::new(state).await;

    let auth_cfg = crate::config::AuthCfg {
        chain: vec!["tokens".to_string()],
        upstream_credentials: crate::auth::UpstreamCreds::Own,
        client_tokens: vec!["the-real-token".to_string()],
        modules: std::collections::HashMap::new(),
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
        .pool("apix", &[(0, 1)])
        .auth(Arc::new(AuthMiddleware::new(&auth_cfg)))
        .build();

    let router = crate::build_router(app);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    let client = reqwest::Client::new();
    let body =
        json!({"model": "apix", "messages": [{"role": "user", "content": "hi"}], "max_tokens": 16})
            .to_string();

    // Wrong token to `/apix/v1/messages`: rejected by the NORMAL auth branch, not the admin
    // branch — a normal-protocol native 401 (anthropic), NOT the admin "admin unauthorized"
    // path and NOT a 500 from a missing CallerToken extension.
    let r = client
        .post(format!("http://{addr}/apix/v1/messages"))
        .header("x-api-key", "wrong-token")
        .body(body)
        .send()
        .await
        .unwrap();
    assert_eq!(
        r.status().as_u16(),
        401,
        "an /apix path with a wrong token must be a normal 401, not 500/admin-500 (got {})",
        r.status()
    );
    assert_eq!(
        r.headers()
            .get(reqwest::header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok()),
        Some("application/json"),
    );
    let env: serde_json::Value = r.json().await.unwrap();
    // Anthropic native envelope (inferred from the `/v1/messages` suffix), proving the path was
    // shaped by the normal ingress branch rather than the admin branch.
    assert_eq!(env["type"], "error", "expected anthropic envelope: {env}");
    assert_eq!(
        env["error"]["type"], "authentication_error",
        "expected anthropic authentication_error: {env}"
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
    use crate::governance::{GovState, MemoryStore, Store, VirtualKey};
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
    let store = Arc::new(MemoryStore::new());
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
        budget_group: None,
        labels: Default::default(),
    };
    store.put_key(&mk("kdis", disabled_secret, false)).unwrap();
    store.put_key(&mk("kena", enabled_secret, true)).unwrap();
    // An admin token makes the governance engine ACTIVE (the vkey-resolution branch enforces). In a
    // real deploy keys can only be minted through the admin API, which requires this token — so a
    // store holding minted keys implies an admin token is set. Without it the engine is INERT and
    // the static auth chain applies (see `test_governance_inert_without_admin_token_*`).
    let gov = Arc::new(GovState::new(store, Some("admintok".to_string())).unwrap());

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
    assert_eq!(
        r_ena.status().as_u16(),
        200,
        "an enabled virtual key must pass auth (got {})",
        r_ena.status()
    );

    handle.abort();
    server.shutdown().await;
}

/// Regression (MEDIUM/correctness): `auth.mode=none` is an open relay, but governance supersedes
/// it. With governance enabled AND auth.mode explicitly None, a request that presents NO token
/// must still be rejected 401 — none-mode's accept-every-request semantics are NOT honoured. This
/// pins the documented override (and the parallel one-shot operator warning the override emits)
/// so a future refactor can't accidentally let none-mode short-circuit the governance lookup and
/// silently re-open the relay.
#[tokio::test]
async fn test_none_mode_with_governance_still_requires_virtual_key() {
    use crate::governance::{GovState, MemoryStore, Store, VirtualKey};
    use crate::test_support::{LaneSpec, MockResponse, MockServer, MockServerState, TestApp};
    use serde_json::json;
    use std::sync::Arc;

    crate::metrics::init();

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

    let secret = "sk-vk-ok";
    let store = Arc::new(MemoryStore::new());
    store
        .put_key(&VirtualKey {
            id: "k".to_string(),
            key_hash: crate::sigv4::sha256_hex(secret.as_bytes()),
            name: "k".to_string(),
            allowed_pools: vec!["pa".to_string()],
            max_budget_cents: None,
            budget_period: "total".to_string(),
            rpm_limit: None,
            tpm_limit: None,
            enabled: true,
            created_at: 0,
            budget_group: None,
            labels: Default::default(),
        })
        .unwrap();
    // An admin token makes the governance engine ACTIVE (the vkey-resolution branch enforces). In a
    // real deploy keys can only be minted through the admin API, which requires this token — so a
    // store holding minted keys implies an admin token is set. Without it the engine is INERT and
    // the static auth chain applies (see `test_governance_inert_without_admin_token_*`).
    let gov = Arc::new(GovState::new(store, Some("admintok".to_string())).unwrap());

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
        .upstream_creds(crate::auth::UpstreamCreds::Own)
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

    // No token at all → 401, even though auth.mode=none would normally admit every request.
    let r_none = client.post(&url).body(req.clone()).send().await.unwrap();
    assert_eq!(
        r_none.status().as_u16(),
        401,
        "none-mode must NOT open the relay when governance is enabled"
    );

    // A valid enabled key still passes auth (governance is what is honoured).
    let r_ok = client
        .post(&url)
        .bearer_auth(secret)
        .body(req)
        .send()
        .await
        .unwrap();
    assert_eq!(
        r_ok.status().as_u16(),
        200,
        "a valid enabled key must pass auth under governance+none (got {})",
        r_ok.status()
    );

    handle.abort();
    server.shutdown().await;
}

/// Regression (LOW/test-coverage): `auth.mode=passthrough` + governance enabled is a documented
/// UNSUPPORTED deployment. Passthrough's contract is "accept any caller credential and forward it
/// upstream", but governance supersedes it: every request must resolve to a valid ENABLED virtual
/// key. The middleware emits a one-shot operator warning (`WARN_ONCE` at the top of the governance
/// branch) and then enforces the governance lookup. Following the project precedent
/// (`test_auth_mode_none_with_client_tokens_is_inert_open_relay` and
/// `test_none_mode_with_governance_still_requires_virtual_key`), the warn line itself is NOT
/// asserted — it is a one-shot, process-global side effect emitted on a worker thread, so its
/// documented BEHAVIOURAL consequence is the contract: passthrough's accept-and-forward semantics
/// are NOT honoured. This pins it end-to-end through the real router so a future refactor can't
/// accidentally let passthrough short-circuit the governance lookup and silently forward an
/// unauthenticated caller upstream:
///   - NO token under passthrough+governance → 401 (passthrough would otherwise admit-and-forward)
///   - a non-virtual-key bearer (the kind passthrough would forward verbatim) → 401
///   - a valid enabled virtual key → admitted past auth (governance is what is honoured)
#[tokio::test]
async fn test_passthrough_mode_with_governance_still_requires_virtual_key() {
    use crate::governance::{GovState, MemoryStore, Store, VirtualKey};
    use crate::test_support::{LaneSpec, MockResponse, MockServer, MockServerState, TestApp};
    use serde_json::json;
    use std::sync::Arc;

    crate::metrics::init();

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

    let secret = "sk-vk-pt-ok";
    let store = Arc::new(MemoryStore::new());
    store
        .put_key(&VirtualKey {
            id: "k".to_string(),
            key_hash: crate::sigv4::sha256_hex(secret.as_bytes()),
            name: "k".to_string(),
            allowed_pools: vec!["pa".to_string()],
            max_budget_cents: None,
            budget_period: "total".to_string(),
            rpm_limit: None,
            tpm_limit: None,
            enabled: true,
            created_at: 0,
            budget_group: None,
            labels: Default::default(),
        })
        .unwrap();
    // An admin token makes the governance engine ACTIVE (the vkey-resolution branch enforces). In a
    // real deploy keys can only be minted through the admin API, which requires this token — so a
    // store holding minted keys implies an admin token is set. Without it the engine is INERT and
    // the static auth chain applies (see `test_governance_inert_without_admin_token_*`).
    let gov = Arc::new(GovState::new(store, Some("admintok".to_string())).unwrap());

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
        .upstream_creds(crate::auth::UpstreamCreds::Passthrough)
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

    // No token at all → 401, even though auth.mode=passthrough would normally admit-and-forward.
    let r_none = client.post(&url).body(req.clone()).send().await.unwrap();
    assert_eq!(
            r_none.status().as_u16(),
            401,
            "passthrough must NOT accept-and-forward an unauthenticated caller when governance is enabled"
        );

    // A non-virtual-key bearer — exactly the kind of caller credential passthrough would forward
    // verbatim upstream — is rejected, because governance requires a known enabled key.
    let r_unknown = client
        .post(&url)
        .bearer_auth("sk-caller-upstream-cred")
        .body(req.clone())
        .send()
        .await
        .unwrap();
    assert_eq!(
        r_unknown.status().as_u16(),
        401,
        "passthrough must NOT forward an arbitrary caller credential when governance is enabled"
    );

    // A valid enabled virtual key still passes auth (governance is what is honoured).
    let r_ok = client
        .post(&url)
        .bearer_auth(secret)
        .body(req)
        .send()
        .await
        .unwrap();
    assert_eq!(
        r_ok.status().as_u16(),
        200,
        "a valid enabled key must pass auth under governance+passthrough (got {})",
        r_ok.status()
    );

    handle.abort();
    server.shutdown().await;
}

/// A `tracing::Layer` that records the messages of WARN-level events it sees, so a test can
/// assert a particular `tracing::warn!` fired. Mirrors the helper used in eventstream/config
/// tests; kept local to the auth test module. Only the `auth-tokens`-gated test below uses it.
#[cfg(feature = "auth-tokens")]
#[derive(Clone, Default)]
struct WarnCapture(std::sync::Arc<std::sync::Mutex<Vec<String>>>);

#[cfg(feature = "auth-tokens")]
impl<S: tracing::Subscriber> tracing_subscriber::Layer<S> for WarnCapture {
    fn on_event(
        &self,
        event: &tracing::Event<'_>,
        _ctx: tracing_subscriber::layer::Context<'_, S>,
    ) {
        if *event.metadata().level() != tracing::Level::WARN {
            return;
        }
        struct Vis(String);
        impl tracing::field::Visit for Vis {
            fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
                if field.name() == "message" {
                    self.0 = format!("{value:?}");
                }
            }
        }
        let mut vis = Vis(String::new());
        event.record(&mut vis);
        if let Ok(mut msgs) = self.0.lock() {
            msgs.push(vis.0);
        }
    }
}

/// Regression (LOW #13, completeness): `auth.mode=token` WITH a non-empty static `client_tokens`
/// allowlist AND governance enabled is a silently inert configuration — governance supersedes the
/// static allowlist, so the configured tokens have ZERO enforcement effect. The OLD code emitted
/// NO diagnostic for this pairing (only the passthrough/none overrides warned), so an operator who
/// believed the static list still gated access had no signal that it was dead. The fix adds a
/// parallel one-shot `WARN_ONCE` inside the governance branch, gated on
/// `auth_mode()==Token && !client_tokens.is_empty()`.
///
/// This pins the WARNING itself (not just behaviour): the inert-allowlist behaviour is unchanged
/// by the fix, so a behaviour-only assertion would pass against the old code too. We drive the
/// real router + `auth_middleware` on a CURRENT-THREAD runtime so the synchronous `tracing::warn!`
/// fires on the same thread as the thread-local subscriber (`with_default`) and is captured — the
/// multi-thread end-to-end siblings (none/passthrough) deliberately could NOT assert their warn
/// line for exactly this thread-affinity reason. Against the old code the message assertion FAILS
/// (no such warning); it passes once the diagnostic is emitted. The static `WARN_ONCE` is
/// process-global, but this is the ONLY test that exercises the token+governance+non-empty pairing,
/// so it observes the first (and only) firing.
#[cfg(feature = "auth-tokens")]
#[test]
fn test_token_mode_with_governance_and_client_tokens_warns_inert_allowlist() {
    use crate::governance::{GovState, MemoryStore, Store, VirtualKey};
    use crate::test_support::{LaneSpec, MockResponse, MockServer, MockServerState, TestApp};
    use serde_json::json;
    use std::sync::Arc;
    use tracing_subscriber::layer::SubscriberExt as _;

    crate::metrics::init();

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("current-thread runtime must build");

    let cap = WarnCapture::default();
    let subscriber = tracing_subscriber::registry().with(cap.clone());

    let admitted = tracing::subscriber::with_default(subscriber, || {
        rt.block_on(async {
                let state = Arc::new(MockServerState::new());
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
                let server = MockServer::new(state).await;

                // The virtual key the request actually authenticates with under governance.
                let vk_secret = "sk-vk-token-gov";
                let store = Arc::new(MemoryStore::new());
                store
                    .put_key(&VirtualKey {
                        id: "k".to_string(),
                        key_hash: crate::sigv4::sha256_hex(vk_secret.as_bytes()),
                        name: "k".to_string(),
                        allowed_pools: vec!["pa".to_string()],
                        max_budget_cents: None,
                        budget_period: "total".to_string(),
                        rpm_limit: None,
                        tpm_limit: None,
                        enabled: true,
                        created_at: 0,
                        budget_group: None,
                        labels: Default::default(),
                    })
                    .unwrap();
                // Admin token → governance is ACTIVE, so the inert-allowlist branch (and its
                // one-shot warning) is reached. An inert engine (no admin token) would fall through
                // to the static chain and never emit the warning.
                let gov =
                    Arc::new(GovState::new(store, Some("admintok".to_string())).unwrap());

                // auth.mode=token WITH a non-empty static allowlist — the inert combination. The
                // listed static token is NOT the governance virtual key.
                let auth_cfg = crate::config::AuthCfg {
                    chain: vec!["tokens".to_string()], upstream_credentials: crate::auth::UpstreamCreds::Own,
                    client_tokens: vec!["static-allowlisted-but-inert".to_string()],
                    modules: std::collections::HashMap::new(),
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
                    .governance(gov)
                    .build();

                let router = crate::build_router(app);
                let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
                let addr = listener.local_addr().unwrap();
                // Spawn on the SAME current-thread runtime so the server-side middleware (and its
                // synchronous warn!) runs on this thread, under the installed subscriber.
                tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });

                let client = reqwest::Client::new();
                let url = format!("http://{addr}/pa/v1/messages");
                let body = json!({"model": "pa", "messages": [{"role": "user", "content": "hi"}], "max_tokens": 16})
                    .to_string();

                // Authenticate with the VIRTUAL KEY (governance is what is honoured), exercising the
                // governance branch where the new warning lives.
                let resp = client
                    .post(&url)
                    .bearer_auth(vk_secret)
                    .body(body)
                    .send()
                    .await
                    .unwrap();
                resp.status().as_u16()
            })
    });

    assert_eq!(
        admitted, 200,
        "the valid enabled virtual key must pass governance auth (got {admitted})"
    );

    let msgs = cap.0.lock().expect("warn capture mutex");
    assert!(
        msgs.iter().any(|m| {
            let lc = m.to_ascii_lowercase();
            lc.contains("auth.chain") && lc.contains("governance") && lc.contains("client_tokens")
        }),
        "token+governance with a non-empty client_tokens allowlist must WARN that governance \
             supersedes the static allowlist; captured warnings: {msgs:?}"
    );
}

#[test]
fn test_extract_admin_header_token_empty_filtered() {
    // Regression (LOW/security-hardening): a present-but-blank `x-admin-token` must be treated as
    // ABSENT, mirroring the empty-filter `extract_client_token` applies to the vendor carriers.
    // The OLD code mapped a blank header to `Some("")` (no `.filter(|t| !t.is_empty())`), so this
    // unit test fails against it; the filtered helper now yields `None`.
    let blank = req_with(X_ADMIN_TOKEN, "");
    assert_eq!(
        extract_admin_header_token(&blank),
        None,
        "a blank x-admin-token must be treated as absent (None)"
    );

    // A whitespace-only value is NOT blank (it is a non-empty string); it is preserved verbatim
    // and will simply fail the constant-time compare downstream — the filter is empty-only, not a
    // trim, matching extract_client_token's carrier filter exactly.
    let present = req_with(X_ADMIN_TOKEN, "admintok");
    assert_eq!(
        extract_admin_header_token(&present),
        Some("admintok".to_string()),
        "a non-empty x-admin-token must be carried verbatim"
    );

    // Absent header → None (unchanged).
    let absent = Request::builder()
        .uri("/api/v1/admin/keys")
        .body(Body::empty())
        .expect("test request must build");
    assert_eq!(extract_admin_header_token(&absent), None);
}

/// Regression (LOW/security-hardening): a present-but-blank `x-admin-token` must be rejected on
/// the admin surface. Driven end-to-end through the real router + `auth_middleware` so the
/// extraction + constant-time compare are exercised together. A correct token via the same header
/// authorizes, proving the 401 is the empty-filter and not a blanket reject.
// Admin-token behavior — requires the compile-removable `admin-tokens` module.
#[cfg(feature = "auth-admin-tokens")]
#[tokio::test]
async fn test_admin_blank_header_token_rejected() {
    use crate::governance::{GovState, MemoryStore};
    use crate::test_support::TestApp;
    use std::sync::Arc;

    crate::metrics::init();

    let store = Arc::new(MemoryStore::new());
    let gov = Arc::new(GovState::new(store, Some("admintok".to_string())).unwrap());
    let app = TestApp::new().governance(gov).build();
    let router = crate::build_router(app);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    let client = reqwest::Client::new();
    let url = format!("http://{addr}/api/v1/admin/keys");

    // Blank x-admin-token (and no Bearer) → 401: a blank header is treated as absent.
    let r_blank = client
        .get(&url)
        .header(X_ADMIN_TOKEN, "")
        .send()
        .await
        .unwrap();
    assert_eq!(
        r_blank.status().as_u16(),
        401,
        "a blank x-admin-token must be rejected (treated as absent), got {}",
        r_blank.status()
    );

    // Correct x-admin-token → authorized, proving the reject above is the empty-filter.
    let r_ok = client
        .get(&url)
        .header(X_ADMIN_TOKEN, "admintok")
        .send()
        .await
        .unwrap();
    assert_eq!(
        r_ok.status().as_u16(),
        200,
        "a correct x-admin-token must authorize, got {}",
        r_ok.status()
    );

    handle.abort();
}

/// Regression for the admin-token carrier-level timing oracle (MEDIUM/security): the two admin
/// carriers (Authorization: Bearer and x-admin-token) are combined with a bitwise-OR fold, NOT a
/// short-circuiting `||`. Behaviorally this means EITHER carrier alone authorizes, AND a request
/// presenting BOTH carriers is authorized whenever EITHER matches — regardless of which one. We
/// drive it through the real router so the inline fold in `auth_middleware` is exercised:
///   - correct Bearer + wrong x-admin-token  → authorized (header compare ran, didn't veto)
///   - wrong Bearer  + correct x-admin-token  → authorized (Bearer miss didn't short-circuit away
///                                               the header compare)
///   - wrong + wrong                          → 401
// Admin-token behavior — requires the compile-removable `admin-tokens` module.
#[cfg(feature = "auth-admin-tokens")]
#[tokio::test]
async fn test_admin_token_both_carriers_or_fold_no_short_circuit() {
    use crate::governance::{GovState, MemoryStore};
    use crate::test_support::TestApp;
    use std::sync::Arc;

    crate::metrics::init();

    let store = Arc::new(MemoryStore::new());
    let gov = Arc::new(GovState::new(store, Some("admintok".to_string())).unwrap());
    let app = TestApp::new().governance(gov).build();
    let router = crate::build_router(app);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    let client = reqwest::Client::new();
    let url = format!("http://{addr}/api/v1/admin/keys");

    // Correct Bearer + WRONG x-admin-token → authorized (the header compare must not veto a
    // matching Bearer; the fold is OR, not AND).
    let r = client
        .get(&url)
        .bearer_auth("admintok")
        .header(X_ADMIN_TOKEN, "wrong")
        .send()
        .await
        .unwrap();
    assert_eq!(
        r.status().as_u16(),
        200,
        "correct Bearer + wrong x-admin-token must authorize (OR fold), got {}",
        r.status()
    );

    // WRONG Bearer + correct x-admin-token → authorized. This is the short-circuit regression: a
    // `||` would have stopped after the Bearer miss only if the header were checked next, but the
    // real risk is the inverse ordering — assert the header compare is reached and admits.
    let r = client
        .get(&url)
        .bearer_auth("wrong")
        .header(X_ADMIN_TOKEN, "admintok")
        .send()
        .await
        .unwrap();
    assert_eq!(
        r.status().as_u16(),
        200,
        "wrong Bearer + correct x-admin-token must authorize (header compare must run), got {}",
        r.status()
    );

    // Both wrong → 401.
    let r = client
        .get(&url)
        .bearer_auth("wrong")
        .header(X_ADMIN_TOKEN, "also-wrong")
        .send()
        .await
        .unwrap();
    assert_eq!(
        r.status().as_u16(),
        401,
        "both carriers wrong must be rejected"
    );

    handle.abort();
}

/// Regression for the admin-surface carrier-separation invariant (HIGH/authz-boundary) promised
/// by the comment at the top of the `is_admin` branch: the `/admin` operator surface is guarded
/// ONLY by `Authorization: Bearer` and `x-admin-token` — NOT by the vendor-SDK client-token
/// carriers (`x-api-key` / `x-goog-api-key`) that `extract_client_token` also reads. A future
/// DRY refactor unifying admin extraction onto `extract_client_token` would let the operator
/// admin token be presented via the carriers every native vendor SDK populates, turning any
/// leaked/observed client header into operator-surface (key create/delete) access. This pins the
/// boundary: the CORRECT admin secret presented via `x-api-key` or `x-goog-api-key` MUST 401,
/// while the two sanctioned admin carriers MUST authorize.
// Admin-token behavior — requires the compile-removable `admin-tokens` module.
#[cfg(feature = "auth-admin-tokens")]
#[tokio::test]
async fn test_admin_token_not_acceptable_via_vendor_carriers() {
    use crate::governance::{GovState, MemoryStore};
    use crate::test_support::TestApp;
    use std::sync::Arc;

    crate::metrics::init();

    let store = Arc::new(MemoryStore::new());
    let gov = Arc::new(GovState::new(store, Some("admintok".to_string())).unwrap());
    let app = TestApp::new().governance(gov).build();
    let router = crate::build_router(app);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    let client = reqwest::Client::new();
    let url = format!("http://{addr}/api/v1/admin/keys");

    // The admin secret presented via the vendor-SDK carriers MUST be rejected: these carriers are
    // the client-token surface, NOT the operator surface. Exercise BOTH carriers, on BOTH the
    // GET (list) and POST (create) admin verbs, since the admin auth branch is verb-agnostic.
    for carrier in ["x-api-key", "x-goog-api-key"] {
        let r_get = client
            .get(&url)
            .header(carrier, "admintok")
            .send()
            .await
            .unwrap();
        assert_eq!(
            r_get.status().as_u16(),
            401,
            "admin secret via {carrier} (GET) must NOT reach the admin surface, got {}",
            r_get.status()
        );

        let r_post = client
            .post(&url)
            .header(carrier, "admintok")
            .json(&serde_json::json!({}))
            .send()
            .await
            .unwrap();
        assert_eq!(
            r_post.status().as_u16(),
            401,
            "admin secret via {carrier} (POST) must NOT reach the admin surface, got {}",
            r_post.status()
        );
    }

    // The two sanctioned admin carriers MUST authorize (proving the 401s above are carrier
    // separation, not a blanket reject).
    let r_bearer = client
        .get(&url)
        .bearer_auth("admintok")
        .send()
        .await
        .unwrap();
    assert_eq!(
        r_bearer.status().as_u16(),
        200,
        "Authorization: Bearer admintok must authorize the admin surface, got {}",
        r_bearer.status()
    );
    let r_hdr = client
        .get(&url)
        .header(X_ADMIN_TOKEN, "admintok")
        .send()
        .await
        .unwrap();
    assert_eq!(
        r_hdr.status().as_u16(),
        200,
        "x-admin-token: admintok must authorize the admin surface, got {}",
        r_hdr.status()
    );

    handle.abort();
}

/// End-to-end through the real router + `auth_middleware` in GOVERNANCE mode, exercising the
/// non-`Authorization` carriers (`x-goog-api-key`, `x-api-key`) into the virtual-key lookup.
/// The existing governance test only uses `Authorization: Bearer`, and the multi-carrier test
/// runs under static-token mode (`governance=None`) — so the intersection (a virtual key
/// presented via a vendor-SDK carrier resolving the governance lookup) was untested. A
/// regression that stopped threading those carriers into `gov.lookup` would otherwise pass CI.
#[tokio::test]
async fn test_governance_accepts_vendor_carriers_and_native_401() {
    use crate::governance::{GovState, MemoryStore, Store, VirtualKey};
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
    let store = Arc::new(MemoryStore::new());
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
            budget_group: None,
            labels: Default::default(),
        })
        .unwrap();
    // An admin token makes the governance engine ACTIVE (the vkey-resolution branch enforces). In a
    // real deploy keys can only be minted through the admin API, which requires this token — so a
    // store holding minted keys implies an admin token is set. Without it the engine is INERT and
    // the static auth chain applies (see `test_governance_inert_without_admin_token_*`).
    let gov = Arc::new(GovState::new(store, Some("admintok".to_string())).unwrap());

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
    let body =
        json!({"model": "pa", "messages": [{"role": "user", "content": "hi"}], "max_tokens": 16})
            .to_string();

    // Valid virtual key via x-goog-api-key (Gemini SDK carrier) → admitted past governance auth.
    let r_goog = client
        .post(&url)
        .header("x-goog-api-key", secret)
        .body(body.clone())
        .send()
        .await
        .unwrap();
    assert_eq!(
        r_goog.status().as_u16(),
        200,
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
    assert_eq!(
        r_xapi.status().as_u16(),
        200,
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

/// Regression for the empty-token governance bypass (finding auth.rs): the governance branch
/// must reject a request that presents NO credential BEFORE calling `gov.lookup`, rather than
/// looking up `sha256("")`. We deliberately seed a virtual key whose `key_hash == sha256("")` —
/// the exact pathological state (reachable via direct DB writes / a future seeding path that
/// bypasses `generate_secret`) the finding warns about — and confirm an unauthenticated request
/// is STILL rejected 401 instead of resolving to that key. Before the fix, the no-token request
/// would call `gov.lookup("")`, match this enabled key, and be admitted unauthenticated.
#[tokio::test]
async fn test_governance_rejects_empty_token_even_if_empty_secret_key_exists() {
    use crate::governance::{GovState, MemoryStore, Store, VirtualKey};
    use crate::test_support::{LaneSpec, MockServer, MockServerState, TestApp};
    use serde_json::json;
    use std::sync::Arc;

    crate::metrics::init();

    // No upstream call should happen — auth must reject before routing.
    let state = Arc::new(MockServerState::new());
    let server = MockServer::new(state).await;

    let store = Arc::new(MemoryStore::new());
    // The pathological key: its hash is sha256("") — what an empty-token lookup would compute.
    store
        .put_key(&VirtualKey {
            id: "empty".to_string(),
            key_hash: crate::sigv4::sha256_hex(b""),
            name: "empty".to_string(),
            allowed_pools: vec!["pa".to_string()],
            max_budget_cents: None,
            budget_period: "total".to_string(),
            rpm_limit: None,
            tpm_limit: None,
            enabled: true,
            created_at: 0,
            budget_group: None,
            labels: Default::default(),
        })
        .unwrap();
    // An admin token makes the governance engine ACTIVE (the vkey-resolution branch enforces). In a
    // real deploy keys can only be minted through the admin API, which requires this token — so a
    // store holding minted keys implies an admin token is set. Without it the engine is INERT and
    // the static auth chain applies (see `test_governance_inert_without_admin_token_*`).
    let gov = Arc::new(GovState::new(store, Some("admintok".to_string())).unwrap());

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
    let body =
        json!({"model": "pa", "messages": [{"role": "user", "content": "hi"}], "max_tokens": 16})
            .to_string();

    // No credential at all → must be 401 (NOT admitted by the sha256("") key).
    let r_none = client.post(&url).body(body.clone()).send().await.unwrap();
    assert_eq!(
        r_none.status().as_u16(),
        401,
        "an unauthenticated request must be rejected even when a key hashing the empty secret \
             exists in the store (got {})",
        r_none.status()
    );

    // A present-but-empty x-api-key must also reject (empty carrier is treated as absent).
    let r_empty = client
        .post(&url)
        .header("x-api-key", "")
        .body(body)
        .send()
        .await
        .unwrap();
    assert_eq!(
        r_empty.status().as_u16(),
        401,
        "a present-but-empty credential must be rejected (got {})",
        r_empty.status()
    );

    handle.abort();
    server.shutdown().await;
}

#[test]
fn test_auth_middleware_debug_redacts_tokens() {
    // Regression (SECURITY LOW #22): `AuthMiddleware` previously DERIVED `Debug`, which prints
    // every `client_tokens` entry in PLAINTEXT — a latent credential leak if it (or `App`) is
    // ever debug-logged. The manual `Debug` must redact the values, exposing only the count.
    let secret_a = "sk-super-secret-token-AAAA";
    let secret_b = "sk-super-secret-token-BBBB";
    let cfg = AuthCfg {
        chain: vec!["tokens".to_string()],
        upstream_credentials: crate::auth::UpstreamCreds::Own,
        client_tokens: vec![secret_a.to_string(), secret_b.to_string()],
        modules: std::collections::HashMap::new(),
    };
    let mw = AuthMiddleware::new(&cfg);
    let dbg = format!("{mw:?}");
    // No token value (nor any non-trivial prefix of one) may appear in the Debug output.
    assert!(
        !dbg.contains(secret_a) && !dbg.contains(secret_b),
        "AuthMiddleware Debug leaked a token value: {dbg}"
    );
    assert!(
        !dbg.contains("sk-super-secret"),
        "AuthMiddleware Debug leaked a token prefix: {dbg}"
    );
    // The count (and the chain length / upstream mode) are non-secret and SHOULD be reported.
    assert!(
        dbg.contains('2'),
        "AuthMiddleware Debug should report the token count: {dbg}"
    );
    assert!(
        dbg.contains("chain_len") && dbg.contains("Own"),
        "AuthMiddleware Debug should report the chain length + upstream mode: {dbg}"
    );
}

#[test]
fn test_caller_token_debug_redacts_value() {
    // `CallerToken` wraps a caller credential threaded into request extensions. Its manual
    // `Debug` must never print the token value (a derived `Debug` would). Present vs. absent is
    // reported; the secret itself is not.
    let secret = "sk-caller-secret-CCCC";
    let present = CallerToken(Some(secret.to_string()));
    let dbg = format!("{present:?}");
    assert!(
        !dbg.contains(secret) && !dbg.contains("sk-caller"),
        "CallerToken Debug leaked the token value: {dbg}"
    );
    assert!(
        dbg.contains("present"),
        "CallerToken Debug should report presence: {dbg}"
    );

    let absent = CallerToken(None);
    let dbg_absent = format!("{absent:?}");
    assert!(
        dbg_absent.contains("absent"),
        "CallerToken Debug should report absence: {dbg_absent}"
    );
}

// ===================== INBOUND BEDROCK SigV4 WIRING TESTS =====================

/// Sign a Bedrock-shaped POST and return the full `Authorization` header value plus the headers
/// (host / x-amz-date / x-amz-content-sha256) the client would send, using the SAME signer
/// (`crate::sigv4::sign_v4`) a real client uses. `amzdate` controls the signature timestamp.
fn sign_bedrock_request(
    secret: &str,
    access_key_id: &str,
    region: &str,
    service: &str,
    path: &str,
    body: &[u8],
    amzdate: &str,
) -> (String, Vec<(String, String)>) {
    let datestamp = &amzdate[0..8];
    let payload_hash = crate::sigv4::sha256_hex(body);
    let headers = vec![
        (
            "host".to_string(),
            "bedrock-runtime.us-east-1.amazonaws.com".to_string(),
        ),
        (X_AMZ_CONTENT_SHA256.to_string(), payload_hash.clone()),
        (X_AMZ_DATE.to_string(), amzdate.to_string()),
    ];
    let canonical_uri = crate::sigv4::uri_encode_path(path);
    let (sig, signed_headers) = crate::sigv4::sign_v4(
        secret,
        region,
        service,
        "POST",
        &canonical_uri,
        "",
        &headers,
        &payload_hash,
        amzdate,
        datestamp,
    );
    let auth = format!(
        "AWS4-HMAC-SHA256 Credential={access_key_id}/{datestamp}/{region}/{service}/aws4_request, \
             SignedHeaders={signed_headers}, Signature={sig}"
    );
    (auth, headers)
}

/// Build a `Request` with the given Authorization + signed headers (for `verify_bedrock_sigv4`).
fn bedrock_request(path: &str, auth: &str, headers: &[(String, String)]) -> Request<Body> {
    let mut b = Request::builder()
        .method("POST")
        .uri(path)
        .header(AUTHORIZATION, auth);
    for (k, v) in headers {
        b = b.header(k.as_str(), v.as_str());
    }
    b.body(Body::empty()).expect("test request must build")
}

fn gov_with_aws_key() -> (std::sync::Arc<crate::governance::GovState>, String, String) {
    use crate::governance::{GovState, MemoryStore, NewKeySpec};
    let store = std::sync::Arc::new(MemoryStore::new());
    let gov = std::sync::Arc::new(GovState::new(store, None).unwrap());
    let (_key, _bearer, akid, secret) = gov
        .create_key_with_aws(
            NewKeySpec {
                name: "bedrock".to_string(),
                allowed_pools: vec![],
                max_budget_cents: None,
                budget_period: "total".to_string(),
                rpm_limit: None,
                tpm_limit: None,
                budget_group: None,
                labels: Default::default(),
            },
            crate::store::now(),
        )
        .unwrap();
    (gov, akid, secret)
}

#[test]
fn test_verify_bedrock_sigv4_roundtrip_admits_with_govctx() {
    // A request signed with the key's REAL secret verifies and yields the owning (enabled) key.
    crate::metrics::init();
    let (gov, akid, secret) = gov_with_aws_key();
    let amzdate = {
        let (a, _d) = crate::sigv4::format_amz_time(crate::store::now());
        a
    };
    let path = "/model/anthropic.claude/converse";
    let (auth, headers) =
        sign_bedrock_request(&secret, &akid, "us-east-1", "bedrock", path, b"", &amzdate);
    let req = bedrock_request(path, &auth, &headers);
    let key =
        verify_bedrock_sigv4(&gov, &req, b"").expect("a correctly-signed request must verify");
    // Behavioral: the function resolved the SPECIFIC owning key (not just "some enabled key").
    // Tying to the key's identity (name) is a stronger statement than `key.enabled`, which merely
    // restates an input property. The owning key here is the one `gov_with_aws_key` created.
    assert_eq!(
        key.name, "bedrock",
        "verify must resolve the AWS-credentialed key that owns this AccessKeyId"
    );
}

#[test]
fn test_verify_bedrock_sigv4_wrong_secret_rejected() {
    crate::metrics::init();
    let (gov, akid, _secret) = gov_with_aws_key();
    let (a, _d) = crate::sigv4::format_amz_time(crate::store::now());
    let path = "/model/anthropic.claude/converse";
    // Sign with a DIFFERENT secret than the key's.
    let (auth, headers) = sign_bedrock_request(
        "not-the-real-secret",
        &akid,
        "us-east-1",
        "bedrock",
        path,
        b"",
        &a,
    );
    let req = bedrock_request(path, &auth, &headers);
    // `verify_bedrock_sigv4` collapses every failure to the SAME opaque `Err(())` (no
    // enumeration oracle). Assert that exact value, not just `is_err()`. The variant-level
    // distinction — that a wrong secret is a `SignatureMismatch`, NOT a distinct key-not-found
    // variant — is pinned one layer down in `sigv4::verify_inbound_sigv4`'s tests (a real-secret
    // signature verified against the dummy secret yields `SignatureMismatch`).
    assert_eq!(
        verify_bedrock_sigv4(&gov, &req, b""),
        Err(()),
        "a wrong-secret signature must be rejected with the opaque Err(())"
    );
}

#[test]
fn test_verify_bedrock_sigv4_unknown_access_key_id_rejected() {
    crate::metrics::init();
    let (gov, _akid, secret) = gov_with_aws_key();
    let (a, _d) = crate::sigv4::format_amz_time(crate::store::now());
    let path = "/model/anthropic.claude/converse";
    // A well-formed signature under an AccessKeyId that does not exist in the store.
    let (auth, headers) = sign_bedrock_request(
        &secret,
        "AKIADOESNOTEXIST0000",
        "us-east-1",
        "bedrock",
        path,
        b"",
        &a,
    );
    let req = bedrock_request(path, &auth, &headers);
    // Identical opaque `Err(())` to the wrong-secret case above — the unknown-AccessKeyId path is
    // verified against a dummy secret precisely so it is indistinguishable from a bad signature
    // (no AccessKeyId-enumeration oracle). Assert the exact value, not just `is_err()`.
    assert_eq!(
        verify_bedrock_sigv4(&gov, &req, b""),
        Err(()),
        "unknown AccessKeyId must be rejected with the SAME opaque Err(()) as a bad signature"
    );
}

#[test]
fn test_verify_bedrock_sigv4_expired_date_rejected() {
    crate::metrics::init();
    let (gov, akid, secret) = gov_with_aws_key();
    // Sign with a timestamp 10 minutes in the past — outside the ±5min skew window.
    let stale = crate::store::now().saturating_sub(crate::sigv4::CLOCK_SKEW_SECS + 60);
    let (a, _d) = crate::sigv4::format_amz_time(stale);
    let path = "/model/anthropic.claude/converse";
    let (auth, headers) =
        sign_bedrock_request(&secret, &akid, "us-east-1", "bedrock", path, b"", &a);
    let req = bedrock_request(path, &auth, &headers);
    assert!(
        verify_bedrock_sigv4(&gov, &req, b"").is_err(),
        "an expired x-amz-date must be rejected"
    );
}

#[test]
fn test_verify_bedrock_sigv4_missing_authorization_rejected() {
    crate::metrics::init();
    let (gov, _akid, _secret) = gov_with_aws_key();
    // No Authorization header at all.
    let req = Request::builder()
        .method("POST")
        .uri("/model/anthropic.claude/converse")
        .body(Body::empty())
        .unwrap();
    assert!(verify_bedrock_sigv4(&gov, &req, b"").is_err());
}

#[test]
fn test_verify_bedrock_sigv4_disabled_key_rejected() {
    crate::metrics::init();
    use crate::governance::{GovState, MemoryStore, NewKeySpec};
    let store = std::sync::Arc::new(MemoryStore::new());
    let gov = std::sync::Arc::new(GovState::new(store, None).unwrap());
    let (key, _b, akid, secret) = gov
        .create_key_with_aws(
            NewKeySpec {
                name: "k".to_string(),
                allowed_pools: vec![],
                max_budget_cents: None,
                budget_period: "total".to_string(),
                rpm_limit: None,
                tpm_limit: None,
                budget_group: None,
                labels: Default::default(),
            },
            crate::store::now(),
        )
        .unwrap();
    // Disable the key.
    gov.update_key(&key.id, Some(false), None, None, None)
        .unwrap();
    let (a, _d) = crate::sigv4::format_amz_time(crate::store::now());
    let path = "/model/anthropic.claude/converse";
    let (auth, headers) =
        sign_bedrock_request(&secret, &akid, "us-east-1", "bedrock", path, b"", &a);
    let req = bedrock_request(path, &auth, &headers);
    assert!(
        verify_bedrock_sigv4(&gov, &req, b"").is_err(),
        "a correctly-signed request for a DISABLED key must be rejected"
    );
}

#[test]
fn test_verify_bedrock_sigv4_body_matches_signed_hash_admits() {
    // (a) A non-empty body whose bytes hash to the signed `x-amz-content-sha256` is accepted.
    // This exercises the body-integrity bind on a real payload (the roundtrip test signs an empty
    // body): the verifier must re-hash THESE bytes and find they match the signed digest.
    crate::metrics::init();
    let (gov, akid, secret) = gov_with_aws_key();
    let (a, _d) = crate::sigv4::format_amz_time(crate::store::now());
    let path = "/model/anthropic.claude/converse";
    let body = br#"{"messages":[{"role":"user","content":"hi"}]}"#;
    let (auth, headers) =
        sign_bedrock_request(&secret, &akid, "us-east-1", "bedrock", path, body, &a);
    let req = bedrock_request(path, &auth, &headers);
    let key = verify_bedrock_sigv4(&gov, &req, body)
        .expect("a correctly-signed request whose body matches the signed hash must verify");
    assert_eq!(key.name, "bedrock");
}

#[test]
fn test_verify_bedrock_sigv4_tampered_body_rejected() {
    // (b) THE core fix: a VALID signature (signed over the original body) but the body bytes
    // actually delivered are DIFFERENT (a MitM tampered them in transit). The signature still
    // verifies against the declared `x-amz-content-sha256`, but the bytes no longer hash to it, so
    // the request MUST be rejected — fail-closed — with the SAME opaque `Err(())` as any other
    // failure (no oracle distinguishing "body tampered" from "bad signature").
    crate::metrics::init();
    let (gov, akid, secret) = gov_with_aws_key();
    let (a, _d) = crate::sigv4::format_amz_time(crate::store::now());
    let path = "/model/anthropic.claude/converse";
    let signed_body = br#"{"max_tokens":16}"#;
    let tampered_body = br#"{"max_tokens":999999}"#;
    // Sign over the ORIGINAL body (so Authorization + x-amz-content-sha256 are valid for it)...
    let (auth, headers) = sign_bedrock_request(
        &secret,
        &akid,
        "us-east-1",
        "bedrock",
        path,
        signed_body,
        &a,
    );
    let req = bedrock_request(path, &auth, &headers);
    // ...but feed the verifier the TAMPERED bytes (what the middleware would have buffered).
    assert_eq!(
        verify_bedrock_sigv4(&gov, &req, tampered_body),
        Err(()),
        "a body whose bytes don't match the signed x-amz-content-sha256 must fail-closed"
    );
}

#[test]
fn test_verify_bedrock_sigv4_unsigned_payload_rejected() {
    // (c) `UNSIGNED-PAYLOAD` is rejected for this governed ingress: we require a signed payload, so
    // a client declaring it did not hash its body cannot authenticate. Sign a request normally,
    // then overwrite the x-amz-content-sha256 header with the sentinel; the body-integrity gate
    // rejects it independently of any signature check, with the same opaque `Err(())`.
    crate::metrics::init();
    let (gov, akid, secret) = gov_with_aws_key();
    let (a, _d) = crate::sigv4::format_amz_time(crate::store::now());
    let path = "/model/anthropic.claude/converse";
    let body = b"some-body";
    let (auth, mut headers) =
        sign_bedrock_request(&secret, &akid, "us-east-1", "bedrock", path, body, &a);
    for (k, v) in headers.iter_mut() {
        if k == X_AMZ_CONTENT_SHA256 {
            *v = "UNSIGNED-PAYLOAD".to_string();
        }
    }
    let req = bedrock_request(path, &auth, &headers);
    assert_eq!(
        verify_bedrock_sigv4(&gov, &req, body),
        Err(()),
        "UNSIGNED-PAYLOAD must be rejected for governed Bedrock ingress"
    );
}

#[test]
fn test_has_sigv4_authorization_detects_scheme() {
    let yes = Request::builder()
        .uri("/x")
        .header(
            AUTHORIZATION,
            "AWS4-HMAC-SHA256 Credential=a/b/c/d/aws4_request, SignedHeaders=host, Signature=z",
        )
        .body(Body::empty())
        .unwrap();
    assert!(has_sigv4_authorization(&yes));
    let bearer = Request::builder()
        .uri("/x")
        .header(AUTHORIZATION, "Bearer tok")
        .body(Body::empty())
        .unwrap();
    assert!(!has_sigv4_authorization(&bearer));
    let none = Request::builder().uri("/x").body(Body::empty()).unwrap();
    assert!(!has_sigv4_authorization(&none));
}

#[test]
fn test_canonical_query_string_sorts_and_encodes() {
    assert_eq!(canonical_query_string(None), "");
    assert_eq!(canonical_query_string(Some("")), "");
    // Sorted by key; values URI-encoded (with '/' → %2F).
    assert_eq!(canonical_query_string(Some("b=2&a=1")), "a=1&b=2");
    assert_eq!(canonical_query_string(Some("p=a/b")), "p=a%2Fb");
    // Bare key signs as key= (empty value).
    assert_eq!(canonical_query_string(Some("flag")), "flag=");
}

// ─────────────────────────────────────────────────────────────────────────────
// BACK-COMPAT REGRESSION: governance is ALWAYS constructed (RAM store by default), but must be
// INERT until an admin token is configured. A legacy deploy that never opted into governance (no
// admin token, no minted keys) must behave EXACTLY as it did when `governance:` defaulted to
// disabled: the static `auth.chain` gates ingress and inference succeeds. These pin that the
// on-by-default governance engine does NOT silently supersede the static chain / open relay.
// See `auth/mod.rs`: the vkey-resolution branch is gated on `admin_token_hash().is_some()`.
// ─────────────────────────────────────────────────────────────────────────────

/// (a) DEFAULT DEPLOY, NO admin token, `auth.chain:[tokens]` + a static client_tokens entry: a
/// request bearing that static token MUST be admitted by the static chain (governance is inert and
/// does NOT require a virtual key). Before the fix this 401'd because the always-present engine
/// forced a vkey lookup that no minted key could satisfy.
#[cfg(feature = "auth-tokens")]
#[tokio::test]
async fn test_governance_inert_without_admin_token_static_token_admitted() {
    use crate::governance::{GovState, MemoryStore};
    use crate::test_support::{LaneSpec, MockResponse, MockServer, MockServerState, TestApp};
    use serde_json::json;
    use std::sync::Arc;

    crate::metrics::init();

    let state = Arc::new(MockServerState::new());
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
    let server = MockServer::new(state).await;

    let token = "busbar-static-token";
    let auth_cfg = crate::config::AuthCfg {
        chain: vec!["tokens".to_string()],
        upstream_credentials: crate::auth::UpstreamCreds::Own,
        client_tokens: vec![token.to_string()],
        modules: std::collections::HashMap::new(),
    };
    // The default-deploy governance engine: RAM store, NO admin token, NO minted keys → INERT.
    let store = Arc::new(MemoryStore::new());
    let gov = Arc::new(GovState::new(store, None).unwrap());
    assert!(
        gov.admin_token_hash().is_none(),
        "precondition: engine must be inert (no admin token)"
    );

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
        .governance(gov)
        .build();

    let router = crate::build_router(app);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    let client = reqwest::Client::new();
    let url = format!("http://{addr}/pa/v1/messages");
    let body =
        json!({"model": "pa", "messages": [{"role": "user", "content": "hi"}], "max_tokens": 16})
            .to_string();

    // The static token MUST be honoured by the static chain — governance is inert, so no vkey needed.
    let r_ok = client
        .post(&url)
        .bearer_auth(token)
        .body(body.clone())
        .send()
        .await
        .unwrap();
    assert_eq!(
        r_ok.status().as_u16(),
        200,
        "an inert governance engine must NOT supersede the static [tokens] chain (got {})",
        r_ok.status()
    );

    // A WRONG token is still rejected by the static chain (the chain still gates, as before).
    let r_bad = client
        .post(&url)
        .bearer_auth("not-the-token")
        .body(body)
        .send()
        .await
        .unwrap();
    assert_eq!(
        r_bad.status().as_u16(),
        401,
        "the static chain must still reject a non-allowlisted token (got {})",
        r_bad.status()
    );

    handle.abort();
    server.shutdown().await;
}

/// (b) NO admin token + EMPTY chain (open relay): a request presenting NO token MUST be admitted —
/// the open front door's accept-every-request semantics are honoured because governance is inert.
/// Before the fix the always-present engine rejected the tokenless request.
#[tokio::test]
async fn test_governance_inert_without_admin_token_open_relay_admits() {
    use crate::governance::{GovState, MemoryStore};
    use crate::test_support::{LaneSpec, MockResponse, MockServer, MockServerState, TestApp};
    use serde_json::json;
    use std::sync::Arc;

    crate::metrics::init();

    let state = Arc::new(MockServerState::new());
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
    let server = MockServer::new(state).await;

    let store = Arc::new(MemoryStore::new());
    let gov = Arc::new(GovState::new(store, None).unwrap());

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
        // Empty chain = open relay (the old `mode: none`).
        .upstream_creds(crate::auth::UpstreamCreds::Own)
        .governance(gov)
        .build();

    let router = crate::build_router(app);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    let client = reqwest::Client::new();
    let url = format!("http://{addr}/pa/v1/messages");
    let body =
        json!({"model": "pa", "messages": [{"role": "user", "content": "hi"}], "max_tokens": 16})
            .to_string();

    // NO token — the open relay must admit (governance is inert, not superseding the open door).
    let r_none = client.post(&url).body(body).send().await.unwrap();
    assert_eq!(
        r_none.status().as_u16(),
        200,
        "an inert governance engine must NOT supersede the open relay (got {})",
        r_none.status()
    );

    handle.abort();
    server.shutdown().await;
}

/// (c) WITH admin token + a minted enabled key: governance is ACTIVE, so a valid virtual key is
/// admitted and an unknown token is rejected — the enforcement path is unchanged once active.
#[tokio::test]
async fn test_governance_active_with_admin_token_enforces_minted_key() {
    use crate::governance::{GovState, MemoryStore, Store, VirtualKey};
    use crate::test_support::{LaneSpec, MockResponse, MockServer, MockServerState, TestApp};
    use serde_json::json;
    use std::sync::Arc;

    crate::metrics::init();

    let state = Arc::new(MockServerState::new());
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
    let server = MockServer::new(state).await;

    let secret = "sk-vk-active";
    let store = Arc::new(MemoryStore::new());
    store
        .put_key(&VirtualKey {
            id: "k".to_string(),
            key_hash: crate::sigv4::sha256_hex(secret.as_bytes()),
            name: "k".to_string(),
            allowed_pools: vec!["pa".to_string()],
            max_budget_cents: None,
            budget_period: "total".to_string(),
            rpm_limit: None,
            tpm_limit: None,
            enabled: true,
            created_at: 0,
            budget_group: None,
            labels: Default::default(),
        })
        .unwrap();
    // Admin token set → governance is ACTIVE (this is the real minted-keys deploy).
    let gov = Arc::new(GovState::new(store, Some("admintok".to_string())).unwrap());
    assert!(
        gov.admin_token_hash().is_some(),
        "precondition: engine active"
    );

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
    let body =
        json!({"model": "pa", "messages": [{"role": "user", "content": "hi"}], "max_tokens": 16})
            .to_string();

    // The enabled virtual key is admitted.
    let r_ok = client
        .post(&url)
        .bearer_auth(secret)
        .body(body.clone())
        .send()
        .await
        .unwrap();
    assert_eq!(
        r_ok.status().as_u16(),
        200,
        "an enabled virtual key must pass under active governance (got {})",
        r_ok.status()
    );

    // An unknown token is rejected — enforcement is live.
    let r_bad = client
        .post(&url)
        .bearer_auth("sk-vk-unknown")
        .body(body)
        .send()
        .await
        .unwrap();
    assert_eq!(
        r_bad.status().as_u16(),
        401,
        "active governance must reject an unknown token (got {})",
        r_bad.status()
    );

    handle.abort();
    server.shutdown().await;
}

/// (d) WITH admin token but the request lacks any virtual key: even with an OPEN static chain,
/// active governance still requires a vkey and rejects the tokenless request. This is the
/// documented "governance supersedes the open relay" behaviour — preserved when active.
#[tokio::test]
async fn test_governance_active_with_admin_token_rejects_missing_vkey() {
    use crate::governance::{GovState, MemoryStore};
    use crate::test_support::{LaneSpec, MockServer, MockServerState, TestApp};
    use serde_json::json;
    use std::sync::Arc;

    crate::metrics::init();

    // No upstream call should happen — auth must reject before routing.
    let state = Arc::new(MockServerState::new());
    let server = MockServer::new(state).await;

    let store = Arc::new(MemoryStore::new());
    let gov = Arc::new(GovState::new(store, Some("admintok".to_string())).unwrap());

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
        // Open static chain — but active governance supersedes it.
        .upstream_creds(crate::auth::UpstreamCreds::Own)
        .governance(gov)
        .build();

    let router = crate::build_router(app);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    let client = reqwest::Client::new();
    let url = format!("http://{addr}/pa/v1/messages");
    let body =
        json!({"model": "pa", "messages": [{"role": "user", "content": "hi"}], "max_tokens": 16})
            .to_string();

    // No virtual key under active governance → 401, even with an open static chain.
    let r_none = client.post(&url).body(body).send().await.unwrap();
    assert_eq!(
        r_none.status().as_u16(),
        401,
        "active governance must require a virtual key even behind an open static chain (got {})",
        r_none.status()
    );

    handle.abort();
    server.shutdown().await;
}

/// BYPASS-EDGE (the durable-store-with-persisted-keys-but-admin-token-removed case): a store that
/// STILL holds a virtual key, but whose engine has NO admin token, is INERT. A request bearing that
/// persisted key's secret is therefore NOT governed by the key's per-key controls — it falls through
/// to the STATIC auth.chain. This pins the exact "bypass by mistake" behaviour the boot guard warns
/// about: the key's `allowed_pools` (here a pool the request does NOT target) is NOT enforced, and
/// the static chain (a token allowlist that does NOT list the key secret) is what decides admission.
///
/// The auth gate keys inertness on `admin_token_hash().is_some()`, independent of the store backend,
/// so a seeded `MemoryStore` + `None` admin token faithfully reproduces the durable-store edge for
/// the middleware's purposes (the store's DURABILITY only matters for the boot-time banner, covered
/// by the main-crate tests).
#[cfg(feature = "auth-tokens")]
#[tokio::test]
async fn test_inert_governance_persisted_key_is_not_enforced_static_chain_wins() {
    use crate::governance::{GovState, MemoryStore, Store, VirtualKey};
    use crate::test_support::{LaneSpec, MockResponse, MockServer, MockServerState, TestApp};
    use serde_json::json;
    use std::sync::Arc;

    crate::metrics::init();

    let state = Arc::new(MockServerState::new());
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

    // A key PERSISTED from a prior run, scoped to pool "restricted" ONLY (a pool the request below
    // does NOT target). If the key's controls were enforced, a request to pool "pa" bearing this
    // secret would be pool-ACL rejected. Under an INERT engine they are NOT consulted at all.
    let persisted_secret = "sk-vk-persisted-from-prior-run";
    let store = Arc::new(MemoryStore::new());
    store
        .put_key(&VirtualKey {
            id: "kold".to_string(),
            key_hash: crate::sigv4::sha256_hex(persisted_secret.as_bytes()),
            name: "kold".to_string(),
            allowed_pools: vec!["restricted".to_string()],
            max_budget_cents: Some(0), // a budget that, if enforced, would block every request
            budget_period: "total".to_string(),
            rpm_limit: Some(0), // an RPM of 0 that, if enforced, would reject every request
            tpm_limit: None,
            enabled: true,
            created_at: 0,
            budget_group: None,
            labels: Default::default(),
        })
        .unwrap();
    // NO admin token → INERT: the persisted key's controls are bypassed.
    let gov = Arc::new(GovState::new(store, None).unwrap());
    assert!(
        gov.admin_token_hash().is_none(),
        "precondition: engine must be inert (no admin token)"
    );

    // The STATIC chain is what actually gates now — a token allowlist that lists a DIFFERENT token,
    // NOT the persisted key secret.
    let static_token = "static-chain-token";
    let auth_cfg = crate::config::AuthCfg {
        chain: vec!["tokens".to_string()],
        upstream_credentials: crate::auth::UpstreamCreds::Own,
        client_tokens: vec![static_token.to_string()],
        modules: std::collections::HashMap::new(),
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
        .governance(gov)
        .build();

    let router = crate::build_router(app);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    let client = reqwest::Client::new();
    let url = format!("http://{addr}/pa/v1/messages");
    let body =
        json!({"model": "pa", "messages": [{"role": "user", "content": "hi"}], "max_tokens": 16})
            .to_string();

    // (1) The persisted key secret is NOT in the static allowlist → the static chain REJECTS it.
    // This is the crux: the persisted key confers NOTHING now (its controls are inert); only the
    // static chain speaks. (If governance were still enforcing, this same secret would be ADMITTED
    // as a valid vkey — then pool-ACL/budget/RPM rejected. The 401-from-the-static-chain proves the
    // vkey path is not taken.)
    let r_key = client
        .post(&url)
        .bearer_auth(persisted_secret)
        .body(body.clone())
        .send()
        .await
        .unwrap();
    assert_eq!(
        r_key.status().as_u16(),
        401,
        "an inert engine's persisted key must confer nothing — the static chain (which does not \
         list it) rejects it (got {})",
        r_key.status()
    );

    // (2) The STATIC token is admitted — the static chain is fully in charge, and the key's zero
    // budget / zero RPM (which would block EVERY request if enforced) are NOT consulted. A 200 here
    // is the direct proof the persisted key's controls are bypassed.
    let r_static = client
        .post(&url)
        .bearer_auth(static_token)
        .body(body)
        .send()
        .await
        .unwrap();
    assert_eq!(
        r_static.status().as_u16(),
        200,
        "the static chain governs an inert engine; the persisted key's 0-budget/0-RPM are NOT \
         enforced (got {})",
        r_static.status()
    );

    handle.abort();
    server.shutdown().await;
}

/// CONTROL for the bypass-edge test: the SAME persisted key, but WITH an admin token set →
/// governance is ACTIVE and the key's per-key controls ARE enforced. The pool-ACL alone is enough
/// to prove enforcement: the key is scoped to "restricted" but the request targets "pa", so an
/// active engine rejects it (403 pool-ACL), whereas the inert twin above let the static chain decide.
#[tokio::test]
async fn test_active_governance_persisted_key_is_enforced() {
    use crate::governance::{GovState, MemoryStore, Store, VirtualKey};
    use crate::test_support::{LaneSpec, MockServer, MockServerState, TestApp};
    use serde_json::json;
    use std::sync::Arc;

    crate::metrics::init();

    // No upstream body queued — enforcement must reject before any upstream call.
    let state = Arc::new(MockServerState::new());
    let server = MockServer::new(state).await;

    let persisted_secret = "sk-vk-persisted-enforced";
    let store = Arc::new(MemoryStore::new());
    store
        .put_key(&VirtualKey {
            id: "kold".to_string(),
            key_hash: crate::sigv4::sha256_hex(persisted_secret.as_bytes()),
            name: "kold".to_string(),
            allowed_pools: vec!["restricted".to_string()], // NOT "pa"
            max_budget_cents: None,
            budget_period: "total".to_string(),
            rpm_limit: None,
            tpm_limit: None,
            enabled: true,
            created_at: 0,
            budget_group: None,
            labels: Default::default(),
        })
        .unwrap();
    // Admin token SET → ACTIVE: the key resolves and its pool-ACL is enforced.
    let gov = Arc::new(GovState::new(store, Some("admintok".to_string())).unwrap());
    assert!(
        gov.admin_token_hash().is_some(),
        "precondition: engine active"
    );

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
    let body =
        json!({"model": "pa", "messages": [{"role": "user", "content": "hi"}], "max_tokens": 16})
            .to_string();

    // The key resolves (active engine) but its allowed_pools excludes "pa" → pool-ACL 403. The key
    // IS enforced — the opposite of the inert twin, where the static chain decided instead.
    let r = client
        .post(&url)
        .bearer_auth(persisted_secret)
        .body(body)
        .send()
        .await
        .unwrap();
    assert_eq!(
        r.status().as_u16(),
        403,
        "an active engine enforces the persisted key's pool-ACL (got {})",
        r.status()
    );

    handle.abort();
    server.shutdown().await;
}
