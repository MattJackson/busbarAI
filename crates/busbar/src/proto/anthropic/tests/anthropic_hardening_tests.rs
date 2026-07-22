use super::*;

#[test]
fn stop_reason_egress_never_leaks_foreign_tokens() {
    use crate::ir::IrStopReason as S;
    // Anthropic-native reasons map to their wire token; `refusal`/`pause_turn` are real Anthropic
    // StopReason members and survive.
    assert_eq!(write_anthropic_stop_reason(S::EndTurn), "end_turn"); // golden wire-contract literal (kept bare on purpose)
    assert_eq!(write_anthropic_stop_reason(S::ToolUse), "tool_use"); // golden wire-contract literal (kept bare on purpose)
    assert_eq!(write_anthropic_stop_reason(S::PauseTurn), "pause_turn"); // golden wire-contract literal (kept bare on purpose)
    assert_eq!(write_anthropic_stop_reason(S::Refusal), "refusal"); // golden wire-contract literal (kept bare on purpose)
                                                                    // `safety` has no Anthropic member, and `error`/`other` are off-enum → all degrade to
                                                                    // end_turn rather than leak an off-spec value a strict Anthropic SDK rejects.
    assert_eq!(write_anthropic_stop_reason(S::Safety), "end_turn"); // golden wire-contract literal (kept bare on purpose)
    assert_eq!(write_anthropic_stop_reason(S::Error), "end_turn"); // golden wire-contract literal (kept bare on purpose)
    assert_eq!(write_anthropic_stop_reason(S::Other), "end_turn"); // golden wire-contract literal (kept bare on purpose)
                                                                   // The reader maps an unknown native token (e.g. the non-enum `model_context_window_exceeded`)
                                                                   // to `Other`, which then degrades on egress — it is never carried verbatim.
    assert_eq!(
        read_anthropic_stop_reason("model_context_window_exceeded"),
        S::Other
    );
}

fn header_value(headers: &[(HeaderName, HeaderValue)], name: &str) -> Option<String> {
    headers
        .iter()
        .find(|(n, _)| n.as_str() == name)
        .map(|(_, v)| v.to_str().unwrap_or_default().to_string())
}

/// A configured API key authenticates the native way: `x-api-key` ONLY, with no
/// `authorization` header — sending both is the upstream-distinguishability tell we fixed.
/// `anthropic-version` is always present.
#[test]
fn auth_headers_api_key_emits_only_x_api_key() {
    let headers = crate::proto::anthropic::anthropic_auth_headers("sk-ant-api03-secret-key", None);

    assert_eq!(
        header_value(&headers, "x-api-key").as_deref(), // golden wire-contract literal (kept bare on purpose)
        Some("sk-ant-api03-secret-key")
    );
    assert!(
        header_value(&headers, "authorization").is_none(),
        "an API key must NOT emit an authorization header (native API-key clients never do)"
    );
    assert_eq!(
        header_value(&headers, "anthropic-version").as_deref(), // golden wire-contract literal (kept bare on purpose)
        Some("2023-06-01")
    );
}

/// Regression: a configured API key with LEADING WHITESPACE (a common config
/// artifact — a stray space or indentation in an env var / secrets file) classifies as `ApiKey`
/// (because `classify_credential` matches on the trimmed key) but, before the fix, was forwarded
/// VERBATIM — emitting `x-api-key: "  sk-ant-api…"`, a malformed header value the upstream rejects
/// with a 401. The configured-key (`ApiKey`) scheme must now emit the key with the leading
/// whitespace stripped, matching the value the classifier matched on.
#[test]
fn auth_headers_api_key_trims_leading_whitespace() {
    // Wire path (sign_request, Token mode) and the mode-blind primitive both route a canonical
    // `sk-ant-api…` key through the ApiKey arm — assert both emit the CLEAN header.
    let raw = "   sk-ant-api03-secret-key";
    let ctx = crate::proto::SigningContext {
        host: "api.anthropic.com",
        canonical_uri: PATH_UPSTREAM.to_string(),
        body: b"{}",
        timestamp_epoch: 0,
        upstream_creds: crate::auth::UpstreamCreds::Own,
    };
    for headers in [
        crate::proto::anthropic::anthropic_auth_headers(raw, None),
        crate::proto::anthropic::anthropic_auth_headers(raw, Some(ctx.upstream_creds)),
    ] {
        assert_eq!(
            header_value(&headers, "x-api-key").as_deref(), // golden wire-contract literal (kept bare on purpose)
            Some("sk-ant-api03-secret-key"),
            "the ApiKey scheme must forward the configured key with leading whitespace stripped"
        );
        // Still single-header (no Bearer tell) and the trim did not corrupt the value.
        assert!(
            header_value(&headers, "authorization").is_none(),
            "an API key must NOT emit an authorization header"
        );
    }
}

/// Precision guard: the leading-whitespace trim is scoped to the configured-key
/// (`ApiKey`) scheme ONLY. An OAuth (`sk-ant-oat…`) credential — and any Ambiguous passthrough
/// Bearer token — must round-trip BYTE-FOR-BYTE, leading whitespace included, so a forwarded
/// caller token reaches the upstream exactly as presented (the passthrough contract). Trimming
/// the Bearer value here would silently rewrite a caller's credential.
#[test]
fn auth_headers_oauth_and_passthrough_preserve_leading_whitespace() {
    // OAuth (sk-ant-oat) keeps its raw Bearer value verbatim — note the leading space is kept
    // inside the value after the `Bearer ` prefix.
    let oat = "  sk-ant-oat01-caller-token";
    let oauth_headers = crate::proto::anthropic::anthropic_auth_headers(oat, None);
    assert_eq!(
        header_value(&oauth_headers, "authorization").as_deref(),
        Some("Bearer   sk-ant-oat01-caller-token"),
        "OAuth Bearer must round-trip the credential verbatim (no trim)"
    );
    assert!(
        header_value(&oauth_headers, "x-api-key").is_none(), // golden wire-contract literal (kept bare on purpose)
        "OAuth must not emit x-api-key"
    );

    // Ambiguous passthrough Bearer (wire path) likewise round-trips verbatim.
    let amb = "  opaque-caller-token";
    let ctx = crate::proto::SigningContext {
        host: "api.anthropic.com",
        canonical_uri: PATH_UPSTREAM.to_string(),
        body: b"{}",
        timestamp_epoch: 0,
        upstream_creds: crate::auth::UpstreamCreds::Passthrough,
    };
    let pt = crate::proto::anthropic::anthropic_auth_headers(amb, Some(ctx.upstream_creds));
    assert_eq!(
        header_value(&pt, "authorization").as_deref(),
        Some("Bearer   opaque-caller-token"),
        "passthrough Bearer must round-trip the caller token verbatim (no trim)"
    );
}

/// A credential matching neither Anthropic family (no `sk-ant-api` / `sk-ant-oat` prefix) is
/// Ambiguous: busbar can't tell a static key from a passthrough Bearer token here, so it emits
/// BOTH headers — preserving both paths. This is the ONLY case where both are sent; real
/// Anthropic credentials never land here.
#[test]
fn auth_headers_unrecognized_credential_emits_both_headers() {
    let headers =
        crate::proto::anthropic::anthropic_auth_headers("caller-specific-token-abc123", None);

    assert_eq!(
        header_value(&headers, "x-api-key").as_deref(), // golden wire-contract literal (kept bare on purpose)
        Some("caller-specific-token-abc123")
    );
    assert_eq!(
        header_value(&headers, "authorization").as_deref(),
        Some("Bearer caller-specific-token-abc123")
    );
    assert_eq!(
        header_value(&headers, "anthropic-version").as_deref(), // golden wire-contract literal (kept bare on purpose)
        Some("2023-06-01")
    );
}

/// Regression: the WIRE path (`sign_request`, which carries the front-door auth mode in the
/// SigningContext) resolves an Ambiguous credential to a SINGLE native header — never the
/// dual-header upstream-distinguishability tell the mode-blind `auth_headers` primitive emits.
/// Passthrough → caller's `authorization: Bearer` only; Token/None → configured `x-api-key` only.
#[test]
fn sign_request_resolves_ambiguous_credential_to_single_header_by_mode() {
    let body = b"{}";
    let ctx = |creds| crate::proto::SigningContext {
        host: "api.anthropic.com",
        canonical_uri: PATH_UPSTREAM.to_string(),
        body,
        timestamp_epoch: 0,
        upstream_creds: creds,
    };
    let amb = "caller-specific-token-abc123";

    // Passthrough: forward the caller's token as Bearer ONLY (no x-api-key tell).
    let pt = crate::proto::anthropic::anthropic_auth_headers(
        amb,
        Some(ctx(crate::auth::UpstreamCreds::Passthrough).upstream_creds),
    );
    assert_eq!(
        header_value(&pt, "authorization").as_deref(),
        Some("Bearer caller-specific-token-abc123")
    );
    assert!(
        header_value(&pt, "x-api-key").is_none(), // golden wire-contract literal (kept bare on purpose)
        "passthrough wire path must NOT also emit x-api-key (dual-header tell)"
    );

    // Own (configured lane key): present the API-key shape ONLY (no Bearer tell).
    let h = crate::proto::anthropic::anthropic_auth_headers(
        amb,
        Some(ctx(crate::auth::UpstreamCreds::Own).upstream_creds),
    );
    assert_eq!(
        header_value(&h, "x-api-key").as_deref(), // golden wire-contract literal (kept bare on purpose)
        Some("caller-specific-token-abc123")
    );
    assert!(
        header_value(&h, "authorization").is_none(),
        "own-key wire path must NOT also emit authorization (dual-header tell)"
    );

    // Clear API-key / OAuth credentials stay single-header on the wire path regardless of mode.
    let api = crate::proto::anthropic::anthropic_auth_headers(
        "sk-ant-api03-x",
        Some(ctx(crate::auth::UpstreamCreds::Own).upstream_creds),
    );
    assert!(
        header_value(&api, "x-api-key").is_some() // golden wire-contract literal (kept bare on purpose)
                && header_value(&api, "authorization").is_none()
    );
}

/// classify_credential maps each credential family deterministically; leading whitespace is
/// trimmed before matching.
#[test]
fn classify_credential_covers_each_family() {
    assert_eq!(
        AnthropicWriter::classify_credential("sk-ant-api03-key"),
        AnthropicCredScheme::ApiKey
    );
    assert_eq!(
        AnthropicWriter::classify_credential("sk-ant-oat01-token"),
        AnthropicCredScheme::OAuth
    );
    assert_eq!(
        AnthropicWriter::classify_credential("opaque-bearer"),
        AnthropicCredScheme::Ambiguous
    );
    // Whitespace must not flip an API key into the Ambiguous (dual-header) bucket.
    assert_eq!(
        AnthropicWriter::classify_credential("  sk-ant-api03-key"),
        AnthropicCredScheme::ApiKey
    );
}

/// An OAuth/passthrough Bearer token (the `sk-ant-oat` family) authenticates the native way:
/// `authorization: Bearer` ONLY, with no `x-api-key`. This preserves the passthrough path that
/// round-trips a caller's Bearer token to upstream.
#[test]
fn auth_headers_oauth_token_emits_only_authorization_bearer() {
    let headers =
        crate::proto::anthropic::anthropic_auth_headers("sk-ant-oat01-caller-token", None);

    assert_eq!(
        header_value(&headers, "authorization").as_deref(),
        Some("Bearer sk-ant-oat01-caller-token")
    );
    assert!(
        header_value(&headers, "x-api-key").is_none(), // golden wire-contract literal (kept bare on purpose)
        "an OAuth token must NOT emit an x-api-key header (native OAuth clients never do)"
    );
    assert_eq!(
        header_value(&headers, "anthropic-version").as_deref(), // golden wire-contract literal (kept bare on purpose)
        Some("2023-06-01")
    );
}

/// Leading whitespace (a likely config artifact) must not cause an OAuth token to be
/// misclassified as an API key.
#[test]
fn auth_headers_oauth_token_classification_trims_leading_whitespace() {
    let headers =
        crate::proto::anthropic::anthropic_auth_headers("  sk-ant-oat01-caller-token", None);
    // The header value itself is the verbatim (untrimmed) credential — only the
    // classification trims. Round-tripping the caller's exact token is the contract.
    assert_eq!(
        header_value(&headers, "authorization").as_deref(),
        Some("Bearer   sk-ant-oat01-caller-token")
    );
    assert!(header_value(&headers, "x-api-key").is_none()); // golden wire-contract literal (kept bare on purpose)
}

/// A key with bytes invalid for an HTTP header value (e.g. a trailing newline) must not panic
/// the worker. Under the warn+OMIT policy (matching the Bearer/Gemini/Cohere/Responses writers)
/// the credential header is now OMITTED entirely — an empty `x-api-key: ` was both a
/// syntactically invalid header and a fingerprinting tell. `anthropic-version` stays present so
/// the upstream still gets a versioned (but unauthenticated) request and returns a clean 401.
#[test]
fn auth_headers_invalid_api_key_omits_credential_no_panic() {
    // A recognizable API key (so the single-header API-key path is exercised) whose bytes are
    // invalid for an HTTP header value.
    let headers = crate::proto::anthropic::anthropic_auth_headers("sk-ant-api03-bad\nkey", None);
    assert!(
        header_value(&headers, "x-api-key").is_none(), // golden wire-contract literal (kept bare on purpose)
        "an invalid API key must OMIT x-api-key, not emit an empty value"
    );
    assert!(
        header_value(&headers, "authorization").is_none(),
        "an invalid API key still must not emit an authorization header"
    );
    // anthropic-version is static and unaffected by the bad key — it remains the only header.
    assert_eq!(
        header_value(&headers, "anthropic-version").as_deref(), // golden wire-contract literal (kept bare on purpose)
        Some("2023-06-01")
    );
    assert_eq!(
        headers.len(),
        1,
        "only anthropic-version remains on a bad key"
    );
}

/// The same warn+OMIT guarantee on the OAuth path: an invalid OAuth token OMITS the
/// `authorization` header (and never emits `x-api-key`), keeping only `anthropic-version`.
#[test]
fn auth_headers_invalid_oauth_token_omits_credential_no_panic() {
    let headers = crate::proto::anthropic::anthropic_auth_headers("sk-ant-oat01-bad\ntoken", None);
    assert!(
        header_value(&headers, "authorization").is_none(),
        "an invalid OAuth token must OMIT authorization, not emit an empty value"
    );
    assert!(
        header_value(&headers, "x-api-key").is_none(), // golden wire-contract literal (kept bare on purpose)
        "an invalid OAuth token still must not emit an x-api-key header"
    );
    assert_eq!(
        header_value(&headers, "anthropic-version").as_deref(), // golden wire-contract literal (kept bare on purpose)
        Some("2023-06-01")
    );
    assert_eq!(
        headers.len(),
        1,
        "only anthropic-version remains on a bad token"
    );
}

/// extract_error parses the body once and surfaces both provider_code and structured_type.
#[test]
fn extract_error_parses_both_fields() {
    let body_json =
        serde_json::json!({"error":{"type": ERR_TYPE_INVALID_REQUEST,"code":"some_code"}});
    let body = serde_json::to_vec(&body_json).unwrap();
    let raw = AnthropicReader.extract_error(StatusCode::BAD_REQUEST, &body);
    assert_eq!(raw.http_status, 400);
    assert_eq!(raw.provider_code.as_deref(), Some("some_code"));
    assert_eq!(
        raw.structured_type.as_deref(),
        Some("invalid_request_error") // golden wire-contract literal (kept bare on purpose)
    );
}

/// A non-JSON error body must not yield codes from the structured fields, but the
/// context-length text heuristic must still fire when the message indicates it.
#[test]
fn extract_error_non_json_body() {
    let raw = AnthropicReader.extract_error(StatusCode::BAD_REQUEST, b"not json at all");
    assert_eq!(raw.provider_code, None);
    assert_eq!(raw.structured_type, None);
}

/// Context-length is signalled via the error message; the single-parse refactor must preserve
/// the canonical code synthesis from the body text.
#[test]
fn extract_error_context_length_from_message() {
    let body_json = serde_json::json!({"error":{"type": ERR_TYPE_INVALID_REQUEST,"message":"prompt is too long"}});
    let body = serde_json::to_vec(&body_json).unwrap();
    let raw = AnthropicReader.extract_error(StatusCode::BAD_REQUEST, &body);
    assert_eq!(
        raw.provider_code.as_deref(),
        Some("context_length_exceeded")
    );
    assert_eq!(
        raw.structured_type.as_deref(),
        Some("invalid_request_error") // golden wire-contract literal (kept bare on purpose)
    );
}

/// Regression (block-index clamp): a streaming `content_block_start` whose `index` is an
/// upstream-controlled pathological value (`u64::MAX`) must be CLAMPED to
/// `MAX_ANTHROPIC_BLOCK_INDEX` before it enters the IR, so a downstream writer (GeminiWriter
/// `open_tools`, Bedrock `contentBlockIndex`) never allocates/serializes against the raw value.
/// Mirrors the Bedrock reader's `MAX_CONTENT_BLOCK_INDEX` clamp test. Against the OLD code
/// (`.map(|v| v as usize)`) this index would be `u64::MAX as usize` and the assertion fails.
#[test]
fn content_block_start_clamps_pathological_index() {
    let data = serde_json::json!({
        "type": EVT_CONTENT_BLOCK_START,
        "index": u64::MAX,
        "content_block": { "type": "text" }
    });
    let ev = AnthropicReader
        .read_response_event(EVT_CONTENT_BLOCK_START, &data)
        .expect("content_block_start parses");
    match ev {
        IrStreamEvent::BlockStart { index, .. } => {
            assert_eq!(
                index, MAX_ANTHROPIC_BLOCK_INDEX as usize,
                "a u64::MAX block index must be clamped to MAX_ANTHROPIC_BLOCK_INDEX"
            );
        }
        other => panic!("expected BlockStart, got {other:?}"),
    }
}

/// Regression (block-index clamp, delta + stop sites): the same clamp must apply to
/// `content_block_delta` and `content_block_stop`, not just `content_block_start` — all three
/// share `read_clamped_block_index`. Guards that the class is fixed at every read site.
#[test]
fn content_block_delta_and_stop_clamp_pathological_index() {
    let delta = serde_json::json!({
        "type": EVT_CONTENT_BLOCK_DELTA,
        "index": u64::MAX,
        "delta": { "type": DELTA_TYPE_TEXT, "text": "x" }
    });
    match AnthropicReader
        .read_response_event(EVT_CONTENT_BLOCK_DELTA, &delta)
        .expect("content_block_delta parses")
    {
        IrStreamEvent::BlockDelta { index, .. } => {
            assert_eq!(index, MAX_ANTHROPIC_BLOCK_INDEX as usize);
        }
        other => panic!("expected BlockDelta, got {other:?}"),
    }

    let stop = serde_json::json!({
        "type": EVT_CONTENT_BLOCK_STOP,
        "index": u64::MAX
    });
    match AnthropicReader
        .read_response_event(EVT_CONTENT_BLOCK_STOP, &stop)
        .expect("content_block_stop parses")
    {
        IrStreamEvent::BlockStop { index } => {
            assert_eq!(index, MAX_ANTHROPIC_BLOCK_INDEX as usize);
        }
        other => panic!("expected BlockStop, got {other:?}"),
    }
}

/// Regression (cross-protocol sibling of the Cohere context-length gate): a 429 whose
/// body merely MENTIONS tokens/length must NOT be reclassified to context_length. The
/// message-scan override is now gated on a request-size status (400/413), so a 429 keeps its
/// rate-limit disposition: `extract_error` leaves `provider_code` empty of the context-length
/// code, and the breaker's `normalize_raw_error` normalizes the 429 to `RateLimit` (penalizing
/// the lane). Against the OLD un-gated code, `provider_code` would become
/// `context_length_exceeded` and `normalize_raw_error` would classify it as `ContextLength`
/// (a non-penalizing fail-over) — so this asserts `RateLimit`, failing the old behavior.
#[test]
fn extract_error_429_with_token_body_not_reclassified_to_context_length() {
    // A 429 rate-limit body that happens to mention tokens (e.g. a per-token rate limit).
    let body_json = serde_json::json!({"error":{"type": ERR_TYPE_RATE_LIMIT,"message":"rate limit exceeds the maximum tokens per minute"}});
    let body = serde_json::to_vec(&body_json).unwrap();
    let raw = AnthropicReader.extract_error(StatusCode::TOO_MANY_REQUESTS, &body);
    assert_eq!(raw.http_status, 429);
    assert_ne!(
        raw.provider_code.as_deref(),
        Some("context_length_exceeded"),
        "a 429 body mentioning tokens must NOT be overridden to the context-length code"
    );
    // End-to-end: the breaker normalizes it to RateLimit, not ContextLength.
    let empty_map = std::collections::HashMap::new();
    let signal = crate::breaker::normalize_raw_error(&raw, &empty_map);
    assert_eq!(
        signal.class,
        StatusClass::RateLimit,
        "a 429 with a token-mentioning body must normalize to RateLimit, not ContextLength"
    );
}

/// Regression (positive case): a genuine 400 oversized-prompt body STILL
/// synthesizes the canonical context-length code under the new 400/413 gate, so legitimate
/// context-length fail-over is unaffected by the gating change.
#[test]
fn extract_error_400_context_length_still_synthesized_under_gate() {
    let body_json = serde_json::json!({"error":{"type": ERR_TYPE_INVALID_REQUEST,"message":"prompt is too long: 250000 tokens"}});
    let body = serde_json::to_vec(&body_json).unwrap();
    let raw = AnthropicReader.extract_error(StatusCode::BAD_REQUEST, &body);
    assert_eq!(
        raw.provider_code.as_deref(),
        Some("context_length_exceeded"),
        "a genuine 400 oversized-prompt body must still synthesize the context-length code"
    );
    let empty_map = std::collections::HashMap::new();
    let signal = crate::breaker::normalize_raw_error(&raw, &empty_map);
    assert_eq!(signal.class, StatusClass::ContextLength);
}

/// write_error must produce the NATIVE Anthropic envelope
/// `{"type":"error","error":{"type":<mapped kind>,"message":<msg>}}`, mapping a generic router
/// `kind` into Anthropic's typed error vocabulary so a native SDK decodes the right exception.
#[test]
fn write_error_native_anthropic_envelope_shape() {
    let v = AnthropicWriter.write_error(404, "not_found", "model 'x' not found");
    // Top-level discriminator is "error" (Anthropic), NOT the generic `{"error":{...}}`.
    assert_eq!(v.get("type").and_then(|t| t.as_str()), Some("error"));
    let err = v.get("error").expect("error object present");
    assert_eq!(
        err.get("type").and_then(|t| t.as_str()),
        Some("not_found_error"), // golden wire-contract literal (kept bare on purpose)
        "generic `not_found` must map to Anthropic `not_found_error`"
    );
    assert_eq!(
        err.get("message").and_then(|m| m.as_str()),
        Some("model 'x' not found")
    );
    // Round-trips as JSON (the caller serves it as application/json) — no panic.
    let s = serde_json::to_string(&v).expect("must serialize");
    let _: serde_json::Value = serde_json::from_str(&s).expect("must be valid JSON");
}

/// A `kind` already in Anthropic's vocabulary passes through unchanged (no double-mapping, no
/// `_ =>` collapse), and a representative sample of generic kinds map to the right native type.
#[test]
fn write_error_kind_vocabulary_mapping() {
    let map_of = |kind: &str| {
        AnthropicWriter
            .write_error(400, kind, "m")
            .get("error")
            .and_then(|e| e.get("type"))
            .and_then(|t| t.as_str())
            .map(String::from)
    };
    assert_eq!(map_of("rate_limit").as_deref(), Some("rate_limit_error")); // golden wire-contract literal (kept bare on purpose)
    assert_eq!(
        map_of("authentication").as_deref(),
        Some("authentication_error") // golden wire-contract literal (kept bare on purpose)
    );
    assert_eq!(
        map_of("invalid_request").as_deref(),
        Some("invalid_request_error") // golden wire-contract literal (kept bare on purpose)
    );
    // Already-native type is emitted verbatim.
    assert_eq!(
        map_of(ERR_TYPE_INVALID_REQUEST).as_deref(),
        Some("invalid_request_error") // golden wire-contract literal (kept bare on purpose)
    );
    // Unknown/unmapped kind passes through rather than being swallowed into one bucket.
    assert_eq!(
        map_of("some_custom_kind").as_deref(),
        Some("some_custom_kind")
    );
}

/// A cross-protocol upstream 503 relayed to an Anthropic-ingress client arrives with the
/// generic router kind `api_error`. Native Anthropic represents upstream overload as the 529
/// `overloaded_error`, NOT a generic `api_error`, so `write_error` must map by status: a 503
/// (and the 529 it canonically maps to) yields `error.type == "overloaded_error"`. Regression
/// guard for the conformance finding — fails against the old `_status`-ignoring code, which
/// emitted `api_error`.
#[test]
fn write_error_503_maps_to_overloaded_error_not_api_error() {
    let type_for = |status: u16| {
        AnthropicWriter
            .write_error(status, ERR_TYPE_API_ERROR, "upstream is overloaded")
            .get("error")
            .and_then(|e| e.get("type"))
            .and_then(|t| t.as_str())
            .map(String::from)
    };
    // The finding's exact scenario: cross-protocol 503 + generic `api_error` kind.
    assert_eq!(
        type_for(STATUS_OVERLOADED).as_deref(),
        Some("overloaded_error"), // golden wire-contract literal (kept bare on purpose)
        "a 503 must surface as Anthropic's overloaded_error, not a generic api_error"
    );
    // The native 529 overload status maps the same way regardless of incoming kind.
    assert_eq!(
        type_for(STATUS_ANTHROPIC_OVERLOADED).as_deref(),
        Some("overloaded_error")
    ); // golden wire-contract literal (kept bare on purpose)
       // A genuine 500-class server error (not the overload family) still maps to api_error —
       // the status override is scoped to 503/529 and does not swallow other server errors.
    assert_eq!(type_for(500).as_deref(), Some("api_error")); // golden wire-contract literal (kept bare on purpose)
                                                             // The envelope is still well-formed and request_id is minted on the status-override path.
    let v = AnthropicWriter.write_error(
        STATUS_OVERLOADED,
        ERR_TYPE_API_ERROR,
        "upstream is overloaded",
    );
    assert_eq!(v.get("type").and_then(|t| t.as_str()), Some("error"));
    assert!(
        v.get("request_id")
            .and_then(|r| r.as_str())
            .is_some_and(|r| r.starts_with("req_")),
        "the status-override path must still mint a native request_id"
    );
    assert_eq!(
        v.get("error")
            .and_then(|e| e.get("message"))
            .and_then(|m| m.as_str()),
        Some("upstream is overloaded")
    );
}

/// Same-protocol (anthropic→anthropic) passthrough must preserve the upstream response identity:
/// `read_response` captures `id`/`stop_sequence` (and model/stop_reason), and `write_response`
/// re-emits them verbatim alongside the constant `type`/`role`. Mirrors the exact non-streaming
/// `Message` shape an official SDK assembles.
#[test]
fn read_then_write_response_preserves_identity() {
    let body = serde_json::json!({
        "id": "msg_01XYZabc123",
        "type": "message",
        "role": "assistant",
        "model": "claude-opus-4-8",
        "content": [{"type": "text", "text": "hi"}],
        "stop_reason": STOP_STOP_SEQUENCE,
        "stop_sequence": "\n\nHuman:",
        "usage": {"input_tokens": 3, "output_tokens": 1}
    });
    let ir = AnthropicReader.read_response(&body).expect("read_response");
    assert_eq!(ir.id.as_deref(), Some("msg_01XYZabc123"));
    assert_eq!(ir.model.as_deref(), Some("claude-opus-4-8"));
    assert_eq!(ir.stop_reason, Some(crate::ir::IrStopReason::StopSequence));
    assert_eq!(ir.stop_sequence.as_deref(), Some("\n\nHuman:"));

    let out = AnthropicWriter.write_response(&ir);
    assert_eq!(
        out.get("id").and_then(|v| v.as_str()),
        Some("msg_01XYZabc123"),
        "id must round-trip verbatim on same-protocol passthrough"
    );
    assert_eq!(out.get("type").and_then(|v| v.as_str()), Some("message"));
    assert_eq!(out.get("role").and_then(|v| v.as_str()), Some("assistant"));
    assert_eq!(
        out.get("model").and_then(|v| v.as_str()),
        Some("claude-opus-4-8")
    );
    assert_eq!(
        out.get("stop_reason").and_then(|v| v.as_str()),
        Some("stop_sequence") // golden wire-contract literal (kept bare on purpose)
    );
    assert_eq!(
        out.get("stop_sequence").and_then(|v| v.as_str()),
        Some("\n\nHuman:")
    );
}

/// Same-protocol streaming `message_start` passthrough must preserve `id`/`model` and re-emit
/// the SDK-expected skeleton (`id`/`type`/`role`/`model`/`content`/`usage`).
#[test]
fn message_start_roundtrip_preserves_id_and_model() {
    let data = serde_json::json!({
        "message": {
            "id": "msg_stream_01",
            "type": "message",
            "role": "assistant",
            "model": "claude-opus-4-8",
            "content": [],
            "usage": {"input_tokens": 7, "output_tokens": 0}
        }
    });
    let ev = AnthropicReader
        .read_response_event(EVT_MESSAGE_START, &data)
        .expect("message_start parses");
    match &ev {
        IrStreamEvent::MessageStart { id, model, .. } => {
            assert_eq!(id.as_deref(), Some("msg_stream_01"));
            assert_eq!(model.as_deref(), Some("claude-opus-4-8"));
        }
        _ => panic!("expected MessageStart"),
    }
    let (et, out) = AnthropicWriter
        .write_response_event(&ev)
        .expect("writes message_start");
    assert_eq!(et, "message_start"); // golden wire-contract literal (kept bare on purpose)
    let msg = out.get("message").expect("message object");
    assert_eq!(
        msg.get("id").and_then(|v| v.as_str()),
        Some("msg_stream_01")
    );
    assert_eq!(msg.get("type").and_then(|v| v.as_str()), Some("message"));
    assert_eq!(msg.get("role").and_then(|v| v.as_str()), Some("assistant"));
    assert_eq!(
        msg.get("model").and_then(|v| v.as_str()),
        Some("claude-opus-4-8")
    );
    assert!(
        msg.get("content").and_then(|c| c.as_array()).is_some(),
        "content[] must be present for an SDK to initialize its Message"
    );
}

/// Cross-protocol write (the backend supplied no Anthropic id, but a non-Anthropic reader
/// recorded `created`) must SYNTHESIZE a protocol-correct `msg_`-prefixed id without panicking,
/// and the synthesized id must be unique across calls (timestamp + atomic counter).
#[test]
fn cross_protocol_write_synthesizes_valid_unique_id() {
    let make = || crate::ir::IrResponse {
        logprobs: Vec::new(),
        role: crate::ir::IrRole::Assistant,
        content: vec![crate::ir::IrBlock::Text {
            text: "x".to_string(),
            cache_control: None,
            citations: Vec::new(),
        }],
        stop_reason: Some(crate::ir::IrStopReason::EndTurn),
        usage: crate::ir::IrUsage {
            input_tokens: 1,
            output_tokens: 1,
            cache_creation_input_tokens: None,
            cache_read_input_tokens: None,
        },
        model: Some("gpt-4o".to_string()),
        id: None,
        // `created` populated → marks a cross-protocol response → synthesis fires.
        created: Some(1_700_000_000),
        system_fingerprint: None,
        stop_sequence: None,
    };
    let out1 = AnthropicWriter.write_response(&make());
    let out2 = AnthropicWriter.write_response(&make());
    let id1 = out1.get("id").and_then(|v| v.as_str()).expect("synth id 1");
    let id2 = out2.get("id").and_then(|v| v.as_str()).expect("synth id 2");
    assert!(
        id1.starts_with("msg_"),
        "synthesized id must carry the Anthropic `msg_` prefix, got {id1}"
    );
    assert!(
        id1.len() > "msg_".len(),
        "synthesized id must have a suffix"
    );
    assert_ne!(id1, id2, "synthesized ids must be unique across calls");
    // Shape stays SDK-valid: type/role/content present, no panic.
    assert_eq!(out1.get("type").and_then(|v| v.as_str()), Some("message"));
}

/// Regression (recurring across rounds): an IR carrying NEITHER `id` NOR `created` — the exact
/// shape a Bedrock Converse reader produces (its `read_response` returns `created: None` and no
/// Anthropic id) — must STILL emit a synthesized `msg_`-prefixed id. `Message.id` is a REQUIRED,
/// non-optional field in the official Anthropic SDK, so omitting it (the old `(None, None)` arm)
/// produced an undecodable Message on the Bedrock→Anthropic non-stream path. `write_response`
/// runs only on the cross-protocol translate path, so there is no same-protocol round-trip to
/// keep id-less; the id must never be absent.
#[test]
fn write_response_synthesizes_id_when_neither_id_nor_created() {
    let resp = crate::ir::IrResponse {
        logprobs: Vec::new(),
        role: crate::ir::IrRole::Assistant,
        content: vec![],
        stop_reason: None,
        usage: crate::ir::IrUsage {
            input_tokens: 0,
            output_tokens: 0,
            cache_creation_input_tokens: None,
            cache_read_input_tokens: None,
        },
        model: None,
        // The Bedrock egress → Anthropic ingress non-stream path: both None.
        id: None,
        created: None,
        system_fingerprint: None,
        stop_sequence: None,
    };
    let out = AnthropicWriter.write_response(&resp);
    let id = out
        .get("id")
        .and_then(|v| v.as_str())
        .expect("id is mandatory and must be synthesized even when id and created are both None");
    assert!(
        id.starts_with("msg_"),
        "synthesized id must carry the Anthropic `msg_` prefix, got {id}"
    );
    assert!(
        id.len() > "msg_".len(),
        "synthesized id must have a non-empty suffix"
    );
}

/// `synth_message_id` must never panic and always returns a non-empty `msg_`-prefixed id.
#[test]
fn synth_message_id_is_well_formed() {
    let id = synth_message_id();
    assert!(id.starts_with("msg_"));
    assert!(id.len() > "msg_".len());
}

/// `synth_request_id` must never panic and always returns a non-empty `req_`-prefixed id.
#[test]
fn synth_request_id_is_well_formed() {
    let id = synth_request_id();
    assert!(id.starts_with("req_"));
    assert!(id.len() > "req_".len());
}

/// write_response_event(Error(...)) must serialize the NATIVE Anthropic in-stream error shape:
/// event type `"error"`, with `error.type` carrying the provider signal AND a non-empty
/// `error.message` (the SDK's `APIError` reads both). Regression guard for the message-omission
/// and the JSON-key shape (a wrong key would silently break SDK decoding into a hang).
#[test]
fn write_response_event_error_serializes_native_shape() {
    let err = IrError {
        class: StatusClass::RateLimit,
        provider_signal: Some(ERR_TYPE_RATE_LIMIT.to_string()),
        retry_after: None,
    };
    let (event_type, data) = AnthropicWriter
        .write_response_event(&IrStreamEvent::Error(err))
        .expect("error event must serialize");
    assert_eq!(event_type, "error");
    // Top-level `type:"error"` discriminator must be present in the data body, matching every
    // other event arm and the documented native shape (`{"type":"error","error":{...}}`).
    assert_eq!(
        data.get("type").and_then(|t| t.as_str()),
        Some("error"),
        "data body must carry the top-level `type`:\"error\" discriminator"
    );
    let error_obj = data.get("error").expect("error sub-object present");
    assert_eq!(
        error_obj.get("type").and_then(|t| t.as_str()),
        Some("rate_limit_error"), // golden wire-contract literal (kept bare on purpose)
        "error.type must carry the provider signal"
    );
    let message = error_obj
        .get("message")
        .and_then(|m| m.as_str())
        .expect("error.message must be present (SDK reads it)");
    assert!(
        !message.is_empty(),
        "error.message must be non-empty so the SDK's APIError is never undefined"
    );
    // Round-trips as valid JSON — no panic on the error path.
    let s = serde_json::to_string(&data).expect("must serialize");
    let _: serde_json::Value = serde_json::from_str(&s).expect("must be valid JSON");
}

/// When the upstream error event carries no `type`, the writer must emit `error.type: null`
/// (not `""`) and still a non-empty `message`. Guards that the Option is carried through
/// (no `unwrap_or_default()`) and that a message is always present.
#[test]
fn write_response_event_error_null_type_when_signal_absent() {
    let err = IrError {
        class: StatusClass::ClientError,
        provider_signal: None,
        retry_after: None,
    };
    let (event_type, data) = AnthropicWriter
        .write_response_event(&IrStreamEvent::Error(err))
        .expect("error event must serialize");
    assert_eq!(event_type, "error");
    assert_eq!(
            data.get("type").and_then(|t| t.as_str()),
            Some("error"),
            "data body must carry the top-level `type`:\"error\" discriminator even when the inner error.type is null"
        );
    let error_obj = data.get("error").expect("error sub-object present");
    assert!(
        error_obj.get("type").map(|t| t.is_null()).unwrap_or(false),
        "error.type must be JSON null when no provider signal, not an empty string"
    );
    assert!(
        error_obj
            .get("message")
            .and_then(|m| m.as_str())
            .map(|m| !m.is_empty())
            .unwrap_or(false),
        "error.message must still be present and non-empty"
    );
}

/// The reader must carry a missing error `type` through as `None` (not `Some("")`), so a
/// `read -> write` of a type-less error event yields `error.type: null` rather than `""`.
#[test]
fn read_error_event_without_type_carries_none() {
    let data = serde_json::json!({ "error": { "message": "boom" } });
    let ev = AnthropicReader
        .read_response_event("error", &data)
        .expect("error event parses");
    match ev {
        IrStreamEvent::Error(err) => assert_eq!(
            err.provider_signal, None,
            "missing error.type must be None, not Some(\"\")"
        ),
        other => panic!("expected Error event, got {other:?}"),
    }
}

/// A reader-captured error type round-trips through the writer verbatim.
#[test]
fn read_error_event_with_type_round_trips() {
    let data = serde_json::json!({ "error": { "type": ERR_TYPE_OVERLOADED } });
    let ev = AnthropicReader
        .read_response_event("error", &data)
        .expect("error event parses");
    let (_, out) = AnthropicWriter
        .write_response_event(&ev)
        .expect("writes error event");
    assert_eq!(
        out.get("error")
            .and_then(|e| e.get("type"))
            .and_then(|t| t.as_str()),
        Some("overloaded_error") // golden wire-contract literal (kept bare on purpose)
    );
}

/// Regression: the streaming `error` reader hardcoded `StatusClass::ClientError`
/// for EVERY error type, so a mid-stream transient/hard-down fault was misclassified as a client
/// fault (`Disposition::ClientFault` records nothing) and the breaker took the wrong transition.
/// The class must now derive from the upstream `error.type`, mirroring the HTTP classifier intent.
/// This drives `read_response_event` end-to-end (not just the helper) so it fails against the old
/// hardcoded code and passes after, AND asserts the downstream breaker disposition is correct.
fn read_stream_error_class(error_type: &str) -> StatusClass {
    let data = serde_json::json!({ "error": { "type": error_type } });
    let ev = AnthropicReader
        .read_response_event("error", &data)
        .expect("error event parses");
    match ev {
        IrStreamEvent::Error(err) => err.class,
        other => panic!("expected Error event, got {other:?}"),
    }
}

#[test]
fn stream_error_overloaded_is_transient_not_client_fault() {
    assert_eq!(
        read_stream_error_class(ERR_TYPE_OVERLOADED),
        StatusClass::Overloaded
    );
    let sig = CanonicalSignal {
        class: read_stream_error_class(ERR_TYPE_OVERLOADED),
        provider_signal: None,
        retry_after: None,
    };
    assert_eq!(
        crate::breaker::classify(&sig),
        crate::breaker::Disposition::TransientUpstream,
        "a mid-stream overloaded_error is a transient upstream fault, not a client fault"
    );
}

#[test]
fn stream_error_rate_limit_is_rate_limit_class() {
    assert_eq!(
        read_stream_error_class(ERR_TYPE_RATE_LIMIT),
        StatusClass::RateLimit
    );
    let sig = CanonicalSignal {
        class: read_stream_error_class(ERR_TYPE_RATE_LIMIT),
        provider_signal: None,
        retry_after: None,
    };
    assert_eq!(
        crate::breaker::classify(&sig),
        crate::breaker::Disposition::TransientUpstream
    );
}

#[test]
fn stream_error_api_error_is_server_error_class() {
    assert_eq!(
        read_stream_error_class(ERR_TYPE_API_ERROR),
        StatusClass::ServerError
    );
    let sig = CanonicalSignal {
        class: read_stream_error_class(ERR_TYPE_API_ERROR),
        provider_signal: None,
        retry_after: None,
    };
    assert_eq!(
        crate::breaker::classify(&sig),
        crate::breaker::Disposition::TransientUpstream
    );
}

#[test]
fn stream_error_timeout_is_timeout_class() {
    assert_eq!(
        read_stream_error_class(ERR_TYPE_TIMEOUT),
        StatusClass::Timeout
    );
}

#[test]
fn stream_error_authentication_is_auth_hard_down() {
    assert_eq!(
        read_stream_error_class(ERR_TYPE_AUTHENTICATION),
        StatusClass::Auth
    );
    let sig = CanonicalSignal {
        class: read_stream_error_class(ERR_TYPE_AUTHENTICATION),
        provider_signal: None,
        retry_after: None,
    };
    assert_eq!(
        crate::breaker::classify(&sig),
        crate::breaker::Disposition::HardDown,
        "a mid-stream authentication_error must hard-down the lane, not record nothing"
    );
}

#[test]
fn stream_error_permission_is_auth_hard_down() {
    assert_eq!(
        read_stream_error_class(ERR_TYPE_PERMISSION),
        StatusClass::Auth
    );
}

#[test]
fn stream_error_billing_is_billing_hard_down() {
    assert_eq!(
        read_stream_error_class("billing_error"),
        StatusClass::Billing
    );
    let sig = CanonicalSignal {
        class: read_stream_error_class("billing_error"),
        provider_signal: None,
        retry_after: None,
    };
    assert_eq!(
        crate::breaker::classify(&sig),
        crate::breaker::Disposition::HardDown
    );
}

#[test]
fn stream_error_invalid_request_stays_client_error() {
    assert_eq!(
        read_stream_error_class(ERR_TYPE_INVALID_REQUEST),
        StatusClass::ClientError
    );
    let sig = CanonicalSignal {
        class: read_stream_error_class(ERR_TYPE_INVALID_REQUEST),
        provider_signal: None,
        retry_after: None,
    };
    assert_eq!(
        crate::breaker::classify(&sig),
        crate::breaker::Disposition::ClientFault,
        "a genuine client-fault error type must still classify as ClientFault"
    );
}

#[test]
fn stream_error_not_found_and_too_large_are_client_error() {
    assert_eq!(
        read_stream_error_class(ERR_TYPE_NOT_FOUND),
        StatusClass::ClientError
    );
    assert_eq!(
        read_stream_error_class(ERR_TYPE_REQUEST_TOO_LARGE),
        StatusClass::ClientError
    );
}

#[test]
fn stream_error_unknown_or_absent_type_falls_back_to_client_error() {
    // Unknown token: conservative non-penalizing fallback (records nothing, never trips a
    // healthy lane).
    assert_eq!(
        read_stream_error_class("some_future_error"),
        StatusClass::ClientError
    );
    // Absent type: the event carries no `type`, so the class defaults to ClientError too.
    let data = serde_json::json!({ "error": { "message": "boom" } });
    let ev = AnthropicReader
        .read_response_event("error", &data)
        .expect("error event parses");
    match ev {
        IrStreamEvent::Error(err) => {
            assert_eq!(err.class, StatusClass::ClientError);
            assert_eq!(err.provider_signal, None);
        }
        other => panic!("expected Error event, got {other:?}"),
    }
}

/// write_error must include a synthesized top-level `request_id` (`req_...`) to match the native
/// Anthropic error envelope, alongside the `type`/`error` fields.
#[test]
fn write_error_includes_synthesized_request_id() {
    let v = AnthropicWriter.write_error(429, "rate_limit", "slow down");
    let request_id = v
        .get("request_id")
        .and_then(|r| r.as_str())
        .expect("top-level request_id must be present");
    assert!(
        request_id.starts_with("req_"),
        "request_id must carry the Anthropic `req_` prefix, got {request_id}"
    );
    assert!(
        request_id.len() > "req_".len(),
        "request_id must have a suffix"
    );
    // The error envelope's other fields are untouched.
    assert_eq!(v.get("type").and_then(|t| t.as_str()), Some("error"));
    assert_eq!(
        v.get("error")
            .and_then(|e| e.get("type"))
            .and_then(|t| t.as_str()),
        Some("rate_limit_error") // golden wire-contract literal (kept bare on purpose)
    );
}

/// Regression: a `system` field in ARRAY form must be read via `as_array()` (no
/// `is_array()`/`unwrap()` pair on the request path) and yield one IR block per element without
/// panicking. Guards that the unwrap-removal refactor preserves array-system behavior.
#[test]
fn read_request_array_system_parses_blocks() {
    let body = serde_json::json!({
        "model": "claude-opus-4-8",
        "system": [
            {"type": "text", "text": "you are helpful"},
            {"type": "text", "text": "be concise"}
        ],
        "messages": [{"role": "user", "content": "hi"}],
        "max_tokens": 16
    });
    let ir = AnthropicReader
        .read_request(&body)
        .expect("array system must parse without panic");
    assert_eq!(ir.system.len(), 2, "both system text blocks must be read");
    match &ir.system[0] {
        crate::ir::IrBlock::Text { text, .. } => assert_eq!(text, "you are helpful"),
        other => panic!("expected text block, got {other:?}"),
    }
}

/// Regression: a non-array, non-string `system` value (e.g. a number) must NOT panic
/// — the refactored `as_array()`/`is_string()` guards simply produce no system blocks rather
/// than reaching a `.unwrap()`. Direct guard that the unwrap is gone from the request path.
#[test]
fn read_request_non_array_non_string_system_is_ignored_no_panic() {
    let body = serde_json::json!({
        "model": "claude-opus-4-8",
        "system": 12345,
        "messages": [{"role": "user", "content": "hi"}],
        "max_tokens": 16
    });
    let ir = AnthropicReader
        .read_request(&body)
        .expect("unexpected system shape must not panic the request path");
    assert!(
        ir.system.is_empty(),
        "a non-array/non-string system yields no blocks (no unwrap panic)"
    );
}

/// Regression: a `tool_result` block whose `content` is an ARRAY of nested blocks
/// must be read via `as_array()` (no `is_array()`/`unwrap()`) and recurse into each nested
/// block without panic. Exercises the read_block tool_result array branch.
#[test]
fn read_block_tool_result_array_content_parses() {
    let block = serde_json::json!({
        "type": "tool_result",
        "tool_use_id": "toolu_01",
        "content": [
            {"type": "text", "text": "result line 1"},
            {"type": "text", "text": "result line 2"}
        ]
    });
    let ir = read_block(&block).expect("tool_result array content must parse without panic");
    match ir {
        crate::ir::IrBlock::ToolResult {
            tool_use_id,
            content,
            ..
        } => {
            assert_eq!(tool_use_id, "toolu_01");
            assert_eq!(content.len(), 2, "both nested blocks must be read");
        }
        other => panic!("expected ToolResult, got {other:?}"),
    }
}

/// Regression: a `read_response` body whose top-level `content` is an array must be
/// read via `as_array()` without the removed `unwrap()`. Guards the response-path array read.
#[test]
fn read_response_array_content_parses_no_unwrap() {
    let body = serde_json::json!({
        "role": "assistant",
        "content": [
            {"type": "text", "text": "a"},
            {"type": "text", "text": "b"}
        ],
        "usage": {"input_tokens": 1, "output_tokens": 2}
    });
    let ir = AnthropicReader
        .read_response(&body)
        .expect("array content must parse without panic");
    assert_eq!(ir.content.len(), 2);
}

/// Id-synthesis collision guard: `synth_message_id` fills its 24-char suffix with pure CSPRNG
/// base62 (no timestamp, no counter), so distinct ids must not collide even under rapid minting.
/// We assert the synthesized ids are strictly unique across many rapid calls, and that each has
/// the native Anthropic shape (`msg_01` + 24 base62 chars = 30 chars).
#[test]
fn synth_message_id_no_collision_under_rapid_minting() {
    let n = 10_000;
    let ids: std::collections::HashSet<String> = (0..n).map(|_| synth_message_id()).collect();
    assert_eq!(
        ids.len(),
        n,
        "every synthesized message id must be unique (fixed-width counter is injective)"
    );
    // Every id matches the native Anthropic shape: `msg_` + `01` version marker + 24 random
    // base62 chars = 30 chars total. The 30-char total matches native `msg_01` + 24 random
    // chars, removing the id-LENGTH tell a client could use to distinguish a synthesized id.
    for id in &ids {
        assert_eq!(
            id.len(),
            30,
            "synthesized message id must match the native 30-char length, got {id}"
        );
        let suffix = id
            .strip_prefix("msg_01")
            .expect("msg_01 version-marker prefix");
        assert_eq!(
            suffix.len(),
            24,
            "the post-`01` token must be the native 24-char width, got {suffix}"
        );
        assert!(
            suffix.bytes().all(|b| b.is_ascii_alphanumeric()),
            "the token is base62 (alphanumeric only), got {suffix}"
        );
    }
}

/// Request ids share the same fixed-width construction and must never collide across rapid minting.
#[test]
fn synth_request_id_no_collision_under_rapid_minting() {
    let n = 10_000;
    let ids: std::collections::HashSet<String> = (0..n).map(|_| synth_request_id()).collect();
    assert_eq!(
        ids.len(),
        n,
        "every synthesized request id must be unique (fixed-width counter is injective)"
    );
}

/// An IR Image carrying the `"image_url"` media_type sentinel (an https:// URL recorded by the
/// OpenAI/Responses reader) must be written as Anthropic's native URL image source
/// `{"type":"url","url":<url>}`, NOT as a base64 source with `media_type:"image_url"`
/// (which Anthropic 400s).
#[test]
fn write_block_image_url_sentinel_emits_native_url_source() {
    let block = crate::ir::IrBlock::Image {
        source: crate::ir::IrImageSource::Url("https://example.com/cat.png".to_string()),
        cache_control: None,
    };
    let out = write_block(&block);
    assert_eq!(out.get("type").and_then(|t| t.as_str()), Some("image"));
    let source = out.get("source").expect("source present");
    assert_eq!(
        source.get("type").and_then(|t| t.as_str()),
        Some("url"),
        "image_url sentinel must map to Anthropic's url source type"
    );
    assert_eq!(
        source.get("url").and_then(|u| u.as_str()),
        Some("https://example.com/cat.png"),
        "the URL must be emitted natively, not as base64 data"
    );
    assert!(
        source.get("data").is_none(),
        "no base64 `data` field for a URL image source"
    );
    assert!(
        source.get("media_type").is_none(),
        "no `media_type:image_url` leak into the wire body"
    );
}

/// A genuine base64 image (a real `image/*` media_type) must still take the base64 source path
/// unchanged — the sentinel handling must not regress the common case.
#[test]
fn write_block_real_base64_image_unchanged() {
    let block = crate::ir::IrBlock::Image {
        source: crate::ir::IrImageSource::Base64 {
            media_type: "image/png".to_string(),
            data: "iVBORw0KGgo=".to_string(),
        },
        cache_control: None,
    };
    let out = write_block(&block);
    let source = out.get("source").expect("source present");
    assert_eq!(source.get("type").and_then(|t| t.as_str()), Some("base64"));
    assert_eq!(
        source.get("media_type").and_then(|m| m.as_str()),
        Some("image/png")
    );
    assert_eq!(
        source.get("data").and_then(|d| d.as_str()),
        Some("iVBORw0KGgo=")
    );
}

/// An Anthropic `cache_control` breakpoint placed ON an `image` or `thinking`
/// content block must survive read→IR→write instead of silently vanishing (a cache-hit cost
/// regression and a same-protocol byte difference). Both block types now carry the breakpoint
/// first-class in the IR; the reader populates it and the writer re-emits it.
#[test]
fn cache_control_on_image_and_thinking_blocks_round_trips() {
    // Image block with an ephemeral cache breakpoint.
    let img_in = serde_json::json!({
        "type": "image",
        "source": {"type": "base64", "media_type": "image/png", "data": "iVBORw0KGgo="},
        "cache_control": {"type": CACHE_KIND_EPHEMERAL}
    });
    let ir_img = read_block(&img_in).expect("read image block");
    match &ir_img {
        crate::ir::IrBlock::Image { cache_control, .. } => assert!(
            cache_control.is_some(),
            "image cache_control must be carried into the IR"
        ),
        other => panic!("expected Image, got {other:?}"),
    }
    let img_out = write_block(&ir_img);
    assert_eq!(
        img_out.get("cache_control"),
        Some(&serde_json::json!({"type": "ephemeral"})), // golden wire-contract literal (kept bare on purpose)
        "image cache_control must be re-emitted on the wire: {img_out}"
    );

    // Thinking block with an ephemeral cache breakpoint.
    let think_in = serde_json::json!({
        "type": "thinking",
        "thinking": "reasoning…",
        "signature": "sig-xyz",
        "cache_control": {"type": CACHE_KIND_EPHEMERAL}
    });
    let ir_think = read_block(&think_in).expect("read thinking block");
    match &ir_think {
        crate::ir::IrBlock::Thinking { cache_control, .. } => assert!(
            cache_control.is_some(),
            "thinking cache_control must be carried into the IR"
        ),
        other => panic!("expected Thinking, got {other:?}"),
    }
    let think_out = write_block(&ir_think);
    assert_eq!(
        think_out.get("cache_control"),
        Some(&serde_json::json!({"type": "ephemeral"})), // golden wire-contract literal (kept bare on purpose)
        "thinking cache_control must be re-emitted on the wire: {think_out}"
    );
}

/// Regression (cross-protocol image data loss): an Anthropic URL-type image source
/// `{"type":"url","url":...}` must round-trip through the `image_url` sentinel rather than
/// silently flatten to empty base64 (the base64 path reads media_type/data, both absent from a
/// url source). Old code: `media_type`/`data` both `""`; fixed code: `media_type:"image_url"`,
/// `data:<url>`, and a re-write emits the native url source again.
#[test]
fn read_block_url_image_source_round_trips_via_sentinel() {
    let block_json = serde_json::json!({
        "type": "image",
        "source": { "type": "url", "url": "https://example.com/cat.png" }
    });
    let ir = read_block(&block_json).expect("url image source parses");
    match &ir {
        crate::ir::IrBlock::Image {
            source: crate::ir::IrImageSource::Url(url),
            ..
        } => {
            assert_eq!(
                url, "https://example.com/cat.png",
                "a url source must map to the typed Url variant, preserved verbatim"
            );
        }
        other => panic!("expected IrBlock::Image(Url), got {other:?}"),
    }
    // Round-trip: writing the parsed block must re-emit Anthropic's native url source.
    let out = write_block(&ir);
    let source = out.get("source").expect("source present");
    assert_eq!(source.get("type").and_then(|t| t.as_str()), Some("url"));
    assert_eq!(
        source.get("url").and_then(|u| u.as_str()),
        Some("https://example.com/cat.png")
    );
    assert!(
        source.get("data").is_none() && source.get("media_type").is_none(),
        "no base64 leak after round-trip"
    );
}

/// Non-regression: a genuine base64 image source must still parse to its real
/// `image/*` media_type and base64 data — the url branch must not intercept it.
#[test]
fn read_block_base64_image_source_unchanged() {
    let block_json = serde_json::json!({
        "type": "image",
        "source": { "type": "base64", "media_type": "image/png", "data": "iVBORw0KGgo=" }
    });
    let ir = read_block(&block_json).expect("base64 image source parses");
    match ir {
        crate::ir::IrBlock::Image {
            source: crate::ir::IrImageSource::Base64 { media_type, data },
            ..
        } => {
            assert_eq!(media_type, "image/png");
            assert_eq!(data, "iVBORw0KGgo=");
        }
        other => panic!("expected IrBlock::Image, got {other:?}"),
    }
}

/// Completeness: a valid native Anthropic content-block type the IR does not model
/// (e.g. `document`) must NOT hard-error the whole request with a ClientError 400. Mirroring the
/// OpenAI reader, `read_block` now degrades an unmodeled block to an empty Text block, preserving
/// the turn. Against the old `_ => Err(ClientError)` catch-all this asserted `Err`, so this test
/// fails on old code and passes after the named graceful-degradation arm.
#[test]
fn read_block_unmodeled_document_type_degrades_not_400() {
    let block_json = serde_json::json!({
        "type": "document",
        "source": { "type": "base64", "media_type": "application/pdf", "data": "JVBERi0=" }
    });
    let ir = read_block(&block_json)
        .expect("unmodeled native block (document) must degrade, not 400 a valid request");
    match ir {
        crate::ir::IrBlock::Text {
            text,
            cache_control,
            citations,
        } => {
            assert_eq!(text, "", "unmodeled block degrades to an empty text block");
            assert!(cache_control.is_none());
            assert!(citations.is_empty());
        }
        other => panic!("expected graceful IrBlock::Text degradation, got {other:?}"),
    }

    // A `redacted_thinking` block (a valid native type the IR does not model directly)
    // is now PRESERVED — not degraded to empty Text — by mapping it onto the redacted-reasoning
    // sentinel carrier (the same IR shape Bedrock's `redactedContent` uses), with the opaque
    // `data` bytes in `text`. It must still not 400.
    let redacted = serde_json::json!({ "type": BLOCK_TYPE_REDACTED_THINKING, "data": "abc123" });
    match read_block(&redacted).expect("redacted_thinking must not 400") {
        crate::ir::IrBlock::Thinking {
            text,
            redacted,
            signature,
            ..
        } => {
            assert_eq!(text, "abc123", "opaque redacted data preserved in text");
            assert!(redacted, "redacted_thinking sets the typed redacted flag");
            assert!(signature.is_none(), "no sentinel smuggled in signature");
        }
        other => panic!("expected Thinking carrier for redacted_thinking, got {other:?}"),
    }
}

/// REGRESSION (audit c2r2): the STREAMING reader must not drop a `redacted_thinking` block. The
/// opaque `data` rides inline on `content_block_start` (no deltas follow), so the reader emits a
/// `Thinking` BlockStart + a `RedactedReasoningDelta` carrying the bytes; the later
/// `content_block_stop` yields the BlockStop. Before the fix the block hit `_ => None` and the
/// encrypted reasoning was silently lost on an any→Anthropic streaming passthrough.
#[test]
fn streaming_redacted_thinking_is_not_dropped() {
    let reader = AnthropicReader;
    let mut state = crate::ir::StreamDecodeState::default();
    let start = serde_json::json!({
        "type": EVT_CONTENT_BLOCK_START,
        "index": 0,
        "content_block": { "type": BLOCK_TYPE_REDACTED_THINKING, "data": "ENCRYPTED_BYTES" }
    });
    let evs = reader.read_response_events(EVT_CONTENT_BLOCK_START, &start, &mut state);
    assert_eq!(
        evs.len(),
        2,
        "redacted_thinking start emits BlockStart + delta, got {evs:?}"
    );
    assert!(
        matches!(
            &evs[0],
            IrStreamEvent::BlockStart {
                index: 0,
                block: IrBlockMeta::Thinking
            }
        ),
        "first event is a Thinking BlockStart: {:?}",
        evs[0]
    );
    match &evs[1] {
        IrStreamEvent::BlockDelta {
            index: 0,
            delta: IrDelta::RedactedReasoningDelta(bytes),
        } => assert_eq!(
            bytes, "ENCRYPTED_BYTES",
            "opaque bytes preserved, not dropped"
        ),
        other => panic!("expected RedactedReasoningDelta carrying the bytes, got {other:?}"),
    }
    // The following content_block_stop still yields a BlockStop.
    let stop = serde_json::json!({"type": EVT_CONTENT_BLOCK_STOP, "index": 0});
    let stop_evs = reader.read_response_events(EVT_CONTENT_BLOCK_STOP, &stop, &mut state);
    assert!(
        matches!(stop_evs.as_slice(), [IrStreamEvent::BlockStop { index: 0 }]),
        "content_block_stop closes the redacted block: {stop_evs:?}"
    );
}

/// Round-trip: an Anthropic `redacted_thinking` block read on the RESPONSE path must
/// re-emit as a NATIVE `redacted_thinking` block (preserving the opaque `data` bytes) on
/// Anthropic egress — NOT as a plaintext `thinking` block, and WITHOUT leaking the `__busbar`
/// sentinel onto the wire. This confirms the reader/writer pairing round-trips response reasoning.
#[test]
fn redacted_thinking_response_round_trips_as_native_block() {
    let native = serde_json::json!({
        "id": "msg_1",
        "type": "message",
        "role": "assistant",
        "model": "claude",
        "content": [{"type": BLOCK_TYPE_REDACTED_THINKING, "data": "OPAQUEBYTES"}],
        "stop_reason": STOP_END_TURN,
        "usage": {"input_tokens": 1, "output_tokens": 1}
    });
    let ir = AnthropicReader
        .read_response(&native)
        .expect("response with redacted_thinking parses");
    // Carrier shape preserved in the IR.
    match &ir.content[0] {
        crate::ir::IrBlock::Thinking { text, redacted, .. } => {
            assert_eq!(text, "OPAQUEBYTES");
            assert!(*redacted, "redacted_thinking sets the typed redacted flag");
        }
        other => panic!("expected redacted Thinking carrier, got {other:?}"),
    }
    // Writer re-emits a NATIVE redacted_thinking block.
    let out = AnthropicWriter.write_response(&ir);
    let block = &out["content"][0];
    assert_eq!(
        block["type"].as_str(),
        Some("redacted_thinking"), // golden wire-contract literal (kept bare on purpose)
        "must re-emit native redacted_thinking, not plaintext thinking"
    );
    assert_eq!(block["data"].as_str(), Some("OPAQUEBYTES"));
    assert!(
        !out.to_string().contains("__busbar"),
        "no busbar marker may reach the wire"
    );
}

/// Uniformity: `synth_id_with_prefix` must draw each base62 character
/// uniformly via rejection sampling, NOT `byte % 62`. The old modulo over-represents characters
/// 0..7 by ~25% (256 = 4*62 + 8). Mint a large burst and assert (a) every id is unique, (b) the
/// per-character frequency of the low/biased band vs the high band is balanced within tolerance.
#[test]
fn synth_id_uniform_and_unique_under_burst() {
    let n = 20_000usize;
    let ids: Vec<String> = (0..n).map(|_| synth_request_id()).collect();
    let unique: std::collections::HashSet<&String> = ids.iter().collect();
    assert_eq!(
        unique.len(),
        n,
        "burst of synthesized ids must be collision-free"
    );

    // Index each token character into the base62 alphabet and tally how many land in the
    // over-represented band (alphabet positions 0..8, which a `% 62` bias inflates) vs the rest.
    let mut low_band = 0u64; // alphabet indices 0..8
    let mut other_band = 0u64; // alphabet indices 8..62
    for id in &ids {
        let token = id.strip_prefix("req_01").expect("req_01 prefix");
        for &b in token.as_bytes() {
            let idx = ANTHROPIC_NATIVE_ALPHABET
                .iter()
                .position(|&a| a == b)
                .expect("token char is in the base62 alphabet");
            if idx < 8 {
                low_band += 1;
            } else {
                other_band += 1;
            }
        }
    }
    // Under a uniform draw the expected per-character probability is 1/62; the 8-char low band
    // should hold ~8/62 of all characters. The biased `% 62` would push the low band to ~10/62
    // (each of 0..7 drawn from 5 source bytes instead of 4 → +25%). Assert the observed low-band
    // share sits near 8/62 and well below the 9/62 a meaningful bias would reach.
    let total = low_band + other_band;
    let low_share = low_band as f64 / total as f64;
    let expected = 8.0 / 62.0;
    assert!(
        (low_share - expected).abs() < 0.01,
        "low-band share {low_share:.4} must be near uniform {expected:.4} (rejection sampling); \
             a `% 62` bias would push it toward {:.4}",
        9.0 / 62.0
    );
}

/// Shape invariant: rejection sampling must not change the native length
/// or alphabet — `req_01` + 24 base62 chars = 30 total.
#[test]
fn synth_id_matches_native_length_and_alphabet() {
    let id = synth_request_id();
    assert_eq!(id.len(), 30, "native 30-char length");
    let token = id.strip_prefix("req_01").expect("req_01 prefix");
    assert_eq!(token.len(), 24, "24-char base62 token");
    assert!(
        token.bytes().all(|b| b.is_ascii_alphanumeric()),
        "token is base62 alphanumeric, got {token}"
    );
}

/// Regression (unchecked cast truncation): `max_tokens`/`top_k` larger than `u32::MAX` must drop to
/// `None` via checked `try_from`, NOT silently truncate. Old code: `4_294_967_297 as u32` == 1,
/// forwarding a corrupted cap. Fixed code: out-of-range → None.
#[test]
fn read_request_oversized_max_tokens_and_top_k_drop_to_none() {
    let body = serde_json::json!({
        "model": "claude-3-5-sonnet",
        "messages": [{ "role": "user", "content": "hi" }],
        "max_tokens": 4_294_967_297u64,
        "top_k": 8_589_934_592u64
    });
    let ir = AnthropicReader.read_request(&body).expect("request parses");
    assert_eq!(
        ir.max_tokens, None,
        "an over-u32 max_tokens must drop to None, not truncate to a small value"
    );
    assert_eq!(
        ir.top_k, None,
        "an over-u32 top_k must drop to None, not truncate to a small value"
    );
    // In-range values still survive the checked cast.
    let body2 = serde_json::json!({
        "model": "claude-3-5-sonnet",
        "messages": [{ "role": "user", "content": "hi" }],
        "max_tokens": 1024u64,
        "top_k": 40u64
    });
    let ir2 = AnthropicReader
        .read_request(&body2)
        .expect("request parses");
    assert_eq!(ir2.max_tokens, Some(1024));
    assert_eq!(ir2.top_k, Some(40));
}

/// On the REQUEST side `write_message` must drop an assistant
/// Thinking block whose `signature` is None (Anthropic 400s an unsigned thinking block), while a
/// signed thinking block and surrounding text survive.
#[test]
fn write_message_drops_unsigned_thinking_block() {
    let msg = crate::ir::IrMessage {
        role: crate::ir::IrRole::Assistant,
        content: vec![
            crate::ir::IrBlock::Thinking {
                text: "unsigned reasoning".to_string(),
                signature: None,
                redacted: false,
                cache_control: None,
            },
            crate::ir::IrBlock::Thinking {
                text: "signed reasoning".to_string(),
                signature: Some("sig-abc".to_string()),
                redacted: false,
                cache_control: None,
            },
            crate::ir::IrBlock::Text {
                text: "the answer".to_string(),
                cache_control: None,
                citations: Vec::new(),
            },
        ],
    };
    let out = write_message(&msg);
    let content = out
        .get("content")
        .and_then(|c| c.as_array())
        .expect("content array");
    assert_eq!(
        content.len(),
        2,
        "the unsigned thinking block must be dropped, signed thinking + text kept"
    );
    // The surviving thinking block is the signed one; no block lacks a signature.
    for block in content {
        if block.get("type").and_then(|t| t.as_str()) == Some("thinking") {
            assert!(
                block.get("signature").and_then(|s| s.as_str()).is_some(),
                "every emitted thinking block must carry a signature"
            );
        }
    }
    let texts: Vec<&str> = content
        .iter()
        .filter_map(|b| b.get("thinking").or_else(|| b.get("text")))
        .filter_map(|v| v.as_str())
        .collect();
    assert!(texts.contains(&"signed reasoning"));
    assert!(texts.contains(&"the answer"));
    assert!(!texts.contains(&"unsigned reasoning"));
}

/// Regression (empty-content): when every content block is filtered out — e.g. an
/// all-thinking assistant message whose unsigned thinking blocks are all dropped on the request
/// path — `write_message` must emit `content: []` (an empty array, a valid zero-block message),
/// NOT `content: ""` (an empty string, which Anthropic's Messages API rejects with a 400). The
/// old code emitted the bare empty string; this guards the regression.
#[test]
fn write_message_emits_empty_array_when_all_blocks_dropped() {
    let msg = crate::ir::IrMessage {
        role: crate::ir::IrRole::Assistant,
        content: vec![
            crate::ir::IrBlock::Thinking {
                text: "unsigned reasoning A".to_string(),
                signature: None,
                redacted: false,
                cache_control: None,
            },
            crate::ir::IrBlock::Thinking {
                text: "unsigned reasoning B".to_string(),
                signature: None,
                redacted: false,
                cache_control: None,
            },
        ],
    };
    let out = write_message(&msg);
    let content = out.get("content").expect("content key present");
    assert!(
            !content.is_string(),
            "content must not be a bare empty string (anthropic 400s an empty content string): {content:?}"
        );
    let arr = content
        .as_array()
        .expect("content must be an array when no blocks survive");
    assert!(
        arr.is_empty(),
        "every block was dropped, so the content array must be empty: {arr:?}"
    );
}

/// Companion: a message with a single surviving block still emits a populated
/// content ARRAY (never the empty-string fallback) — confirms the non-empty branch is intact
/// after collapsing the old `if blocks.is_empty()` split.
#[test]
fn write_message_emits_array_for_surviving_block() {
    let msg = crate::ir::IrMessage {
        role: crate::ir::IrRole::Assistant,
        content: vec![crate::ir::IrBlock::Text {
            text: "kept".to_string(),
            cache_control: None,
            citations: Vec::new(),
        }],
    };
    let out = write_message(&msg);
    let arr = out
        .get("content")
        .and_then(|c| c.as_array())
        .expect("content must be an array");
    assert_eq!(arr.len(), 1, "the single text block must survive: {arr:?}");
    assert_eq!(arr[0].get("text").and_then(|t| t.as_str()), Some("kept"));
}

/// Non-regression: the request-side filter must NOT affect the response
/// path — `write_response` still surfaces an unsigned thinking block as a `thinking` content
/// block (response reasoning has no signature requirement).
#[test]
fn write_response_keeps_unsigned_thinking_block() {
    let resp = crate::ir::IrResponse {
        logprobs: Vec::new(),
        role: crate::ir::IrRole::Assistant,
        content: vec![crate::ir::IrBlock::Thinking {
            text: "visible reasoning".to_string(),
            signature: None,
            redacted: false,
            cache_control: None,
        }],
        stop_reason: None,
        usage: crate::ir::IrUsage {
            input_tokens: 1,
            output_tokens: 1,
            cache_creation_input_tokens: None,
            cache_read_input_tokens: None,
        },
        model: Some("claude-3-5-sonnet".to_string()),
        id: Some("msg_123".to_string()),
        created: None,
        system_fingerprint: None,
        stop_sequence: None,
    };
    let out = AnthropicWriter.write_response(&resp);
    let content = out
        .get("content")
        .and_then(|c| c.as_array())
        .expect("content array");
    assert!(
        content
            .iter()
            .any(|b| b.get("type").and_then(|t| t.as_str()) == Some("thinking")),
        "response reasoning must still surface even without a signature"
    );
}

/// `message_start` must carry a `usage` object even when the IR `MessageStart.usage` is None
/// (the OpenAI→Anthropic case). The native API always emits `usage:{input_tokens,output_tokens}`
/// at stream open, and the TS SDK types it as required — a missing key crashes a client that
/// reads `message.usage.input_tokens`.
#[test]
fn message_start_emits_zero_usage_when_none() {
    let ev = IrStreamEvent::MessageStart {
        role: crate::ir::IrRole::Assistant,
        usage: None,
        id: None,
        created: Some(1_700_000_000),
        model: Some("gpt-4o".to_string()),
    };
    let (et, out) = AnthropicWriter
        .write_response_event(&ev)
        .expect("message_start writes");
    assert_eq!(et, "message_start"); // golden wire-contract literal (kept bare on purpose)
    let usage = out
        .get("message")
        .and_then(|m| m.get("usage"))
        .expect("usage object must be present even when source usage is None");
    assert_eq!(
        usage.get("input_tokens").and_then(|v| v.as_u64()),
        Some(0),
        "input_tokens must default to 0, not be omitted"
    );
    assert_eq!(
        usage.get("output_tokens").and_then(|v| v.as_u64()),
        Some(0),
        "output_tokens must be 0 at stream open (native behavior)"
    );
}

/// When usage IS present on `message_start`, its values and the optional cache fields must flow
/// through verbatim.
#[test]
fn message_start_emits_present_usage_with_cache_fields() {
    let ev = IrStreamEvent::MessageStart {
        role: crate::ir::IrRole::Assistant,
        usage: Some(IrUsage {
            input_tokens: 42,
            output_tokens: 0,
            cache_creation_input_tokens: Some(5),
            cache_read_input_tokens: Some(7),
        }),
        id: Some("msg_x".to_string()),
        created: None,
        model: None,
    };
    let (_, out) = AnthropicWriter
        .write_response_event(&ev)
        .expect("message_start writes");
    let usage = out
        .get("message")
        .and_then(|m| m.get("usage"))
        .expect("usage present");
    assert_eq!(usage.get("input_tokens").and_then(|v| v.as_u64()), Some(42));
    assert_eq!(
        usage
            .get("cache_creation_input_tokens")
            .and_then(|v| v.as_u64()),
        Some(5)
    );
    assert_eq!(
        usage
            .get("cache_read_input_tokens")
            .and_then(|v| v.as_u64()),
        Some(7)
    );
}

/// Regression (terminal-event drop): reading a `message_delta` whose data omits the
/// `usage` key must STILL yield the `MessageDelta` event — `usage` is optional on read and must
/// not be `?`-propagated, because dropping the event would discard the terminal `stop_reason` and
/// leave the client unable to tell whether generation completed. Counters default to zero.
#[test]
fn read_message_delta_without_usage_preserves_terminal_event() {
    let data = serde_json::json!({
        "delta": { "stop_reason": STOP_END_TURN, "stop_sequence": null }
    });
    let ev = AnthropicReader
        .read_response_event(EVT_MESSAGE_DELTA, &data)
        .expect("message_delta without usage must still parse, not be dropped");
    match ev {
        IrStreamEvent::MessageDelta {
            stop_reason,
            stop_sequence,
            usage,
        } => {
            assert_eq!(
                stop_reason,
                Some(crate::ir::IrStopReason::EndTurn),
                "terminal stop_reason must survive a missing usage"
            );
            assert_eq!(stop_sequence, None);
            assert_eq!(usage.input_tokens, 0, "missing usage zero-defaults input");
            assert_eq!(usage.output_tokens, 0, "missing usage zero-defaults output");
            assert_eq!(usage.cache_creation_input_tokens, None);
            assert_eq!(usage.cache_read_input_tokens, None);
        }
        other => panic!("expected MessageDelta event, got {other:?}"),
    }
}

/// When `usage` IS present on a `message_delta`,
/// its counters and optional cache fields flow through verbatim.
#[test]
fn read_message_delta_with_usage_flows_through() {
    let data = serde_json::json!({
        "delta": { "stop_reason": STOP_MAX_TOKENS },
        "usage": {
            "input_tokens": 11,
            "output_tokens": 22,
            "cache_creation_input_tokens": 3,
            "cache_read_input_tokens": 4
        }
    });
    let ev = AnthropicReader
        .read_response_event(EVT_MESSAGE_DELTA, &data)
        .expect("message_delta parses");
    match ev {
        IrStreamEvent::MessageDelta { usage, .. } => {
            assert_eq!(usage.input_tokens, 11);
            assert_eq!(usage.output_tokens, 22);
            assert_eq!(usage.cache_creation_input_tokens, Some(3));
            assert_eq!(usage.cache_read_input_tokens, Some(4));
        }
        other => panic!("expected MessageDelta event, got {other:?}"),
    }
}

/// Conformance: the non-stream `write_response` must
/// emit `model` UNCONDITIONALLY — the official SDKs type `Message.model` as a required string, so
/// a body that omits it fails to decode. On a Bedrock→Anthropic path where `resp.model` is None,
/// the key must still be present (empty-string fallback), not dropped.
#[test]
fn write_response_emits_model_even_when_none() {
    let resp = crate::ir::IrResponse {
        logprobs: Vec::new(),
        role: crate::ir::IrRole::Assistant,
        content: vec![],
        stop_reason: None,
        usage: crate::ir::IrUsage {
            input_tokens: 0,
            output_tokens: 0,
            cache_creation_input_tokens: None,
            cache_read_input_tokens: None,
        },
        model: None,
        id: Some("msg_x".to_string()),
        created: None,
        system_fingerprint: None,
        stop_sequence: None,
    };
    let out = AnthropicWriter.write_response(&resp);
    assert_eq!(
        out.get("model").and_then(|v| v.as_str()),
        Some(""),
        "model is mandatory; absent source model must emit \"\" rather than omit the key"
    );
}

/// A present model round-trips verbatim.
#[test]
fn write_response_preserves_present_model() {
    let resp = crate::ir::IrResponse {
        logprobs: Vec::new(),
        role: crate::ir::IrRole::Assistant,
        content: vec![],
        stop_reason: None,
        usage: crate::ir::IrUsage {
            input_tokens: 0,
            output_tokens: 0,
            cache_creation_input_tokens: None,
            cache_read_input_tokens: None,
        },
        model: Some("claude-opus-4-8".to_string()),
        id: Some("msg_x".to_string()),
        created: None,
        system_fingerprint: None,
        stop_sequence: None,
    };
    let out = AnthropicWriter.write_response(&resp);
    assert_eq!(
        out.get("model").and_then(|v| v.as_str()),
        Some("claude-opus-4-8")
    );
}

/// Conformance (streaming sibling): the streaming
/// `message_start.message` must also carry `model` UNCONDITIONALLY — it's the skeleton the SDK
/// reads to populate the assembled streaming Message. A None source model emits "" rather than
/// dropping the mandatory field.
#[test]
fn message_start_emits_model_even_when_none() {
    let ev = IrStreamEvent::MessageStart {
        role: crate::ir::IrRole::Assistant,
        usage: None,
        id: None,
        created: None,
        model: None,
    };
    let (_, out) = AnthropicWriter
        .write_response_event(&ev)
        .expect("message_start writes");
    assert_eq!(
        out.get("message")
            .and_then(|m| m.get("model"))
            .and_then(|v| v.as_str()),
        Some(""),
        "message_start.message.model is mandatory; emit \"\" when source model is None"
    );
}

/// EVERY event the writer emits
/// — including the Error variant — must carry a top-level `type` in its data body that matches
/// the SSE event name. A native SDK dispatches on `data.type`; a missing/mismatched `type` is a
/// decode failure and a proxy-signature tell. This sweeps all `write_response_event` arms, not
/// just the cited Error arm.
#[test]
fn every_write_response_event_carries_matching_top_level_type() {
    let events = vec![
        IrStreamEvent::MessageStart {
            role: crate::ir::IrRole::Assistant,
            usage: None,
            id: None,
            created: None,
            model: None,
        },
        IrStreamEvent::BlockStart {
            index: 0,
            block: IrBlockMeta::Text,
        },
        IrStreamEvent::BlockDelta {
            index: 0,
            delta: IrDelta::TextDelta("hi".to_string()),
        },
        IrStreamEvent::BlockStop { index: 0 },
        IrStreamEvent::MessageDelta {
            stop_reason: Some(crate::ir::IrStopReason::EndTurn),
            stop_sequence: None,
            usage: IrUsage {
                input_tokens: 1,
                output_tokens: 1,
                cache_creation_input_tokens: None,
                cache_read_input_tokens: None,
            },
        },
        IrStreamEvent::MessageStop,
        IrStreamEvent::Error(IrError {
            class: StatusClass::ServerError,
            provider_signal: Some(ERR_TYPE_OVERLOADED.to_string()),
            retry_after: None,
        }),
    ];
    for ev in events {
        let (event_type, data) = AnthropicWriter
            .write_response_event(&ev)
            .expect("event must serialize");
        let data_type = data
            .get("type")
            .and_then(|t| t.as_str())
            .unwrap_or_else(|| panic!("data body for `{event_type}` must carry a `type` field"));
        assert_eq!(
            data_type, event_type,
            "data.type must equal the SSE event name for every arm"
        );
    }
}

/// A non-streaming `write_response` whose IR carried no stop sequence must still emit
/// `stop_sequence: null` — a native `Message` always carries the key. IR-idempotence is
/// preserved: re-reading a `null` stop_sequence yields `None` again.
#[test]
fn write_response_emits_null_stop_sequence_when_absent() {
    let resp = crate::ir::IrResponse {
        logprobs: Vec::new(),
        role: crate::ir::IrRole::Assistant,
        content: vec![crate::ir::IrBlock::Text {
            text: "hi".to_string(),
            cache_control: None,
            citations: Vec::new(),
        }],
        stop_reason: Some(crate::ir::IrStopReason::EndTurn),
        usage: crate::ir::IrUsage {
            input_tokens: 1,
            output_tokens: 1,
            cache_creation_input_tokens: None,
            cache_read_input_tokens: None,
        },
        model: Some("claude-opus-4-8".to_string()),
        id: Some("msg_01abc".to_string()),
        created: None,
        system_fingerprint: None,
        stop_sequence: None,
    };
    let out = AnthropicWriter.write_response(&resp);
    let ss = out
        .get("stop_sequence")
        .expect("stop_sequence key must be present in a non-streaming Message");
    assert!(
        ss.is_null(),
        "stop_sequence must be JSON null when absent, not omitted, got {ss:?}"
    );
    // IR-idempotence: re-reading the written body maps the null back to None.
    let reread = AnthropicReader.read_response(&out).expect("reread");
    assert_eq!(reread.stop_sequence, None);
}

/// When a stop sequence IS present, the non-streaming `write_response` must carry the matched
/// string verbatim.
#[test]
fn write_response_emits_matched_stop_sequence_string() {
    let resp = crate::ir::IrResponse {
        logprobs: Vec::new(),
        role: crate::ir::IrRole::Assistant,
        content: vec![],
        stop_reason: Some(crate::ir::IrStopReason::StopSequence),
        usage: crate::ir::IrUsage {
            input_tokens: 1,
            output_tokens: 1,
            cache_creation_input_tokens: None,
            cache_read_input_tokens: None,
        },
        model: None,
        id: Some("msg_01abc".to_string()),
        created: None,
        system_fingerprint: None,
        stop_sequence: Some("STOP".to_string()),
    };
    let out = AnthropicWriter.write_response(&resp);
    assert_eq!(
        out.get("stop_sequence").and_then(|s| s.as_str()),
        Some("STOP")
    );
}

/// A billing error whose body carries a message
/// substring but NO structured `error.code` must still classify as Billing — the message check
/// must not be gated behind the `error.code` guard. Mirror for the auth substring.
#[test]
fn classify_billing_substring_without_code_field() {
    // 200-status body (not 401/403/429), only a message — the regime the old nesting missed.
    let body = br#"{"error":{"type":"some_error","message":"insufficient balance to complete"}}"#;
    let sig = AnthropicReader.classify(StatusCode::OK, body);
    assert!(
            matches!(sig.class, StatusClass::Billing),
            "billing message substring must classify as Billing even without an error.code field, got {:?}",
            sig.class
        );

    let auth_body = br#"{"error":{"type":"some_error","message":"unauthorized request"}}"#;
    let auth_sig = AnthropicReader.classify(StatusCode::OK, auth_body);
    assert!(
        matches!(auth_sig.class, StatusClass::Auth),
        "auth message substring must classify as Auth even without an error.code field, got {:?}",
        auth_sig.class
    );
}

/// Non-regression: the structured `error.code` 400/422 → ClientError path must
/// still fire when the code IS present (the lift-out of the message checks must not regress it).
#[test]
fn classify_structured_code_still_maps_client_error() {
    let body_json = serde_json::json!({"error":{"type": ERR_TYPE_INVALID_REQUEST,"code":"400","message":"bad"}});
    let body = serde_json::to_vec(&body_json).unwrap();
    let sig = AnthropicReader.classify(StatusCode::BAD_REQUEST, &body);
    assert!(
        matches!(sig.class, StatusClass::ClientError),
        "structured code 400 must still classify as ClientError, got {:?}",
        sig.class
    );
}

/// Synthesized ids must match the native
/// Anthropic shape — `<prefix>01` version marker, a mixed-case base62 alphabet (`[0-9A-Za-z]`,
/// NOT lowercase hex), and a FIXED length — so a client inspecting id shape can't tell a
/// synthesized id from a native one. Covers both `msg_` and `req_`.
#[test]
fn synth_ids_match_native_shape_base62_versioned_fixed_length() {
    let check = |id: &str, prefix: &str| {
        let suffix = id
            .strip_prefix(prefix)
            .unwrap_or_else(|| panic!("{id} must start with {prefix}"));
        assert!(
            suffix.starts_with("01"),
            "{id} must carry the native `01` version marker after the prefix"
        );
        let token = &suffix[2..];
        // 12 base62 digits per u64 field × 2 fields = 24 chars, fixed-width — matching the
        // native `<prefix>01` + 24-char token (30 chars total for `msg_`/`req_`).
        assert_eq!(
            token.len(),
            24,
            "token must be fixed-length (2×12 base62 digits), got `{token}`"
        );
        assert!(
            token.bytes().all(|b| b.is_ascii_alphanumeric()),
            "token must be mixed-case base62 (no hex-only/non-alphanumeric chars), got `{token}`"
        );
        // The previous clock+counter `(unix_second, counter)` scheme
        // encoding base62-padded the timestamp to a fixed `000000…` run, so every synthesized
        // id began `01000000…` — a structural tell impossible in a native (CSPRNG) Anthropic id.
        // Assert the CSPRNG-backed token carries no run of six or more leading '0' chars.
        let leading_zeros = token.bytes().take_while(|&b| b == b'0').count();
        assert!(
                leading_zeros < 6,
                "token must not have a 6+ run of leading '0' (the clock+counter fingerprint), got `{token}`"
            );
    };
    check(&synth_message_id(), "msg_");
    check(&synth_request_id(), "req_");
}

/// Regression: synthesized ids must come from the CSPRNG, not a deterministic clock+counter
/// scheme. Two back-to-back calls within the same clock tick must differ (the old
/// scheme relied on the second-resolution clock for its high bits, so rapid calls within one
/// second shared a 12-char prefix and differed only in the counter tail — here the leading 13
/// chars are random and the counter backstop still forces distinctness). Also asserts the token
/// is not all-zero (which would mean the RNG path silently produced no entropy).
#[test]
fn synth_ids_are_csprng_unique_within_tick() {
    let a = synth_message_id();
    let b = synth_message_id();
    assert_ne!(a, b, "two synthesized message ids must never collide");
    let ra = synth_request_id();
    let rb = synth_request_id();
    assert_ne!(ra, rb, "two synthesized request ids must never collide");

    // The full 24-char token must never be all-'0' (that would mean no entropy AND a degenerate
    // counter overlay) — a stronger form of the no-leading-zero-run check.
    for id in [&a, &b, &ra, &rb] {
        let token = &id[id.len() - 24..];
        assert!(
            token.bytes().any(|c| c != b'0'),
            "token must carry entropy, not be all-zero, got `{token}`"
        );
    }
}

/// Regression: the leading characters of the token must vary across calls. The old
/// clock+counter scheme produced an IDENTICAL leading prefix for every id minted in the same
/// second; the CSPRNG scheme keeps the leading 13 chars random, so across many samples the first
/// character must take on more than one distinct value (a deterministic prefix would yield one).
#[test]
fn synth_id_leading_chars_are_not_constant() {
    let mut firsts = std::collections::HashSet::new();
    for _ in 0..64 {
        let id = synth_message_id();
        let token = &id[id.len() - 24..];
        firsts.insert(token.as_bytes()[0]);
    }
    assert!(
        firsts.len() > 1,
        "leading token char is constant across 64 samples — looks deterministic, not CSPRNG"
    );
}

/// Regression: the modeled-key filter (now a sorted `binary_search` slice rather
/// than a per-request `HashSet`) must still route every unmodeled top-level key into `extra` and
/// must still EXCLUDE every modeled key. Guards against a typo/ordering break in `MODELED_KEYS`.
#[test]
fn read_request_routes_unmodeled_keys_to_extra() {
    let body = serde_json::json!({
        "model": "claude-3",
        "system": "sys",
        "messages": [{"role": "user", "content": "hi"}],
        "tools": [],
        "max_tokens": 10,
        "temperature": 0.5,
        "top_p": 0.9,
        "top_k": 40,
        "stop_sequences": ["x"],
        "stream": true,
        // Unmodeled passthrough keys:
        "metadata": {"user_id": "u1"},
        "service_tier": "auto"
    });
    let ir = AnthropicReader
        .read_request(&body)
        .expect("request must parse");
    assert!(
        ir.extra.contains_key("metadata"),
        "unmodeled `metadata` must flow into extra"
    );
    assert!(
        ir.extra.contains_key("service_tier"),
        "unmodeled `service_tier` must flow into extra"
    );
    for modeled in [
        "model",
        "system",
        "messages",
        "tools",
        "max_tokens",
        "temperature",
        "top_p",
        "top_k",
        "stop_sequences",
        "stream",
    ] {
        assert!(
            !ir.extra.contains_key(modeled),
            "modeled key `{modeled}` must NOT leak into extra"
        );
    }
}

/// The in-stream `error` event's
/// `error.message` must NEVER carry reverse-proxy vocabulary ("upstream", "gateway",
/// "backend", "proxy"). When a provider signal is present, the message is the provider's own
/// type token VERBATIM (no router prefix).
#[test]
fn write_response_event_error_message_has_no_proxy_vocabulary() {
    for (signal, expected) in [
        (Some(ERR_TYPE_OVERLOADED.to_string()), "overloaded_error"), // golden wire-contract literal (kept bare on purpose)
        (Some(ERR_TYPE_RATE_LIMIT.to_string()), "rate_limit_error"), // golden wire-contract literal (kept bare on purpose)
        (None, "an error occurred while streaming the response"),
    ] {
        let err = IrError {
            class: StatusClass::ServerError,
            provider_signal: signal.clone(),
            retry_after: None,
        };
        let (_, data) = AnthropicWriter
            .write_response_event(&IrStreamEvent::Error(err))
            .expect("error event must serialize");
        let message = data
            .get("error")
            .and_then(|e| e.get("message"))
            .and_then(|m| m.as_str())
            .expect("error.message must be present");
        assert_eq!(
                message, expected,
                "message must be native-plausible (verbatim signal or generic fallback) for signal {signal:?}"
            );
        let lower = message.to_lowercase();
        for tell in ["upstream", "gateway", "backend", "proxy", "router"] {
            assert!(
                !lower.contains(tell),
                "error.message leaks proxy vocabulary `{tell}`: `{message}`"
            );
        }
    }
}

/// Regression: a 200 `read_response` body that OMITS `usage` must read back
/// successfully with each counter zero-defaulted, NOT 400. The prior `obj.get("usage").ok_or?`
/// hard-required the field — inconsistent with this protocol's own streaming readers
/// (`message_start`/`message_delta` already zero-default a missing `usage`) and the gemini/cohere
/// tolerance. Fails against the old `ok_or?` (which returned Err), passes after.
#[test]
fn read_response_without_usage_zero_defaults_no_error() {
    let body = serde_json::json!({
        "role": "assistant",
        "content": [{"type": "text", "text": "hi"}]
        // NOTE: no `usage` field
    });
    let ir = AnthropicReader
        .read_response(&body)
        .expect("a 200 body without usage must read back, not 400");
    assert_eq!(ir.usage.input_tokens, 0, "missing usage → input_tokens 0");
    assert_eq!(ir.usage.output_tokens, 0, "missing usage → output_tokens 0");
    assert_eq!(ir.usage.cache_creation_input_tokens, None);
    assert_eq!(ir.usage.cache_read_input_tokens, None);
    match &ir.content[0] {
        crate::ir::IrBlock::Text { text, .. } => assert_eq!(text, "hi"),
        other => panic!("expected text block, got {other:?}"),
    }
}

/// Regression: a wire `role:"system"` message inside `messages` must be
/// PROMOTED into `IrRequest.system` by `read_request`, not pushed into `req.messages` as an
/// `IrRole::System` message. Anthropic's Messages API has no `system` role in `messages`
/// (system goes top-level), so the writer must never see a System message. Guards the root.
#[test]
fn read_request_promotes_system_role_message_into_system_blocks() {
    let body = serde_json::json!({
        "model": "claude-opus-4-8",
        "messages": [
            {"role": "system", "content": "you are terse"},
            {"role": "user", "content": "hi"}
        ],
        "max_tokens": 16
    });
    let ir = AnthropicReader
        .read_request(&body)
        .expect("system-role message must parse, not panic");
    // The system message was promoted out of `messages` into `system`.
    assert!(
        ir.messages
            .iter()
            .all(|m| m.role != crate::ir::IrRole::System),
        "no IrRole::System message may remain in req.messages after read_request"
    );
    assert_eq!(
        ir.messages.len(),
        1,
        "only the user message survives in messages"
    );
    assert_eq!(ir.messages[0].role, crate::ir::IrRole::User);
    assert_eq!(
        ir.system.len(),
        1,
        "system content promoted into req.system"
    );
    match &ir.system[0] {
        crate::ir::IrBlock::Text { text, .. } => assert_eq!(text, "you are terse"),
        other => panic!("expected promoted system text block, got {other:?}"),
    }
}

/// Regression (writer): `write_request` must NEVER emit a message with
/// `role:"system"` — even for a CROSS-PROTOCOL IR that still carries an `IrRole::System` message
/// in `req.messages` (one that never passed through Anthropic's own `read_request` promotion).
/// The writer folds it into the top-level `system` field and filters it out of `messages`,
/// mirroring the gemini/bedrock writers. Fails against old code (which emitted `role:"system"`).
#[test]
fn write_request_never_emits_system_role_message() {
    let req = crate::ir::IrRequest {
        reasoning: None,
        reasoning_budgets: None,
        logprobs: None,
        top_logprobs: None,
        user: None,
        parallel_tool_calls: None,
        system: Vec::new(),
        messages: vec![
            crate::ir::IrMessage {
                role: crate::ir::IrRole::System,
                content: vec![crate::ir::IrBlock::Text {
                    text: "be terse".to_string(),
                    cache_control: None,
                    citations: Vec::new(),
                }],
            },
            crate::ir::IrMessage {
                role: crate::ir::IrRole::User,
                content: vec![crate::ir::IrBlock::Text {
                    text: "hi".to_string(),
                    cache_control: None,
                    citations: Vec::new(),
                }],
            },
        ],
        tools: Vec::new(),
        max_tokens: Some(16),
        temperature: None,
        top_p: None,
        top_k: None,
        stop: Vec::new(),
        tool_choice: None,
        stream: false,
        frequency_penalty: None,
        presence_penalty: None,
        seed: None,
        n: None,
        response_format: None,
        extra: serde_json::Map::new(),
    };
    let out = AnthropicWriter.write_request(&req);
    let messages = out
        .get("messages")
        .and_then(|m| m.as_array())
        .expect("messages array must be present");
    for msg in messages {
        assert_ne!(
            msg.get("role").and_then(|r| r.as_str()),
            Some("system"),
            "write_request must never emit an Anthropic message with role:\"system\""
        );
    }
    assert_eq!(messages.len(), 1, "only the user message remains");
    assert_eq!(
        messages[0].get("role").and_then(|r| r.as_str()),
        Some("user")
    );
    // The system content was folded into the top-level `system` field.
    let system = out
        .get("system")
        .and_then(|s| s.as_array())
        .expect("system content must be promoted to top-level system field");
    assert_eq!(system.len(), 1);
    assert_eq!(
        system[0].get("text").and_then(|t| t.as_str()),
        Some("be terse")
    );
}

/// Regression (writer unit): a direct `write_message` call on an `IrRole::System`
/// message must NOT emit `role:"system"` (the invalid Anthropic role). Defense-in-depth: even if
/// a future caller bypasses `write_request`, the writer can never produce the rejected role.
#[test]
fn write_message_system_role_does_not_emit_system() {
    let msg = crate::ir::IrMessage {
        role: crate::ir::IrRole::System,
        content: vec![crate::ir::IrBlock::Text {
            text: "x".to_string(),
            cache_control: None,
            citations: Vec::new(),
        }],
    };
    let out = write_message(&msg);
    assert_ne!(
        out.get("role").and_then(|r| r.as_str()),
        Some("system"),
        "write_message must never emit role:\"system\" for an IrRole::System message"
    );
}

// ---- tool_choice round-trips (Anthropic native shape) ----

fn read_anthropic_request(body: serde_json::Value) -> crate::ir::IrRequest {
    AnthropicReader.read_request(&body).expect("read_request")
}

#[test]
fn tool_choice_any_required_roundtrips() {
    // Anthropic {type:"any"} == "must call some tool" == IR Required; round-trips back to {any}.
    let ir = read_anthropic_request(serde_json::json!({
        "model": "claude", "max_tokens": 16, "messages": [],
        "tool_choice": {"type": "any"}
    }));
    assert_eq!(ir.tool_choice, Some(crate::ir::IrToolChoice::Required));
    let out = AnthropicWriter.write_request(&ir);
    assert_eq!(out["tool_choice"], serde_json::json!({"type": "any"}));
}

#[test]
fn tool_choice_specific_tool_roundtrips() {
    let ir = read_anthropic_request(serde_json::json!({
        "model": "claude", "max_tokens": 16, "messages": [],
        "tool_choice": {"type": "tool", "name": "get_weather"}
    }));
    assert_eq!(
        ir.tool_choice,
        Some(crate::ir::IrToolChoice::Tool {
            name: "get_weather".to_string()
        })
    );
    let out = AnthropicWriter.write_request(&ir);
    assert_eq!(
        out["tool_choice"],
        serde_json::json!({"type": "tool", "name": "get_weather"})
    );
}

#[test]
fn tool_choice_auto_and_none_roundtrip() {
    for (native_type, variant) in [
        ("auto", crate::ir::IrToolChoice::Auto),
        ("none", crate::ir::IrToolChoice::None),
    ] {
        let ir = read_anthropic_request(serde_json::json!({
            "model": "c", "max_tokens": 16, "messages": [],
            "tool_choice": {"type": native_type}
        }));
        assert_eq!(ir.tool_choice, Some(variant));
        let out = AnthropicWriter.write_request(&ir);
        assert_eq!(out["tool_choice"], serde_json::json!({"type": native_type}));
    }
}

#[test]
fn tool_choice_absent_emits_nothing() {
    let ir = read_anthropic_request(serde_json::json!({
        "model": "c", "max_tokens": 16, "messages": []
    }));
    assert_eq!(ir.tool_choice, None);
    let out = AnthropicWriter.write_request(&ir);
    assert!(
        out.get("tool_choice").is_none(),
        "absent tool_choice must NOT gain a spurious value on write"
    );
}

/// Cross-protocol: an OpenAI forced-function `tool_choice` reaches an Anthropic backend as
/// the native `{type:"tool", name}` directive — NOT silently degraded to auto. Simulates the
/// cross-protocol seam by clearing `extra` between read and write (proxy engine `ir.extra.clear()`).
#[test]
fn tool_choice_openai_specific_to_anthropic_targeted() {
    let openai_body = serde_json::json!({
        "model": "gpt", "messages": [],
        "tools": [{"type":"function","function":{"name":"get_weather","parameters":{}}}],
        "tool_choice": {"type":"function","function":{"name":"get_weather"}}
    });
    let mut ir = crate::proto::openai_chat::OpenAiReader
        .read_request(&openai_body)
        .expect("openai read");
    assert_eq!(
        ir.tool_choice,
        Some(crate::ir::IrToolChoice::Tool {
            name: "get_weather".to_string()
        })
    );
    ir.extra.clear(); // cross-protocol seam
    let out = AnthropicWriter.write_request(&ir);
    assert_eq!(
        out["tool_choice"],
        serde_json::json!({"type": "tool", "name": "get_weather"}),
        "forced OpenAI tool must round-trip to Anthropic's targeted tool_choice, not auto"
    );
}

// ---- tool-scoped cache_control survives the cross-protocol seam ----

#[test]
fn tool_definition_cache_control_roundtrips() {
    let ir = read_anthropic_request(serde_json::json!({
        "model": "c", "max_tokens": 16, "messages": [],
        "tools": [{
            "name": "big_tool", "input_schema": {"type":"object"},
            "cache_control": {"type": CACHE_KIND_EPHEMERAL}
        }]
    }));
    assert!(
        ir.tools[0].cache_control.is_some(),
        "tool-def cache_control must be promoted into the IR"
    );
    let out = AnthropicWriter.write_request(&ir);
    assert_eq!(
        out["tools"][0]["cache_control"],
        serde_json::json!({"type": "ephemeral"}), // golden wire-contract literal (kept bare on purpose)
        "tool-def cache breakpoint must survive to the Anthropic egress"
    );
}

#[test]
fn tool_use_and_result_cache_control_roundtrips() {
    let ir = read_anthropic_request(serde_json::json!({
        "model": "c", "max_tokens": 16,
        "messages": [
            {"role": "assistant", "content": [
                {"type":STOP_TOOL_USE,"id":"t1","name":"f","input":{},
                 "cache_control":{"type": CACHE_KIND_EPHEMERAL}}
            ]},
            {"role": "user", "content": [
                {"type":"tool_result","tool_use_id":"t1","content":"ok",
                 "cache_control":{"type": CACHE_KIND_EPHEMERAL}}
            ]}
        ]
    }));
    // ToolUse cache_control promoted...
    match &ir.messages[0].content[0] {
        crate::ir::IrBlock::ToolUse { cache_control, .. } => {
            assert!(cache_control.is_some(), "tool_use cache_control lost")
        }
        other => panic!("expected ToolUse, got {other:?}"),
    }
    // ...and ToolResult cache_control promoted.
    match &ir.messages[1].content[0] {
        crate::ir::IrBlock::ToolResult { cache_control, .. } => {
            assert!(cache_control.is_some(), "tool_result cache_control lost")
        }
        other => panic!("expected ToolResult, got {other:?}"),
    }
    let out = AnthropicWriter.write_request(&ir);
    assert_eq!(
        out["messages"][0]["content"][0]["cache_control"],
        serde_json::json!({"type": "ephemeral"}) // golden wire-contract literal (kept bare on purpose)
    );
    assert_eq!(
        out["messages"][1]["content"][0]["cache_control"],
        serde_json::json!({"type": "ephemeral"}) // golden wire-contract literal (kept bare on purpose)
    );
}

// ---- temperature clamp to Anthropic's [0,1] ----

#[test]
fn temperature_above_one_is_clamped_not_422() {
    // An OpenAI/Responses-valid temp of 1.5 must be clamped to 1.0 for Anthropic (which rejects
    // >1.0 with a 422), never forwarded verbatim.
    let mut ir = read_anthropic_request(serde_json::json!({
        "model": "c", "max_tokens": 16, "messages": []
    }));
    ir.temperature = Some(1.5);
    let out = AnthropicWriter.write_request(&ir);
    assert_eq!(
        out["temperature"],
        serde_json::json!(1.0),
        "temperature 1.5 must clamp to 1.0, not produce a 422-bound body"
    );
    // A value already in range is untouched.
    ir.temperature = Some(0.7);
    let out = AnthropicWriter.write_request(&ir);
    assert_eq!(out["temperature"], serde_json::json!(0.7));
    // A negative value clamps up to 0.0.
    ir.temperature = Some(-0.3);
    let out = AnthropicWriter.write_request(&ir);
    assert_eq!(out["temperature"], serde_json::json!(0.0));
}

// ---- temperature clamp is NON-SILENT (signals when it changes the value) ----
#[test]
fn test_clamp_temperature_for_anthropic_signals_on_change() {
    // An out-of-range value is clamped AND flagged as changed (so the writer warns).
    assert_eq!(clamp_temperature_for_anthropic(1.5), (1.0, true));
    assert_eq!(clamp_temperature_for_anthropic(2.0), (1.0, true));
    assert_eq!(clamp_temperature_for_anthropic(-0.3), (0.0, true));
    // An in-range value is untouched AND NOT flagged (no spurious warn on a faithful value).
    assert_eq!(clamp_temperature_for_anthropic(0.7), (0.7, false));
    assert_eq!(clamp_temperature_for_anthropic(0.0), (0.0, false));
    assert_eq!(clamp_temperature_for_anthropic(1.0), (1.0, false));
}

// ---- is_finite guard: a non-finite temperature is returned unchanged, was_clamped=false. ----
// Unreachable via valid JSON (sonic_rs rejects NaN/Inf at parse) but makes the helper total: a
// NaN/Inf must NOT be treated as a real value clamped from range.
#[test]
fn test_clamp_temperature_for_anthropic_passes_through_non_finite() {
    let (nan_out, nan_clamped) = clamp_temperature_for_anthropic(f64::NAN);
    assert!(nan_out.is_nan(), "NaN must pass through unchanged");
    assert!(!nan_clamped, "NaN must NOT be flagged as clamped");
    assert_eq!(
        clamp_temperature_for_anthropic(f64::INFINITY),
        (f64::INFINITY, false)
    );
    assert_eq!(
        clamp_temperature_for_anthropic(f64::NEG_INFINITY),
        (f64::NEG_INFINITY, false)
    );
}

// ---- max_tokens: 0 is treated as absent (matches the 5 sibling readers' `.filter(|&v| v > 0)`).
#[test]
fn test_anthropic_reader_max_tokens_zero_yields_none() {
    let wire = serde_json::json!({
        "model": "claude-3-5-sonnet",
        "max_tokens": 0,
        "messages": [{"role": "user", "content": "hi"}]
    });
    let ir = AnthropicReader.read_request(&wire).expect("read_request");
    assert_eq!(
        ir.max_tokens, None,
        "max_tokens: 0 must be treated as absent (None), matching the sibling readers"
    );
    // A positive cap is still read normally.
    let wire_ok = serde_json::json!({
        "model": "claude-3-5-sonnet",
        "max_tokens": 256,
        "messages": [{"role": "user", "content": "hi"}]
    });
    let ir_ok = AnthropicReader
        .read_request(&wire_ok)
        .expect("read_request");
    assert_eq!(ir_ok.max_tokens, Some(256));
}

// ---- OpenAI -> Anthropic tool_choice cross-protocol translation ----
// The IR variant is protocol-neutral, so an OpenAI-ingress tool_choice (read into the IR by the
// OpenAI reader) must emit the correct Anthropic native shape on the Anthropic writer. The
// `required` -> `{"type":"any"}` mapping is the load-bearing case.
#[test]
fn test_openai_to_anthropic_tool_choice_directions() {
    use crate::ir::IrToolChoice;
    let cases = [
        (IrToolChoice::Auto, serde_json::json!({"type": "auto"})),
        (IrToolChoice::None, serde_json::json!({"type": "none"})),
        // OpenAI `"required"` reads to IR `Required`; Anthropic's native form is `{"type":"any"}`.
        (IrToolChoice::Required, serde_json::json!({"type": "any"})),
        (
            IrToolChoice::Tool {
                name: "get_weather".to_string(),
            },
            serde_json::json!({"type": "tool", "name": "get_weather"}),
        ),
    ];
    for (tc, expected) in cases {
        let mut ir = read_anthropic_request(serde_json::json!({
            "model": "c", "max_tokens": 16, "messages": []
        }));
        ir.tool_choice = Some(tc.clone());
        let out = AnthropicWriter.write_request(&ir);
        assert_eq!(out["tool_choice"], expected, "tool_choice {tc:?}");
    }
}

// ---- catch-all tool_choice values map to None (never silently Auto/Required) ----
#[test]
fn test_anthropic_unknown_tool_choice_type_is_none() {
    // An object with an unrecognized `type` must degrade to None, not force a tool call.
    assert_eq!(
        read_anthropic_tool_choice(Some(&serde_json::json!({"type": "future_mode"}))),
        None
    );
}

#[test]
fn test_anthropic_tool_choice_tool_without_name_is_none() {
    // `{"type":"tool"}` with NO `name` is structurally incomplete -> None (we can't target an
    // unnamed tool, and must not fall back to forcing some tool).
    assert_eq!(
        read_anthropic_tool_choice(Some(&serde_json::json!({"type": "tool"}))),
        None
    );
}

// ---- IR `safety` stop_reason is not a native Anthropic stop_reason -> map to end_turn ----
#[test]
fn test_anthropic_safety_stop_reason_maps_to_end_turn() {
    let resp = crate::ir::IrResponse {
        logprobs: Vec::new(),
        role: crate::ir::IrRole::Assistant,
        content: vec![],
        stop_reason: Some(crate::ir::IrStopReason::Safety),
        usage: crate::ir::IrUsage {
            input_tokens: 1,
            output_tokens: 1,
            cache_creation_input_tokens: None,
            cache_read_input_tokens: None,
        },
        model: Some("claude-x".to_string()),
        id: Some("msg_01abc".to_string()),
        created: None,
        system_fingerprint: None,
        stop_sequence: None,
    };
    let out = AnthropicWriter.write_response(&resp);
    assert_eq!(
        out["stop_reason"],
        serde_json::json!("end_turn"), // golden wire-contract literal (kept bare on purpose)
        "IR `safety` must collapse to the native `end_turn` on Anthropic egress; got {out}"
    );
    // A native reason still passes through verbatim.
    let resp2 = crate::ir::IrResponse {
        stop_reason: Some(crate::ir::IrStopReason::MaxTokens),
        ..resp
    };
    let out2 = AnthropicWriter.write_response(&resp2);
    assert_eq!(out2["stop_reason"], serde_json::json!("max_tokens")); // golden wire-contract literal (kept bare on purpose)
}

// ---- Streaming egress: the SAME `safety` -> `end_turn` collapse must hold on the streaming
// path (`write_response_event` / `MessageDelta`), not just the non-stream `write_response`.
// A non-native IR `safety` reason must never leak into the wire
// `message_delta.delta.stop_reason`. ----
#[test]
fn test_anthropic_streaming_safety_stop_reason_maps_to_end_turn() {
    let ev = IrStreamEvent::MessageDelta {
        stop_reason: Some(crate::ir::IrStopReason::Safety),
        stop_sequence: None,
        usage: crate::ir::IrUsage {
            input_tokens: 1,
            output_tokens: 1,
            cache_creation_input_tokens: None,
            cache_read_input_tokens: None,
        },
    };
    let (event, data) = AnthropicWriter
        .write_response_event(&ev)
        .expect("MessageDelta must emit a message_delta event");
    assert_eq!(event, "message_delta"); // golden wire-contract literal (kept bare on purpose)
    assert_eq!(
        data["delta"]["stop_reason"],
        serde_json::json!("end_turn"), // golden wire-contract literal (kept bare on purpose)
        "IR `safety` must collapse to native `end_turn` on the STREAMING Anthropic egress \
             (not leak `safety`); got {data}"
    );

    // A native reason still passes through verbatim on the streaming path.
    let ev2 = IrStreamEvent::MessageDelta {
        stop_reason: Some(crate::ir::IrStopReason::MaxTokens),
        stop_sequence: None,
        usage: crate::ir::IrUsage {
            input_tokens: 1,
            output_tokens: 1,
            cache_creation_input_tokens: None,
            cache_read_input_tokens: None,
        },
    };
    let (_event2, data2) = AnthropicWriter
        .write_response_event(&ev2)
        .expect("MessageDelta must emit a message_delta event");
    assert_eq!(
        data2["delta"]["stop_reason"],
        serde_json::json!("max_tokens") // golden wire-contract literal (kept bare on purpose)
    );
}

// ---- Phase 0 fidelity items (Anthropic egress): sampling-param OMIT, response_format-drop
// warn, and native thinking-block round-trip with signature. ----

/// Minimal WARN-capturing tracing layer, kept local to this test module (mirrors the helper in
/// auth.rs / config_validate.rs). Records each WARN event's `message` field so a test can assert
/// a particular `tracing::warn!` fired without a global subscriber.
#[derive(Clone, Default)]
struct WarnCapture(std::sync::Arc<std::sync::Mutex<Vec<String>>>);

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

/// SAMPLING (Phase 0): Anthropic's Messages API does NOT support `frequency_penalty`,
/// `presence_penalty`, `seed`, or `n`. A cross-protocol IR carrying every one of them (e.g. read
/// from an OpenAI request) must produce an egress that emits NONE of those keys — the writer never
/// references these fields, so they are dropped (the correct lossy-by-target behavior; emitting an
/// unknown key would 400 the upstream). Pins that nothing silently mis-maps them onto the wire.
#[test]
fn write_request_omits_unsupported_sampling_params() {
    let req = crate::ir::IrRequest {
        messages: vec![crate::ir::IrMessage {
            role: crate::ir::IrRole::User,
            content: vec![crate::ir::IrBlock::Text {
                text: "hi".to_string(),
                cache_control: None,
                citations: Vec::new(),
            }],
        }],
        max_tokens: Some(16),
        frequency_penalty: Some(0.5),
        presence_penalty: Some(0.25),
        seed: Some(42),
        n: Some(3),
        ..Default::default()
    };
    let out = AnthropicWriter.write_request(&req);
    let obj = out.as_object().expect("write_request emits an object");
    for key in ["frequency_penalty", "presence_penalty", "seed", "n"] {
        assert!(
            !obj.contains_key(key),
            "Anthropic egress must NOT emit `{key}` (Messages API has no such field); got {out}"
        );
    }
    // Sanity: the modeled fields it DOES support are still present, so the omission is targeted.
    assert_eq!(obj.get("max_tokens"), Some(&serde_json::json!(16)));
    assert!(obj.contains_key("messages"));
}

/// Anthropic 400s on a FORCED/TARGETED `tool_choice` (`{type:"any"}`/`{type:"tool"}`) alongside
/// extended `thinking` — only `auto`/`none` are legal. The writer must downgrade a now-illegal
/// forced directive to `{type:"auto"}` (dropping any `name`) WHEN thinking is emitted, and
/// PRESERVE it verbatim when thinking is NOT emitted.
#[test]
fn write_request_downgrades_forced_tool_choice_to_auto_when_thinking_emitted() {
    let mk = |reasoning: Option<crate::ir::IrReasoningAsk>,
              tc: crate::ir::IrToolChoice|
     -> crate::ir::IrRequest {
        crate::ir::IrRequest {
            messages: vec![crate::ir::IrMessage {
                role: crate::ir::IrRole::User,
                content: vec![crate::ir::IrBlock::Text {
                    text: "hi".to_string(),
                    cache_control: None,
                    citations: Vec::new(),
                }],
            }],
            tools: vec![crate::ir::IrTool {
                name: "get_weather".to_string(),
                description: Some("look up weather".to_string()),
                input_schema: serde_json::json!({"type": "object"}),
                cache_control: None,
            }],
            tool_choice: Some(tc),
            reasoning,
            // Large enough that the clamped thinking budget clears the 1024 minimum under
            // max_tokens, so `thinking` is actually emitted.
            max_tokens: Some(8192),
            ..Default::default()
        }
    };

    // WITH a thinking ask: the forced `any` (IrToolChoice::Required) downgrades to `auto`, and
    // `thinking` is present on the egress.
    let req = mk(
        Some(crate::ir::IrReasoningAsk::Effort(
            crate::ir::IrReasoningEffort::Low,
        )),
        crate::ir::IrToolChoice::Required,
    );
    let out = AnthropicWriter.write_request(&req);
    assert!(
        out.get("thinking").is_some(),
        "thinking must be emitted: {out}"
    );
    assert_eq!(
        out.pointer("/tool_choice/type").and_then(|v| v.as_str()),
        Some("auto"),
        "forced tool_choice must downgrade to auto with thinking: {out}"
    );

    // A TARGETED `tool` choice likewise downgrades, dropping the now-invalid `name`.
    let req_tool = mk(
        Some(crate::ir::IrReasoningAsk::Effort(
            crate::ir::IrReasoningEffort::Low,
        )),
        crate::ir::IrToolChoice::Tool {
            name: "get_weather".to_string(),
        },
    );
    let out_tool = AnthropicWriter.write_request(&req_tool);
    assert_eq!(
        out_tool
            .pointer("/tool_choice/type")
            .and_then(|v| v.as_str()),
        Some("auto"),
        "targeted tool_choice must downgrade to auto with thinking: {out_tool}"
    );
    assert!(
        out_tool.pointer("/tool_choice/name").is_none(),
        "downgraded tool_choice must drop `name`: {out_tool}"
    );

    // WITHOUT a thinking ask: the forced `any` is preserved verbatim (no spurious downgrade).
    let req_no_think = mk(None, crate::ir::IrToolChoice::Required);
    let out_no_think = AnthropicWriter.write_request(&req_no_think);
    assert!(
        out_no_think.get("thinking").is_none(),
        "no thinking must be emitted without a reasoning ask: {out_no_think}"
    );
    assert_eq!(
        out_no_think
            .pointer("/tool_choice/type")
            .and_then(|v| v.as_str()),
        Some("any"),
        "forced tool_choice must be preserved without thinking: {out_no_think}"
    );
}

/// response_format (M1): a cross-protocol IR carrying `response_format` reaching the Anthropic
/// writer must NOT silently lose it — Anthropic has no native `response_format` and tool-forcing
/// is not implemented this pass, so the writer DROPS the directive but emits a `warn!` naming
/// response_format so the divergence is observable. Asserts (a) the warn fires and (b) no
/// `response_format` key leaks onto the egress (which would 400 the upstream).
#[test]
fn write_request_warns_and_drops_response_format_on_cross_protocol_egress() {
    use tracing_subscriber::layer::SubscriberExt as _;

    let req = crate::ir::IrRequest {
        messages: vec![crate::ir::IrMessage {
            role: crate::ir::IrRole::User,
            content: vec![crate::ir::IrBlock::Text {
                text: "extract".to_string(),
                cache_control: None,
                citations: Vec::new(),
            }],
        }],
        max_tokens: Some(16),
        response_format: Some(crate::ir::IrResponseFormat {
            json: true,
            schema: Some(serde_json::json!({"type": "object"})),
            name: Some("out".to_string()),
            strict: None,
            description: None,
        }),
        ..Default::default()
    };

    let cap = WarnCapture::default();
    let subscriber = tracing_subscriber::registry().with(cap.clone());
    let out = tracing::subscriber::with_default(subscriber, || AnthropicWriter.write_request(&req));

    assert!(
        !out.as_object().unwrap().contains_key("response_format"),
        "Anthropic egress must NOT emit `response_format` (no native field); got {out}"
    );
    let msgs = cap.0.lock().unwrap();
    assert!(
        msgs.iter().any(|m| m.contains("response_format")),
        "a response_format-drop warning must fire on cross-protocol Anthropic egress; got {msgs:?}"
    );
}

/// LOW (json-tool-result drop observability + no-leak): a Bedrock `tool_result_json` sentinel
/// block (JSON_BLOCK_SENTINEL) nested in a ToolResult reaching the Anthropic egress must (a) NOT
/// leak a corrupt base64 image source (`media_type:"tool_result_json"`) onto the wire and (b) emit
/// a `warn!` so the structured-payload loss is observable (drop-with-warn convention).
#[test]
fn write_request_warns_and_drops_json_tool_result_block() {
    use tracing_subscriber::layer::SubscriberExt as _;

    let req = crate::ir::IrRequest {
        messages: vec![crate::ir::IrMessage {
            role: crate::ir::IrRole::User,
            content: vec![crate::ir::IrBlock::ToolResult {
                tool_use_id: "call-1".to_string(),
                content: vec![
                    crate::ir::IrBlock::Text {
                        text: "ok".to_string(),
                        cache_control: None,
                        citations: Vec::new(),
                    },
                    crate::ir::IrBlock::Json(serde_json::json!({ "answer": 42 })),
                ],
                is_error: false,
                cache_control: None,
            }],
        }],
        max_tokens: Some(16),
        ..Default::default()
    };

    let cap = WarnCapture::default();
    let subscriber = tracing_subscriber::registry().with(cap.clone());
    let out = tracing::subscriber::with_default(subscriber, || AnthropicWriter.write_request(&req));

    let wire = serde_json::to_string(&out).unwrap();
    assert!(
        !wire.contains("tool_result_json"),
        "a json-tool-result sentinel must NOT leak onto the Anthropic wire; got {wire}"
    );
    let msgs = cap.0.lock().unwrap();
    assert!(
        msgs.iter().any(|m| m.contains("json tool-result")),
        "a json-tool-result drop warning must fire on Anthropic egress; got {msgs:?}"
    );
}

/// Counter-case: a request WITHOUT `response_format` must NOT emit the drop warning — the warn is
/// gated on the directive's presence, so a request that never carried one is silent.
#[test]
fn write_request_no_response_format_warning_when_absent() {
    use tracing_subscriber::layer::SubscriberExt as _;

    let req = crate::ir::IrRequest {
        messages: vec![crate::ir::IrMessage {
            role: crate::ir::IrRole::User,
            content: vec![crate::ir::IrBlock::Text {
                text: "hi".to_string(),
                cache_control: None,
                citations: Vec::new(),
            }],
        }],
        max_tokens: Some(16),
        ..Default::default()
    };

    let cap = WarnCapture::default();
    let subscriber = tracing_subscriber::registry().with(cap.clone());
    let _ = tracing::subscriber::with_default(subscriber, || AnthropicWriter.write_request(&req));

    let msgs = cap.0.lock().unwrap();
    assert!(
        !msgs.iter().any(|m| m.contains("response_format")),
        "no response_format warning must fire when the directive is absent; got {msgs:?}"
    );
}

/// THINKING (native Anthropic path): an extended-thinking content block with a `signature` must
/// round-trip through the Anthropic reader/writer LOSSLESSLY — `read_block` maps a native
/// `{type:"thinking", thinking, signature}` to `IrBlock::Thinking{text, signature}`, and
/// `write_block` re-emits exactly that native shape (with the signature preserved). This pins the
/// native path to the same fidelity already verified on the Bedrock reasoningContent↔Thinking
/// path. A read→write→read cycle must preserve both the text and the (mandatory-on-request)
/// signature.
#[test]
fn thinking_block_roundtrips_with_signature() {
    let native = serde_json::json!({
        "type": "thinking",
        "thinking": "let me reason about this",
        "signature": "EqoBCkgIARAB...sig-bytes"
    });
    // Read → IR.
    let block = read_block(&native).expect("thinking block reads");
    match &block {
        crate::ir::IrBlock::Thinking {
            text, signature, ..
        } => {
            assert_eq!(text, "let me reason about this");
            assert_eq!(
                signature.as_deref(),
                Some("EqoBCkgIARAB...sig-bytes"),
                "the extended-thinking signature must survive into the IR"
            );
        }
        other => panic!("expected IrBlock::Thinking, got {other:?}"),
    }
    // IR → wire: native shape with the signature preserved.
    let out = write_block(&block);
    assert_eq!(out.get("type").and_then(|t| t.as_str()), Some("thinking"));
    assert_eq!(
        out.get("thinking").and_then(|t| t.as_str()),
        Some("let me reason about this")
    );
    assert_eq!(
        out.get("signature").and_then(|s| s.as_str()),
        Some("EqoBCkgIARAB...sig-bytes"),
        "write_block must re-emit the thinking signature, not drop it"
    );
    // Full round-trip: re-reading the written block yields the identical IR block.
    let reread = read_block(&out).expect("written thinking block re-reads");
    assert_eq!(reread, block, "thinking block must round-trip losslessly");
}

/// THINKING (response egress, signed): a Thinking block carried in an IR RESPONSE surfaces on the
/// Anthropic response egress with its signature intact — `write_response` routes content blocks
/// through `write_block`, which preserves the signature (the request-path `write_message` filter
/// that drops UNSIGNED thinking blocks does NOT apply here, so a signed reasoning block reaches the
/// client). Guards that native reasoning is not lost on the response writer.
#[test]
fn thinking_block_with_signature_survives_response_egress() {
    let resp = crate::ir::IrResponse {
        logprobs: Vec::new(),
        role: crate::ir::IrRole::Assistant,
        content: vec![
            crate::ir::IrBlock::Thinking {
                text: "step-by-step".to_string(),
                signature: Some("sig-abc".to_string()),
                redacted: false,
                cache_control: None,
            },
            crate::ir::IrBlock::Text {
                text: "answer".to_string(),
                cache_control: None,
                citations: Vec::new(),
            },
        ],
        stop_reason: Some(crate::ir::IrStopReason::EndTurn),
        usage: crate::ir::IrUsage {
            input_tokens: 1,
            output_tokens: 1,
            cache_creation_input_tokens: None,
            cache_read_input_tokens: None,
        },
        model: Some("claude-opus-4-8".to_string()),
        id: Some("msg_01abc".to_string()),
        created: None,
        system_fingerprint: None,
        stop_sequence: None,
    };
    let out = AnthropicWriter.write_response(&resp);
    let content = out
        .get("content")
        .and_then(|c| c.as_array())
        .expect("response carries a content array");
    let thinking = content
        .iter()
        .find(|b| b.get("type").and_then(|t| t.as_str()) == Some("thinking"))
        .expect("a thinking block must be present on the response egress");
    assert_eq!(
        thinking.get("thinking").and_then(|t| t.as_str()),
        Some("step-by-step")
    );
    assert_eq!(
        thinking.get("signature").and_then(|s| s.as_str()),
        Some("sig-abc"),
        "the signed thinking block must reach the client with its signature on response egress"
    );
}

/// D2: a Responses `file_id` image (the FILE_ID_IMAGE_SENTINEL media_type) reaching the Anthropic
/// egress is an unresolvable cross-vendor reference. It must be SKIPPED — NOT emitted as a corrupt
/// base64 `source` with `media_type:"file_id"` (which Anthropic rejects). The user message's
/// content must carry no image block; the text block still survives.
#[test]
fn test_write_request_file_id_image_dropped_not_corrupted() {
    let writer = AnthropicWriter;
    let req = crate::ir::IrRequest {
        reasoning: None,
        reasoning_budgets: None,
        logprobs: None,
        top_logprobs: None,
        user: None,
        parallel_tool_calls: None,
        system: vec![],
        messages: vec![crate::ir::IrMessage {
            role: crate::ir::IrRole::User,
            content: vec![
                crate::ir::IrBlock::Text {
                    text: "describe this".to_string(),
                    cache_control: None,
                    citations: Vec::new(),
                },
                crate::ir::IrBlock::Image {
                    source: crate::ir::IrImageSource::Vendor {
                        vendor: "responses",
                        value: serde_json::json!({ "file_id": "file-abc123" }),
                    },
                    cache_control: None,
                },
            ],
        }],
        tools: vec![],
        max_tokens: Some(64),
        temperature: None,
        top_p: None,
        top_k: None,
        stop: vec![],
        tool_choice: None,
        stream: false,
        frequency_penalty: None,
        presence_penalty: None,
        seed: None,
        n: None,
        response_format: None,
        extra: serde_json::Map::new(),
    };
    let out = writer.write_request(&req);
    let wire = serde_json::to_string(&out).unwrap();
    assert!(
        !wire.contains("file-abc123") && !wire.contains("file_id"),
        "a file_id image must not leak onto the Anthropic wire (no corrupt base64 source); \
             got {wire}"
    );
    let content = out
        .pointer("/messages/0/content")
        .and_then(|c| c.as_array())
        .expect("user message content array");
    assert!(
        content
            .iter()
            .all(|b| b.get("type").and_then(|t| t.as_str()) != Some("image")),
        "no image block may be emitted for a file_id image; got {out}"
    );
    assert!(
        content
            .iter()
            .any(|b| b.get("type").and_then(|t| t.as_str()) == Some("text")),
        "the text block must still survive; got {out}"
    );
}

/// HIGH (asymmetric twin of the file_id leak): a Bedrock S3-source image (IMAGE_S3_SENTINEL
/// media_type, `data` = serialized s3Location JSON) reaching the Anthropic egress must be SKIPPED,
/// NOT emitted as a corrupt base64 `source` with `media_type:"image_s3"` (which leaks the
/// s3Location JSON + a busbar fingerprint and is rejected by Anthropic).
#[test]
fn test_write_request_image_s3_dropped_not_corrupted() {
    let writer = AnthropicWriter;
    let req = crate::ir::IrRequest {
        reasoning: None,
        reasoning_budgets: None,
        logprobs: None,
        top_logprobs: None,
        user: None,
        parallel_tool_calls: None,
        system: vec![],
        messages: vec![crate::ir::IrMessage {
            role: crate::ir::IrRole::User,
            content: vec![
                crate::ir::IrBlock::Text {
                    text: "describe this".to_string(),
                    cache_control: None,
                    citations: Vec::new(),
                },
                crate::ir::IrBlock::Image {
                    source: crate::ir::IrImageSource::Vendor {
                        vendor: "bedrock",
                        value: serde_json::json!({ "format": "png", "s3Location": { "uri": "s3://bucket/key.png" } }),
                    },
                    cache_control: None,
                },
            ],
        }],
        tools: vec![],
        max_tokens: Some(64),
        temperature: None,
        top_p: None,
        top_k: None,
        stop: vec![],
        tool_choice: None,
        stream: false,
        frequency_penalty: None,
        presence_penalty: None,
        seed: None,
        n: None,
        response_format: None,
        extra: serde_json::Map::new(),
    };
    let out = writer.write_request(&req);
    let wire = serde_json::to_string(&out).unwrap();
    assert!(
        !wire.contains("image_s3")
            && !wire.contains("s3://bucket/key.png")
            && !wire.contains("s3Location"),
        "an image_s3 image must not leak onto the Anthropic wire (no corrupt base64 source); \
             got {wire}"
    );
    let content = out
        .pointer("/messages/0/content")
        .and_then(|c| c.as_array())
        .expect("user message content array");
    assert!(
        content
            .iter()
            .all(|b| b.get("type").and_then(|t| t.as_str()) != Some("image")),
        "no image block may be emitted for an image_s3 image; got {out}"
    );
    assert!(
        content
            .iter()
            .any(|b| b.get("type").and_then(|t| t.as_str()) == Some("text")),
        "the text block must still survive; got {out}"
    );
}

/// Forge prevention (now STRUCTURAL): a CLIENT cannot forge an upstream-origin redacted-reasoning
/// block. `redacted` is a TYPED flag the reader sets only for a native `redacted_thinking` block —
/// a regular `thinking` block (whatever its `signature` string) reads as `redacted: false`, so it
/// can never re-emit as a Bedrock `redactedContent` on egress. No signature scrub needed.
#[test]
fn test_client_thinking_block_cannot_forge_redacted() {
    let reader = AnthropicReader;
    let body = serde_json::json!({
        "model": "claude-x",
        "max_tokens": 64,
        "messages": [{
            "role": "assistant",
            "content": [{
                "type": "thinking",
                "thinking": "forged",
                "signature": "__busbar_bedrock_redacted_reasoning"
            }]
        }]
    });
    let ir = reader.read_request(&body).expect("request must parse");
    match &ir.messages[0].content[0] {
        crate::ir::IrBlock::Thinking { redacted, .. } => assert!(
            !redacted,
            "a client `thinking` block must NEVER read as redacted — the forge vector is closed"
        ),
        other => panic!("expected a Thinking block, got {other:?}"),
    }
}

/// L2: an Anthropic text block carrying citations of EVERY variant (char/page/content_block
/// document locations AND the web-search `web_search_result_location`) must round-trip BYTE-EXACT
/// through IR (reader → IrCitation incl. `raw` → writer re-emits `raw` verbatim). This is the
/// no-regression guarantee for the historical raw-`Value` fidelity.
#[test]
fn anthropic_citations_roundtrip_byte_exact_all_variants() {
    let block = serde_json::json!({
        "type": "text",
        "text": "Grounded answer.",
        "citations": [
            {
                "type": CITATION_TYPE_CHAR,
                "cited_text": "quoted span",
                "document_index": 0,
                "document_title": "Doc A",
                "start_char_index": 12,
                "end_char_index": 23
            },
            {
                "type": CITATION_TYPE_PAGE,
                "cited_text": "page span",
                "document_index": 1,
                "document_title": "Doc B",
                "start_page_number": 3,
                "end_page_number": 4
            },
            {
                "type": CITATION_TYPE_CONTENT_BLOCK,
                "cited_text": "block span",
                "document_index": 2,
                "document_title": "Doc C",
                "start_block_index": 5,
                "end_block_index": 7
            },
            {
                "type": "web_search_result_location",
                "url": "https://example.com/page",
                "title": "Example Page",
                "cited_text": "web span",
                "encrypted_index": "opaque-cursor-token"
            }
        ]
    });
    let ir = read_block(&block).expect("text block with citations must parse");
    // Neutral fields are populated (cross-protocol projection works) ...
    let citations = match &ir {
        crate::ir::IrBlock::Text { citations, .. } => citations,
        other => panic!("expected Text, got {other:?}"),
    };
    assert_eq!(citations.len(), 4);
    assert_eq!(citations[0].kind.as_deref(), Some("char_location")); // golden wire-contract literal (kept bare on purpose)
    assert_eq!(citations[0].start_index, Some(12));
    assert_eq!(citations[1].start_index, Some(3)); // page number into shared slot
    assert_eq!(citations[2].end_index, Some(7)); // block index into shared slot
    assert_eq!(
        citations[3].url.as_deref(),
        Some("https://example.com/page")
    );
    assert_eq!(
        citations[3].encrypted_index.as_deref(),
        Some("opaque-cursor-token")
    );
    // ... AND `raw` is preserved on each, guaranteeing byte-exact re-emission.
    assert!(citations.iter().all(|c| c.raw.is_some()));
    let wire = write_block(&ir);
    assert_eq!(
        wire, block,
        "Anthropic citations must round-trip byte-exact via raw"
    );
}

/// L2: when an IrCitation has NO `raw` (synthesized on a cross-protocol hop, e.g. Gemini→IR), the
/// Anthropic writer BUILDS the correct Anthropic shape from neutral fields. Covers the
/// web_search_result_location synthesis path (url/title/cited_text) a Gemini grounding source maps to.
#[test]
fn anthropic_writes_web_search_citation_from_neutral_fields() {
    let block = crate::ir::IrBlock::Text {
        text: "answer".to_string(),
        cache_control: None,
        citations: vec![crate::ir::IrCitation {
            kind: Some("web_search_result_location".to_string()),
            cited_text: None,
            title: Some("Source Title".to_string()),
            url: Some("https://grounding.example/doc".to_string()),
            document_index: None,
            start_index: Some(10),
            end_index: Some(42),
            encrypted_index: None,
            raw: None,
        }],
    };
    let wire = write_block(&block);
    let c = wire
        .pointer("/citations/0")
        .expect("citation must be emitted");
    assert_eq!(
        c.get("type").and_then(|v| v.as_str()),
        Some("web_search_result_location")
    );
    assert_eq!(
        c.get("url").and_then(|v| v.as_str()),
        Some("https://grounding.example/doc")
    );
    assert_eq!(
        c.get("title").and_then(|v| v.as_str()),
        Some("Source Title")
    );
}

/// L2: an empty-citations Text block is unaffected — no `citations` key is emitted.
#[test]
fn anthropic_empty_citations_text_block_unaffected() {
    let block = crate::ir::IrBlock::Text {
        text: "plain".to_string(),
        cache_control: None,
        citations: Vec::new(),
    };
    let wire = write_block(&block);
    assert!(
        wire.get("citations").is_none(),
        "no citations key for an empty-citations block; got {wire}"
    );
}

/// L2-5 STREAMING citations, Anthropic same-protocol byte-exactness: a native streaming
/// `content_block_delta`/`citations_delta` must read into `IrDelta::CitationsDelta` (via
/// `read_citation`, which stashes the source object in `raw`) and the Anthropic writer must
/// re-emit the citation object VERBATIM through the `raw` escape hatch — so an Anthropic-shaped
/// streamed citation round-trips byte-exact, never a lossy field-by-field reconstruction.
#[test]
fn read_write_streaming_citations_delta_roundtrips_byte_exact() {
    // A native web-search streaming citation (one of the 4 Anthropic variants), with a field the
    // synthesize-from-neutral path would NOT reproduce (`encrypted_index`) to prove `raw` is used.
    let native_citation = serde_json::json!({
        "type": "web_search_result_location",
        "url": "https://example.com/a",
        "title": "Source A",
        "cited_text": "the quoted span",
        "encrypted_index": "opaque-cursor-123"
    });
    let data = serde_json::json!({
        "type": EVT_CONTENT_BLOCK_DELTA,
        "index": 0,
        "delta": { "type": DELTA_TYPE_CITATIONS, "citation": native_citation }
    });

    // READ: a citations_delta content_block_delta → IrDelta::CitationsDelta(vec![citation]).
    let ev = AnthropicReader
        .read_response_event(EVT_CONTENT_BLOCK_DELTA, &data)
        .expect("a citations_delta content_block_delta must parse, not be dropped");
    let (index, citations) = match &ev {
        IrStreamEvent::BlockDelta {
            index,
            delta: IrDelta::CitationsDelta(cs),
        } => (*index, cs.clone()),
        other => panic!("expected a CitationsDelta BlockDelta, got {other:?}"),
    };
    assert_eq!(index, 0);
    assert_eq!(citations.len(), 1, "one citation per citations_delta");
    // Neutral fields filled AND the verbatim source preserved in `raw`.
    assert_eq!(citations[0].url.as_deref(), Some("https://example.com/a"));
    assert_eq!(
        citations[0].encrypted_index.as_deref(),
        Some("opaque-cursor-123")
    );
    assert_eq!(citations[0].raw.as_ref(), Some(&native_citation));

    // WRITE: the same IR delta re-emits the native content_block_delta/citations_delta, and the
    // `citation` object is BYTE-EXACT the source (raw verbatim, not reconstructed).
    let (event_type, body) = AnthropicWriter
        .write_response_event(&ev)
        .expect("a CitationsDelta must emit a content_block_delta, not None");
    assert_eq!(event_type, "content_block_delta"); // golden wire-contract literal (kept bare on purpose)
    assert_eq!(
        body.pointer("/delta/type").and_then(|t| t.as_str()),
        Some("citations_delta") // golden wire-contract literal (kept bare on purpose)
    );
    assert_eq!(
        body.pointer("/index").and_then(|i| i.as_u64()),
        Some(0),
        "the delta must re-emit on the same block index"
    );
    assert_eq!(
        body.pointer("/delta/citation"),
        Some(&native_citation),
        "Anthropic-shaped streamed citation must round-trip BYTE-EXACT via raw"
    );
}

/// An Anthropic `cache_control` breakpoint placed ON a `tool_use` block must survive
/// read→IR→write byte-for-byte. The IR carries it on `IrBlock::ToolUse.cache_control` (ir.rs:292)
/// precisely so this Anthropic-native prefix-cache breakpoint is not silently dropped (a cache-hit
/// cost/latency regression on the same-protocol path).
#[test]
fn cache_control_on_tool_use_block_round_trips() {
    let block = serde_json::json!({
        "type": STOP_TOOL_USE,
        "id": "toolu_01abc",
        "name": "get_weather",
        "input": {"location": "SF"},
        "cache_control": {"type": CACHE_KIND_EPHEMERAL}
    });
    let ir = read_block(&block).expect("tool_use block with cache_control parses");
    match &ir {
        crate::ir::IrBlock::ToolUse {
            id,
            name,
            input,
            cache_control,
        } => {
            assert_eq!(id, "toolu_01abc");
            assert_eq!(name, "get_weather");
            assert_eq!(input, &serde_json::json!({"location": "SF"}));
            assert!(
                cache_control.is_some(),
                "cache_control on tool_use must be captured in the IR, not dropped"
            );
        }
        other => panic!("expected ToolUse, got {other:?}"),
    }
    // WRITE: the breakpoint re-emits in Anthropic's native `{type:"ephemeral"}` shape.
    let out = write_block(&ir);
    assert_eq!(
        out.pointer("/cache_control/type").and_then(|t| t.as_str()),
        Some("ephemeral"), // golden wire-contract literal (kept bare on purpose)
        "cache_control must re-emit on the tool_use block"
    );
    assert_eq!(out.get("id").and_then(|v| v.as_str()), Some("toolu_01abc"));
}

/// An Anthropic `cache_control` breakpoint on a `tool_result` block must survive
/// read→IR→write. Anthropic places breakpoints on tool_result to cache the (often large) result
/// content (ir.rs:302); the IR field `IrBlock::ToolResult.cache_control` keeps it cross-hop.
#[test]
fn cache_control_on_tool_result_block_round_trips() {
    let block = serde_json::json!({
        "type": "tool_result",
        "tool_use_id": "toolu_01abc",
        "content": [{"type": "text", "text": "72F and sunny"}],
        "is_error": false,
        "cache_control": {"type": CACHE_KIND_EPHEMERAL}
    });
    let ir = read_block(&block).expect("tool_result block with cache_control parses");
    match &ir {
        crate::ir::IrBlock::ToolResult {
            tool_use_id,
            cache_control,
            is_error,
            ..
        } => {
            assert_eq!(tool_use_id, "toolu_01abc");
            assert!(!is_error);
            assert!(
                cache_control.is_some(),
                "cache_control on tool_result must be captured, not dropped"
            );
        }
        other => panic!("expected ToolResult, got {other:?}"),
    }
    let out = write_block(&ir);
    assert_eq!(
        out.pointer("/cache_control/type").and_then(|t| t.as_str()),
        Some("ephemeral"), // golden wire-contract literal (kept bare on purpose)
        "cache_control must re-emit on the tool_result block"
    );
}

/// A `cache_control` breakpoint on a tool DEFINITION (`tools[].cache_control`) round-trips through
/// `IrTool.cache_control` (ir.rs:449). Anthropic caches the large tool schemas as a prefix; the
/// breakpoint was being dropped every hop before this field existed.
#[test]
fn cache_control_on_tool_definition_round_trips() {
    let tool = serde_json::json!({
        "name": "get_weather",
        "description": "Get weather",
        "input_schema": {"type": "object", "properties": {}},
        "cache_control": {"type": CACHE_KIND_EPHEMERAL}
    });
    let ir = read_tool(&tool).expect("tool with cache_control parses");
    assert_eq!(ir.name, "get_weather");
    assert!(
        ir.cache_control.is_some(),
        "cache_control on a tool definition must be captured in IrTool"
    );
    let out = write_tool(&ir);
    assert_eq!(
        out.pointer("/cache_control/type").and_then(|t| t.as_str()),
        Some("ephemeral"), // golden wire-contract literal (kept bare on purpose)
        "cache_control must re-emit on the tool definition"
    );
}

/// Full non-stream response round-trip for an UNKNOWN native `stop_reason`: the reader maps a
/// token it does not model (here a plausible future `max_tokens_reached` variant spelling) to
/// `IrStopReason::Other`, and the writer degrades `Other` to the safe `end_turn` default — a
/// foreign token is NEVER echoed into a strict client's closed enum (the bug class ir.rs:186
/// documents).
#[test]
fn read_write_response_unknown_stop_reason_degrades_to_end_turn() {
    let body = serde_json::json!({
        "id": "msg_01xyz",
        "type": "message",
        "role": "assistant",
        "model": "claude-opus-4-8",
        "content": [{"type": "text", "text": "hi"}],
        "stop_reason": "some_future_reason",
        "stop_sequence": null,
        "usage": {"input_tokens": 3, "output_tokens": 1}
    });
    let ir = AnthropicReader.read_response(&body).expect("read_response");
    assert_eq!(
        ir.stop_reason,
        Some(crate::ir::IrStopReason::Other),
        "an unmodeled native stop_reason must map to Other (never carried verbatim)"
    );
    let out = AnthropicWriter.write_response(&ir);
    assert_eq!(
        out.get("stop_reason").and_then(|v| v.as_str()),
        Some("end_turn"), // golden wire-contract literal (kept bare on purpose)
        "Other must degrade to the safe end_turn default on egress, never leak the foreign token"
    );
}

/// Anthropic's `usage` cache fields are ADDITIVE (ir.rs:457): the reader stores
/// `cache_creation_input_tokens`/`cache_read_input_tokens` AS-IS (unlike OpenAI/Gemini, which
/// subtract the cached prefix out of the input total). This pins that a non-stream response
/// carries the wire cache counts through unchanged and that `input_tokens` is NOT reduced by them.
#[test]
fn read_response_cache_usage_is_additive_not_subtracted() {
    let body = serde_json::json!({
        "id": "msg_01xyz",
        "type": "message",
        "role": "assistant",
        "model": "claude-opus-4-8",
        "content": [{"type": "text", "text": "hi"}],
        "stop_reason": STOP_END_TURN,
        "stop_sequence": null,
        "usage": {
            "input_tokens": 10,
            "output_tokens": 5,
            "cache_creation_input_tokens": 200,
            "cache_read_input_tokens": 1000
        }
    });
    let ir = AnthropicReader.read_response(&body).expect("read_response");
    // Wire values stored verbatim — Anthropic input is already the UNCACHED count, so no subtract.
    assert_eq!(
        ir.usage.input_tokens, 10,
        "Anthropic input_tokens stored as-is (already uncached)"
    );
    assert_eq!(ir.usage.output_tokens, 5);
    assert_eq!(ir.usage.cache_creation_input_tokens, Some(200));
    assert_eq!(ir.usage.cache_read_input_tokens, Some(1000));
    // billable_tokens sums all four additively: 10 + 5 + 200 + 1000.
    assert_eq!(ir.usage.billable_tokens(), 1215);

    // WRITE re-emits the additive cache fields on the same-protocol egress.
    let out = AnthropicWriter.write_response(&ir);
    assert_eq!(
        out.pointer("/usage/cache_creation_input_tokens")
            .and_then(|v| v.as_u64()),
        Some(200)
    );
    assert_eq!(
        out.pointer("/usage/cache_read_input_tokens")
            .and_then(|v| v.as_u64()),
        Some(1000)
    );
    assert_eq!(
        out.pointer("/usage/input_tokens").and_then(|v| v.as_u64()),
        Some(10)
    );
}

/// REGRESSION (finding P1 #1): the request-side unsigned-thinking filter in `write_message` must
/// NOT drop a REDACTED thinking block. A `redacted_thinking` block is carried in the IR as
/// `Thinking { redacted: true, signature: None }` (opaque encrypted `data`, no signature — the
/// Anthropic Messages API accepts `redacted_thinking` WITHOUT a signature, unlike a plaintext
/// `thinking` block). The old filter matched `Thinking { signature: None, .. }` and dropped it,
/// silently losing the encrypted reasoning that lets a multi-turn extended-thinking conversation
/// replay. It must survive and re-emit as a native `redacted_thinking` block carrying the opaque
/// `data` bytes. FAILS before the `redacted: false` guard was added (the block was dropped and
/// content.len() == 1); passes after.
#[test]
fn write_message_keeps_redacted_thinking_block() {
    let msg = crate::ir::IrMessage {
        role: crate::ir::IrRole::Assistant,
        content: vec![
            crate::ir::IrBlock::Thinking {
                text: "ENCRYPTED_OPAQUE_BYTES".to_string(),
                signature: None,
                redacted: true,
                cache_control: None,
            },
            crate::ir::IrBlock::Text {
                text: "the answer".to_string(),
                cache_control: None,
                citations: Vec::new(),
            },
        ],
    };
    let out = write_message(&msg);
    let content = out
        .get("content")
        .and_then(|c| c.as_array())
        .expect("content array");
    assert_eq!(
        content.len(),
        2,
        "the redacted_thinking block must survive the request-side filter alongside the text: \
         {content:?}"
    );
    // The redacted block re-emits as a native `redacted_thinking` block carrying `data`, NOT a
    // plaintext `thinking` block and NOT with a `signature`.
    let redacted = content
        .iter()
        .find(|b| b.get("type").and_then(|t| t.as_str()) == Some("redacted_thinking"))
        .expect("a native redacted_thinking block must be emitted");
    assert_eq!(
        redacted.get("data").and_then(|d| d.as_str()),
        Some("ENCRYPTED_OPAQUE_BYTES"),
        "the opaque bytes must ride under `data` on the redacted_thinking block"
    );
    assert!(
        redacted.get("thinking").is_none(),
        "a redacted block must NOT leak its opaque bytes as plaintext `thinking`: {redacted:?}"
    );
    // A plaintext UNSIGNED thinking block is still correctly dropped (the fix is surgical).
    assert!(
        !content
            .iter()
            .any(|b| b.get("type").and_then(|t| t.as_str()) == Some("thinking")),
        "no plaintext thinking block was present in the input; none should appear"
    );
}

/// REGRESSION (finding P1 #2): the streaming `content_block_start` skeleton must carry the SEED
/// field for each block type so an SDK accumulator initializes the field before any delta arrives:
/// a `text` start ships `text:""`, a `tool_use` start ships `input:{}`, and a `thinking` start
/// ships `thinking:""`. Omitting the seed leaves the SDK accumulator field undefined and the first
/// delta concatenates onto `undefined` / raises a KeyError. FAILS before the seeds were added (the
/// skeletons carried only `type`, plus `id`/`name` for tool_use); passes after.
#[test]
fn content_block_start_carries_seed_fields() {
    // Text block start → `text: ""`.
    let (_et, out) = AnthropicWriter
        .write_response_event(&crate::ir::IrStreamEvent::BlockStart {
            index: 0,
            block: crate::ir::IrBlockMeta::Text,
        })
        .expect("text block_start writes");
    assert_eq!(
        out.pointer("/content_block/type").and_then(|v| v.as_str()),
        Some("text")
    );
    assert_eq!(
        out.pointer("/content_block/text").and_then(|v| v.as_str()),
        Some(""),
        "a text content_block_start must seed `text:\"\"` for SDK accumulator init: {out}"
    );

    // Tool-use block start → `input: {}` (plus id/name).
    let (_et, out) = AnthropicWriter
        .write_response_event(&crate::ir::IrStreamEvent::BlockStart {
            index: 1,
            block: crate::ir::IrBlockMeta::ToolUse {
                id: "toolu_01".to_string(),
                name: "get_weather".to_string(),
            },
        })
        .expect("tool_use block_start writes");
    assert_eq!(
        out.pointer("/content_block/type").and_then(|v| v.as_str()),
        Some("tool_use")
    );
    assert_eq!(
        out.pointer("/content_block/id").and_then(|v| v.as_str()),
        Some("toolu_01")
    );
    assert_eq!(
        out.pointer("/content_block/name").and_then(|v| v.as_str()),
        Some("get_weather")
    );
    assert_eq!(
        out.pointer("/content_block/input")
            .and_then(|v| v.as_object())
            .map(|o| o.is_empty()),
        Some(true),
        "a tool_use content_block_start must seed `input:{{}}` for partial-json accumulation: {out}"
    );

    // Thinking block start → `thinking: ""`.
    let (_et, out) = AnthropicWriter
        .write_response_event(&crate::ir::IrStreamEvent::BlockStart {
            index: 2,
            block: crate::ir::IrBlockMeta::Thinking,
        })
        .expect("thinking block_start writes");
    assert_eq!(
        out.pointer("/content_block/type").and_then(|v| v.as_str()),
        Some("thinking")
    );
    assert_eq!(
        out.pointer("/content_block/thinking")
            .and_then(|v| v.as_str()),
        Some(""),
        "a thinking content_block_start must seed `thinking:\"\"`: {out}"
    );
}
