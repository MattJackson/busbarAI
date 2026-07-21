use super::*;

/// extract the host (no scheme, no trailing slash, no userinfo) from a base URL, for SigV4's signed
/// `host` header. base_urls are already trailing-slash-trimmed and carry no path.
///
/// A `base_url` carrying an embedded `user:pass@` userinfo component (accidental misconfiguration)
/// must NOT leak into the signed `host` value: the HTTP stack sends `Host: host.example.com` while
/// SigV4 would otherwise sign `host: user:pass@host.example.com`, producing a signature mismatch
/// (every Bedrock request fails) AND embedding the credential in the signed string (which may surface
/// in request logs/traces). Strip any userinfo (everything up to and including the last `@` in the
/// authority) so the signed host always matches what the HTTP layer transmits.
///
/// Returns the AUTHORITY ONLY (`host[:port]`) — never any path/query/fragment. The HTTP stack always
/// transmits `Host: <authority>` regardless of any path in `base_url`, so a `host` value that
/// included a path (e.g. a misconfigured `https://bedrock.../prefix`) would be signed but never sent,
/// yielding a silent `SignatureDoesNotMatch` on every request. Stripping the path here makes the
/// signed `host` equal to the transmitted `Host` byte-for-byte even if config validation is bypassed.
pub(crate) fn host_from_base(base: &str) -> String {
    let no_scheme = base
        .strip_prefix("https://")
        .or_else(|| base.strip_prefix("http://"))
        .unwrap_or(base);
    // Normalize backslash → forward slash BEFORE locating the authority boundary. The WHATWG URL
    // parser the `url` crate (and thus reqwest) uses treats `\` as an authority/path delimiter
    // exactly like `/`, so reqwest connects to the host that ENDS at the first backslash. Splitting
    // here only on `/?#` (a backslash-blind split, the SAME defect `ssrf_blocked_host` had) would
    // make this function read PAST the backslash: e.g. `https://evil.example.com\@victim.example/`
    // connects to `evil.example.com` on the wire, but a `/?#`-only split yields authority
    // `evil.example.com\@victim.example` whose `rfind('@')` returns `victim.example` — a signed
    // `Host` that DESYNCS from the host actually contacted (SigV4 signs one host, the TCP/TLS layer
    // dials another). Folding `\`→`/` first makes the authority boundary — and the returned signed
    // host — match what reqwest dials, byte-for-byte.
    // Only ALLOCATE the backslash-normalized copy when a backslash is actually present (rare
    // misconfiguration / attack shape). A well-formed base_url has none, so the common request path
    // borrows the input and skips this per-request heap allocation.
    let no_scheme: std::borrow::Cow<str> = if no_scheme.contains('\\') {
        std::borrow::Cow::Owned(no_scheme.replace('\\', "/"))
    } else {
        std::borrow::Cow::Borrowed(no_scheme)
    };
    let no_scheme = no_scheme.as_ref();
    // The authority ends at the first `/`, `?`, or `#`; userinfo (if any) precedes the LAST `@`
    // within that authority. Split on the authority boundary first so an `@` appearing later in a
    // path/query (not userinfo) is never mistaken for a userinfo delimiter. Only the authority is
    // returned — the path/query/fragment (`rest`) is intentionally discarded (see doc above).
    let authority_end = no_scheme.find(['/', '?', '#']).unwrap_or(no_scheme.len());
    let authority = &no_scheme[..authority_end];
    match authority.rfind('@') {
        Some(at) => authority[at + 1..].to_string(),
        None => authority.to_string(),
    }
}

/// Produce the path that is BOTH signed (as the SigV4 canonical URI) and sent on the wire, so the
/// two can never diverge. Only the path component (before any `?`) is URI-encoded — reserved chars
/// in a Bedrock modelId such as `:` become `%3A`; the query string (if any) is preserved verbatim
/// (encoding `?`/`=`/`&` would corrupt it). The percent-encoded `%XX` sequences pass through the
/// `url` crate's path parser unchanged, so the transmitted request path equals the signed canonical
/// path byte-for-byte and AWS cannot reject with SignatureDoesNotMatch over a path-encoding mismatch.
pub(crate) fn sign_and_wire_path(url_path: &str) -> String {
    sign_and_wire_path_parts(url_path).0
}

/// Like [`sign_and_wire_path`] but ALSO returns the SigV4 `canonical_uri` (the encoded path with the
/// query stripped) so callers that need both don't re-split the wire path and allocate a SECOND
/// `String` for the canonical URI. On the common no-query path the encoded path IS the canonical URI,
/// so it is reused for both fields and only the wire path is (cheaply) cloned; with a query the wire
/// path is `canonical?query`. Output is byte-identical to the previous split-and-`to_string` form.
/// True when every byte of `path` is SigV4-unreserved (`A-Z a-z 0-9 - _ . ~ /`), i.e.
/// `uri_encode_path` would return it byte-for-byte unchanged. The openai/anthropic/cohere/responses
/// lanes (all `/v1/...` style paths, no reserved chars) hit this; only a Bedrock modelId (carrying a
/// `:` and other reserved chars) fails it. Lets the encode fast path skip the redundant second
/// double-encode scan+allocation without changing any signed byte.
#[inline]
fn path_is_sigv4_unreserved(path: &str) -> bool {
    path.bytes().all(|b| {
        matches!(b,
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' | b'/')
    })
}

pub(crate) fn sign_and_wire_path_parts(url_path: &str) -> (String, String) {
    // The wire path is single-URI-encoded (what actually goes on the request line). The SigV4
    // CANONICAL path is DOUBLE-URI-encoded for every service except S3 (Bedrock included): AWS
    // re-encodes the already-encoded path it receives before recomputing the signature, so the
    // signature must be taken over the double-encoded form. Using the single-encoded path for BOTH
    // (as before) makes any path with an encodable char — every Bedrock model id has a `:` — fail
    // with SignatureDoesNotMatch (403). The signature-blind mock cannot catch this; only a real
    // upstream does, so it was invisible to the harness. For paths with no encodable chars
    // (openai/anthropic `/v1/...`) `uri_encode_path` is a no-op and canonical == wire, unchanged.
    let (path, query) = match url_path.split_once('?') {
        Some((p, q)) => (p, Some(q)),
        None => (url_path, None),
    };
    // Fast path (openai/anthropic/cohere/responses — every non-Bedrock lane, i.e. the throughput
    // hot path): the path holds only SigV4-unreserved bytes, so both `uri_encode_path` passes are
    // identity no-ops (`encoded == path`) and the double-encode `canonical == wire_path == path`.
    // Skip BOTH encode allocations and the second pass; allocate the owned `wire`/`canonical` the
    // callers require exactly once each straight from the borrowed path. Byte-identical output to
    // the always-encode form — `uri_encode_path` provably returns its input unchanged here. Only a
    // path carrying an encodable char (a Bedrock modelId's `:`) takes the full double-encode below.
    if path_is_sigv4_unreserved(path) {
        let wire = match query {
            Some(q) => format!("{path}?{q}"),
            None => path.to_string(),
        };
        return (wire, path.to_string());
    }
    let wire_path = crate::sigv4::uri_encode_path(path);
    let canonical = crate::sigv4::uri_encode_path(&wire_path); // double-encode (non-S3 SigV4 rule)
    let wire = match query {
        Some(q) => format!("{wire_path}?{q}"),
        None => wire_path,
    };
    (wire, canonical)
}

/// Build outbound auth headers for a lane. Defaults to the protocol's native auth via
/// `sign_request` (bearer for openai/anthropic/responses, `x-goog-api-key` for gemini, per-request
/// SigV4 for bedrock). When the provider declares `auth: api-key` (Azure OpenAI), send an
/// `api-key: <key>` header instead — the deployment and `?api-version=` live in the provider's
/// `path` override, so no new protocol is needed. An un-encodable key yields no auth header (the
/// upstream then rejects with 401, classified by the breaker like any other auth failure).
pub(crate) fn lane_auth_headers(
    lane: &crate::state::Lane,
    key: &str,
    ctx: &crate::proto::SigningContext,
) -> Vec<(axum::http::HeaderName, axum::http::HeaderValue)> {
    lane.credential.headers_for(key, ctx)
}

// ─── EGRESS User-Agent strings — RELEASE-CHECKLIST AUDIT SURFACE ──────────────────────────────────
//
// These mirror the `User-Agent` a real first-party SDK emits for each provider's API. They embed
// PINNED SDK VERSION NUMBERS that drift from upstream as those SDKs publish new releases (the OpenAI
// Python SDK alone ships several times per quarter). A backend that logs/filters by UA version can
// eventually observe a frozen, implausible version and separate busbar traffic from native traffic —
// a silent decay of the backend-facing indistinguishability guarantee.
//
// CONTAINMENT (no config/CI feature added here, per the 1.0 hardening scope): every pinned string is
// hoisted into a single named-constant block so the drift hazard lives on ONE auditable surface
// instead of being scattered as inline literals across `egress_user_agent`, and `egress_ua_versions_*`
// tests pin each protocol's UA to its constant so any silent edit/drift trips a test that forces a
// CONSCIOUS update. **RELEASE OBLIGATION:** before each busbar release, re-verify every version below
// against the latest published SDK release (PyPI / Crates.io / etc.) and bump as needed; the test
// guard ensures this block can never change unnoticed.
//
// Anthropic Python SDK UA shape (api.anthropic.com). The official SDK is Stainless-generated and
// emits `<Title>/Python <ver>` — `Anthropic/Python <ver>` — the SAME grammar as the OpenAI SDK below,
// NOT a `anthropic-sdk-python/<ver>` shape (which no released Anthropic SDK has ever sent). Emitting
// the wrong shape was a wire tell that distinguished busbar-proxied traffic from a native client on
// the User-Agent alone — the egress-UA tests now also assert the shared `<Title>/Python <ver>` grammar.
pub(crate) const EGRESS_UA_ANTHROPIC: &str = "Anthropic/Python 0.39.0";
// OpenAI Python SDK shape; the Responses API is served by the same SDK/UA.
pub(crate) const EGRESS_UA_OPENAI: &str = "OpenAI/Python 1.54.0";
// Google GenAI SDK shape (generativelanguage.googleapis.com).
pub(crate) const EGRESS_UA_GEMINI: &str = "google-genai-sdk/0.8.0 gl-python/3.11";
// AWS Bedrock is reached via boto3/botocore.
pub(crate) const EGRESS_UA_BEDROCK: &str = "Boto3/1.35.0 md/Botocore#1.35.0";
// Cohere Python SDK shape (api.cohere.com).
pub(crate) const EGRESS_UA_COHERE: &str = "cohere-python/5.11.0";
// Unknown/foreign egress protocol: a generic-but-present UA still beats sending none.
pub(crate) const EGRESS_UA_DEFAULT: &str = "okhttp/4.12.0";

/// Plausible native-SDK `User-Agent` for the chosen EGRESS protocol. reqwest sends NO default
/// User-Agent unless one is set, so without this every proxied upstream request reaches the backend
/// with no UA at all — a trivial backend-side fingerprint distinguishing busbar-proxied traffic from
/// a native vendor SDK (which always sends a recognizable UA). (Backend-facing only; does not affect
/// client indistinguishability.) The version numbers are PINNED and drift over time — see the
/// `EGRESS_UA_*` constant block above for the release-time audit obligation that keeps them current.
///
/// Thin wrapper: dispatches through `ProtocolWriter::egress_user_agent` so the name-match lives in
/// the per-protocol writer, not in this agnostic function. Call sites that already hold a resolved
/// writer (`writer.egress_user_agent()`) bypass this wrapper; it exists for test-code paths that
/// look up by name.
pub(crate) fn egress_user_agent(egress_protocol: &str) -> &'static str {
    crate::proto::protocol_for(egress_protocol)
        .map(|p| p.writer().egress_user_agent())
        .unwrap_or(EGRESS_UA_DEFAULT)
}

/// The `Accept` header a native SDK for `egress_protocol` sends, given the caller's stream intent.
/// `accept` is NOT part of SigV4 SignedHeaders, so adding it never affects a Bedrock signature — but
/// a native SDK ALWAYS sends one, so omitting it is a deterministic backend-side proxy fingerprint
/// (a busbar-proxied request carries none where a native one does). Set to what the real SDK emits so
/// the backend cannot separate busbar traffic from native traffic on this header.
///
/// Thin wrapper: dispatches through `ProtocolWriter::egress_accept` so the per-protocol logic (Bedrock
/// → eventstream/json; all others → text/event-stream/json) lives in the writer vtable, not in this
/// agnostic function. Call sites that already hold a resolved writer (`writer.egress_accept(stream)`)
/// bypass this wrapper; it exists for test-code paths that look up by name.
pub(crate) fn egress_accept(egress_protocol: &str, wants_stream: bool) -> &'static str {
    crate::proto::protocol_for(egress_protocol)
        .map(|p| p.writer().egress_accept(wants_stream))
        .unwrap_or(if wants_stream {
            TEXT_EVENT_STREAM
        } else {
            APPLICATION_JSON
        })
}
