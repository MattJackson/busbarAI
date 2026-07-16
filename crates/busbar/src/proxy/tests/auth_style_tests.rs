use super::lane_auth_headers;
use crate::proto::{Protocol, SigningContext};
use crate::state::Lane;
use std::collections::HashMap;
use std::sync::Arc;

fn lane_with_auth(auth: Option<&str>) -> Lane {
    let resolved_auth = auth.map(|a| match a {
        "api-key" => crate::config::ProviderAuth::ApiKey,
        "bearer" => crate::config::ProviderAuth::Bearer,
        other => panic!("unexpected test auth style: {other}"),
    });
    Lane {
        credential: crate::egress_auth::resolve("openai", resolved_auth),
        reasoning: false,
        prompt_caching: false,
        default_max_tokens: None,
        model: "gpt-4o".to_string(),
        provider: "azure".to_string(),
        base_url: "https://res.openai.azure.com".to_string(),
        api_key: "SECRETKEY".to_string(),
        protocol: Arc::new(Protocol::openai()),
        max: 1,
        error_map: Arc::new(HashMap::new()),
        context_max: None,
        path: Some(
            "/openai/deployments/gpt-4o/chat/completions?api-version=2024-06-01".to_string(),
        ),
        path_base: None,
        health: None,
        upstream_model: None,
        attempt_timeout_ms: None,
    }
}

fn ctx<'a>(body: &'a [u8]) -> SigningContext<'a> {
    SigningContext {
        host: "res.openai.azure.com".to_string(),
        canonical_uri: "/openai/deployments/gpt-4o/chat/completions".to_string(),
        body,
        timestamp_epoch: 0,
        upstream_creds: crate::auth::UpstreamCreds::Own,
    }
}

#[test]
fn test_api_key_auth_sends_api_key_header() {
    // Azure-style: `auth: api-key` sends `api-key: <key>`, NOT a bearer Authorization header.
    let lane = lane_with_auth(Some("api-key"));
    let headers = lane_auth_headers(&lane, "SECRETKEY", &ctx(b"{}"));
    assert_eq!(headers.len(), 1);
    assert_eq!(headers[0].0.as_str(), "api-key");
    assert_eq!(headers[0].1.to_str().unwrap(), "SECRETKEY");
}

#[test]
fn test_default_auth_falls_back_to_protocol_bearer() {
    // No/`bearer` auth override uses the protocol's native sign_request (openai → bearer).
    for auth in [None, Some("bearer")] {
        let lane = lane_with_auth(auth);
        let headers = lane_auth_headers(&lane, "SECRETKEY", &ctx(b"{}"));
        assert_eq!(headers.len(), 1);
        assert_eq!(headers[0].0.as_str(), "authorization");
        assert_eq!(headers[0].1.to_str().unwrap(), "Bearer SECRETKEY");
    }
}

#[test]
fn test_host_from_base_strips_scheme_and_userinfo() {
    use super::host_from_base;
    // Plain host: scheme stripped, nothing else touched.
    assert_eq!(
        host_from_base("https://bedrock-runtime.us-east-1.amazonaws.com"),
        "bedrock-runtime.us-east-1.amazonaws.com"
    );
    assert_eq!(host_from_base("http://localhost:8080"), "localhost:8080");
    // No scheme: returned unchanged.
    assert_eq!(host_from_base("example.com"), "example.com");
    // Embedded userinfo MUST be stripped so the SigV4-signed `host` matches the `Host` header
    // the HTTP stack actually transmits (otherwise: signature mismatch + credential in the
    // signed string). The host (and port) survive; the credential is gone.
    assert_eq!(
        host_from_base("https://user:pass@host.example.com"),
        "host.example.com"
    );
    assert_eq!(
        host_from_base("https://user:pass@host.example.com:443"),
        "host.example.com:443"
    );
    // An `@` later in a path/query is NOT userinfo and must not be treated as one — and the path
    // itself is discarded, so only the host survives.
    assert_eq!(
        host_from_base("https://host.example.com/x@y"),
        "host.example.com"
    );
    // A path-bearing base_url yields ONLY the authority: a signed `host` that included the path
    // would never match the `Host:` header the HTTP stack transmits (SignatureDoesNotMatch).
    assert_eq!(
        host_from_base("https://bedrock.us-east-1.amazonaws.com/some-prefix"),
        "bedrock.us-east-1.amazonaws.com"
    );
    // Port preserved, path discarded.
    assert_eq!(
        host_from_base("https://host.example.com:8443/v1/foo?x=1"),
        "host.example.com:8443"
    );
    // Userinfo stripped AND path discarded together.
    assert_eq!(
        host_from_base("https://user:pass@host.example.com/p"),
        "host.example.com"
    );
}

#[test]
fn test_host_from_base_backslash_authority_matches_wire_host() {
    // CLASS-SIBLING of the SSRF backslash defect: the WHATWG URL parser the `url` crate (and
    // thus reqwest) uses treats `\` as an authority/path delimiter exactly like `/`, so reqwest
    // dials the host that ENDS at the first backslash. A `/?#`-only split read PAST the
    // backslash and (via `rfind('@')`) returned a DIFFERENT host than reqwest connects to,
    // desyncing the SigV4-signed `Host` from the host actually contacted.
    use super::host_from_base;
    // Backslash where a `/` would normally start the path: reqwest connects to
    // `evil.example.com`; the signed host must be the SAME, not the post-`@` `victim.example`.
    assert_eq!(
        host_from_base("https://evil.example.com\\@victim.example/path"),
        "evil.example.com"
    );
    // Bare backslash path delimiter, no userinfo trickery: authority still ends at the `\`.
    assert_eq!(
        host_from_base("https://host.example.com\\some\\path"),
        "host.example.com"
    );
    // Backslash before a port-bearing authority boundary: port survives, backslash path gone.
    assert_eq!(
        host_from_base("https://host.example.com:8443\\v1\\foo"),
        "host.example.com:8443"
    );
    // Legitimate userinfo with a backslash path AFTER the real authority: userinfo stripped,
    // authority ends at the backslash, the real host survives.
    assert_eq!(
        host_from_base("https://user:pass@host.example.com\\p"),
        "host.example.com"
    );
}

#[test]
fn test_sign_and_wire_path_parts_strips_query_from_canonical() {
    use super::sign_and_wire_path_parts;
    // The SigV4 canonical_uri MUST exclude the query string while the wire path retains it. This
    // guards the operator `path:`-override branch (Bedrock's own paths are query-free, so the
    // single-return wrapper test never reaches the `?` split).
    let (wire, canonical) = sign_and_wire_path_parts("/model/foo/converse?api-version=2024-05-01");
    assert_eq!(
        canonical, "/model/foo/converse",
        "canonical uri excludes the query"
    );
    assert_eq!(
        wire, "/model/foo/converse?api-version=2024-05-01",
        "wire path keeps the query"
    );
    assert_ne!(wire, canonical);
}

#[test]
fn test_sign_and_wire_path_signed_equals_sent_for_reserved_chars() {
    use super::sign_and_wire_path;
    // A Bedrock modelId carrying reserved chars (`:` for a cross-region inference profile /
    // provisioned-throughput ARN, `.` already unreserved). The path must be encoded ONCE and used
    // for BOTH the SigV4 canonical URI and the wire URL, or AWS rejects with SignatureDoesNotMatch.
    let model = "us.anthropic.claude-3-5-sonnet-20240620-v1:0";
    // Raw, un-encoded path as built by the Bedrock writer's `upstream_path_for_stream`.
    let url_path = format!("/model/{model}/converse");
    let wire_path = sign_and_wire_path(&url_path);
    // `:` encoded to %3A; `/` and `.` preserved.
    assert_eq!(
        wire_path,
        "/model/us.anthropic.claude-3-5-sonnet-20240620-v1%3A0/converse"
    );

    // The path actually SIGNED (the canonical_uri the forward path passes to SigningContext).
    let signed_canonical = wire_path
        .split('?')
        .next()
        .unwrap_or(&wire_path)
        .to_string();

    // The path actually SENT: reqwest parses `{base}{wire_path}` into a `url::Url`. Its parser
    // must preserve the existing `%3A` (not double-encode the `%`), so the transmitted path is
    // byte-identical to the signed canonical path.
    let url = reqwest::Url::parse(&format!(
        "https://bedrock-runtime.us-east-1.amazonaws.com{wire_path}"
    ))
    .expect("url parses");
    assert_eq!(
        url.path(),
        signed_canonical,
        "transmitted path must equal the signed canonical path"
    );
}
