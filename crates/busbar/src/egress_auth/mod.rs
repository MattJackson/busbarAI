//! Egress credential seam — how Busbar presents ITS OWN identity to an upstream provider.
//!
//! This is the OUTBOUND counterpart to the ingress [`crate::auth`] chain ("who is calling us"). A
//! [`CredentialProvider`] turns a lane's configured credential material into the exact auth headers
//! an outbound request carries. It is [`resolve`]d once per lane at boot from the lane's protocol +
//! configured auth style, and lives on [`crate::state::Lane`], so the request path dispatches
//! (`lane.credential.headers_for(...)`) instead of branching.
//!
//! "Protocol is post-auth": auth answers *who am I to this upstream* (headers / signature); the
//! protocol answers *how do I shape this payload*. They compose through [`SigningContext`] — a signer
//! (SigV4) consumes the protocol's already-written body + path — but auth no longer lives on the
//! `ProtocolWriter`. The per-scheme logic lives in `pub(crate)` free functions co-located with each
//! protocol's constants (`proto::bearer_auth_headers`, `proto::anthropic::anthropic_auth_headers`,
//! `proto::bedrock::sigv4_sign_headers`); this module owns the *dispatch*. Those same free functions
//! are what the byte-pinning auth tests call, so a credential and its test can never diverge.

use crate::proto::SigningContext;
use axum::http::{HeaderName, HeaderValue};
use std::sync::Arc;

pub(crate) mod bearer_token;
pub(crate) mod jwt_bearer;
pub(crate) mod oauth_client_credentials;

/// HTTP client used by the self-minting OAuth credentials (`jwt-bearer`, `oauth-client-credentials`)
/// to POST to a token endpoint. Hardened like the data-path upstream client (see `main.rs`):
///   * `redirect: none` — the credential (a signed assertion, or `client_secret`) rides in the POST
///     BODY, so reqwest's cross-host Authorization-stripping does not protect it; a 307/308 from a
///     compromised or typo'd token endpoint would re-POST the plaintext secret to the redirect target
///     (169.254.169.254 / localhost / RFC1918). The boot-time SSRF check only vets the configured URL
///     string, never a runtime redirect target, so following redirects reopens that exfil vector.
///   * bounded connect + overall timeouts — a stalled token endpoint must not hang the mint/refresh
///     future forever (the refresh loop only retries on `Err`, so a hang would silently freeze the
///     lane's token and serve an empty bearer → upstream 401).
pub(crate) fn minter_client() -> reqwest::Client {
    reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .connect_timeout(std::time::Duration::from_secs(10))
        .timeout(std::time::Duration::from_secs(30))
        .build()
        .expect("build OAuth token-minter HTTP client")
}

/// Default token TTL when a token endpoint omits `expires_in` (RFC 6749 §5.1 makes it RECOMMENDED, not
/// required): a conservative 1 h so the token still refreshes on schedule.
pub(crate) fn default_expires_in() -> u64 {
    3600
}

/// Deserialize an OAuth `expires_in` TOLERANTLY. RFC 6749 specifies a number of seconds, but real IdPs
/// vary — ADFS and Azure AD v1 emit it as a JSON STRING (`"3600"`), and some omit it (handled by
/// `#[serde(default = "default_expires_in")]` on the field). A strict `u64` field breaks token minting
/// for those providers, silently downing the lane. Accept a number or a numeric string.
pub(crate) fn deserialize_expires_in<'de, D>(d: D) -> Result<u64, D::Error>
where
    D: serde::Deserializer<'de>,
{
    use serde::Deserialize as _;
    #[derive(serde::Deserialize)]
    #[serde(untagged)]
    enum NumOrStr {
        Num(u64),
        Str(String),
    }
    match NumOrStr::deserialize(d)? {
        NumOrStr::Num(n) => Ok(n),
        NumOrStr::Str(s) => s.trim().parse::<u64>().map_err(serde::de::Error::custom),
    }
}

/// Produces the outbound auth headers for a single upstream request.
///
/// `key` is the per-request credential the caller resolved — the lane's configured key for
/// [`crate::auth::UpstreamCreds::Own`], or the forwarded caller token for `Passthrough`. A
/// self-minting credential (e.g. a future OAuth token provider) ignores `key`. `ctx` carries the
/// host / canonical-uri / body / timestamp a signer needs, plus the `Own | Passthrough` mode.
/// The operator's metadata-SSRF posture, threaded into a token-endpoint check so the boot/reload
/// validation matches `config_validate`'s validate-time check EXACTLY (validate == apply). Its three
/// fields are the SAME arguments `config_validate::ssrf_blocked_host` is called with: the union of the
/// provider's and global `allow_metadata_hosts` carve-outs, the nuclear `allow_all_metadata`, and the
/// operator's extra `blocked_metadata_hosts`. Without threading these, a token endpoint an operator
/// deliberately allow-listed passes `--validate` but dies at boot — the reverse of the safety guarantee.
/// (found: 1.4.0 audit, egress-auth.)
pub(crate) struct MetadataSsrfPolicy<'a> {
    pub(crate) allow_overrides: &'a [String],
    pub(crate) allow_all: bool,
    pub(crate) blocked_hosts: &'a [String],
}

pub(crate) trait CredentialProvider: Send + Sync {
    fn headers_for(&self, key: &str, ctx: &SigningContext) -> Vec<(HeaderName, HeaderValue)>;

    /// Whether this credential can currently produce a usable auth header. Static credentials
    /// (api-key, bearer, sigv4, anthropic-native) are always ready. A self-minting credential (OAuth
    /// jwt-bearer / client-credentials) is NOT ready during the boot/reload window before its first
    /// mint completes — `headers_for` returns no header then, so an active health probe would send an
    /// unauthenticated request and a guaranteed 401 could HardDown-park a healthy lane. The prober
    /// consults this to skip a not-yet-minted lane until its token is live. Default: always ready.
    /// (1.4.0 audit, egress-auth.)
    fn is_ready(&self) -> bool {
        true
    }
}

/// Resolve a lane's egress credential at boot from its protocol name and auth style.
/// `auth: api-key` overrides the protocol's native scheme.
pub(crate) fn resolve(
    protocol_name: &str,
    auth: Option<crate::config::ProviderAuth>,
) -> Arc<dyn CredentialProvider> {
    if matches!(auth, Some(crate::config::ProviderAuth::ApiKey)) {
        return Arc::new(ApiKeyHeader { header: "api-key" });
    }
    if matches!(
        auth,
        Some(crate::config::ProviderAuth::JwtBearer)
            | Some(crate::config::ProviderAuth::OAuthClientCredentials)
    ) {
        // The OAuth styles mint their token asynchronously at boot (see `jwt_bearer::build` /
        // `oauth_client_credentials::build`), so the boot path special-cases them and never routes
        // them through this sync resolver. Reaching here means that wiring was bypassed — fail closed
        // with a credential that emits no auth header (upstream 401) rather than sending raw secret
        // material as a bearer.
        return Arc::new(NoCredential);
    }
    match protocol_name {
        "gemini" => Arc::new(ApiKeyHeader {
            header: "x-goog-api-key",
        }),
        "anthropic" => Arc::new(AnthropicNative),
        "bedrock" => Arc::new(SigV4),
        // openai / cohere / responses and any other bearer-native protocol.
        "cohere" => Arc::new(StaticBearer { proto: "cohere" }),
        "responses" => Arc::new(StaticBearer { proto: "responses" }),
        _ => Arc::new(StaticBearer { proto: "openai" }),
    }
}

/// Fail-closed credential: emits no auth header. Used only as a defensive fallback if an
/// async-constructed credential (e.g. `jwt-bearer`) reaches the sync resolver — the upstream then
/// rejects with 401 rather than receiving a wrong or raw-secret header.
struct NoCredential;
impl CredentialProvider for NoCredential {
    fn headers_for(&self, _key: &str, _ctx: &SigningContext) -> Vec<(HeaderName, HeaderValue)> {
        Vec::new()
    }
}

/// `Authorization: Bearer <key>` — openai / cohere / responses. Drops the header on a control-char key.
struct StaticBearer {
    proto: &'static str,
}
impl CredentialProvider for StaticBearer {
    fn headers_for(&self, key: &str, _ctx: &SigningContext) -> Vec<(HeaderName, HeaderValue)> {
        crate::proto::bearer_auth_headers(self.proto, key)
    }
}

/// Static custom header carrying the raw key (`api-key` or `x-goog-api-key`). An un-encodable key
/// yields no header (upstream 401s). Free function so auth tests exercise the exact same code.
pub(crate) fn api_key_headers(header: &'static str, key: &str) -> Vec<(HeaderName, HeaderValue)> {
    match HeaderValue::from_str(key) {
        Ok(v) => vec![(HeaderName::from_static(header), v)],
        Err(_) => {
            tracing::warn!(
                header,
                "egress credential contains invalid header bytes (ASCII control character); \
                 omitting auth header — upstream will reject with 401"
            );
            Vec::new()
        }
    }
}

struct ApiKeyHeader {
    header: &'static str,
}
impl CredentialProvider for ApiKeyHeader {
    fn headers_for(&self, key: &str, _ctx: &SigningContext) -> Vec<(HeaderName, HeaderValue)> {
        api_key_headers(self.header, key)
    }
}

/// Anthropic's api-key (`sk-ant-api…` → `x-api-key`) vs Bearer (`sk-ant-oat…` → `Authorization`)
/// disambiguation, resolved against the `Own | Passthrough` mode for an ambiguous credential.
struct AnthropicNative;
impl CredentialProvider for AnthropicNative {
    fn headers_for(&self, key: &str, ctx: &SigningContext) -> Vec<(HeaderName, HeaderValue)> {
        crate::proto::anthropic::anthropic_auth_headers(key, Some(ctx.upstream_creds))
    }
}

/// AWS SigV4 over the request (body + canonical path from `ctx`) — Bedrock.
struct SigV4;
impl CredentialProvider for SigV4 {
    fn headers_for(&self, key: &str, ctx: &SigningContext) -> Vec<(HeaderName, HeaderValue)> {
        crate::proto::bedrock::sigv4_sign_headers(key, ctx)
    }
}

// License-header meta-test lives in tests/ per the repo layout rule (no inline test bodies in a
// mod.rs); keep the module here via a #[path] decl.
#[cfg(test)]
#[path = "tests/license_tests.rs"]
mod license_header_tests;
