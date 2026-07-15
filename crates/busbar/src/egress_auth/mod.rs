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

/// Produces the outbound auth headers for a single upstream request.
///
/// `key` is the per-request credential the caller resolved — the lane's configured key for
/// [`crate::auth::UpstreamCreds::Own`], or the forwarded caller token for `Passthrough`. A
/// self-minting credential (e.g. a future OAuth token provider) ignores `key`. `ctx` carries the
/// host / canonical-uri / body / timestamp a signer needs, plus the `Own | Passthrough` mode.
pub(crate) trait CredentialProvider: Send + Sync {
    fn headers_for(&self, key: &str, ctx: &SigningContext) -> Vec<(HeaderName, HeaderValue)>;
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
