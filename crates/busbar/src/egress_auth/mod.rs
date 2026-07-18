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

#[cfg(test)]
mod license_header_tests {
    use std::path::Path;

    /// M2: every first-party `.rs` file that declares an SPDX license MUST declare `Apache-2.0`.
    /// cargo-deny only checks crate-level `Cargo.toml`, so a stray file header (the three new OAuth
    /// files shipped as `AGPL-3.0-or-later`) would go undetected — this meta-test catches it. Files
    /// with no SPDX line are ignored (headers are not mandatory); a WRONG one is a hard fail.
    fn scan(dir: &Path, offenders: &mut Vec<String>) {
        let Ok(entries) = std::fs::read_dir(dir) else {
            return;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                scan(&path, offenders);
            } else if path.extension().is_some_and(|x| x == "rs") {
                let head: String = std::fs::read_to_string(&path)
                    .unwrap_or_default()
                    .lines()
                    .take(3)
                    .collect::<Vec<_>>()
                    .join("\n");
                if head.contains("SPDX-License-Identifier") && !head.contains("Apache-2.0") {
                    offenders.push(path.display().to_string());
                }
            }
        }
    }

    #[test]
    fn all_source_files_declare_apache_license() {
        let src = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
        let mut offenders = Vec::new();
        scan(&src, &mut offenders);
        assert!(
            offenders.is_empty(),
            "these first-party files declare a non-Apache-2.0 SPDX license: {offenders:#?}"
        );
    }
}
