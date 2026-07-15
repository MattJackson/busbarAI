// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use std::fmt;

use axum::{
    body::Body,
    http::{header::AUTHORIZATION, Request, StatusCode},
    middleware::Next,
    response::Response,
};

use crate::config::AuthCfg;
use crate::sigv4::{SIGV4_ALGORITHM, X_AMZ_CONTENT_SHA256, X_AMZ_DATE};

/// The two non-`Authorization` headers that native vendor SDKs use to carry their API key:
/// the Anthropic SDK sends `x-api-key`, the Gemini SDK sends `x-goog-api-key`. busbar accepts
/// either as a carrier of the SAME busbar client token / virtual key (validated identically,
/// in constant time, against the same allowlist / governance lookup). Checked AFTER
/// `Authorization: Bearer` (see `extract_client_token`).
const X_API_KEY: &str = "x-api-key";
const X_GOOG_API_KEY: &str = "x-goog-api-key";

/// The header name for the operator admin token carrier (busbar-proprietary surface).
pub(crate) const X_ADMIN_TOKEN: &str = "x-admin-token";
/// The Bearer auth-scheme token (case-insensitive match in `extract_bearer_token`).
const AUTH_SCHEME_BEARER: &str = "bearer";
/// The liveness-probe path that bypasses auth entirely.
const HEALTHZ_PATH: &str = "/healthz";
/// The exact `/api` path (the native-API root — every busbar-own surface mounts under it;
/// see `admin::v1::contract::API_ROOT`).
const ADMIN_PATH: &str = "/api";
/// The `/api/` prefix that all native-API sub-routes share. A path must match ADMIN_PATH exactly
/// OR start with ADMIN_PATH_PREFIX to be treated as an admin-plane request — preventing sibling
/// paths like `/apix/…` from being mis-classified. The WHOLE `/api/` root is admin-classified
/// (fail-closed): a future area (`events`, `metrics`) mounted under `/api/` is admin-guarded by
/// default and must explicitly carve out a weaker class if it ever wants one.
const ADMIN_PATH_PREFIX: &str = "/api/";
/// Fixed dummy secret used when an inbound SigV4 AccessKeyId is unknown: we still run the
/// full HMAC verification so the timing is indistinguishable from a bad-signature rejection
/// (no AccessKeyId-enumeration oracle). The `crate::sigv4` test module references this via
/// `crate::auth::DUMMY_SECRET` rather than maintaining a separate copy.
pub(crate) const DUMMY_SECRET: &str = "AWS4-DUMMY-SECRET-FOR-CONSTANT-TIME-REJECT-PATH";

/// The UPSTREAM-credential mode (`upstream_credentials:`) — whose credential reaches the provider.
/// DISTINCT from authentication (which auth module, if any, ran at the front door — that's the
/// `auth.chain`): `Own` (default) signs the upstream call with busbar's configured lane key;
/// `Passthrough` forwards the CALLER's credential upstream. A proto writer uses THIS to resolve an
/// otherwise-ambiguous credential scheme to the single native header the caller's real client
/// produces. (Split out of the old `AuthMode`, now its own config key — `AuthMode` is gone.)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum UpstreamCreds {
    #[default]
    Own,
    Passthrough,
}

/// The caller's bearer token, threaded into request extensions by `auth_middleware` so handlers can
/// forward it upstream in passthrough mode. `None` when no usable bearer token was presented.
#[derive(Clone, Default)]
pub(crate) struct CallerToken(pub(crate) Option<String>);

// MANUAL Debug that NEVER prints the token contents. `CallerToken` wraps a caller credential and is
// threaded into request extensions, so it can be reached by any future code that debug-formats the
// extension map (or a struct that holds it). A derived `Debug` would print the plaintext token — a
// latent credential leak the moment anything debug-logs it. Redact to presence only ("present" /
// "absent"); never the length and never the value, since even the length is a (small) oracle.
impl fmt::Debug for CallerToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("CallerToken")
            .field(&if self.0.is_some() {
                "<present>"
            } else {
                "<absent>"
            })
            .finish()
    }
}

// The auth CONTRACT — [`Principal`], [`AuthOutcome`], the [`AuthModule`] trait, and the
// constant-time credential primitives — lives in the `busbar-api` crate (the one crate both the
// engine and every plugin build against). Re-exported here so engine-internal paths are unchanged.
pub(crate) use busbar_api::{AuthModule, AuthOutcome, Principal};

/// The whole CHAIN's verdict for one request: admitted-with-identity, admitted-anonymously (the
/// empty-chain open front door), or denied. Distinct from the per-module [`AuthOutcome`] so the
/// middleware can attach the principal (or its absence) to the request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ChainVerdict {
    Identified(Principal),
    Open,
    Denied,
}

// The built-in `tokens` auth module IMPLEMENTATION lives in its own WORKSPACE CRATE
// (`auth/tokens/`), NOT in the engine core — the engine holds only the `AuthModule` contract
// (re-exported above from `busbar-api`). `grep token` in the engine is clean; the plugin is
// default-included and REMOVABLE (the `auth-tokens` feature; a `--no-default-features` build
// contains no token auth code at all).
#[cfg(feature = "auth-tokens")]
use busbar_auth_tokens::TokensModule;

/// AuthMiddleware holds the resolved auth chain, the upstream-credential mode, and the token allowlist.
pub(crate) struct AuthMiddleware {
    /// The upstream-credential mode (`upstream_credentials:`) — whether the egress path signs with
    /// busbar's key (`Own`) or forwards the caller's (`Passthrough`). Read by the egress signing path.
    pub(crate) upstream_creds: UpstreamCreds,
    pub(crate) client_tokens: Vec<String>,
    /// Per-module `allowed_groups:` caps (`auth.modules:`), applied to a module's Identify verdict
    /// before anything downstream reads the groups. (The admin chain applies the same caps from
    /// `App.auth_modules`; this copy serves the data-plane chain, which runs before `App` routing.)
    module_caps: std::collections::HashMap<String, crate::config::AuthModuleCfg>,
    /// The AUTH CHAIN — the ordered `auth.chain` modules. `validate_token` runs it: the first module
    /// to `Identify` admits, a `Reject` denies, and if every module `Pass`es (no usable credential
    /// matched) a NON-EMPTY chain denies (fail-closed). An EMPTY chain admits unconditionally — the
    /// open front door (`chain: []`, the old none/passthrough). No `AuthMode` — the front-door policy
    /// is the chain shape, the egress policy is `upstream_creds`.
    chain: Vec<Box<dyn AuthModule>>,
}

// MANUAL Debug that REDACTS the allowlist. A derived `Debug` would print every entry of
// `client_tokens` in PLAINTEXT — a latent credential leak if an `AuthMiddleware` (or any struct that
// holds one, e.g. `App`) is ever debug-logged. Print only the COUNT of configured tokens, never the
// values (and never any prefix/suffix, which would be a partial-secret oracle).
impl fmt::Debug for AuthMiddleware {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AuthMiddleware")
            .field("upstream_creds", &self.upstream_creds)
            .field("chain_len", &self.chain.len())
            .field(
                "client_tokens",
                &format_args!("<redacted; {} configured>", self.client_tokens.len()),
            )
            .finish()
    }
}

impl AuthMiddleware {
    pub(crate) fn new(cfg: &AuthCfg) -> Self {
        // client_tokens are already env-interpolated: `interpolate_env` runs over the WHOLE
        // config.yaml text once at load (main.rs), before deserialization. A second per-token pass
        // here would double-interpolate — a token that legitimately contains the literal `${...}`
        // (legal in opaque API keys) would be re-expanded or abort startup via `.expect`. Interpolate
        // exactly once; just clone the resolved values.
        let tokens: Vec<String> = cfg.client_tokens.clone();

        // Build the auth chain by RESOLVING the configured module names. `tokens` -> the built-in
        // tokens module (owns the pre-hashed allowlist). An unknown name is skipped here with a loud
        // log; config_validate rejects it at boot, so a running server never has a silently-dropped
        // module. An EMPTY chain is the open front door (the old none/passthrough).
        let chain: Vec<Box<dyn AuthModule>> = cfg
            .chain
            .iter()
            .filter_map(|name| -> Option<Box<dyn AuthModule>> {
                match name.as_str() {
                    // The built-in tokens module — present only in an `auth-tokens` build. When
                    // compiled OUT, `chain: [tokens]` is a config_validate BOOT ERROR (never a
                    // silently-dropped module -> never a silent open relay), so this arm's absence is
                    // safe.
                    #[cfg(feature = "auth-tokens")]
                    "tokens" => Some(Box::new(TokensModule::new(&tokens))),
                    // TEST-ONLY external-module stand-in for the DATA-PLANE chain (the admin
                    // chain has its own): `grp:<group>` identifies as a principal carrying that
                    // group, so the governance re-key is e2e-testable. Compiled out of release
                    // binaries entirely.
                    #[cfg(test)]
                    "test-groups-module" => Some(Box::new(TestGroupsModule)),
                    other => {
                        tracing::error!(
                            module = other,
                            "auth.chain names an unknown/uncompiled module; skipping \
                             (config_validate rejects this at boot)"
                        );
                        None
                    }
                }
            })
            .collect();

        if chain.is_empty() {
            if tokens.is_empty() {
                tracing::warn!(
                    "auth.chain is empty (open relay) — only acceptable for dev; reject in production"
                );
            } else {
                // An empty chain admits every request, so a configured `client_tokens` allowlist has
                // ZERO enforcement effect. Warn loudly that the listed tokens are inert (mirrored at
                // boot in `config_validate::validate`).
                tracing::warn!(
                    "auth.chain is empty but client_tokens ({} listed) are configured: an empty \
                     chain is an open relay and admits every request regardless of token. The \
                     allowlist has no effect — add `tokens` to auth.chain to enforce it.",
                    tokens.len()
                );
            }
        }

        Self {
            upstream_creds: cfg.upstream_credentials,
            client_tokens: tokens,
            chain,
            module_caps: cfg.modules.clone(),
        }
    }

    /// The ordered names of the auth chain's modules (`module.name()` for each). For the Admin API
    /// v1 plugin catalog — reporting which compiled-in/external auth modules are ACTIVE (in the
    /// chain). Never a secret: a module name is a plugin identifier, not a credential.
    pub(crate) fn chain_names(&self) -> Vec<&'static str> {
        self.chain.iter().map(|m| m.name()).collect()
    }

    /// Whether the front door is OPEN — an empty auth chain admits every request unconditionally
    /// (the old `none`/`passthrough`). Governance, when enabled, supersedes this.
    pub(crate) fn is_open(&self) -> bool {
        self.chain.is_empty()
    }

    /// Run the auth chain over the presented candidate credential. Empty chain -> admit with NO
    /// principal (the `none`/`passthrough` open front door — anonymous). Otherwise the first
    /// `Identify` admits with its [`Principal`], a `Reject` denies, and all-`Pass` (no module
    /// matched a presented credential) denies — fail-closed for a configured chain. Constant-time
    /// within each module; the loop order is config order.
    pub(crate) fn run_chain(&self, candidate: Option<&str>) -> ChainVerdict {
        self.run_chain_cached(candidate, None)
    }

    /// [`run_chain`] with the CREDENTIAL CACHE consulted around each `cacheable()` module
    /// (design-hooks-v2 §2.5). The cache stores the module's RAW verdict; the `allowed_groups:`
    /// intersection is applied AFTER retrieval, so a config change to the caps takes effect
    /// immediately even for cached identities. In-process modules report `cacheable() == false`
    /// and never touch the cache (caching a microsecond compare only widens revocation).
    pub(crate) fn run_chain_cached(
        &self,
        candidate: Option<&str>,
        cache: Option<&crate::auth_cache::CredentialCache>,
    ) -> ChainVerdict {
        if self.chain.is_empty() {
            return ChainVerdict::Open;
        }
        let now = crate::store::now();
        for module in &self.chain {
            let cache_here = match (cache, candidate) {
                (Some(c), Some(cred)) if module.cacheable() => Some((c, cred)),
                _ => None,
            };
            let outcome = cache_here
                .and_then(|(c, cred)| c.get(module.name(), cred, now))
                .unwrap_or_else(|| {
                    let o = module.authenticate(candidate);
                    if let Some((c, cred)) = cache_here {
                        c.put(module.name(), cred, &o, now);
                    }
                    o
                });
            match outcome {
                AuthOutcome::Identify(mut principal) => {
                    // `allowed_groups:` intersection (design-hooks-v2 §2.4), BEFORE group_map — a
                    // module cannot assert a group the operator did not pre-authorize for it.
                    if !principal.groups.is_empty() {
                        if let Some(allowed) = self
                            .module_caps
                            .get(module.name())
                            .and_then(|c| c.allowed_groups.as_ref())
                        {
                            principal.groups.retain(|g| allowed.contains(g));
                        }
                    }
                    return ChainVerdict::Identified(principal);
                }
                AuthOutcome::Reject => return ChainVerdict::Denied,
                AuthOutcome::Pass => {}
            }
        }
        ChainVerdict::Denied
    }

    /// Constant-time string comparison — the single timing-safe primitive, now provided by the
    /// `busbar-api` contract crate (plugins compare with the SAME primitive). Kept as an associated
    /// fn so engine call sites are unchanged.
    pub(crate) fn constant_time_eq(a: &str, b: &str) -> bool {
        busbar_api::constant_time_eq(a, b)
    }

    /// Extract the token from an `Authorization: Bearer <token>` header (scheme match is
    /// case-insensitive). Splits on the first space rather than byte-slicing, so a malformed header
    /// with a multibyte character in the scheme position can't panic on a UTF-8 boundary.
    pub(crate) fn extract_bearer_token(auth_header: &str) -> Option<String> {
        let (scheme, token) = auth_header.split_once(' ')?;
        if scheme.eq_ignore_ascii_case(AUTH_SCHEME_BEARER) && !token.is_empty() {
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
    /// Bedrock SDKs authenticate with inbound AWS SigV4, NOT a bearer-style token, so this extractor
    /// deliberately does NOT read any `x-amz-*` / SigV4 `Authorization` header — a non-Bearer
    /// `Authorization` (AWS4-HMAC-SHA256 or Basic) falls through to the vendor carriers and otherwise
    /// yields `None` here. Inbound SigV4 is now handled SEPARATELY, under governance, by
    /// `verify_bedrock_sigv4` (the MinIO/S3-compatible model: an AWS-style access-key-id + secret
    /// access key issued per virtual key, whose signature busbar verifies via `crate::sigv4`). On a
    /// successful verify the same `GovCtx` a bearer auth attaches is attached, so Bedrock ingress now
    /// receives full virtual-key governance under `token`/governance mode — it no longer requires
    /// `passthrough`. This token path itself is unchanged.
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

    /// Validate the request's token by running the AUTH CHAIN. `token` accepts a credential extracted
    /// from ANY supported carrier (see `extract_client_token`); the comparison is identical and
    /// constant-time regardless of which header carried it. No `AuthMode` branch here — the front-door
    /// policy is entirely encoded in the chain shape (`[]` admits, `[tokens]` validates).
    // Thin admit/deny view over `run_chain` — kept for tests and callers that don't need the
    // principal. The middleware itself calls `run_chain` (it attaches the principal).
    #[allow(dead_code)]
    pub(crate) fn validate_token(&self, token: Option<&str>) -> bool {
        !matches!(self.run_chain(token), ChainVerdict::Denied)
    }
}

/// The ingress wire protocol a request targets, inferred from its path prefix. Auth runs BEFORE
/// routing, so the path is the only signal available for shaping a native 401 envelope.
///
/// This is a THIN delegation to the CANONICAL `crate::proto::proto_for_path` (the single source of
/// truth shared with `main.rs`'s fallback/405 handlers): the previous private copy here was a
/// wire-identical duplicate that COULD drift from the routing-time classifier — the exact
/// indistinguishability tell where one handler shapes `/model/foo/bar` as bedrock and another as
/// openai. Calling the canonical fn makes that drift impossible by construction; the auth-time and
/// routing-time classifiers are now literally the same code.
fn proto_for_path(path: &str) -> &'static str {
    crate::proto::proto_for_path(path)
}

/// The auth-failure wire message for an inferred ingress protocol — a THIN delegation to the
/// CANONICAL `crate::proto::vendor_auth_failure_message` so the auth path and any other site that
/// shapes a native bad-credential body cannot drift on the vendor copy. The string lands verbatim in
/// the native error body (`error.message` for anthropic/openai/gemini/responses, the bare top-level
/// `message` for cohere, the `message` field alongside `__type` for bedrock — every writer echoes
/// it unchanged), so it MUST read like the copy the REAL vendor returns for a bad/missing credential
/// and carry NO busbar-internal vocabulary ("virtual key", "client token", "allowlist", "disabled",
/// "passthrough", …). The wording is chosen PURELY from the inferred protocol and is deliberately
/// independent of WHY auth failed (missing token vs. wrong token vs. disabled virtual key vs.
/// admin-token mismatch) — surfacing that distinction on the wire is itself an oracle. Call sites
/// therefore pass no reason string.
fn vendor_auth_failure_message(proto: &str) -> &'static str {
    crate::proto::vendor_auth_failure_message(proto)
}

/// The HTTP status and protocol-agnostic error `kind` a bad/missing credential yields for an
/// inferred ingress protocol. The pair is chosen to MATCH what the genuine vendor returns for a
/// bad API key, because the status code and the writer-mapped `error.type`/`error.status` are both
/// deterministic protocol tells a native SDK keys its typed exception off:
///   - bedrock → HTTP 403 + "auth": a real SigV4 rejection is 403 AccessDenied (NOT 401).
///   - gemini  → HTTP 400 + "invalid_request_error": the Generative Language API does NOT return
///     401/UNAUTHENTICATED for a bad API key; it returns HTTP 400 with `error.status:
///     "INVALID_ARGUMENT"` (google.rpc.Code; the gemini writer maps `invalid_request_error` →
///     INVALID_ARGUMENT and echoes `code: 400`). A 401/UNAUTHENTICATED body would be a tell the
///     google-genai SDK never sees from real Google on the bad-key path.
///   - openai / responses → HTTP 401 + "authentication_error": the genuine OpenAI/Responses bad-key
///     401 body carries `error.code: "invalid_api_key"`, and the official SDKs surface that value as
///     `AuthenticationError.code`. Emitting `code: null` is a deterministic proxy tell a native SDK
///     keys its typed-exception comparison off. The openai/responses writers pair
///     `code: "invalid_api_key"` ONLY with `error.type: "authentication_error"` (see
///     `proto::openai_family::bearer_error_code`); the alternate `invalid_request_error` type maps
///     to `code: null`. We therefore pass `authentication_error` here so the wire body carries the
///     real `code: "invalid_api_key"` pairing — matching the modern OpenAI bad-key shape the writers
///     document — rather than the `code: null` tell.
///   - anthropic / cohere / unknown → HTTP 401 + "authentication_error": the standard
///     bad-credential shape for those vendors.
///
/// Not a disposition/breaker match, so an unknown future proto falls back to the Anthropic-family
/// 401 authentication_error, keeping the request path panic-free.
///
/// Thin wrapper: dispatches through `ProtocolWriter::auth_failure_status_and_kind` so the
/// per-protocol decision lives in the writer vtable, not in this agnostic function. `BedrockWriter`
/// overrides to (403, "auth"); `GeminiWriter` to (400, "invalid_request_error"); all others use the
/// default (401, "authentication_error"). An unknown future proto falls back to the default.
pub(crate) fn auth_failure_status_and_kind(proto: &str) -> (StatusCode, &'static str) {
    crate::proto::protocol_for(proto)
        .map(|p| p.writer().auth_failure_status_and_kind())
        .unwrap_or((StatusCode::UNAUTHORIZED, crate::proxy::KIND_AUTHENTICATION))
}

/// Build an auth-failure response carrying the inferred ingress protocol's NATIVE error envelope.
/// Auth runs before routing, so the protocol is inferred from the request path. A native vendor SDK
/// hitting busbar in `token`/governance mode with a bad credential gets the vendor's JSON error
/// shape (`application/json`) instead of a bare `text/plain` 401 — removing a deterministic proxy
/// tell. Falls back to the generic envelope for an unknown path.
///
/// The wire `message` comes from `vendor_auth_failure_message(proto)` — vendor-plausible copy keyed
/// solely off the inferred protocol — NOT from the call site. Callers must never thread a
/// busbar-internal reason ("invalid or disabled virtual key", "unauthorized", "admin unauthorized")
/// onto the wire: that vocabulary is a protocol tell and an auth-model disclosure, and the
/// invalid-vs-disabled / missing-vs-wrong distinction is itself an oracle. A caller may still log
/// the real reason server-side; it just never reaches the client body.
///
/// Status and the writer `kind` are protocol-shaped too (see `auth_failure_status_and_kind`): a real
/// AWS Bedrock SigV4 auth failure returns HTTP 403 (not 401) and carries `x-amzn-ErrorType` /
/// `x-amzn-RequestId`; a real Gemini bad-key returns HTTP 400 INVALID_ARGUMENT (not 401
/// UNAUTHENTICATED); the other vendors use 401 authentication_error. (Bedrock ingress is documented
/// as unsupported under token/governance mode, so that branch is only reachable under a
/// misconfiguration — but when it is reached, the envelope must still match native AWS.)
///
/// No unwrap / expect / panic on this request path: `ingress_error` degrades a serialization failure
/// to a generic JSON object internally.
///
/// The envelope is built by `crate::proxy::ingress_error`, the single source of truth for native
/// error shaping: it selects the protocol writer, sets `application/json`, and attaches the Bedrock
/// `x-amzn-RequestId` / `x-amzn-errortype` headers via the
/// `ProtocolWriter::attach_error_response_headers` vtable method. Using the shared builder means the
/// auth path, the forward path, and the route/fallback path CANNOT diverge on error shape or
/// headers. Bedrock's auth-failure modeled exception is `AccessDeniedException`;
/// `ingress_error`'s header attach derives the same `x-amzn-errortype` from the `kind` we pass
/// (`auth` → `AccessDeniedException`), so the wire body `__type` and the header agree.
fn unauthorized_response(path: &str) -> Response {
    let proto = proto_for_path(path);
    let message = vendor_auth_failure_message(proto);
    let (status, kind) = auth_failure_status_and_kind(proto);
    crate::proxy::ingress_error(proto, status, kind, message)
}

/// Extract the operator admin token from the `x-admin-token` header, treating a present-but-blank
/// value as ABSENT. This mirrors the empty-filter (`.filter(|t| !t.is_empty())`) that
/// `extract_client_token` applies to the `x-api-key` / `x-goog-api-key` carriers, closing the same
/// class of empty-credential bug on the admin carrier: a blank header never reaches the constant-time
/// compare below, so it cannot match even if a future change paired the configured admin token with
/// an empty string (the empty-token collision the `GovState` constructor guard in `governance.rs` is
/// separately meant to prevent — that guard is not owned here). `None` when the header is absent,
/// non-UTF-8, or blank.
fn extract_admin_header_token(req: &Request<Body>) -> Option<String> {
    req.headers()
        .get(X_ADMIN_TOKEN)
        .and_then(|v| v.to_str().ok())
        .filter(|t| !t.is_empty())
        .map(String::from)
}

/// Request-extension carrier for the authenticated [`Principal`]. ALWAYS inserted by the auth
/// middleware on admitted requests (`None` = the empty-chain anonymous front door), so downstream
/// consumers (audit attribution, the hook `send_user` projection, admin scopes) can extract it
/// without an is-it-there dance. Never carries the credential.
#[derive(Debug, Clone)]
pub(crate) struct AuthPrincipal(pub(crate) Option<Principal>);

/// The EFFECTIVE admin scope resolved by the admin middleware (group_map + module ceiling), attached
/// to admin-path requests so mutation handlers can apply body-derived authorization refinements the
/// route-level `required_scope` matrix cannot (design-admin-api-v1 §6.3). `None` = no admin grant
/// (the request would have been 403'd) OR the explicit open posture; a handler treats non-`Full` as
/// "restricted automation".
#[derive(Debug, Clone, Copy)]
pub(crate) struct AdminScope(pub(crate) Option<crate::admin::v1::contract::Scope>);

impl AuthPrincipal {
    /// The attribution handle for audit records: the principal id, or `anonymous` for the
    /// explicit open-front-door postures.
    pub(crate) fn actor_id(&self) -> &str {
        self.0
            .as_ref()
            .map(|p| p.id.as_str())
            .unwrap_or("anonymous")
    }
}

/// TEST-ONLY data-plane module (see the `test-groups-module` chain arm): credential `grp:<g>`
/// identifies as `test:<g>` carrying exactly that group; anything else defers (`Pass`).
#[cfg(test)]
struct TestGroupsModule;

#[cfg(test)]
impl AuthModule for TestGroupsModule {
    fn name(&self) -> &'static str {
        "test-groups-module"
    }
    fn authenticate(&self, candidate: Option<&str>) -> AuthOutcome {
        match candidate.and_then(|t| t.strip_prefix("grp:")) {
            Some(group) => {
                let mut p = Principal::from_id(format!("test:{group}"));
                p.groups = vec![group.to_string()];
                AuthOutcome::Identify(p)
            }
            None => AuthOutcome::Pass,
        }
    }
}

/// Execute the ADMIN auth chain (`admin_auth:`) over the extracted admin credential carriers.
/// Mirrors `AuthMiddleware::run_chain` (first Identify admits, Reject denies, all-Pass denies,
/// empty chain = the explicit open posture) but takes BOTH carriers — an admin credential
/// legitimately arrives as `Authorization: Bearer` or `X-Admin-Token`, and the constant-time
/// both-carriers fold lives inside the module. Unknown / compiled-out names are skipped with a
/// loud log (config_validate rejects them at boot).
// With admin-tokens compiled out (and outside test builds) no chain arm reads the carriers — the
// loop still runs for the unknown-name log + fail-closed deny, so the parameters stay.
#[cfg_attr(not(any(feature = "auth-admin-tokens", test)), allow(unused_variables))]
fn run_admin_chain(
    app: &crate::state::App,
    bearer: Option<&str>,
    header: Option<&str>,
) -> (ChainVerdict, Option<crate::admin::v1::contract::Scope>) {
    if app.admin_chain.is_empty() {
        return (ChainVerdict::Open, None);
    }
    // One composite credential string for the cache key: an admin credential legitimately rides
    // two carriers, and both participate in the identity of "what was presented".
    let composite = match (bearer, header) {
        (None, None) => None,
        (b, h) => Some(format!("b:{}\nh:{}", b.unwrap_or(""), h.unwrap_or(""))),
    };
    let now = crate::store::now();
    for name in &app.admin_chain {
        // The built-in admin-tokens module is in-process and NEVER cached (caching a microsecond
        // compare only widens the rotation window); external admin modules are the cache's case.
        let cacheable = name != "admin-tokens";
        if let Some(cred) = composite.as_deref().filter(|_| cacheable) {
            if let Some(outcome) = app.credential_cache.get(name, cred, now) {
                match outcome {
                    AuthOutcome::Identify(mut principal) => {
                        intersect_allowed_groups(app, name, &mut principal);
                        let cap = module_admin_scope_cap(app, name);
                        return (ChainVerdict::Identified(principal), cap);
                    }
                    AuthOutcome::Reject => return (ChainVerdict::Denied, None),
                    AuthOutcome::Pass => continue,
                }
            }
        }
        let outcome = match name.as_str() {
            #[cfg(feature = "auth-admin-tokens")]
            "admin-tokens" => busbar_auth_admin_tokens::authenticate_admin_tokens(
                app.governance.as_ref().and_then(|g| g.admin_token_hash()),
                bearer,
                header,
            ),
            // TEST-ONLY external-module stand-in: lets the e2e suite exercise group-mapped,
            // NON-full principals (unreachable with admin-tokens alone). Credential grammar:
            // `grp:<group>` identifies as a principal carrying exactly that group. Compiled out
            // of release binaries entirely.
            #[cfg(test)]
            "test-scope-module" => match bearer.or(header).and_then(|t| t.strip_prefix("grp:")) {
                Some(group) => {
                    let mut p = Principal::from_id(format!("test:{group}"));
                    p.groups = vec![group.to_string()];
                    AuthOutcome::Identify(p)
                }
                // Not my credential shape — defer to the next module (the PAM contract).
                None => AuthOutcome::Pass,
            },
            other => {
                tracing::error!(
                    module = other,
                    "admin_auth names an unknown/uncompiled module; skipping (config_validate \
                     rejects this at boot)"
                );
                AuthOutcome::Pass
            }
        };
        if let Some(cred) = composite.as_deref().filter(|_| cacheable) {
            app.credential_cache.put(name, cred, &outcome, now);
        }
        match outcome {
            AuthOutcome::Identify(mut principal) => {
                // TRUST-BOUNDARY CAPS (design-hooks-v2 §2.4), applied at the moment of identity:
                // intersect the module's asserted groups with its operator-owned `allowed_groups:`
                // allowlist BEFORE group_map resolution — a module cannot claim a group the
                // operator did not pre-authorize for it — and carry the module's admin-scope
                // ceiling out for the authorization step.
                intersect_allowed_groups(app, name, &mut principal);
                let cap = module_admin_scope_cap(app, name);
                return (ChainVerdict::Identified(principal), cap);
            }
            AuthOutcome::Reject => return (ChainVerdict::Denied, None),
            AuthOutcome::Pass => {}
        }
    }
    (ChainVerdict::Denied, None)
}

/// Intersect an identifying module's asserted `groups` with its configured `allowed_groups:`
/// allowlist (no cap configured = every group passes). Runs BEFORE `group_map:` — the ORDER is the
/// security property: a filtered-out group never reaches governance/scope resolution at all.
fn intersect_allowed_groups(app: &crate::state::App, module: &str, principal: &mut Principal) {
    if principal.groups.is_empty() {
        return;
    }
    if let Some(allowed) = app
        .auth_modules
        .get(module)
        .and_then(|c| c.allowed_groups.as_ref())
    {
        let before = principal.groups.len();
        principal.groups.retain(|g| allowed.contains(g));
        if principal.groups.len() < before {
            tracing::warn!(
                module,
                principal = %principal.id,
                dropped = before - principal.groups.len(),
                "auth module asserted groups outside its allowed_groups cap; dropped"
            );
        }
    }
}

/// The ADMIN-SCOPE CEILING for an identifying module (`max_admin_scope:`): the built-in
/// `admin-tokens` operator credential is exempt (full by definition — the root credential); every
/// other module is capped at its configured ceiling, DEFAULT `read-only` — `full` through an
/// external chain is an explicit opt-in (boot-warned in config_validate).
fn module_admin_scope_cap(
    app: &crate::state::App,
    module: &str,
) -> Option<crate::admin::v1::contract::Scope> {
    use crate::admin::v1::contract::Scope;
    if module == "admin-tokens" {
        return None;
    }
    Some(
        app.auth_modules
            .get(module)
            .and_then(|c| c.max_admin_scope.as_deref())
            .and_then(Scope::parse)
            .unwrap_or(Scope::ReadOnly),
    )
}

/// D4 DRY-RUN: evaluate what EFFECTIVE admin scope the presented carriers would earn under
/// `app`'s admin chain (chain verdict → group_map resolution → module ceiling), without serving
/// anything. `None` = denied / no grant. `PUT /api/v1/admin/auth` runs the CALLER through the
/// CANDIDATE chain with this before committing — a chain that would lock the caller out is
/// rejected instead of applied (D4 ruling; restart remains the backstop).
pub(crate) fn dry_run_admin_scope(
    app: &crate::state::App,
    bearer: Option<&str>,
    header: Option<&str>,
) -> Option<crate::admin::v1::contract::Scope> {
    let (verdict, cap) = run_admin_chain(app, bearer, header);
    let principal = match verdict {
        ChainVerdict::Identified(p) => Some(p),
        ChainVerdict::Open => None,
        ChainVerdict::Denied => return None,
    };
    let scope = admin_scope_for(principal.as_ref(), &app.group_map);
    match (scope, cap) {
        (Some(s), Some(c)) => Some(std::cmp::min(s, c)),
        (s, _) => s,
    }
}

/// Resolve a principal's ADMIN SCOPE — the authorization half, operator-owned by construction:
/// the built-in operator token (the `admin-tokens` principal) is FULL by definition (it is the
/// root credential); any other principal gets the most permissive `admin_scope` its groups map to
/// in `group_map:` (unmapped groups grant nothing — fail closed). `None` principal = the explicit
/// open admin posture (empty `admin_auth:`) — full, dev-only.
fn admin_scope_for(
    principal: Option<&Principal>,
    group_map: &std::collections::HashMap<String, crate::config::GroupMapEntry>,
) -> Option<crate::admin::v1::contract::Scope> {
    use crate::admin::v1::contract::Scope;
    let Some(p) = principal else {
        return Some(Scope::Full);
    };
    // The operator credential. Scope is MODULE-intrinsic, keyed off the fixed principal id the
    // admin-tokens module mints — an external module returning `id: "admin"` cannot reach here
    // with it, because group-carrying principals resolve THROUGH group_map below only when they
    // carry groups; a groupless external "admin" id would land Some(Full) — so the id is reserved:
    // config_validate forbids `group_map` entries that could shadow it, and external modules are
    // capped by `allowed_groups`/`max_admin_scope` when they land. Until external ADMIN modules
    // exist (none are compiled today), the only producer of a groupless principal on this path is
    // admin-tokens itself.
    if p.groups.is_empty() {
        #[cfg(feature = "auth-admin-tokens")]
        if p.id == busbar_auth_admin_tokens::ADMIN_TOKENS_PRINCIPAL_ID {
            return Some(Scope::Full);
        }
        return None;
    }
    p.groups
        .iter()
        .filter_map(|g| group_map.get(g))
        .filter_map(|e| e.admin_scope.as_deref())
        .filter_map(Scope::parse)
        .max()
}

/// A 403 in the frozen admin error envelope (`{"error":{"code":"forbidden","message":…}}`),
/// naming the scope that WOULD have sufficed — never any other principal's data.
/// A 401 in the frozen admin error envelope — no/invalid admin credential. The admin plane's
/// most-frequent error must carry the SAME `{error:{code,message}}` shape tooling branches on
/// (3rd-party audit #9); the data plane keeps vendor-native 401 shaping (`unauthorized_response`).
fn admin_unauthorized_response() -> Response {
    let e = crate::admin::v1::contract::AdminError::Unauthorized;
    let body = serde_json::json!({
        "error": { "code": e.code(), "message": e.message() }
    })
    .to_string();
    Response::builder()
        .status(StatusCode::UNAUTHORIZED)
        .header(axum::http::header::CONTENT_TYPE, "application/json")
        .body(Body::from(body))
        .expect("static unauthorized response")
}

fn forbidden_response(needed: crate::admin::v1::contract::Scope) -> Response {
    let body = serde_json::json!({
        "error": {
            "code": "forbidden",
            "message": format!(
                "this endpoint requires the `{}` admin scope",
                needed.as_str()
            ),
        }
    })
    .to_string();
    Response::builder()
        .status(StatusCode::FORBIDDEN)
        .header(axum::http::header::CONTENT_TYPE, "application/json")
        .body(Body::from(body))
        .expect("static forbidden response")
}

/// A 429 in the frozen admin error envelope — the per-principal mutation budget is spent. Carries
/// `Retry-After: 60` (the fixed window length): a compliant client backs off without guessing.
fn rate_limited_response() -> Response {
    let e = crate::admin::v1::contract::AdminError::RateLimited;
    let body = serde_json::json!({
        "error": { "code": e.code(), "message": e.message() }
    })
    .to_string();
    Response::builder()
        .header(
            axum::http::header::RETRY_AFTER,
            crate::admin::rate::MUTATION_RATE_WINDOW_SECS.to_string(),
        )
        .status(StatusCode::TOO_MANY_REQUESTS)
        .header(axum::http::header::CONTENT_TYPE, "application/json")
        .body(Body::from(body))
        .expect("static rate-limited response")
}

/// Fire the synthetic `rejected_by_auth` completion taps (fire-and-forget) and return the auth
/// denial — so audit taps see auth denials, not just served traffic (design-hooks-v2 §3.2). The
/// request body is unparsed at the auth stage, so the shape is the zeroed default bucket with the
/// path-inferred protocol. The tap's `status` MUST be the client-visible HTTP status, which is
/// PROTOCOL-NATIVE for an auth failure — 401 for anthropic/openai/responses/cohere, 403 for Bedrock
/// (SigV4 → AccessDenied), 400 for Gemini (INVALID_ARGUMENT). Hardcoding 401 made a tap watching a
/// gemini/bedrock ingress denial contradict the response the client actually got (found: audit c1r6).
fn unauthorized_with_completion_taps(app: &crate::state::App, path: &str) -> Response {
    let proto = proto_for_path(path);
    if !app.tap_hooks_completion.is_empty() {
        let shape = crate::proxy::capture_stage_shape(None, "", proto, false);
        let status = auth_failure_status_and_kind(proto).0.as_u16();
        crate::proxy::fire_stage_taps(
            &app.tap_hooks_completion,
            &shape,
            crate::hooks::wire::HookStageProjection {
                at: "completion",
                model: None,
                attempt_number: None,
                remaining_candidates: None,
                previous_failure: None,
                outcome: Some("rejected_by_auth"),
                status: Some(status),
            },
        );
    }
    unauthorized_response(path)
}

/// Axum middleware layer that validates auth before routing.
pub(crate) async fn auth_middleware(
    crate::state::CurrentApp(app): crate::state::CurrentApp,
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
    if path == HEALTHZ_PATH {
        return Ok(next.run(req).await);
    }

    // Derive owned values up front so no immutable borrow of `req` is live when we mutate its
    // extensions below.
    //
    // Admin detection must be path-boundary-safe: a bare `starts_with("/api")` also captures
    // sibling paths like `/apix/v1/messages`, which are NOT native-API routes. Such a path would be
    // sent down the admin auth branch and (with a valid admin token) early-return WITHOUT the
    // `CallerToken` extension a non-admin handler requires — yielding a 500 MissingExtension and
    // leaking that the path was treated as admin-protected. Require either the exact `/api` segment
    // or an `/api/` delimiter so only the native-API root (`/api/<version>/<area>/…`) matches.
    let is_admin = path == ADMIN_PATH || path.starts_with(ADMIN_PATH_PREFIX);
    let admin_header_token = extract_admin_header_token(&req);
    // The busbar client token, taken from whichever carrier the SDK used (Authorization: Bearer,
    // then x-api-key, then x-goog-api-key). This single value drives BOTH the static-allowlist
    // check and the governance virtual-key lookup, so every scheme is validated identically and in
    // constant time. Replaces the previous Bearer-only `bearer_token`.
    let client_token: Option<String> = AuthMiddleware::extract_client_token(&req);
    let chain_verdict = app
        .auth
        .run_chain_cached(client_token.as_deref(), Some(&app.credential_cache));
    let token_valid = !matches!(chain_verdict, ChainVerdict::Denied);

    // Thread the caller's token into request extensions for passthrough forwarding, using the same
    // multi-scheme carrier precedence as auth (Bearer / x-api-key / x-goog-api-key). Inserted BEFORE
    // any early-return below so EVERY request that reaches `next.run(req)` through this middleware
    // carries the extension — the `Extension<CallerToken>` extractor in handlers never sees it
    // absent (which would surface as a 500 MissingExtension). Always inserted (even when `None`).
    req.extensions_mut()
        .insert(CallerToken(client_token.clone()));

    // the /admin management API is gated by the ADMIN AUTH CHAIN (`admin_auth:`, default
    // `[admin-tokens]` — the single operator token, Bearer or X-Admin-Token) — NOT a virtual key,
    // and NOT the vendor-SDK carriers (admin is a busbar operator surface, not a native SDK
    // ingress). The chain authenticates (WHO); the principal's admin SCOPE then authorizes against
    // the endpoint's required scope (WHAT) — the §1 matrix, checked here at the one chokepoint
    // every /admin path crosses. Extract the admin Bearer separately so the multi-scheme
    // client-token carriers can't present an operator token via `x-api-key`/`x-goog-api-key`.
    if is_admin {
        let admin_bearer = req
            .headers()
            .get(AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .and_then(AuthMiddleware::extract_bearer_token);
        let (verdict, scope_cap) =
            run_admin_chain(&app, admin_bearer.as_deref(), admin_header_token.as_deref());
        let principal = match verdict {
            ChainVerdict::Identified(p) => Some(p),
            // The explicit `admin_auth: []` OPEN posture (dev): anonymous, full authority —
            // symmetric with the data plane's empty chain. The default config never lands here.
            ChainVerdict::Open => None,
            // The ADMIN plane 401 speaks the frozen v1 envelope ({error:{code:"unauthorized"}}) —
            // the most frequent error a tooling consumer hits (setup/rotation) must branch on the
            // SAME `code` seam as every other admin error, never a protocol-shaped body (the
            // vendor-native shaping below is for the DATA plane, whose SDKs must parse it).
            ChainVerdict::Denied => return Err(admin_unauthorized_response()),
        };
        // AUTHORIZATION: resolve the principal's admin scope (module-intrinsic for the operator
        // token; `group_map:` for group-carrying principals — most permissive wins, unmapped
        // groups grant nothing), CAPPED by the identifying module's `max_admin_scope:` ceiling,
        // and check it against the endpoint's required scope. An identified principal with NO
        // grant is 403, never 401 — authenticated but not authorized.
        let scope = admin_scope_for(principal.as_ref(), &app.group_map);
        let scope = match (scope, scope_cap) {
            (Some(s), Some(cap)) => Some(std::cmp::min(s, cap)),
            (s, _) => s,
        };
        let required = crate::admin::v1::contract::required_scope(req.method(), &path);
        match scope {
            Some(s) if s.allows(required) => {}
            _ => {
                // Denied authorization is AUDITED (§6.7: failures leave a trail — a credential
                // probing beyond its scope is exactly what an operator wants to see).
                crate::admin::audit::AUDIT.record_by(
                    "admin.forbidden",
                    &path,
                    crate::admin::audit::OUTCOME_REJECTED,
                    principal
                        .as_ref()
                        .map(|p| p.id.as_str())
                        .unwrap_or("anonymous"),
                );
                return Err(forbidden_response(required));
            }
        }
        // MUTATION RATE LIMITS (§6.6): per-principal fixed windows, spent BEFORE the handler so
        // FAILED attempts count too (anti-enumeration). Config-plane mutations (apply/rollback)
        // are the tight class; every other mutation is the CRUD class. Reads are unmetered.
        let method = req.method();
        let is_mutation = method == axum::http::Method::POST
            || method == axum::http::Method::PUT
            || method == axum::http::Method::PATCH
            || method == axum::http::Method::DELETE;
        if is_mutation {
            // The CONFIG class (10/min) is the blast-radius set: whole-config mutations AND the
            // admin auth chain itself (`PUT /admin-auth` — the L3 remount moved it off `/auth`).
            // Everything else that mutates (hooks, keys, cache flush) is the CRUD class (60/min).
            // Matched RELATIVE to the one contract prefix so this gate can never drift from the
            // mount grammar.
            let rel = path
                .strip_prefix(crate::admin::v1::contract::ADMIN_PREFIX)
                .unwrap_or(&path);
            // `/config/validate` is a stateless dry-run (read-only scope, no blast radius) — it
            // meters in the roomy CRUD class so a CI pipeline linting configs never contends with
            // the 10/min budget that guards real config mutations (re-audit M3).
            let class = if (rel.starts_with("/config/")
                && rel != crate::admin::v1::contract::PATH_CONFIG_VALIDATE)
                || rel == crate::admin::v1::contract::PATH_ADMIN_AUTH
            {
                crate::admin::rate::MutationClass::Config
            } else {
                crate::admin::rate::MutationClass::Crud
            };
            let actor = principal
                .as_ref()
                .map(|p| p.id.as_str())
                .unwrap_or("anonymous");
            if !app
                .mutation_limiter
                .check(actor, class, crate::store::now())
            {
                crate::admin::audit::AUDIT.record_by(
                    "admin.rate_limited",
                    &format!("{}:{path}", class.label()),
                    crate::admin::audit::OUTCOME_REJECTED,
                    actor,
                );
                return Err(rate_limited_response());
            }
        }
        req.extensions_mut().insert(AuthPrincipal(principal));
        // The EFFECTIVE admin scope (resolved + capped) is attached so mutation handlers can apply
        // the §6.3 body-derived refinements the route-level `required_scope` matrix cannot express —
        // e.g. a `hooks-register` principal may create a hook DEFINITION but must not register one
        // wired into a security-critical path (a `prompt: ro|rw` gate, or an inline `global: true`).
        req.extensions_mut().insert(AdminScope(scope));
        // INTENTIONAL governance bypass for the operator admin token. A successful admin auth attaches
        // an EMPTY `GovCtx::default()` (no resolved virtual key) and returns HERE — BEFORE the
        // virtual-key governance resolution below — so per-key controls (`allowed_pools`, budget, RPM/
        // TPM) are deliberately NOT applied to admin requests. This is by design, not an oversight:
        // the admin token is an operator-only credential, and the /admin routes expose ONLY
        // key-management (create / list / disable / usage), never inference. There is no per-key
        // budget or pool to enforce on a key-management call, and holding the admin token already
        // confers full authority over EVERY key by design, so subjecting it to a single key's
        // governance would be meaningless. Inference ingress (every non-/admin path) still falls
        // through to the governance resolution below and is fully governed.
        req.extensions_mut()
            .insert(crate::governance::GovCtx::default());
        return Ok(next.run(req).await);
    }

    // when governance is enabled, the caller's token MUST resolve to an enabled virtual key; the
    // resolved key is attached for downstream allowed-pools enforcement. This supersedes the static
    // Auth-chain token check. The token may arrive via any supported carrier (Bearer / x-api-key /
    // x-goog-api-key) — `client_token` already encodes that precedence. When governance is
    // disabled, the configured auth chain (empty = open, [tokens] = validated) applies unchanged.
    if let Some(gov) = &app.governance {
        // governance enabled + `upstream_credentials: passthrough` is a self-contradictory deployment: the
        // governance branch below requires every request to present a valid enabled busbar virtual
        // key (superseding passthrough's "accept any caller credential and forward it upstream"
        // intent), so a server an operator believes is in passthrough silently rejects every caller
        // that lacks a virtual key. There is no place in `validate(&RootCfg)` to catch this —
        // governance is read separately from the resolved config — so warn once here, at the first
        // request that exercises the combination, rather than letting it pass unremarked.
        if app.upstream_creds() == UpstreamCreds::Passthrough {
            static WARN_ONCE: std::sync::Once = std::sync::Once::new();
            WARN_ONCE.call_once(|| {
                tracing::warn!(
                    "upstream_credentials: passthrough with governance enabled: governance \
                     supersedes passthrough — every request must present a valid enabled virtual \
                     key, and passthrough's accept-and-forward-caller-credential semantics are NOT \
                     honoured. This combination is unsupported; use upstream_credentials: own (or \
                     omit it) alongside governance."
                );
            });
        }
        // Same class of silent contradiction for an empty `auth.chain` (open relay): the open front
        // door (the static path) admits every request unconditionally, but the governance branch below requires a
        // valid enabled virtual key on EVERY request, so a server an operator believes is open
        // silently rejects every caller without a key. `validate_governance` accepts the pairing (it
        // is a supported combination — governance simply wins), so there is no boot-time error;
        // mirror the passthrough advisory with a parallel one-shot warning at the first request that
        // exercises it, rather than leaving the override undiagnosed.
        if app.auth.is_open() && app.upstream_creds() == UpstreamCreds::Own {
            static WARN_ONCE: std::sync::Once = std::sync::Once::new();
            WARN_ONCE.call_once(|| {
                tracing::warn!(
                    "auth.chain is empty (open relay) with governance enabled: governance supersedes \
                     the open-relay mode — every request must present a valid enabled virtual key; \
                     the open front door's accept-every-request semantics are NOT honoured."
                );
            });
        }
        // Same class of silent override for `auth.chain: [tokens]` WITH a non-empty static client_tokens
        // allowlist: the governance branch resolves every request against the virtual-key store, so
        // the static allowlist is NEVER consulted — its configured entries have ZERO enforcement
        // effect (governance supersedes them, exactly as it supersedes passthrough/none above). An
        // operator who set `auth.chain: [tokens]` + `client_tokens: [...]` AND enabled governance in the
        // belief the static list still gates access is running a config that reads as doubly-secured
        // but whose static tokens are inert. `validate_governance` accepts the pairing (governance
        // simply wins), so there is no boot-time error; mirror the passthrough/none advisories with a
        // parallel one-shot warning at the first request that exercises it, rather than leaving the
        // inert allowlist undiagnosed.
        if !app.auth.is_open() && !app.auth.client_tokens.is_empty() {
            static WARN_ONCE: std::sync::Once = std::sync::Once::new();
            WARN_ONCE.call_once(|| {
                tracing::warn!(
                    "auth.chain with governance enabled: governance supersedes the static \
                     client_tokens allowlist — every request is resolved against the virtual-key \
                     store and the configured client_tokens entries have NO enforcement effect. \
                     Remove them, or disable governance, to avoid a misleading config."
                );
            });
        }
        // BEDROCK INGRESS via inbound AWS SigV4 (the MinIO/S3-compatible model). A Bedrock-SDK client
        // does NOT present a bearer-style token — it signs the request with an AWS-style
        // access-key-id + secret access key busbar issued (tied to a virtual key). When the request
        // targets the Bedrock ingress protocol AND carries an `AWS4-HMAC-SHA256` Authorization header,
        // VERIFY that signature and, on success, attach the SAME `GovCtx` a bearer auth would — so
        // budgets / RPM / TPM / allowed_pools all apply. This runs ONLY for a protocol that
        // authenticates ingress with SigV4 (Bedrock today) AND a request that actually carries the
        // `AWS4-HMAC-SHA256` header; every other request (bearer / x-api-key / x-goog-api-key, or a
        // non-SigV4 protocol) falls straight through to the unchanged token path below. On a
        // verification failure we return the native-vendor (Bedrock 403 AccessDenied) auth error —
        // never a bearer-style 401. The "which protocol uses SigV4" decision is a `ProtocolReader`
        // vtable predicate, NOT a `proto == "bedrock"` name-branch.
        let ingress_uses_sigv4 = crate::proto::protocol_for(proto_for_path(&path))
            .map(|p| p.reader().uses_sigv4_ingress_auth())
            .unwrap_or(false);
        if ingress_uses_sigv4 && has_sigv4_authorization(&req) {
            // BODY INTEGRITY: a SigV4 signature only binds the payload if we re-hash the actual bytes
            // and confirm they match the signed `x-amz-content-sha256` (which the signature covers).
            // Verifying the signature alone leaves a MitM free to tamper the body in transit while the
            // request still authenticates. Buffer the body HERE so the verifier can compare
            // `sha256_hex(body)` to the declared hash, then reconstruct the request from the SAME bytes
            // so the downstream handler receives the payload intact (no consumption bug). A buffering
            // failure (e.g. a truncated/aborted body) is itself a failed request — collapse it to the
            // same opaque auth error so it leaks nothing about why it failed.
            //
            // CAP the buffer at the SAME knob (`limits.request_body_max_bytes`) that drives the inbound
            // `DefaultBodyLimit` layer, rather than `usize::MAX`. This auth middleware runs BEFORE
            // authentication is confirmed and the SigV4 branch is reachable from attacker-controlled
            // headers alone (a fabricated AccessKeyId still reaches here), so relying on the body-limit
            // layer being present and ordered ahead of us is a stack assumption, not enforcement. An
            // in-code cap means a never-terminating / oversized body cannot exhaust the heap even if
            // the layer is absent or misconfigured (defense-in-depth).
            let (parts, body) = req.into_parts();
            let Ok(body_bytes) =
                axum::body::to_bytes(body, crate::limits::translate_body_max_bytes()).await
            else {
                return Err(unauthorized_response(&path));
            };
            let mut req = Request::from_parts(parts, Body::from(body_bytes.clone()));
            return match verify_bedrock_sigv4(gov, &req, &body_bytes) {
                Ok(key) => {
                    req.extensions_mut()
                        .insert(crate::governance::GovCtx { key: Some(key) });
                    Ok(next.run(req).await)
                }
                // EVERY failure (missing/malformed header, unknown AccessKeyId, expired date,
                // signed-headers mismatch, bad signature, OR a body whose bytes don't match the signed
                // x-amz-content-sha256) maps to the identical native auth error — the distinction is
                // logged inside the verifier, never surfaced, so there is no oracle.
                Err(()) => Err(unauthorized_response(&path)),
            };
        }

        // Reject a missing / empty token BEFORE the governance lookup, mirroring the
        // `validate_token` guard that the static-token path applies. Without this, an
        // unauthenticated request would call `gov.lookup(sha256(""))` — admitting the caller if any
        // virtual key in the store ever hashed an empty secret (reachable via direct DB writes or a
        // future seeding path that bypasses `generate_secret`). Making the empty-token reject
        // explicit removes that latent hash-collision dependency rather than relying on the absence
        // of a `sha256("")` entry in the key store.
        let Some(client_token) = client_token.as_deref().filter(|t| !t.is_empty()) else {
            return Err(unauthorized_with_completion_taps(&app, &path));
        };
        match gov.lookup(client_token) {
            Some(key) if key.enabled => {
                // The governance principal: id = the virtual-key id (stable), name = its label.
                req.extensions_mut().insert(AuthPrincipal(Some(Principal {
                    id: key.id.clone(),
                    name: Some(key.name.clone()),
                    groups: Vec::new(),
                    ttl_secs: None,
                })));
                req.extensions_mut()
                    .insert(crate::governance::GovCtx { key: Some(key) });
            }
            // Not a virtual key (or disabled). THE GOVERNANCE RE-KEY (§2.3): if the auth chain
            // identified a GROUP-carrying principal whose groups earn a data-plane grant in
            // `group_map:`, admit it with a SYNTHESIZED key — governance enforcement (pool ACL,
            // RPM/TPM, budget, usage) keyed by the principal id, identical to a virtual key.
            // Groups that map to nothing grant nothing (fail closed): reject as before.
            Some(_) | None => {
                let synth = match &chain_verdict {
                    ChainVerdict::Identified(p) if !p.groups.is_empty() => {
                        crate::governance::synthesize_principal_key(p, &app.group_map)
                    }
                    _ => None,
                };
                match (synth, chain_verdict) {
                    (Some(key), ChainVerdict::Identified(p)) => {
                        req.extensions_mut().insert(AuthPrincipal(Some(p)));
                        req.extensions_mut()
                            .insert(crate::governance::GovCtx { key: Some(key) });
                    }
                    _ => return Err(unauthorized_with_completion_taps(&app, &path)),
                }
            }
        }
    } else {
        // Governance disabled: enforce the static-allowlist token check on every non-admin path.
        if !token_valid {
            return Err(unauthorized_with_completion_taps(&app, &path));
        }
        // Attach WHO was identified: the chain's principal, or `None` for the empty-chain
        // anonymous front door. A GROUP principal additionally carries its `group_map:` grants as
        // a synthesized key even with governance off — the pool ACL still applies; the rate/budget
        // axes need the governance store and stay off with it. A group principal whose groups earn
        // no grant keeps `key: None` (the chain admitted it; group_map only ADDS enforcement here).
        let principal = match chain_verdict {
            ChainVerdict::Identified(p) => Some(p),
            ChainVerdict::Open | ChainVerdict::Denied => None,
        };
        let synth = principal
            .as_ref()
            .filter(|p| !p.groups.is_empty())
            .and_then(|p| crate::governance::synthesize_principal_key(p, &app.group_map));
        req.extensions_mut().insert(AuthPrincipal(principal));
        req.extensions_mut()
            .insert(crate::governance::GovCtx { key: synth });
    }

    Ok(next.run(req).await)
}

/// Does the request carry an inbound AWS SigV4 `Authorization` header (`AWS4-HMAC-SHA256 ...`)? Cheap
/// pre-check so the SigV4 verify path is entered ONLY for genuine SigV4 requests; everything else
/// (bearer, x-api-key, x-goog-api-key, or no Authorization) takes the unchanged token path. The full
/// structural parse/validation happens inside the verifier — this only gates entry.
fn has_sigv4_authorization(req: &Request<Body>) -> bool {
    req.headers()
        .get(AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .map(|v| v.trim_start().starts_with(SIGV4_ALGORITHM))
        .unwrap_or(false)
}

/// Canonicalize the request query string for SigV4: split into key=value pairs, URI-encode each key
/// and value (RFC 3986 unreserved pass through), sort by encoded key (then encoded value), and join
/// with `&`. An empty/absent query yields `""`. A bare key (`?foo`) canonicalizes to `foo=` (AWS
/// signs a missing value as empty). This must match what the client's signer produced. Bedrock
/// Converse requests normally carry no query, but canonicalizing correctly keeps the verifier general.
fn canonical_query_string(query: Option<&str>) -> String {
    let Some(q) = query.filter(|q| !q.is_empty()) else {
        return String::new();
    };
    let mut pairs: Vec<(String, String)> = q
        .split('&')
        .filter(|p| !p.is_empty())
        .map(|pair| {
            let (k, v) = pair.split_once('=').unwrap_or((pair, ""));
            (
                crate::sigv4::uri_encode_query(k),
                crate::sigv4::uri_encode_query(v),
            )
        })
        .collect();
    pairs.sort();
    pairs
        .into_iter()
        .map(|(k, v)| format!("{k}={v}"))
        .collect::<Vec<_>>()
        .join("&")
}

/// Verify an inbound Bedrock SigV4 request against the governance virtual-key store. On success
/// returns the resolved, ENABLED `VirtualKey` (so the caller attaches its `GovCtx`); on ANY failure
/// returns `Err(())` — the SINGLE opaque failure the caller maps to the native auth error, with no
/// distinction reaching the wire (the specific `VerifyError` is logged here for operators only).
///
/// Indistinguishability / no enumeration oracle: an UNKNOWN AccessKeyId does NOT short-circuit. We
/// still run the full constant-time signature verification against a fixed DUMMY secret, so the
/// unknown-key path and the wrong-signature path do the same work and reject identically. A DISABLED
/// key likewise still verifies before rejecting, so "disabled" is not distinguishable from "bad sig".
fn verify_bedrock_sigv4(
    gov: &crate::governance::GovState,
    req: &Request<Body>,
    body: &[u8],
) -> Result<crate::governance::VirtualKey, ()> {
    use crate::sigv4::{parse_authorization_header, verify_inbound_sigv4, InboundRequest};

    // Parse the Authorization header. (has_sigv4_authorization already confirmed the algorithm token,
    // but re-parse fully here — a malformed-but-AWS4-prefixed header still rejects.)
    let auth_value = req
        .headers()
        .get(AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    let parsed = match parse_authorization_header(auth_value) {
        Ok(p) => p,
        Err(e) => {
            tracing::debug!(reason = ?e, "inbound SigV4 rejected: unparseable Authorization");
            return Err(());
        }
    };

    // Gather the signed-header VALUES from the request (every name the client listed in SignedHeaders;
    // the verifier rejects if any is missing). Lowercase the names to match the signer.
    //
    // PREFILTER: `verify_inbound_sigv4` consumes ONLY the headers named in `SignedHeaders` (plus the
    // payload-hash and amzdate it reads from struct fields, both of which are themselves signed
    // headers). Lowercasing + allocating EVERY inbound header — many of them irrelevant — is wasted
    // work on every request. Restrict to the signed subset BEFORE allocating, matching names
    // case-insensitively against the signer's list. Semantics are unchanged: the verifier's signed-set
    // selection (step 3) sees exactly the same {name→value} mapping it would have found in the full
    // list; an unsigned `x-amz-content-sha256`/`x-amz-date` would not have been bound by the signature
    // anyway, so omitting it here is the same fail-closed outcome the verifier already produces.
    let signed_names: std::collections::HashSet<String> = parsed
        .signed_headers
        .split(';')
        .map(|h| h.trim().to_ascii_lowercase())
        .filter(|h| !h.is_empty())
        .collect();
    let headers: Vec<(String, String)> = req
        .headers()
        .iter()
        .filter_map(|(name, value)| {
            let lname = name.as_str().to_ascii_lowercase();
            if !signed_names.contains(&lname) {
                return None;
            }
            value.to_str().ok().map(|v| (lname, v.to_string()))
        })
        .collect();

    // The payload hash the client signed is its `x-amz-content-sha256` header value. We verify the
    // signature against that DECLARED hash (it is itself a signed header, so the signature binds it).
    // A request that omits the header cannot have signed it, so reject — there is nothing to feed the
    // canonical request.
    let Some(payload_hash) = headers
        .iter()
        .find(|(k, _)| k == X_AMZ_CONTENT_SHA256)
        .map(|(_, v)| v.clone())
    else {
        tracing::debug!("inbound SigV4 rejected: missing x-amz-content-sha256");
        return Err(());
    };

    // BODY INTEGRITY (the real bind): the signature only proves the client signed `payload_hash`; it
    // does NOT prove the bytes we actually received hash to that value. Without this check a MitM who
    // cannot forge the signature can still tamper the body in transit and the request authenticates —
    // the signature stops binding the payload. Re-hash the buffered body and require it to equal the
    // signed declared hash (lowercase-hex, constant-time compare to avoid leaking a prefix-match
    // length via timing). `UNSIGNED-PAYLOAD` is the AWS sentinel for "I did not hash my body"; for
    // this governed ingress we REQUIRE a signed payload, so reject it outright (it can never equal a
    // real sha256 digest anyway — the explicit reject documents the decision and avoids a future
    // signer that hashes the literal string "UNSIGNED-PAYLOAD" sneaking past). On ANY mismatch reject
    // with the SAME opaque `Err(())` every other failure returns — the reason is logged here only, so
    // the wire cannot tell "body tampered" from "bad signature".
    const UNSIGNED_PAYLOAD: &str = "UNSIGNED-PAYLOAD";
    if payload_hash.eq_ignore_ascii_case(UNSIGNED_PAYLOAD) {
        tracing::debug!(
            "inbound SigV4 rejected: UNSIGNED-PAYLOAD not permitted for governed ingress"
        );
        return Err(());
    }
    let actual_body_hash = crate::sigv4::sha256_hex(body);
    if !AuthMiddleware::constant_time_eq(&actual_body_hash, &payload_hash.to_ascii_lowercase()) {
        tracing::debug!(
            "inbound SigV4 rejected: request body does not match signed x-amz-content-sha256"
        );
        return Err(());
    };
    let Some(amzdate) = headers
        .iter()
        .find(|(k, _)| k == X_AMZ_DATE)
        .map(|(_, v)| v.clone())
    else {
        tracing::debug!("inbound SigV4 rejected: missing x-amz-date");
        return Err(());
    };

    let canonical_uri = crate::sigv4::uri_encode_path(req.uri().path());
    let canonical_qs = canonical_query_string(req.uri().query());
    let method = req.method().as_str().to_string();

    let inbound = InboundRequest {
        method: &method,
        canonical_uri: &canonical_uri,
        canonical_querystring: &canonical_qs,
        headers: &headers,
        payload_hash: &payload_hash,
        amzdate: &amzdate,
    };

    // Resolve the AccessKeyId to (key, secret). On an UNKNOWN AccessKeyId, verify against a fixed dummy
    // secret so the work — and the timing/response — is indistinguishable from a wrong-signature
    // rejection (no AccessKeyId-enumeration oracle). The dummy is a constant, never a real secret.
    let now = crate::store::now();
    let (secret, resolved): (String, Option<crate::governance::VirtualKey>) =
        match gov.lookup_by_access_key_id(&parsed.access_key_id) {
            Some(entry) => (entry.secret_access_key, Some(entry.key)),
            None => (DUMMY_SECRET.to_string(), None),
        };

    let verify = verify_inbound_sigv4(&parsed, &inbound, &secret, now);

    // Decide admission. The signature must verify; the resolved key must exist AND be enabled. All
    // three conditions are evaluated, and only the combined success admits — a failure in any one
    // rejects with the same opaque `Err(())`. An unknown AccessKeyId has `resolved == None`, so even a
    // (cryptographically impossible) signature match against the dummy secret cannot admit.
    match (verify, resolved) {
        (Ok(()), Some(key)) if key.enabled => Ok(key),
        (Ok(()), Some(_key)) => {
            tracing::debug!("inbound SigV4 rejected: virtual key disabled");
            Err(())
        }
        (Ok(()), None) => {
            // Signature "verified" against the dummy secret but the AccessKeyId is unknown — this is
            // not reachable for a real signer (it would need to have signed with the dummy secret) but
            // is handled explicitly so an unknown key can NEVER authenticate.
            tracing::debug!("inbound SigV4 rejected: unknown access key id");
            Err(())
        }
        (Err(e), _) => {
            tracing::debug!(reason = ?e, "inbound SigV4 rejected");
            Err(())
        }
    }
}

#[cfg(test)]
#[path = "tests/tests.rs"]
mod tests;
