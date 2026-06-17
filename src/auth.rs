// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Matthew Jackson

use std::fmt;
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

    /// The canonical config/wire spelling of this mode — the exact inverse of `from_config_str`
    /// (`from_config_str(m.as_config_str()) == Some(m)` for every variant). Lets callers build an
    /// `AuthCfg` from a mode without hardcoding the strings. Currently only the test harness needs it
    /// (to build a mode-carrying `AuthMiddleware`); gated `#[cfg(test)]` so it isn't dead in release.
    #[cfg(test)]
    pub(crate) fn as_config_str(self) -> &'static str {
        match self {
            AuthMode::Token => Self::TOKEN,
            AuthMode::Passthrough => Self::PASSTHROUGH,
            AuthMode::None => Self::NONE,
        }
    }
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

/// AuthMiddleware holds the resolved auth mode and token allowlist.
pub(crate) struct AuthMiddleware {
    pub(crate) mode: AuthMode,
    pub(crate) client_tokens: Vec<String>,
}

// MANUAL Debug that REDACTS the allowlist. A derived `Debug` would print every entry of
// `client_tokens` in PLAINTEXT — a latent credential leak if an `AuthMiddleware` (or any struct that
// holds one, e.g. `App`) is ever debug-logged. Print only the COUNT of configured tokens, never the
// values (and never any prefix/suffix, which would be a partial-secret oracle).
impl fmt::Debug for AuthMiddleware {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AuthMiddleware")
            .field("mode", &self.mode)
            .field(
                "client_tokens",
                &format_args!("<redacted; {} configured>", self.client_tokens.len()),
            )
            .finish()
    }
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

        if mode == AuthMode::None {
            if tokens.is_empty() {
                tracing::warn!(
                    "auth.mode=none (open relay) — only acceptable for dev; reject in production"
                );
            } else {
                // `validate_token` admits unconditionally in None mode (see below), so a configured
                // `client_tokens` allowlist has ZERO enforcement effect here. An operator who set
                // BOTH `mode: none` and a `client_tokens` list in the belief the list constrains
                // access is running an unrestricted open relay while their config reads as secured.
                // Warn loudly that the listed tokens are inert (mirrored at boot in
                // `config_validate::validate`, which can see the config before this runs).
                tracing::warn!(
                    "auth.mode=none ignores the configured client_tokens ({} listed): None mode is \
                     an open relay and admits every request regardless of token. The allowlist has \
                     no effect — set auth.mode=token to enforce it.",
                    tokens.len()
                );
            }
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
    pub(crate) fn constant_time_eq(a: &str, b: &str) -> bool {
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
///     `proto::bearer_error_code`); the alternate `invalid_request_error` type maps
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
        .unwrap_or((StatusCode::UNAUTHORIZED, "authentication_error"))
}

/// Build an auth-failure response carrying the inferred ingress protocol's NATIVE error envelope
/// (design §8 BLOCKER #1). Auth runs before routing, so the protocol is inferred from the request
/// path. A native vendor SDK hitting busbar in `token`/governance mode with a bad credential then
/// gets the vendor's JSON error shape (`application/json`) instead of a bare `text/plain` 401 —
/// removing a deterministic proxy tell. Falls back to the generic envelope for an unknown path.
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
/// The envelope is built by the CANONICAL `crate::forward::ingress_error` (CORE made it
/// `pub(crate)`), the single source of truth for native error shaping: it selects the protocol
/// writer, sets `application/json`, and attaches the Bedrock `x-amzn-RequestId` / `x-amzn-errortype`
/// headers via the shared `proto::attach_bedrock_error_headers` helper. Migrating here means the
/// auth path, the forward path, and the route/fallback path CANNOT diverge on error shape or headers
/// — converging the three error builders the design called out. Bedrock's auth-failure modeled
/// exception is `AccessDeniedException`; `ingress_error`'s header attach derives the same
/// `x-amzn-errortype` from the `kind` we pass (`auth` → `AccessDeniedException`), so the wire body
/// `__type` and the header agree.
fn unauthorized_response(path: &str) -> Response {
    let proto = proto_for_path(path);
    let message = vendor_auth_failure_message(proto);
    let (status, kind) = auth_failure_status_and_kind(proto);
    crate::forward::ingress_error(proto, status, kind, message)
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
        .get("x-admin-token")
        .and_then(|v| v.to_str().ok())
        .filter(|t| !t.is_empty())
        .map(String::from)
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
    //
    // Admin detection must be path-boundary-safe: a bare `starts_with("/admin")` also captures
    // sibling paths like `/adminx/v1/messages` or `/admin_portal`, which are NOT registered admin
    // routes. Such a path would be sent down the admin auth branch and (with a valid admin token)
    // early-return WITHOUT the `CallerToken` extension a non-admin handler requires — yielding a
    // 500 MissingExtension and leaking that the path was treated as admin-protected. Require either
    // the exact `/admin` segment or a `/admin/` delimiter so only the four registered admin routes
    // (`/admin/keys`, `/admin/keys/:id`, `/admin/keys/:id/usage`) match.
    let is_admin = path == "/admin" || path.starts_with("/admin/");
    let admin_header_token = extract_admin_header_token(&req);
    // The busbar client token, taken from whichever carrier the SDK used (Authorization: Bearer,
    // then x-api-key, then x-goog-api-key). This single value drives BOTH the static-allowlist
    // check and the governance virtual-key lookup, so every scheme is validated identically and in
    // constant time. Replaces the previous Bearer-only `bearer_token`.
    let client_token: Option<String> = AuthMiddleware::extract_client_token(&req);
    let token_valid = app.auth.validate_token(client_token.as_deref());

    // Thread the caller's token into request extensions for passthrough forwarding, using the same
    // multi-scheme carrier precedence as auth (Bearer / x-api-key / x-goog-api-key). Inserted BEFORE
    // any early-return below so EVERY request that reaches `next.run(req)` through this middleware
    // carries the extension — the `Extension<CallerToken>` extractor in handlers never sees it
    // absent (which would surface as a 500 MissingExtension). Always inserted (even when `None`).
    req.extensions_mut()
        .insert(CallerToken(client_token.clone()));

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
            // side channel. BOTH carrier comparisons run UNCONDITIONALLY and are combined with a
            // bitwise-OR fold (`|`, NOT `||`): a `||` short-circuits, so a request presenting BOTH a
            // Bearer and an x-admin-token would skip the header compare whenever the Bearer matched —
            // a carrier-level timing observable distinguishing "Bearer matched" (one compare) from
            // "Bearer missed, fell through to header" (two compares), leaking one bit of oracle about
            // the Bearer value. Mirror the client-token allowlist fold: compute each compare into a
            // `u8`, OR them, and `black_box` the result so the optimizer can't reintroduce an early
            // exit. A missing carrier contributes 0 (no compare to a secret leaks via its absence).
            Some(t) => {
                // Length-independent compare: `constant_time_eq` early-returns on a length mismatch,
                // which leaks the admin token's LENGTH via timing (a candidate of the right length runs
                // the full byte loop; a wrong-length one returns immediately). Remove that oracle by
                // hashing BOTH the presented candidate and the configured token with SHA-256 (the same
                // `sha256_hex` facility used for virtual keys) and constant-time-comparing the
                // fixed-length (64-hex-char) digests — every candidate now does identical work
                // regardless of its length. A missing carrier contributes 0 (no compare against a
                // secret-derived digest, so its absence leaks nothing). The compares run
                // UNCONDITIONALLY and fold with bitwise-OR (see the no-short-circuit rationale above).
                let configured_hash = crate::sigv4::sha256_hex(t.as_bytes());
                let bearer_match = u8::from(
                    admin_bearer
                        .as_deref()
                        .map(|b| {
                            AuthMiddleware::constant_time_eq(
                                &crate::sigv4::sha256_hex(b.as_bytes()),
                                &configured_hash,
                            )
                        })
                        .unwrap_or(false),
                );
                let header_match = u8::from(
                    admin_header_token
                        .as_deref()
                        .map(|h| {
                            AuthMiddleware::constant_time_eq(
                                &crate::sigv4::sha256_hex(h.as_bytes()),
                                &configured_hash,
                            )
                        })
                        .unwrap_or(false),
                );
                std::hint::black_box(bearer_match | header_match) != 0
            }
            None => false,
        };
        if !authorized {
            return Err(unauthorized_response(&path));
        }
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
    // AuthMode token check. The token may arrive via any supported carrier (Bearer / x-api-key /
    // x-goog-api-key) — `client_token` already encodes that precedence. When governance is
    // disabled, the existing AuthMode (None/Token/Passthrough) applies unchanged.
    if let Some(gov) = &app.governance {
        // governance enabled + `auth.mode: passthrough` is a self-contradictory deployment: the
        // governance branch below requires every request to present a valid enabled busbar virtual
        // key (superseding passthrough's "accept any caller credential and forward it upstream"
        // intent), so a server an operator believes is in passthrough silently rejects every caller
        // that lacks a virtual key. There is no place in `validate(&RootCfg)` to catch this —
        // governance is read separately from the resolved config — so warn once here, at the first
        // request that exercises the combination, rather than letting it pass unremarked.
        if app.auth_mode() == AuthMode::Passthrough {
            static WARN_ONCE: std::sync::Once = std::sync::Once::new();
            WARN_ONCE.call_once(|| {
                tracing::warn!(
                    "auth.mode=passthrough with governance enabled: governance supersedes \
                     passthrough — every request must present a valid enabled virtual key, and \
                     passthrough's accept-and-forward-caller-credential semantics are NOT honoured. \
                     This combination is unsupported; configure auth.mode=token (or omit auth) \
                     alongside governance."
                );
            });
        }
        // Same class of silent contradiction for `auth.mode=none`: none is an open relay (the static
        // path admits every request unconditionally), but the governance branch below requires a
        // valid enabled virtual key on EVERY request, so a server an operator believes is open
        // silently rejects every caller without a key. `validate_governance` accepts the pairing (it
        // is a supported combination — governance simply wins), so there is no boot-time error;
        // mirror the passthrough advisory with a parallel one-shot warning at the first request that
        // exercises it, rather than leaving the override undiagnosed.
        if app.auth_mode() == AuthMode::None {
            static WARN_ONCE: std::sync::Once = std::sync::Once::new();
            WARN_ONCE.call_once(|| {
                tracing::warn!(
                    "auth.mode=none with governance enabled: governance supersedes the open-relay \
                     mode — every request must present a valid enabled virtual key; none mode's \
                     accept-every-request semantics are NOT honoured."
                );
            });
        }
        // Same class of silent override for `auth.mode=token` WITH a non-empty static client_tokens
        // allowlist: the governance branch resolves every request against the virtual-key store, so
        // the static allowlist is NEVER consulted — its configured entries have ZERO enforcement
        // effect (governance supersedes them, exactly as it supersedes passthrough/none above). An
        // operator who set `auth.mode=token` + `client_tokens: [...]` AND enabled governance in the
        // belief the static list still gates access is running a config that reads as doubly-secured
        // but whose static tokens are inert. `validate_governance` accepts the pairing (governance
        // simply wins), so there is no boot-time error; mirror the passthrough/none advisories with a
        // parallel one-shot warning at the first request that exercises it, rather than leaving the
        // inert allowlist undiagnosed.
        if app.auth_mode() == AuthMode::Token && !app.auth.client_tokens.is_empty() {
            static WARN_ONCE: std::sync::Once = std::sync::Once::new();
            WARN_ONCE.call_once(|| {
                tracing::warn!(
                    "auth.mode=token with governance enabled: governance supersedes the static \
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
            // request still authenticates. Buffer the body HERE (Bedrock ingress is bounded JSON; the
            // 32 MiB `DefaultBodyLimit` layer already caps it, so `to_bytes(usize::MAX)` cannot be used
            // to exhaust memory) so the verifier can compare `sha256_hex(body)` to the declared hash,
            // then reconstruct the request from the SAME bytes so the downstream handler receives the
            // payload intact (no consumption bug). A buffering failure (e.g. a truncated/aborted body)
            // is itself a failed request — collapse it to the same opaque auth error so it leaks
            // nothing about why it failed.
            let (parts, body) = req.into_parts();
            let Ok(body_bytes) = axum::body::to_bytes(body, usize::MAX).await else {
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
            return Err(unauthorized_response(&path));
        };
        match gov.lookup(client_token) {
            Some(key) if key.enabled => {
                req.extensions_mut()
                    .insert(crate::governance::GovCtx { key: Some(key) });
            }
            // A resolved-but-disabled key and a no-such-key both reject. Spelled out (no `_ =>`
            // catch-all) so a future `GovKey` field or lookup outcome can't silently fall through.
            Some(_) | None => return Err(unauthorized_response(&path)),
        }
    } else {
        // /stats requires auth by default (per spec decision).
        if !token_valid {
            return Err(unauthorized_response(&path));
        }
        req.extensions_mut()
            .insert(crate::governance::GovCtx::default());
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
        .map(|v| v.trim_start().starts_with("AWS4-HMAC-SHA256"))
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
        .find(|(k, _)| k == "x-amz-content-sha256")
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
        .find(|(k, _)| k == "x-amz-date")
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
    const DUMMY_SECRET: &str = "AWS4-DUMMY-SECRET-FOR-CONSTANT-TIME-REJECT-PATH";
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
#[allow(deprecated)] // allow deprecated field access in tests
mod tests {
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
        // `crate::proto::synth_amzn_request_id` (via `forward::ingress_error` →
        // `attach_bedrock_error_headers`), not a private copy — assert the canonical fn's shape so the
        // bedrock auth-failure header contract stays covered. Two consecutive ids must differ
        // (entropy-sourced, not a predictable timestamp||counter).
        let a =
            crate::proto::synth_amzn_request_id().expect("entropy must be available under test");
        let b =
            crate::proto::synth_amzn_request_id().expect("entropy must be available under test");
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
    fn test_auth_mode_none_with_client_tokens_is_inert_open_relay() {
        // Regression (MEDIUM/correctness): `mode: none` together with a non-empty client_tokens list
        // is an open relay — the listed tokens have ZERO enforcement effect. The constructor must not
        // panic, must preserve the configured tokens, and `validate_token` must still admit EVERY
        // request (including a token NOT in the list, and no token at all), proving the allowlist is
        // inert. (A startup warning is emitted but is not asserted here — behaviour is the contract.)
        let cfg = AuthCfg {
            mode: "none".to_string(),
            client_tokens: vec!["listed-but-ignored".to_string()],
            _legacy_token: None,
        };
        let mw = AuthMiddleware::new(&cfg);
        assert_eq!(mw.client_tokens, vec!["listed-but-ignored".to_string()]);
        // Open relay: a token NOT on the list is admitted (the list does not constrain access).
        assert!(mw.validate_token(Some("some-other-token")));
        // And so is no token at all.
        assert!(mw.validate_token(None));
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
            "/admin/keys",                      // admin path → inferred-proto fallback (openai)
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
            "API key not valid. Please pass a valid API key."
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
            // BOTH Gemini ingress prefixes the router registers (main.rs:700-701) must resolve to a
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
            mode: "token".to_string(),
            client_tokens: vec!["the-real-token".to_string()],
            _legacy_token: None,
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
        let body =
            json!({"model": "pa", "messages": [{"role": "user", "content": "hi"}]}).to_string();

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
            mode: "token".to_string(),
            client_tokens: vec!["the-real-token".to_string()],
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
    #[tokio::test]
    async fn test_gemini_ingress_wrong_token_is_native_bad_key_envelope() {
        use crate::test_support::{LaneSpec, MockServer, MockServerState, TestApp};
        use serde_json::json;
        use std::sync::Arc;

        crate::metrics::init();

        let state = Arc::new(MockServerState::new());
        let server = MockServer::new(state).await;

        let auth_cfg = crate::config::AuthCfg {
            mode: "token".to_string(),
            client_tokens: vec!["the-real-token".to_string()],
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
    /// bytes `/admin` but is not a registered `/admin/...` route (e.g. `/adminx/...`) must NOT be
    /// classified as admin. Under TOKEN mode with a wrong token it should be rejected by the normal
    /// auth branch with the inferred-protocol native 401 envelope — never routed down the admin
    /// branch (which would early-return without the `CallerToken` extension and 500 in a non-admin
    /// handler). `/adminx/v1/messages` infers the anthropic protocol via the `/v1/messages` suffix.
    #[tokio::test]
    async fn test_admin_prefix_is_boundary_safe() {
        use crate::test_support::{LaneSpec, MockServer, MockServerState, TestApp};
        use serde_json::json;
        use std::sync::Arc;

        crate::metrics::init();

        let state = Arc::new(MockServerState::new());
        let server = MockServer::new(state).await;

        let auth_cfg = crate::config::AuthCfg {
            mode: "token".to_string(),
            client_tokens: vec!["the-real-token".to_string()],
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
            .pool("adminx", &[(0, 1)])
            .auth(Arc::new(AuthMiddleware::new(&auth_cfg)))
            .build();

        let router = crate::build_router(app);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let handle = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
        let client = reqwest::Client::new();
        let body = json!({"model": "adminx", "messages": [{"role": "user", "content": "hi"}], "max_tokens": 16})
            .to_string();

        // Wrong token to `/adminx/v1/messages`: rejected by the NORMAL auth branch, not the admin
        // branch — a normal-protocol native 401 (anthropic), NOT the admin "admin unauthorized"
        // path and NOT a 500 from a missing CallerToken extension.
        let r = client
            .post(format!("http://{addr}/adminx/v1/messages"))
            .header("x-api-key", "wrong-token")
            .body(body)
            .send()
            .await
            .unwrap();
        assert_eq!(
            r.status().as_u16(),
            401,
            "an /adminx path with a wrong token must be a normal 401, not 500/admin-500 (got {})",
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
        use crate::governance::{GovState, SqliteStore, Store, VirtualKey};
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
        let store = Arc::new(SqliteStore::open_in_memory().unwrap());
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
            })
            .unwrap();
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
            .auth_mode(AuthMode::None)
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
        use crate::governance::{GovState, SqliteStore, Store, VirtualKey};
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
        let store = Arc::new(SqliteStore::open_in_memory().unwrap());
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
            })
            .unwrap();
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
            .auth_mode(AuthMode::Passthrough)
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
    /// tests; kept local to the auth test module.
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
                fn record_debug(
                    &mut self,
                    field: &tracing::field::Field,
                    value: &dyn std::fmt::Debug,
                ) {
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
    #[test]
    fn test_token_mode_with_governance_and_client_tokens_warns_inert_allowlist() {
        use crate::governance::{GovState, SqliteStore, Store, VirtualKey};
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
                let store = Arc::new(SqliteStore::open_in_memory().unwrap());
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
                    })
                    .unwrap();
                let gov = Arc::new(GovState::new(store, 0, 0, None).unwrap());

                // auth.mode=token WITH a non-empty static allowlist — the inert combination. The
                // listed static token is NOT the governance virtual key.
                let auth_cfg = crate::config::AuthCfg {
                    mode: AuthMode::Token.as_config_str().to_string(),
                    client_tokens: vec!["static-allowlisted-but-inert".to_string()],
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
                lc.contains("auth.mode=token")
                    && lc.contains("governance")
                    && lc.contains("client_tokens")
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
        let blank = req_with("x-admin-token", "");
        assert_eq!(
            extract_admin_header_token(&blank),
            None,
            "a blank x-admin-token must be treated as absent (None)"
        );

        // A whitespace-only value is NOT blank (it is a non-empty string); it is preserved verbatim
        // and will simply fail the constant-time compare downstream — the filter is empty-only, not a
        // trim, matching extract_client_token's carrier filter exactly.
        let present = req_with("x-admin-token", "admintok");
        assert_eq!(
            extract_admin_header_token(&present),
            Some("admintok".to_string()),
            "a non-empty x-admin-token must be carried verbatim"
        );

        // Absent header → None (unchanged).
        let absent = Request::builder()
            .uri("/admin/keys")
            .body(Body::empty())
            .expect("test request must build");
        assert_eq!(extract_admin_header_token(&absent), None);
    }

    /// Regression (LOW/security-hardening): a present-but-blank `x-admin-token` must be rejected on
    /// the admin surface. Driven end-to-end through the real router + `auth_middleware` so the
    /// extraction + constant-time compare are exercised together. A correct token via the same header
    /// authorizes, proving the 401 is the empty-filter and not a blanket reject.
    #[tokio::test]
    async fn test_admin_blank_header_token_rejected() {
        use crate::governance::{GovState, SqliteStore};
        use crate::test_support::TestApp;
        use std::sync::Arc;

        crate::metrics::init();

        let store = Arc::new(SqliteStore::open_in_memory().unwrap());
        let gov = Arc::new(GovState::new(store, 0, 0, Some("admintok".to_string())).unwrap());
        let app = TestApp::new().governance(gov).build();
        let router = crate::build_router(app);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let handle = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
        let client = reqwest::Client::new();
        let url = format!("http://{addr}/admin/keys");

        // Blank x-admin-token (and no Bearer) → 401: a blank header is treated as absent.
        let r_blank = client
            .get(&url)
            .header("x-admin-token", "")
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
            .header("x-admin-token", "admintok")
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
    #[tokio::test]
    async fn test_admin_token_both_carriers_or_fold_no_short_circuit() {
        use crate::governance::{GovState, SqliteStore};
        use crate::test_support::TestApp;
        use std::sync::Arc;

        crate::metrics::init();

        let store = Arc::new(SqliteStore::open_in_memory().unwrap());
        let gov = Arc::new(GovState::new(store, 0, 0, Some("admintok".to_string())).unwrap());
        let app = TestApp::new().governance(gov).build();
        let router = crate::build_router(app);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let handle = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
        let client = reqwest::Client::new();
        let url = format!("http://{addr}/admin/keys");

        // Correct Bearer + WRONG x-admin-token → authorized (the header compare must not veto a
        // matching Bearer; the fold is OR, not AND).
        let r = client
            .get(&url)
            .bearer_auth("admintok")
            .header("x-admin-token", "wrong")
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
            .header("x-admin-token", "admintok")
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
            .header("x-admin-token", "also-wrong")
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
    #[tokio::test]
    async fn test_admin_token_not_acceptable_via_vendor_carriers() {
        use crate::governance::{GovState, SqliteStore};
        use crate::test_support::TestApp;
        use std::sync::Arc;

        crate::metrics::init();

        let store = Arc::new(SqliteStore::open_in_memory().unwrap());
        let gov = Arc::new(GovState::new(store, 0, 0, Some("admintok".to_string())).unwrap());
        let app = TestApp::new().governance(gov).build();
        let router = crate::build_router(app);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let handle = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
        let client = reqwest::Client::new();
        let url = format!("http://{addr}/admin/keys");

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
            .header("x-admin-token", "admintok")
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

    /// Regression for the empty-token governance bypass (finding auth.rs:420): the governance branch
    /// must reject a request that presents NO credential BEFORE calling `gov.lookup`, rather than
    /// looking up `sha256("")`. We deliberately seed a virtual key whose `key_hash == sha256("")` —
    /// the exact pathological state (reachable via direct DB writes / a future seeding path that
    /// bypasses `generate_secret`) the finding warns about — and confirm an unauthenticated request
    /// is STILL rejected 401 instead of resolving to that key. Before the fix, the no-token request
    /// would call `gov.lookup("")`, match this enabled key, and be admitted unauthenticated.
    #[tokio::test]
    async fn test_governance_rejects_empty_token_even_if_empty_secret_key_exists() {
        use crate::governance::{GovState, SqliteStore, Store, VirtualKey};
        use crate::test_support::{LaneSpec, MockServer, MockServerState, TestApp};
        use serde_json::json;
        use std::sync::Arc;

        crate::metrics::init();

        // No upstream call should happen — auth must reject before routing.
        let state = Arc::new(MockServerState::new());
        let server = MockServer::new(state).await;

        let store = Arc::new(SqliteStore::open_in_memory().unwrap());
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
            mode: "token".to_string(),
            client_tokens: vec![secret_a.to_string(), secret_b.to_string()],
            _legacy_token: None,
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
        // The count (and the mode) are non-secret and SHOULD be reported.
        assert!(
            dbg.contains('2'),
            "AuthMiddleware Debug should report the token count: {dbg}"
        );
        assert!(
            dbg.contains("Token"),
            "AuthMiddleware Debug should report the mode: {dbg}"
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
            ("x-amz-content-sha256".to_string(), payload_hash.clone()),
            ("x-amz-date".to_string(), amzdate.to_string()),
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
        use crate::governance::{GovState, NewKeySpec, SqliteStore};
        let store = std::sync::Arc::new(SqliteStore::open_in_memory().unwrap());
        let gov = std::sync::Arc::new(GovState::new(store, 0, 0, None).unwrap());
        let (_key, _bearer, akid, secret) = gov
            .create_key_with_aws(
                NewKeySpec {
                    name: "bedrock".to_string(),
                    allowed_pools: vec![],
                    max_budget_cents: None,
                    budget_period: "total".to_string(),
                    rpm_limit: None,
                    tpm_limit: None,
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
        use crate::governance::{GovState, NewKeySpec, SqliteStore};
        let store = std::sync::Arc::new(SqliteStore::open_in_memory().unwrap());
        let gov = std::sync::Arc::new(GovState::new(store, 0, 0, None).unwrap());
        let (key, _b, akid, secret) = gov
            .create_key_with_aws(
                NewKeySpec {
                    name: "k".to_string(),
                    allowed_pools: vec![],
                    max_budget_cents: None,
                    budget_period: "total".to_string(),
                    rpm_limit: None,
                    tpm_limit: None,
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
            if k == "x-amz-content-sha256" {
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
}
