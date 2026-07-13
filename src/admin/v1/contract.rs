// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The Admin API v1 CONTRACT — transport-agnostic types shared by every adapter.
//!
//! This is the frozen surface expressed in Rust: the operation VIEWS (what a read returns), the
//! stable ERROR taxonomy (`AdminError` → stable `code` + HTTP status), and the authorization SCOPE
//! model. It knows nothing about HTTP, JSON, or GraphQL — a transport adapter (`super::transport`)
//! projects these into a wire format, and the service (`super::service`) produces them. Because the
//! contract lives here as typed Rust, a second transport reuses it verbatim and `openapi.json` can be
//! generated from the same structs.
//!
//! ADDITIVE-ONLY (design-admin-api-v1 §0.2): fields may be ADDED to a view; an error `code` string is
//! never removed or repurposed once shipped. Serde `Serialize` derives give the JSON projection for
//! free; a non-JSON transport maps the same fields differently.

use serde::Serialize;

/// The root every busbar-NATIVE API surface mounts under (`/api/<version>/<area>/…`). The data
/// plane (the six mimicked SDK wire protocols) is deliberately OUTSIDE this root — its paths are
/// dictated by the upstream SDKs, not by busbar.
pub(crate) const API_ROOT: &str = "/api";

/// The frozen Admin API v1 path prefix — `API_ROOT` + version + area. Every admin endpoint hangs
/// off this; the router nest, the scope matrix, and the OpenAPI doc all derive from it (one source
/// of truth, drift-proof by construction — see `admin::transport::mount`).
pub(crate) const ADMIN_PREFIX: &str = "/api/v1/admin";

/// The three built-in authorization scopes, totally ordered `ReadOnly ⊂ HooksRegister ⊂ Full`
/// (design-admin-api-v1 §1). Authorization is checked on the PRINCIPAL per endpoint and is NEVER
/// derived from the request body, so a crafted request cannot escalate. `Ord` derives from
/// declaration order (low → high), so `principal_scope >= required` is the check.
///
/// The full variant set is the FROZEN authorization contract; the per-endpoint scope checks that
/// compare these land with the config/hooks/auth endpoints (upcoming slices), so the set is
/// deliberately ahead of its first consumer.
#[allow(dead_code)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum Scope {
    /// Every read (`GET`) across config, keys, hooks, versions, audit, usage, info.
    ReadOnly,
    /// read-only + register/update/delete/PATCH-settings of `tap|gate|route` HOOK definitions ONLY.
    /// Deliberately narrow (for automation that only registers hooks): cannot mint keys, change
    /// auth, or wire chains.
    HooksRegister,
    /// Everything: keys, config apply/rollback, auth chains, group_map, cache.
    Full,
}

impl Scope {
    /// The stable wire token for this scope (used in `openapi.json` annotations and `info`).
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Scope::ReadOnly => "read-only",
            Scope::HooksRegister => "hooks-register",
            Scope::Full => "full",
        }
    }

    /// Parse a config-side scope token (`group_map.<g>.admin_scope`). `None` = unknown token —
    /// config_validate rejects it at boot; runtime callers treat it as no grant (fail closed).
    pub(crate) fn parse(token: &str) -> Option<Self> {
        match token {
            "read-only" => Some(Scope::ReadOnly),
            "hooks-register" => Some(Scope::HooksRegister),
            "full" => Some(Scope::Full),
            _ => None,
        }
    }

    /// Whether a principal holding `self` may call an endpoint requiring `needed`. The scopes are
    /// a strict ladder (`read-only ⊂ hooks-register ⊂ full`), encoded in the derive(Ord) variant
    /// order above.
    pub(crate) fn allows(self, needed: Scope) -> bool {
        self >= needed
    }
}

/// The AUTHORIZATION MATRIX (design-admin-api-v1 §1, §6.3): the scope an admin endpoint requires,
/// derived from METHOD + PATH — never from the body (a crafted request cannot escalate). The
/// ladder: every read is `read-only`; the hook-DEFINITION lifecycle (`/api/v1/admin/hooks*` mutations)
/// is `hooks-register` (deliberately narrow — automation can register itself but cannot mint keys
/// or change auth); every other mutation — keys, config apply/rollback, auth chains, group_map,
/// cache — is `full`. Unknown methods fail closed to `full`. Body-derived refinements (§6.3: a
/// `hooks-register` principal must not register a hook wired into a security-critical path) are
/// enforced at the service layer, where the body is parsed.
pub(crate) fn required_scope(method: &axum::http::Method, path: &str) -> Scope {
    use axum::http::Method;
    if method == Method::GET || method == Method::HEAD {
        return Scope::ReadOnly;
    }
    // Only the enumerated mutation verbs earn the narrower hooks scope; anything else (OPTIONS,
    // TRACE, extension methods) fails closed to `full`.
    let is_mutation = method == Method::POST
        || method == Method::PUT
        || method == Method::PATCH
        || method == Method::DELETE;
    // Match RELATIVE to the one true prefix so the matrix can never drift from the mount grammar.
    // A path outside the prefix (impossible for a mounted admin route) fails closed to `full`.
    let rel = path.strip_prefix(ADMIN_PREFIX).unwrap_or(path);
    if is_mutation && (rel == "/hooks" || rel.starts_with("/hooks/")) {
        return Scope::HooksRegister;
    }
    Scope::Full
}

/// The stable v1 error taxonomy. Each variant maps to a fixed `code` (the machine-stable branch key
/// tooling switches on — NEVER `message`) and an HTTP status the JSON-REST adapter uses. A non-HTTP
/// transport reads `code` and ignores the status. Adding a variant is additive; an existing
/// `code` string is frozen.
///
/// Some variants are exercised only by endpoints in upcoming slices (conflict/forbidden land with the
/// mutation surface); the taxonomy is defined whole so the frozen contract + its test lock exist from
/// the start.
#[allow(dead_code)]
#[derive(Debug, Clone)]
pub(crate) enum AdminError {
    /// The named resource does not exist. `code = not_found`.
    NotFound(String),
    /// The principal's scope is insufficient for the endpoint. `code = forbidden`. Carries the scope
    /// that WOULD have sufficed, for a precise client message (never leaks other principals' data).
    Forbidden { needed: Scope },
    /// The request is structurally invalid (bad field, unknown enum, failed validation). `code =
    /// invalid_request`.
    Validation(String),
    /// Optimistic-concurrency mismatch: the caller's `expected_version`/`If-Match` is stale. `code =
    /// conflict`.
    Conflict(String),
    /// The principal exhausted its per-minute mutation budget (§6.6). `code = rate_limited`.
    RateLimited,
    /// An internal failure (store/plugin). `code = internal`. The human `message` is generic; details
    /// are logged server-side, never returned.
    Internal,
}

impl AdminError {
    /// The FROZEN stable code. Tooling branches on this string; it never changes for a shipped variant.
    pub(crate) fn code(&self) -> &'static str {
        match self {
            AdminError::NotFound(_) => "not_found",
            AdminError::Forbidden { .. } => "forbidden",
            AdminError::Validation(_) => "invalid_request",
            AdminError::Conflict(_) => "conflict",
            AdminError::RateLimited => "rate_limited",
            AdminError::Internal => "internal",
        }
    }

    /// The HTTP status the JSON-REST adapter returns for this error. A non-HTTP transport ignores it.
    pub(crate) fn http_status(&self) -> u16 {
        match self {
            AdminError::NotFound(_) => 404,
            AdminError::Forbidden { .. } => 403,
            AdminError::Validation(_) => 400,
            AdminError::Conflict(_) => 409,
            AdminError::RateLimited => 429,
            AdminError::Internal => 500,
        }
    }

    /// The human-facing message. Caller-safe only — internal store/plugin detail never lands here.
    pub(crate) fn message(&self) -> String {
        match self {
            AdminError::NotFound(what) => format!("{what} not found"),
            AdminError::Forbidden { needed } => {
                format!(
                    "insufficient scope: this endpoint requires `{}`",
                    needed.as_str()
                )
            }
            AdminError::Validation(msg) => msg.clone(),
            AdminError::Conflict(msg) => msg.clone(),
            AdminError::RateLimited => {
                "admin mutation rate limit exceeded; retry next minute".to_string()
            }
            AdminError::Internal => "internal error".to_string(),
        }
    }
}

/// The compiled-in plugin catalog + topology + uptime returned by `GET /api/v1/admin/info`. Powers
/// version negotiation for tooling AND the compliance-by-compilation proof: `auth_modules`/`hook_plugins` reflect
/// the ACTUAL binary (feature-gated at compile time), not config, so `--no-default-features` shows a
/// provably smaller surface. No LLM content, ever.
#[derive(Debug, Clone, Serialize)]
pub(crate) struct InfoView {
    /// busbar semantic version (`CARGO_PKG_VERSION`).
    pub(crate) version: &'static str,
    pub(crate) build: BuildInfo,
    /// Seconds since process start, or `None` if the start instant was never stamped.
    pub(crate) uptime_seconds: Option<u64>,
    pub(crate) topology: TopologyInfo,
    /// Whether config-overlay persistence is enabled (`BUSBAR_CONFIG_OVERLAY` set): `true` = API-applied
    /// config changes are durable across restarts; `false` = live-only (lost on restart). Lets tooling
    /// tell an operator whether their runtime changes will survive a restart.
    pub(crate) config_persistence: bool,
    /// Monotonic config version — `0` at boot, +1 per API config apply. Drift-detection: re-read and
    /// compare to tell whether the running config changed. Process-local (resets on restart).
    pub(crate) config_version: u64,
}

/// The compiled-in feature proof (`InfoView.build`).
#[derive(Debug, Clone, Serialize)]
pub(crate) struct BuildInfo {
    /// Auth modules baked into this binary (e.g. `["tokens"]`; empty under `--no-default-features`).
    pub(crate) auth_modules: Vec<&'static str>,
    /// Hook plugins baked into this binary (e.g. `["ranking"]`).
    pub(crate) hook_plugins: Vec<&'static str>,
    /// The inline SWRR floor — ALWAYS `true` (compiled in unconditionally, non-removable).
    pub(crate) weighted_floor: bool,
}

/// Pool/model/provider counts (`InfoView.topology`).
#[derive(Debug, Clone, Serialize)]
pub(crate) struct TopologyInfo {
    pub(crate) pools: usize,
    pub(crate) models: usize,
    pub(crate) providers: usize,
}

/// A pool in the topology read (`GET /api/v1/admin/pools`). Summary shape today: name + the member
/// models and their weights. LIVE per-member status (breaker state, available concurrency, latency
/// EWMA, budget/rate headroom — design-admin-api-v1 §6.9) is an additive follow-up; the field set
/// only grows.
#[derive(Debug, Clone, Serialize)]
pub(crate) struct PoolView {
    pub(crate) name: String,
    pub(crate) members: Vec<PoolMemberView>,
}

/// One member of a pool: the model it targets and its SWRR weight.
#[derive(Debug, Clone, Serialize)]
pub(crate) struct PoolMemberView {
    pub(crate) model: String,
    pub(crate) weight: u32,
}

/// The LIVE per-pool detail read (`GET /api/v1/admin/pools/{name}`) — the reliability/capacity dashboard
/// data (design-admin-api-v1 §6.9): each member's breaker state, concurrency headroom, in-flight
/// count, latency EWMA, and success/error tallies, read from the SAME store signals the routing seam
/// ranks on. No LLM content, no credentials.
#[derive(Debug, Clone, Serialize)]
pub(crate) struct PoolDetailView {
    pub(crate) name: String,
    pub(crate) members: Vec<PoolMemberStatusView>,
}

/// One member's live status within a pool. The breaker signal is the release-exposed
/// `usable`/`cooldown_remaining_s` pair (a lane in breaker cooldown reports `usable: false` with the
/// seconds remaining) — the same summary `/stats` surfaces.
#[derive(Debug, Clone, Serialize)]
pub(crate) struct PoolMemberStatusView {
    pub(crate) model: String,
    pub(crate) weight: u32,
    /// Whether the lane can currently take dispatch (breaker closed / recovered). `false` while a
    /// tripped breaker cools down or the lane is dead.
    pub(crate) usable: bool,
    /// Seconds until a tripped breaker's cooldown elapses; `0` when not cooling down.
    pub(crate) cooldown_remaining_s: u64,
    /// Free concurrency slots on this lane right now (lane-global; permits are shared across pools).
    pub(crate) available_concurrency: usize,
    /// In-flight requests on this lane right now.
    pub(crate) inflight: i64,
    /// Latency EWMA in milliseconds, or `None` if no sample yet.
    pub(crate) latency_ms: Option<f64>,
    /// Successful and errored request tallies for this lane.
    pub(crate) ok: u64,
    pub(crate) err: u64,
    /// Whether the lane is hard-down/dead (distinct from a transiently-tripped breaker).
    pub(crate) dead: bool,
}

/// A model lane in the topology read (`GET /api/v1/admin/models`): the config key + its upstream
/// provider. No credentials, ever.
#[derive(Debug, Clone, Serialize)]
pub(crate) struct ModelView {
    pub(crate) model: String,
    pub(crate) provider: String,
}

/// A provider in the topology read (`GET /api/v1/admin/providers`): the provider name + how many model
/// lanes route through it.
#[derive(Debug, Clone, Serialize)]
pub(crate) struct ProviderView {
    pub(crate) provider: String,
    pub(crate) model_count: usize,
}

/// A hook definition in the registry read (`GET /api/v1/admin/hooks`, `GET /api/v1/admin/hooks/{name}`) — the
/// plugin catalog read. Projects the DEFINITION (kind, transport, grants, ordering, stage), never a
/// secret. `global` reports whether the hook fires on every request (named in `global_hooks:` or
/// declared `global: true`). Live connection status (`health`) is a separate endpoint. Additive-only.
#[derive(Debug, Clone, Serialize)]
pub(crate) struct HookView {
    pub(crate) name: String,
    /// `"tap"` (fire-and-forget) or `"gate"` (fire-and-wait).
    pub(crate) kind: &'static str,
    pub(crate) transport: HookTransportView,
    /// Prompt access grant: `"no"` | `"ro"` | `"rw"`.
    pub(crate) prompt: &'static str,
    /// Caller-identity access grant: `"no"` | `"ro"`.
    pub(crate) user: &'static str,
    /// Rewrite/reject ordering key (transform-chain order + reject tie-break).
    pub(crate) priority: u16,
    /// TAP observation stage (`"request"`/`"route"`/`"attempt"`/`"completion"`), or `None` for a gate.
    pub(crate) at: Option<&'static str>,
    /// Gate fallback on timeout/error — a reserved terminal (`"weighted"` | `"reject"` |
    /// `"first"`) or the NAME of the fallback hook the chain continues through.
    pub(crate) on_error: String,
    /// Gate decision deadline in milliseconds.
    pub(crate) timeout_ms: u64,
    /// The hook's opaque settings map (operator/API-owned; pushed via the configure wire). Never
    /// interpreted by busbar; never a secret by contract (hook settings are operator config).
    pub(crate) settings: serde_json::Map<String, serde_json::Value>,
    /// Whether this hook fires on every request (globally wired).
    pub(crate) global: bool,
}

/// The transport half of a `HookView`: which wire the hook speaks and its target (socket path or
/// webhook URL — operator config, not a secret). Exactly one of `socket`/`webhook` is set.
#[derive(Debug, Clone, Serialize)]
pub(crate) struct HookTransportView {
    /// `"socket"` or `"webhook"` (or `"none"` for a misconfigured entry with neither).
    pub(crate) kind: &'static str,
    /// The socket path or webhook URL. `None` only if the definition set neither transport.
    pub(crate) target: Option<String>,
}

/// The live health of one hook's transport (`GET /api/v1/admin/hooks/{name}/health`). BEST-EFFORT: for a
/// socket transport `reachable` is `Some(true/false)` from a short-timeout connect probe; for a webhook
/// (or on a non-unix host) it is `None` (probed on demand, not here) with a `detail` note. Never fires
/// the hook — just checks whether the endpoint accepts a connection. Additive-only.
#[derive(Debug, Clone, Serialize)]
pub(crate) struct HookHealthView {
    pub(crate) name: String,
    pub(crate) transport: HookTransportView,
    /// `Some(true)` = the transport accepted a connection; `Some(false)` = it did not; `None` = not
    /// probed here (webhook / non-unix).
    pub(crate) reachable: Option<bool>,
    /// A short human note on the probe (why `None`, or the connect error class). Never a secret.
    pub(crate) detail: Option<String>,
}

/// One plugin in the plugin catalog (`GET /api/v1/admin/plugins?type=`). A plugin is either
/// COMPILED-IN (baked into the binary, feature-gated — provably removable via `--no-default-features`)
/// or EXTERNAL (registered at runtime over socket/webhook). `active` is `Some(true/false)` where
/// activation is tracked (auth modules: in the chain?; external hooks: configured = true) and `None`
/// where it is a per-pool concern not summarized here (compiled-in ranking policies). Additive-only.
#[derive(Debug, Clone, Serialize)]
pub(crate) struct PluginView {
    pub(crate) name: String,
    /// `"auth"` or `"hooks"` — the plugin TYPE (each a distinct engine contract).
    pub(crate) r#type: &'static str,
    /// `"compiled-in"` or `"external"`.
    pub(crate) loader: &'static str,
    /// Whether the plugin is currently active, where tracked; `None` when activation is not summarized
    /// at this level.
    pub(crate) active: Option<bool>,
    /// For an external plugin, its transport target (socket path / webhook URL). `None` for compiled-in.
    pub(crate) target: Option<String>,
}

/// The ingress auth chain read (`GET /api/v1/admin/auth`): the ordered module names that authenticate
/// callers + the upstream-credential mode. Never a secret — module names and the mode are config
/// identifiers, not credentials. An empty `chain` is the open front door (admits every request).
#[derive(Debug, Clone, Serialize)]
pub(crate) struct AuthView {
    /// Ordered auth-chain module names (`[]` = open front door).
    pub(crate) chain: Vec<&'static str>,
    /// `"own"` (busbar signs egress with its configured key) or `"passthrough"` (forward the caller's
    /// credential upstream).
    pub(crate) upstream_credentials: &'static str,
    /// Whether the front door is open (empty chain admits unconditionally).
    pub(crate) open: bool,
}

/// A cursor-paginated list envelope. `items` is this page; `next_cursor` is `Some` when more remain
/// (design-admin-api-v1 §0.4). Generic over the item view so every list endpoint shares one shape.
#[derive(Debug, Clone, Serialize)]
pub(crate) struct Page<T> {
    pub(crate) items: Vec<T>,
    pub(crate) next_cursor: Option<String>,
}

impl<T> Page<T> {
    /// A single-page result (no further pages). The topology reads are small and unpaginated today.
    pub(crate) fn single(items: Vec<T>) -> Self {
        Self {
            items,
            next_cursor: None,
        }
    }
}

/// The pagination cursor is OPAQUE by contract — clients must round-trip it verbatim, never parse it.
/// Under the hood it is just the hex of a tagged byte offset (`o:<n>`); the encoding is an
/// implementation detail that can change to a keyset cursor later without a wire break. Dependency-free
/// (no base64 crate) — hex keeps it URL-safe.
pub(crate) fn encode_offset_cursor(offset: usize) -> String {
    use std::fmt::Write;
    format!("o:{offset}")
        .bytes()
        .fold(String::new(), |mut s, b| {
            let _ = write!(s, "{b:02x}");
            s
        })
}

/// Decode an opaque `?cursor=` back to its byte offset. Returns `None` for any malformed/foreign
/// cursor so the transport can answer `invalid_request` rather than silently ignoring it.
pub(crate) fn decode_offset_cursor(cursor: &str) -> Option<usize> {
    if cursor.is_empty() || !cursor.len().is_multiple_of(2) {
        return None;
    }
    let bytes: Option<Vec<u8>> = (0..cursor.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(cursor.get(i..i + 2)?, 16).ok())
        .collect();
    let s = String::from_utf8(bytes?).ok()?;
    s.strip_prefix("o:")?.parse::<usize>().ok()
}

#[cfg(test)]
mod cursor_tests {
    use super::{decode_offset_cursor, encode_offset_cursor};

    #[test]
    fn offset_cursor_round_trips_and_is_opaque() {
        for n in [0usize, 1, 42, 1000, usize::MAX] {
            let c = encode_offset_cursor(n);
            assert!(
                c.bytes().all(|b| b.is_ascii_hexdigit()),
                "cursor is URL-safe hex: {c}"
            );
            assert_ne!(c, n.to_string(), "cursor is opaque, not the bare integer");
            assert_eq!(decode_offset_cursor(&c), Some(n));
        }
        // Foreign / malformed cursors decode to None (transport -> invalid_request, not silent skip).
        assert_eq!(decode_offset_cursor(""), None);
        assert_eq!(decode_offset_cursor("zz"), None);
        assert_eq!(decode_offset_cursor("abc"), None); // odd length
        assert_eq!(decode_offset_cursor("6f"), None); // "o" alone — no ":<n>" tail
    }
}

/// The EFFECTIVE config snapshot (`GET /api/v1/admin/config`) — the running configuration as busbar
/// resolved it, for drift detection (compare against your desired config) and one-shot inspection.
/// Composed from the same REDACTED reads as the individual endpoints (auth chain names, pool/model/
/// provider topology, hook definitions, global-hook wiring) — so it carries NO secret: no client
/// tokens, no provider keys, no hook payloads. Additive-only; the source-layer annotation (base vs
/// overlay) lands with the config overlay substrate.
#[derive(Debug, Clone, Serialize)]
pub(crate) struct EffectiveConfigView {
    /// The monotonic config version at the time of this read (see `InfoView.config_version`) — so a
    /// drift-detection read gets the config AND its version in one call.
    pub(crate) version: u64,
    pub(crate) auth: AuthView,
    pub(crate) pools: Vec<PoolView>,
    pub(crate) models: Vec<ModelView>,
    pub(crate) providers: Vec<ProviderView>,
    pub(crate) hooks: Vec<HookView>,
    /// Names fired on every request (`global_hooks:` + any inline `global: true`).
    pub(crate) global_hooks: Vec<String>,
}

/// Fleet usage aggregation (`GET /api/v1/admin/usage`) — spend/tokens/requests totals plus a per-key
/// breakdown, read from governance's per-key counters. The data-plane half of metering. Empty (zero
/// totals, no keys) when governance is disabled. No secrets — key ids/names only, never a token.
#[derive(Debug, Clone, Serialize)]
pub(crate) struct UsageView {
    pub(crate) total: UsageTotals,
    pub(crate) keys: Vec<KeyUsageView>,
}

/// Aggregate spend/tokens/requests across all keys (the fleet totals).
#[derive(Debug, Clone, Default, Serialize)]
pub(crate) struct UsageTotals {
    pub(crate) spend_cents: i64,
    pub(crate) tokens: u64,
    pub(crate) requests: u64,
}

/// One key's usage in the fleet breakdown: the key id/name (never the secret) + its counters.
#[derive(Debug, Clone, Serialize)]
pub(crate) struct KeyUsageView {
    pub(crate) id: String,
    pub(crate) name: String,
    pub(crate) spend_cents: i64,
    pub(crate) tokens: u64,
    pub(crate) requests: u64,
}

/// The admin-plane auth read (`GET /api/v1/admin/admin-auth`) — which modules guard the ADMIN surface
/// (distinct from the ingress `auth` chain). `modules` is the live `admin_auth` chain (the SAME
/// resource `PUT /api/v1/admin/admin-auth` writes), so a read-after-write is coherent. An empty chain is
/// the open (anonymous, full-authority) dev posture — `configured: false`. Never a secret.
#[derive(Debug, Clone, Serialize)]
pub(crate) struct AdminAuthView {
    /// Whether an admin credential chain is configured. `false` = the empty chain = open dev posture.
    pub(crate) configured: bool,
    /// The active admin-plane guard module names — the `admin_auth` chain verbatim (e.g.
    /// `["admin-tokens"]`), reported in order. Empty when the admin plane is open.
    pub(crate) modules: Vec<String>,
}

/// The result of `POST /api/v1/admin/config/validate` — a DRY-RUN: does a proposed config resolve +
/// validate, WITHOUT applying anything. `ok` is the verdict; `errors` lists every structural/resolution
/// failure at once (empty when `ok`). A well-formed request always returns 200 with this view (a valid
/// request that describes an INVALID config is `ok: false`, not an HTTP error); only a MALFORMED request
/// body is an `invalid_request`. Env-var interpolation is out of scope — this checks structure and
/// cross-reference resolution, not runtime secret presence.
#[derive(Debug, Clone, Serialize)]
pub(crate) struct ConfigValidateView {
    pub(crate) ok: bool,
    pub(crate) errors: Vec<String>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::Method;

    /// The §1 authorization matrix, test-locked: reads are read-only, hook-definition mutations
    /// are hooks-register, everything else (keys, config, auth, cache) is full. Unknown methods
    /// fail closed to full.
    #[test]
    fn required_scope_matrix() {
        for path in [
            "/api/v1/admin/info",
            "/api/v1/admin/hooks",
            "/api/v1/admin/keys",
            "/api/v1/admin/config",
            "/api/v1/admin/audit",
        ] {
            assert_eq!(
                required_scope(&Method::GET, path),
                Scope::ReadOnly,
                "{path}"
            );
        }
        assert_eq!(
            required_scope(&Method::POST, "/api/v1/admin/hooks"),
            Scope::HooksRegister
        );
        assert_eq!(
            required_scope(&Method::DELETE, "/api/v1/admin/hooks/my-hook"),
            Scope::HooksRegister
        );
        assert_eq!(
            required_scope(&Method::PATCH, "/api/v1/admin/hooks/my-hook/settings"),
            Scope::HooksRegister
        );
        // A sibling path must not inherit the hooks scope (boundary-safe prefix).
        assert_eq!(
            required_scope(&Method::POST, "/api/v1/admin/hooksx"),
            Scope::Full
        );
        assert_eq!(
            required_scope(&Method::POST, "/api/v1/admin/keys"),
            Scope::Full
        );
        assert_eq!(
            required_scope(&Method::POST, "/api/v1/admin/config/apply"),
            Scope::Full
        );
        assert_eq!(
            required_scope(&Method::OPTIONS, "/api/v1/admin/hooks"),
            Scope::Full,
            "unknown methods fail closed"
        );
    }

    /// The scope ladder: read-only ⊂ hooks-register ⊂ full — and parse round-trips the tokens.
    #[test]
    fn scope_ladder_allows() {
        assert!(Scope::Full.allows(Scope::ReadOnly));
        assert!(Scope::Full.allows(Scope::HooksRegister));
        assert!(Scope::HooksRegister.allows(Scope::ReadOnly));
        assert!(!Scope::HooksRegister.allows(Scope::Full));
        assert!(!Scope::ReadOnly.allows(Scope::HooksRegister));
        assert!(Scope::parse("bogus").is_none());
        assert_eq!(Scope::parse("hooks-register"), Some(Scope::HooksRegister));
    }

    /// The stable error taxonomy is locked: each variant's `code` + HTTP status is the frozen wire
    /// contract tooling branches on. A change here is a breaking change to v1 and must fail this test.
    #[test]
    fn admin_error_codes_and_statuses_are_frozen() {
        let cases = [
            (AdminError::NotFound("key".into()), "not_found", 404u16),
            (
                AdminError::Forbidden {
                    needed: Scope::Full,
                },
                "forbidden",
                403,
            ),
            (AdminError::Validation("bad".into()), "invalid_request", 400),
            (AdminError::Conflict("stale".into()), "conflict", 409),
            (AdminError::RateLimited, "rate_limited", 429),
            (AdminError::Internal, "internal", 500),
        ];
        for (e, code, status) in cases {
            assert_eq!(e.code(), code, "frozen error code changed");
            assert_eq!(e.http_status(), status, "frozen error status changed");
        }
    }
}
