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

// SCHEMA-ONLY response views for the ad-hoc-`json!` endpoints (keys, config mutations, hook
// schema/status, version detail/diff, list envelopes). Compiled ONLY under the CI-only
// `openapi-schema` feature — never in the shipped binary — so `openapi_doc()` can emit a typed
// `$ref` for every operation. See the module doc.
#[cfg(feature = "openapi-schema")]
pub(crate) mod schema;

/// The root every busbar-NATIVE API surface mounts under (`/api/<version>/<area>/…`). The data
/// plane (the six mimicked SDK wire protocols) is deliberately OUTSIDE this root — its paths are
/// dictated by the upstream SDKs, not by busbar.
pub(crate) const API_ROOT: &str = "/api";

/// The frozen Admin API v1 path prefix — `API_ROOT` + version + area. Every admin endpoint hangs
/// off this; the router nest, the scope matrix, and the OpenAPI doc all derive from it (one source
/// of truth, drift-proof by construction — see `admin::transport::mount`).
pub(crate) const ADMIN_PREFIX: &str = "/api/v1/admin";

/// Relative (post-`ADMIN_PREFIX`) path segments matched in more than one place — the scope matrix
/// (`required_scope`), auth.rs's mutation-rate classifier, and the json.rs router/OpenAPI builder —
/// single-sourced here so the three surfaces cannot drift.
pub(crate) const PATH_ADMIN_AUTH: &str = "/admin-auth";
pub(crate) const PATH_CONFIG_VALIDATE: &str = "/config/validate";
pub(crate) const PATH_HOOKS: &str = "/hooks";
pub(crate) const PATH_GROUPS: &str = "/groups";
/// The keys collection path — `POST` here MINTS a key (the delegated `mint` scope; auto-provision
/// rides the same request). Exact-matched in `required_scope` so only the collection POST earns
/// `mint`; per-key lifecycle verbs (`/keys/{id}` PATCH/DELETE, rotate, revoke) stay `full`.
pub(crate) const PATH_KEYS: &str = "/keys";

/// Shared pagination limit policy (§0.4, one cursor grammar → one limit policy) for the admin
/// lists: `?limit=` hard cap and default page size, used by the keys list (admin.rs) and the
/// audit list (json.rs).
pub(crate) const LIST_LIMIT_MAX: usize = 1000;
pub(crate) const LIST_LIMIT_DEFAULT: usize = 200;
/// The versions list's DELIBERATELY smaller default page (100, not the shared 200): each item
/// carries full config-version metadata, heavier than a key/audit row. The hard cap is still the
/// shared `LIST_LIMIT_MAX`.
pub(crate) const VERSIONS_LIMIT_DEFAULT: usize = 100;

/// The built-in authorization scopes. They form a DIAMOND lattice, NOT a strict chain:
/// `ReadOnly` at the bottom, `Full` at the top, and `HooksRegister` + `Mint` as two INCOMPARABLE
/// siblings in the middle (design-admin-api-v1 §1; self-service governance D2). Authorization is
/// checked on the PRINCIPAL per endpoint and is NEVER derived from the request body, so a crafted
/// request cannot escalate.
///
/// SIBLING, NOT A LADDER RUNG (self-service D2): `HooksRegister` and `Mint` are delegated,
/// least-privilege scopes for two DIFFERENT automations — a hook-registration bot vs. the
/// self-service portal that mints keys. Neither must confer the other: a mint credential cannot
/// register a hook, and a hooks-register credential cannot mint a key. So `allows` is NOT
/// `self >= needed` — it encodes the lattice explicitly (see `allows`).
///
/// `Ord` STILL derives from declaration order (low → high), but is used ONLY as an ordinal
/// PRIVILEGE LEVEL for the `max_admin_scope:` ceiling arithmetic (`min(scope, cap)`) and the
/// role-binding `max()` — NEVER as the authorization check. The ordinal places `Mint` above
/// `HooksRegister` purely so that ceiling math stays TOTAL (a lattice `min`/`max` over incomparable
/// elements is undefined); it does NOT mean mint subsumes hooks-register. The `allows` lattice is
/// the sole truth for what a scope may DO. Practical consequence: a `max_admin_scope: hooks-register`
/// ceiling capping a `mint`-granting role yields `hooks-register` (the ordinal floor), i.e. the cap
/// still strictly narrows; and a `max_admin_scope: mint` ceiling never widens a `hooks-register`
/// role into hook authority (min keeps it at hooks-register). Both directions are safe.
///
/// The full variant set is the FROZEN authorization contract.
#[allow(dead_code)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum Scope {
    /// Every read (`GET`) across config, keys, hooks, versions, audit, usage, info.
    ReadOnly,
    /// read-only + register/update/delete/PATCH-settings of `tap|gate|route` HOOK definitions ONLY.
    /// Deliberately narrow (for automation that only registers hooks): cannot mint keys, change
    /// auth, or wire chains. SIBLING of `Mint` — carries NO key-mint authority.
    HooksRegister,
    /// read-only + MINT keys (`POST /keys`, INCLUDING the auto-provision-on-mint leaf-group
    /// creation). The delegated scope for the customer's self-service portal (self-service §6a): it
    /// can mint a key into a group and auto-provision the `user:<sub>` leaf, but CANNOT register
    /// hooks, change auth, or mutate arbitrary config. SIBLING of `HooksRegister` — carries NO hook
    /// authority.
    Mint,
    /// Everything: keys, config apply/rollback, auth chains, group_map, cache.
    Full,
}

impl Scope {
    /// The stable wire token for this scope (used in `openapi.json` annotations and `info`).
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Scope::ReadOnly => "read-only",
            Scope::HooksRegister => "hooks-register",
            Scope::Mint => "mint",
            Scope::Full => "full",
        }
    }

    /// Parse a config-side scope token (`group_map.<g>.admin_scope`, `max_admin_scope:`). `None` =
    /// unknown token — config_validate rejects it at boot; runtime callers treat it as no grant
    /// (fail closed).
    pub(crate) fn parse(token: &str) -> Option<Self> {
        match token {
            "read-only" => Some(Scope::ReadOnly),
            "hooks-register" => Some(Scope::HooksRegister),
            "mint" => Some(Scope::Mint),
            "full" => Some(Scope::Full),
            _ => None,
        }
    }

    /// Whether a principal holding `self` may call an endpoint requiring `needed`. NOT a `>=`
    /// ladder: the scopes are a DIAMOND lattice (`ReadOnly` ⊂ {`HooksRegister`, `Mint`} ⊂ `Full`)
    /// where `HooksRegister` and `Mint` are INCOMPARABLE siblings — so this is enumerated explicitly
    /// rather than derived from `Ord`, precisely so a mint credential can never satisfy a
    /// hook-register requirement and vice versa (self-service D2). `Full` satisfies everything;
    /// `ReadOnly` is satisfied by anything (every grant can read); a sibling requirement is
    /// satisfied only by itself or `Full`.
    pub(crate) fn allows(self, needed: Scope) -> bool {
        match needed {
            // Every grant can read.
            Scope::ReadOnly => true,
            // Only the god-mode grant satisfies a full requirement.
            Scope::Full => self == Scope::Full,
            // The two middle rungs are SIBLINGS: satisfied only by the exact scope or `Full`.
            // (This is the whole point of enumerating instead of `self >= needed`: under `>=`,
            // `Mint >= HooksRegister` would be true by ordinal and a mint token could register
            // hooks.)
            Scope::HooksRegister => self == Scope::HooksRegister || self == Scope::Full,
            Scope::Mint => self == Scope::Mint || self == Scope::Full,
        }
    }
}

/// The AUTHORIZATION MATRIX (design-admin-api-v1 §1, §6.3): the scope an admin endpoint requires,
/// derived from METHOD + PATH — never from the body (a crafted request cannot escalate). NOT a
/// ladder (the scope lattice is a diamond — see `Scope`): every read is `read-only`; the
/// hook-DEFINITION lifecycle (`/api/v1/admin/hooks*` mutations) needs `hooks-register`; MINTING a
/// key (`POST /keys`, which carries the auto-provision-on-mint leaf creation) needs `mint`; every
/// other mutation — config apply/rollback, auth chains, group_map, cache, group CRUD — needs
/// `full`. Because `HooksRegister`/`Mint` are SIBLINGS in `allows`, a `mint` requirement is
/// satisfied by exactly `mint` or `full` — never by `hooks-register`, and vice versa. Unknown
/// methods fail closed to `full`. Body-derived refinements (§6.3: a `hooks-register` principal must
/// not register a hook wired into a security-critical path) are enforced at the service layer.
pub(crate) fn required_scope(method: &axum::http::Method, path: &str) -> Scope {
    use axum::http::Method;
    if method == Method::GET || method == Method::HEAD {
        return Scope::ReadOnly;
    }
    // Only the enumerated mutation verbs earn a narrower delegated scope; anything else (OPTIONS,
    // TRACE, extension methods) fails closed to `full`.
    let is_mutation = method == Method::POST
        || method == Method::PUT
        || method == Method::PATCH
        || method == Method::DELETE;
    // Match RELATIVE to the one true prefix so the matrix can never drift from the mount grammar.
    // A path outside the prefix (impossible for a mounted admin route) fails closed to `full`.
    let rel = path.strip_prefix(ADMIN_PREFIX).unwrap_or(path);
    // `POST /config/validate` is a STATELESS DRY-RUN — a read in POST clothing (the body is the
    // config to lint, far past URL length limits). A read-only CI token must be able to lint
    // configs (re-audit M3; the service doc always said "Read scope" — now the matrix agrees).
    if rel == PATH_CONFIG_VALIDATE {
        return Scope::ReadOnly;
    }
    if is_mutation && (rel == PATH_HOOKS || rel.starts_with("/hooks/")) {
        return Scope::HooksRegister;
    }
    // MINTING a key is the delegated self-service verb (self-service §6a): `POST /keys` (only) —
    // the auto-provision-on-mint leaf creation rides the same request, so the whole mint path is
    // `mint`, not `full`. Everything else under `/keys*` (list/get are reads above; PATCH/DELETE/
    // rotate/revoke are lifecycle mutations) stays `full` — a self-service portal mints, it does
    // not revoke or rotate. Boundary-safe: `PATH_KEYS` exact match only (a sibling like `/keysx`
    // falls through to `full`).
    if method == Method::POST && rel == PATH_KEYS {
        return Scope::Mint;
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
    /// No/invalid admin credential (the auth middleware could not authenticate the caller).
    /// `code = unauthorized`. Distinct from `forbidden` (authenticated but under-scoped).
    Unauthorized,
    /// The path exists on the surface but not with this HTTP method. `code = method_not_allowed`.
    MethodNotAllowed,
    /// The principal's scope is insufficient for the endpoint. `code = forbidden`. Carries the scope
    /// that WOULD have sufficed, for a precise client message (never leaks other principals' data).
    Forbidden { needed: Scope },
    /// The request is structurally invalid (bad field, unknown enum, failed validation). `code =
    /// invalid_request`.
    Validation(String),
    /// Optimistic-concurrency mismatch: the caller's `If-Match` is STALE — re-read the resource
    /// and retry. `code = version_conflict`. Split from `conflict` (external review R3): a client
    /// must distinguish RETRYABLE (this) from TERMINAL state conflicts without string-matching the
    /// human message.
    VersionConflict(String),
    /// A TERMINAL state conflict: the request contradicts server state in a way a retry cannot fix
    /// (governance disabled, base-defined hook, immutable grant change, in-flight idempotency
    /// reservation). `code = conflict`.
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
            AdminError::Unauthorized => "unauthorized",
            AdminError::MethodNotAllowed => "method_not_allowed",
            AdminError::Forbidden { .. } => "forbidden",
            AdminError::Validation(_) => "invalid_request",
            AdminError::VersionConflict(_) => "version_conflict",
            AdminError::Conflict(_) => "conflict",
            AdminError::RateLimited => "rate_limited",
            AdminError::Internal => "internal",
        }
    }

    /// The HTTP status the JSON-REST adapter returns for this error. A non-HTTP transport ignores it.
    pub(crate) fn http_status(&self) -> u16 {
        match self {
            AdminError::NotFound(_) => 404,
            AdminError::Unauthorized => 401,
            AdminError::MethodNotAllowed => 405,
            AdminError::Forbidden { .. } => 403,
            AdminError::Validation(_) => 400,
            AdminError::VersionConflict(_) => 409,
            AdminError::Conflict(_) => 409,
            AdminError::RateLimited => 429,
            AdminError::Internal => 500,
        }
    }

    /// The human-facing message. Caller-safe only — internal store/plugin detail never lands here.
    pub(crate) fn message(&self) -> String {
        match self {
            AdminError::NotFound(what) => format!("{what} not found"),
            AdminError::Unauthorized => {
                "missing or invalid admin credential (Bearer or x-admin-token)".to_string()
            }
            AdminError::MethodNotAllowed => "method not allowed for this resource".to_string(),
            AdminError::Forbidden { needed } => {
                format!(
                    "insufficient scope: this endpoint requires `{}`",
                    needed.as_str()
                )
            }
            AdminError::Validation(msg) => msg.clone(),
            AdminError::VersionConflict(msg) => msg.clone(),
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
#[cfg_attr(feature = "openapi-schema", derive(schemars::JsonSchema))]
pub(crate) struct InfoView {
    /// busbar semantic version (`CARGO_PKG_VERSION`).
    pub(crate) version: &'static str,
    pub(crate) build: BuildInfo,
    /// Seconds since process start, or `None` if the start instant was never stamped.
    pub(crate) uptime_seconds: Option<u64>,
    /// Epoch seconds of process start — the BOOT EPOCH marker: `config_version` (and any
    /// process-local counter) resets on restart, so a consumer that sees `started_at` change knows
    /// to read a counter reset as "new epoch", never as "reverted" (audit minor #2 / #4).
    pub(crate) started_at: Option<u64>,
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
#[cfg_attr(feature = "openapi-schema", derive(schemars::JsonSchema))]
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
#[cfg_attr(feature = "openapi-schema", derive(schemars::JsonSchema))]
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
#[cfg_attr(feature = "openapi-schema", derive(schemars::JsonSchema))]
pub(crate) struct PoolView {
    pub(crate) name: String,
    pub(crate) members: Vec<PoolMemberView>,
}

/// One member of a pool: the model it targets and its SWRR weight.
#[derive(Debug, Clone, Serialize)]
#[cfg_attr(feature = "openapi-schema", derive(schemars::JsonSchema))]
pub(crate) struct PoolMemberView {
    pub(crate) model: String,
    pub(crate) weight: u32,
}

/// The LIVE per-pool detail read (`GET /api/v1/admin/pools/{name}`) — the reliability/capacity dashboard
/// data (design-admin-api-v1 §6.9): each member's breaker state, concurrency headroom, in-flight
/// count, latency EWMA, and success/error tallies, read from the SAME store signals the routing seam
/// ranks on. No LLM content, no credentials.
#[derive(Debug, Clone, Serialize)]
#[cfg_attr(feature = "openapi-schema", derive(schemars::JsonSchema))]
pub(crate) struct PoolDetailView {
    pub(crate) name: String,
    pub(crate) members: Vec<PoolMemberStatusView>,
}

/// One member's live status within a pool. The breaker signal is the release-exposed
/// `usable`/`cooldown_remaining_seconds` pair (a lane in breaker cooldown reports `usable: false` with the
/// seconds remaining) — the same summary `/stats` surfaces.
#[derive(Debug, Clone, Serialize)]
#[cfg_attr(feature = "openapi-schema", derive(schemars::JsonSchema))]
pub(crate) struct PoolMemberStatusView {
    pub(crate) model: String,
    pub(crate) weight: u32,
    /// Whether the lane can currently take dispatch (breaker closed / recovered). `false` while a
    /// tripped breaker cools down or the lane is dead.
    pub(crate) usable: bool,
    /// Seconds until a tripped breaker's cooldown elapses; `0` when not cooling down. (`_seconds`
    /// suffix — the one unit-suffix spelling across the surface, like `uptime_seconds`.)
    pub(crate) cooldown_remaining_seconds: u64,
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
    /// MONOTONIC count of Closed→Open breaker trips on this lane. Breaker episodes are transient
    /// and can open+close entirely between two polls — a consumer alerting on trips diffs this
    /// count instead of trying to catch the live edge (audit #5). Carried across config apply and
    /// restart with the rest of the learned health.
    pub(crate) trip_count: u64,
    /// Epoch seconds of the most recent trip; `None` = never tripped.
    pub(crate) last_trip_at: Option<u64>,
}

/// A model lane in the topology read (`GET /api/v1/admin/models`): the config key + its upstream
/// provider. No credentials, ever.
#[derive(Debug, Clone, Serialize)]
#[cfg_attr(feature = "openapi-schema", derive(schemars::JsonSchema))]
pub(crate) struct ModelView {
    pub(crate) model: String,
    pub(crate) provider: String,
}

/// A provider in the topology read (`GET /api/v1/admin/providers`): the provider name + how many model
/// lanes route through it.
#[derive(Debug, Clone, Serialize)]
#[cfg_attr(feature = "openapi-schema", derive(schemars::JsonSchema))]
pub(crate) struct ProviderView {
    pub(crate) provider: String,
    pub(crate) model_count: usize,
}

/// A hook definition in the registry read (`GET /api/v1/admin/hooks`, `GET /api/v1/admin/hooks/{name}`) — the
/// plugin catalog read. Projects the DEFINITION (kind, transport, grants, ordering, stage), never a
/// secret. `global` reports whether the hook fires on every request (named in `global_hooks:` or
/// declared `global: true`). Live connection status (`health`) is a separate endpoint. Additive-only.
#[derive(Debug, Clone, Serialize)]
#[cfg_attr(feature = "openapi-schema", derive(schemars::JsonSchema))]
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
    /// Gate fallback on timeout/error — a CLOSED, unambiguous string union (audit #8): one of the
    /// reserved terminals (`"weighted"` | `"reject"` | `"first"` | `"nothing"`) or the NAME of the
    /// fallback hook the chain continues through. Unambiguous by construction: the terminal words
    /// are ILLEGAL hook names on every write path (`config::RESERVED_HOOK_NAMES`), so a value in
    /// the terminal set is always a terminal and anything else is always a hook reference.
    pub(crate) on_error: String,
    /// Gate decision deadline in milliseconds.
    pub(crate) timeout_ms: u64,
    /// The hook's opaque settings map (operator/API-owned; pushed via the configure wire). Never
    /// interpreted by busbar; never a secret by contract (hook settings are operator config).
    pub(crate) settings: serde_json::Map<String, serde_json::Value>,
    /// Whether this hook fires on every request (globally wired).
    pub(crate) global: bool,
}

/// A group definition in the registry read (`GET /api/v1/admin/groups`,
/// `GET /api/v1/admin/groups/{name}`) — the limit-tree read surface. Projects the `groups:` config
/// entry faithfully (parent chain, enabled freeze flag, the ordered limits, the `child_default`
/// budget template for auto-provisioned children), never a secret. This is the READ shape; the
/// WRITE verbs accept a `GroupCfg` verbatim (paste a config.yaml group block). Additive-only.
#[derive(Debug, Clone, Serialize)]
#[cfg_attr(feature = "openapi-schema", derive(schemars::JsonSchema))]
pub(crate) struct GroupView {
    pub(crate) name: String,
    /// The parent group whose limits this one is ANDed under (the enforcement chain). `None` = a
    /// root group. Skipped from the body when absent.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) parent: Option<String>,
    /// `false` FREEZES the group (every request charging through it is rejected; history kept).
    pub(crate) enabled: bool,
    /// The group's own limits, enforced together (AND). Order preserved from config.
    pub(crate) limits: Vec<LimitView>,
    /// The limit template stamped onto children auto-provisioned under this group (e.g. a
    /// `user:<sub>` leaf on first self-mint). Skipped from the body when the group sets none.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) child_default: Option<Vec<LimitView>>,
}

/// One limit inside a `GroupView`: an explicit `{ metric, amount, per, pool }` projection of a
/// config `LimitCfg`. The config file's compact `{ budget: 3000, per: month }` form is
/// deserialize-only sugar; the read API projects it explicitly so a consumer never has to know
/// the metric is the map key. `per` is `None` only for `concurrent` (an instantaneous gauge, no
/// window); `pool` is present only on a pool-scoped limit.
#[derive(Debug, Clone, Serialize)]
#[cfg_attr(feature = "openapi-schema", derive(schemars::JsonSchema))]
pub(crate) struct LimitView {
    /// One of `requests` | `tokens` | `budget` | `concurrent`.
    pub(crate) metric: &'static str,
    /// The cap amount (requests/tokens/cents, or the in-flight gauge for `concurrent`).
    pub(crate) amount: u64,
    /// The accounting window: `minute` | `hour` | `day` | `month` | `total`. Absent for `concurrent`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) per: Option<&'static str>,
    /// The pool scope: present when the limit carries `pool: <name>` (it accounts and enforces
    /// only that pool's traffic, per `(group, pool)`); absent for a group-wide limit.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) pool: Option<String>,
    /// The budget-exhaustion behavior: `block` or `downgrade`. Absent = block (the default).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) on_exhaust: Option<&'static str>,
    /// Where `on_exhaust: downgrade` sends exhausted traffic. Present iff downgrading.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) downgrade_to: Option<String>,
}

impl LimitView {
    /// Project a config `LimitCfg` into its explicit read shape.
    pub(crate) fn from_cfg(l: &crate::config::LimitCfg) -> Self {
        LimitView {
            metric: l.metric.as_str(),
            amount: l.amount,
            per: l.per.map(|w| w.as_str()),
            pool: l.pool.clone(),
            on_exhaust: l.on_exhaust.map(|e| match e {
                crate::config::groups::OnExhaust::Block => "block",
                crate::config::groups::OnExhaust::Downgrade => "downgrade",
            }),
            downgrade_to: l.downgrade_to.clone(),
        }
    }
}

impl GroupView {
    /// Project a named `groups:` config entry into its read shape.
    pub(crate) fn from_cfg(name: &str, cfg: &crate::config::GroupCfg) -> Self {
        GroupView {
            name: name.to_string(),
            parent: cfg.parent.clone(),
            enabled: cfg.enabled,
            limits: cfg.limits.iter().map(LimitView::from_cfg).collect(),
            child_default: cfg
                .child_default
                .as_ref()
                .map(|cd| cd.limits.iter().map(LimitView::from_cfg).collect()),
        }
    }
}

/// `GET /groups/{name}/usage` — one group's DERIVED current-window usage, one row per
/// enforcement bucket (each `(window, pool?)` its limits materialise), against that bucket's
/// caps. The §6d dashboard read: spend/tokens/requests per tier vs the budgets, straight off the
/// ledger x the CURRENT rate card (reprice-on-read, nothing stored). The customer's self-service
/// tool consumes this per group (`user:<sub>` leaf = one person's view) and re-scopes it.
#[derive(Debug, Clone, Serialize)]
#[cfg_attr(feature = "openapi-schema", derive(schemars::JsonSchema))]
pub(crate) struct GroupUsageView {
    /// The group name (echoed from the path).
    pub(crate) group: String,
    /// `false` = the group is FROZEN (`enabled: false`): every request through it rejects.
    pub(crate) enabled: bool,
    /// One row per enforcement bucket, in the group's resolved bucket order. Empty for a group
    /// with only a `concurrent` limit (or none) — there is no windowed ledger to read.
    pub(crate) buckets: Vec<GroupBucketUsageView>,
    /// Epoch seconds the read was taken at (the windows below are current AS OF this instant).
    pub(crate) as_of: u64,
}

/// One `(window, pool?)` enforcement bucket's usage vs caps inside a [`GroupUsageView`].
#[derive(Debug, Clone, Serialize)]
#[cfg_attr(feature = "openapi-schema", derive(schemars::JsonSchema))]
pub(crate) struct GroupBucketUsageView {
    /// The accounting window: `minute` | `hour` | `day` | `month` | `total`.
    pub(crate) window: &'static str,
    /// The pool scope for a pool-qualified bucket; absent for a group-wide bucket.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) pool: Option<String>,
    /// Requests admitted this window (the requests-limit truth: failures are not refunded).
    pub(crate) requests: u64,
    /// Total tokens ledgered this window (all tiers).
    pub(crate) tokens: u64,
    /// Spend derived at read time (tokens x current rate card), abstract cents.
    pub(crate) spend_cents: i64,
    /// The bucket's caps, when configured (absent = uncapped on that metric).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) requests_cap: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) tokens_cap: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) budget_cap: Option<i64>,
    /// Cents left under `budget_cap` (floored at 0); absent when no budget cap is set.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) budget_remaining_cents: Option<i64>,
}

/// The transport half of a `HookView`: which wire the hook speaks and its target (socket path or
/// webhook URL — operator config, not a secret). Exactly one of `socket`/`webhook` is set.
#[derive(Debug, Clone, Serialize)]
#[cfg_attr(feature = "openapi-schema", derive(schemars::JsonSchema))]
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
#[cfg_attr(feature = "openapi-schema", derive(schemars::JsonSchema))]
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
/// COMPILED-IN (baked into the binary, feature-gated — provably removable via `--no-default-features`),
/// EXTERNAL (registered at runtime over socket/webhook), or a DYNAMIC-LIBRARY plugin (a loadable
/// `.so`/`.dll`/`.dylib` in the plugins directory, loaded over the store C ABI). `active` is
/// `Some(true/false)` where activation is tracked (auth modules: in the chain?; external hooks:
/// configured = true; dynamic store: the configured `store.module`) and `None` where it is a
/// per-pool concern not summarized here (compiled-in ranking policies). Additive-only.
#[derive(Debug, Clone, Serialize)]
#[cfg_attr(feature = "openapi-schema", derive(schemars::JsonSchema))]
pub(crate) struct PluginView {
    pub(crate) name: String,
    /// `"auth"`, `"hooks"`, or `"store"` — the plugin TYPE (each a distinct engine contract).
    pub(crate) r#type: &'static str,
    /// `"compiled-in"`, `"external"`, or `"dynamic-library"`.
    pub(crate) loader: &'static str,
    /// Whether the plugin is currently active, where tracked; `None` when activation is not summarized
    /// at this level.
    pub(crate) active: Option<bool>,
    /// For an external plugin, its transport target (socket path / webhook URL); for a dynamic-library
    /// plugin, its library FILENAME in the plugins directory (the handle `DELETE` takes). `None` for
    /// compiled-in.
    pub(crate) target: Option<String>,
    /// The plugin's semantic version, from its signed sidecar manifest (dynamic-library plugins only).
    /// `None` for compiled-in/external, or a dynamic plugin with no/invalid manifest.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) version: Option<String>,
    /// The manifest's declared publisher (dynamic-library plugins with a manifest).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) publisher: Option<String>,
    /// The store C-ABI (`interface_version`) the manifest declares (dynamic-library plugins with a
    /// manifest). Operator-facing name for the "ABI" the engine speaks.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) interface_version: Option<u32>,
    /// The server-side trust verdict for a dynamic-library plugin, re-evaluated against the running
    /// `plugins.trust` posture: `"trusted"` (signed by an allowlisted publisher), `"unverified"`
    /// (loaded but not verified — the posture permits it), or `"rejected"` (the `halt` posture would
    /// refuse it). `None` for compiled-in/external.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) trust: Option<&'static str>,
    /// For a dynamic-library plugin: whether the library validated as a busbar store plugin the engine
    /// can load (ABI handshake). `None` for compiled-in/external.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) valid: Option<bool>,
    /// Why a dynamic-library plugin did not validate (`valid: false`) — a short, secret-free reason.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) error: Option<String>,
}

impl PluginView {
    /// A COMPILED-IN or EXTERNAL plugin row (no manifest metadata) — the historical shape. The
    /// dynamic-library fields (`version`/`publisher`/`interface_version`/`trust`/`valid`/`error`) are
    /// `None` and skip serialization, so the wire is byte-identical to before this addition.
    pub(crate) fn basic(
        name: String,
        r#type: &'static str,
        loader: &'static str,
        active: Option<bool>,
        target: Option<String>,
    ) -> Self {
        Self {
            name,
            r#type,
            loader,
            active,
            target,
            version: None,
            publisher: None,
            interface_version: None,
            trust: None,
            valid: None,
            error: None,
        }
    }
}

/// The result of installing a dynamic-library store plugin (`POST /api/v1/admin/plugins`). The
/// engine RE-VERIFIED the uploaded bytes against the running trust posture (the client is never
/// trusted), validated the ABI handshake, and atomically wrote the library (+ its manifest sidecar)
/// into the plugins directory. `active` takes effect on the next store (re)load — a store change
/// applies on restart / `store.module` apply, not as a hot swap (design: store install is
/// boot-time/config-apply). Additive-only; never a secret.
#[derive(Debug, Clone, Serialize)]
#[cfg_attr(feature = "openapi-schema", derive(schemars::JsonSchema))]
pub(crate) struct PluginInstallView {
    /// The library FILENAME written into the plugins directory (the handle `DELETE` takes).
    pub(crate) file: String,
    /// The plugin name from its manifest (or the filename when unsigned).
    pub(crate) name: String,
    /// The store C-ABI (`interface_version`) the engine validated the library against.
    pub(crate) interface_version: u32,
    /// The server-side trust verdict from the RE-VERIFY: `"trusted"` | `"unverified"`. (A `"rejected"`
    /// verdict is an error, never a success body.)
    pub(crate) trust: &'static str,
    /// The manifest version, when the upload carried a signed manifest.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) version: Option<String>,
    /// The manifest publisher, when signed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) publisher: Option<String>,
    /// A human note: this install is durable in the folder but takes effect on the next store (re)load.
    pub(crate) note: &'static str,
}

/// The result of removing a dynamic-library plugin (`DELETE /api/v1/admin/plugins/{file}`) — the
/// library and its manifest sidecar are deleted from the plugins directory. `204 No Content` is the
/// wire response; this view backs the OpenAPI schema for tooling that models a body.
#[derive(Debug, Clone, Serialize)]
#[cfg_attr(feature = "openapi-schema", derive(schemars::JsonSchema))]
pub(crate) struct PluginRemoveView {
    pub(crate) file: String,
    pub(crate) removed: bool,
}

/// The result of re-scanning the plugins directory (`POST /api/v1/admin/plugins/reload`): the
/// current dynamic-library inventory, each with its ABI-validity. Reconciles the reported set to the
/// folder (the folder is the source of truth), exactly as `config/reload` reconciles config to disk.
/// A store change still applies on the next store (re)load, not as a hot swap.
#[derive(Debug, Clone, Serialize)]
#[cfg_attr(feature = "openapi-schema", derive(schemars::JsonSchema))]
pub(crate) struct PluginReloadView {
    /// The dynamic-library plugins now present in the directory, sorted by filename.
    pub(crate) plugins: Vec<PluginView>,
    /// A human note on when a store change actually takes effect.
    pub(crate) note: &'static str,
}

/// The result of an EXPLICIT plugin ROLLBACK (`POST /api/v1/admin/plugins/rollback`, 1.5.0
/// rollback-friendly versioning): the operator deliberately pinned a plugin DOWN to a prior version and
/// the engine hot-swapped to that artifact. The pin is persisted (survives restart) and the trust
/// floor was lowered to EXACTLY the pinned version for THIS plugin — a lower artifact still cannot
/// load, and an automatic/silent replay of an old artifact is still refused (only this explicit,
/// audited action lowered the floor). Additive-only; never a secret.
#[derive(Debug, Clone, Serialize)]
#[cfg_attr(feature = "openapi-schema", derive(schemars::JsonSchema))]
pub(crate) struct PluginRollbackView {
    /// The plugin's canonical manifest name that was pinned.
    pub(crate) name: String,
    /// The library FILENAME the rollback selected in the plugins directory.
    pub(crate) file: String,
    /// The version the plugin was pinned DOWN to (now serving), from the target artifact's manifest.
    pub(crate) version: String,
    /// The manifest publisher of the pinned artifact (`busbar` = first-party).
    pub(crate) publisher: String,
    /// The now-live config version after the hot swap (the ETag the response also carries).
    pub(crate) config_version: u64,
    /// A human note on the rollback's semantics + durability.
    pub(crate) note: &'static str,
}

/// The ingress auth chain read (`GET /api/v1/admin/auth`): the ordered module names that authenticate
/// callers + the upstream-credential mode. Never a secret — module names and the mode are config
/// identifiers, not credentials. An empty `chain` is the open front door (admits every request).
#[derive(Debug, Clone, Serialize)]
#[cfg_attr(feature = "openapi-schema", derive(schemars::JsonSchema))]
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
// The generic list envelope. `rename = "Page_{T}"` interpolates the item type into the schema
// name so each instantiation (`Page_HookView`, `Page_ModelView`, …) is a DISTINCT
// `#/components/schemas/` entry — otherwise every `Page<T>` would collide on the bare name `Page`.
#[cfg_attr(feature = "openapi-schema", derive(schemars::JsonSchema))]
#[cfg_attr(feature = "openapi-schema", schemars(rename = "Page_{T}"))]
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
#[path = "tests/cursor_tests.rs"]
mod cursor_tests;

/// The EFFECTIVE config snapshot (`GET /api/v1/admin/config`) — the running configuration as busbar
/// resolved it, for drift detection (compare against your desired config) and one-shot inspection.
/// Composed from the same REDACTED reads as the individual endpoints (auth chain names, pool/model/
/// provider topology, hook definitions, global-hook wiring) — so it carries NO secret: no client
/// tokens, no provider keys, no hook payloads. Additive-only; the source-layer annotation (base vs
/// overlay) lands with the config overlay substrate.
#[derive(Debug, Clone, Serialize)]
#[cfg_attr(feature = "openapi-schema", derive(schemars::JsonSchema))]
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

/// Fleet METERING read (`GET /api/v1/admin/usage`) — the FinOps surface. Design principle:
/// busbar exposes the RAW INPUTS of cost, not just its own number. Every row carries the full token
/// SPLIT (input / output / cache-read / cache-creation — each prices differently), so a consumer
/// with its own (special/negotiated) price catalog reconstructs cost independently; `spend_micros`
/// is busbar's DERIVED estimate from the operator's configured global prices, computed at read time
/// (raw counts are what's stored — a price change re-prices history consistently).
///
/// Time base — THE PINNED SHAPE RULING (external review R3 #1): a usage response is ALWAYS exactly
/// ONE fixed UTC-day metering bucket (`window`). `?window=<bucket-start-epoch>` selects a PAST
/// bucket (default: the current one); a multi-window series is the CLIENT fetching N buckets — or
/// a future additive `?from=&to=` returning an ARRAY OF THIS SAME PER-BUCKET SHAPE, never a
/// differently-shaped merged view. Billing periods aggregate client-side from day buckets (raw
/// counts are stored, so the math is exact). Deliberately decoupled from per-key budget windows so
/// per-model aggregation across keys is well-defined; budget ENFORCEMENT state lives on
/// `GET /keys/{id}/usage`, not here. Empty aggregations when governance is disabled. No secrets —
/// key ids/names only, never a token.
///
/// LEDGER RULE (one loud contract sentence): `spend_micros` is a MUTABLE ESTIMATE — derived at
/// read time from the operator's CURRENT prices, so a price change re-prices history. Never store
/// it as a ledger charge; bill from the raw token split.
/// The denomination reported alongside every `spend_micros` in the admin usage response. A SINGLE
/// source of truth so a future removal (returning to the currency-agnostic stance) is one line.
/// Emitted ONLY on `GET /api/v1/admin/usage` (the `currency` field of `UsageView`), never on the
/// per-key views (those stay currency-agnostic raw-split ledgers).
pub(crate) const USAGE_CURRENCY: &str = "USD";

/// Serialize helper: `UsageView::currency` is a fixed contract constant, not a stored field.
fn serialize_usage_currency<S: serde::Serializer>(_: &(), s: S) -> Result<S::Ok, S::Error> {
    s.serialize_str(USAGE_CURRENCY)
}

#[derive(Debug, Clone, Serialize)]
#[cfg_attr(feature = "openapi-schema", derive(schemars::JsonSchema))]
pub(crate) struct UsageView {
    /// The UTC-day metering bucket this response aggregates: `[start, end)` epoch seconds.
    pub(crate) window: UsageWindow,
    /// Freshness marker: the epoch this read was computed at (counters accumulate live).
    pub(crate) as_of: u64,
    /// The denomination of every `spend_micros` in this response (`USAGE_CURRENCY`, currently
    /// `"USD"`). A single-const source of truth so removal is one line. Emitted only here.
    #[serde(serialize_with = "serialize_usage_currency")]
    #[cfg_attr(feature = "openapi-schema", schemars(with = "String"))]
    pub(crate) currency: (),
    pub(crate) total: UsageBreakdown,
    /// Per-(model, provider) aggregation — cost attribution by model (the FinOps unit).
    pub(crate) by_model: Vec<ModelUsageView>,
    /// Per-key aggregation (same raw-split shape). CAPPED at the top 1000 rows by spend (the
    /// FinOps-relevant ordering); `by_key_truncated` says the cap fired — never a silent cut.
    pub(crate) by_key: Vec<KeyUsageView>,
    /// True when `by_key` was truncated to the cap (a deployment with more active keys than the
    /// cap). `by_model` is never capped (bounded by the configured model fleet).
    pub(crate) by_key_truncated: bool,
    /// The summed remainder BEYOND the `by_key` cap — present exactly when `by_key_truncated`, so
    /// every unit of consumption is attributable at least to "others" (FinOps completeness:
    /// `total == sum(by_key) + others`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) others: Option<UsageBreakdown>,
}

/// A metering window: `[start, end)` epoch seconds.
#[derive(Debug, Clone, Copy, Serialize)]
#[cfg_attr(feature = "openapi-schema", derive(schemars::JsonSchema))]
pub(crate) struct UsageWindow {
    pub(crate) start: u64,
    pub(crate) end: u64,
}

/// The raw consumption counts + the derived spend estimate — the one shape shared by `total`,
/// `by_model` rows, and `by_key` rows, so a consumer writes ONE aggregation reader.
#[derive(Debug, Clone, Copy, Default, Serialize)]
#[cfg_attr(feature = "openapi-schema", derive(schemars::JsonSchema))]
pub(crate) struct UsageBreakdown {
    /// Uncached input tokens (normalized additive-cache convention).
    pub(crate) tokens_input: u64,
    pub(crate) tokens_output: u64,
    pub(crate) tokens_cache_read: u64,
    pub(crate) tokens_cache_creation: u64,
    pub(crate) requests: u64,
    /// Busbar's derived cost estimate in MICRO-units of the ABSTRACT cost unit (1e-6 unit -
    /// integer math, sub-cent precise, no float drift), recomputed at read time from the raw token
    /// split x the operator's CURRENT per-model rate card. Busbar attaches no currency - the rate
    /// card's numbers are whatever unit the operator priced in; display/denomination is entirely
    /// the consumer's concern. A consumer with its own per-model catalog recomputes from the raw
    /// token split instead.
    pub(crate) spend_micros: i64,
}

/// One (model, provider) row of the per-model aggregation.
#[derive(Debug, Clone, Serialize)]
#[cfg_attr(feature = "openapi-schema", derive(schemars::JsonSchema))]
pub(crate) struct ModelUsageView {
    pub(crate) model: String,
    pub(crate) provider: String,
    #[serde(flatten)]
    pub(crate) usage: UsageBreakdown,
}

/// One key's row of the per-key aggregation: the key id/name (never the secret) + its counts.
#[derive(Debug, Clone, Serialize)]
#[cfg_attr(feature = "openapi-schema", derive(schemars::JsonSchema))]
pub(crate) struct KeyUsageView {
    pub(crate) id: String,
    /// The key's display name; `None` when the key was deleted after metering accumulated (history
    /// outlives the key — the id still attributes it).
    pub(crate) name: Option<String>,
    #[serde(flatten)]
    pub(crate) usage: UsageBreakdown,
}

/// The admin-plane auth read (`GET /api/v1/admin/admin-auth`) — which modules guard the ADMIN surface
/// (distinct from the ingress `auth` chain). `modules` is the live `admin_auth` chain (the SAME
/// resource `PUT /api/v1/admin/admin-auth` writes), so a read-after-write is coherent. An empty chain is
/// the open (anonymous, full-authority) dev posture — `configured: false`. Never a secret.
#[derive(Debug, Clone, Serialize)]
#[cfg_attr(feature = "openapi-schema", derive(schemars::JsonSchema))]
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
#[cfg_attr(feature = "openapi-schema", derive(schemars::JsonSchema))]
pub(crate) struct ConfigValidateView {
    pub(crate) ok: bool,
    pub(crate) errors: Vec<String>,
}

#[cfg(test)]
#[path = "tests/tests.rs"]
mod tests;
