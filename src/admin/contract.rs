// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Matthew Jackson

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
            AdminError::Internal => "internal error".to_string(),
        }
    }
}

/// The compiled-in plugin catalog + topology + uptime returned by `GET /admin/v1/info`. Powers
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

/// A pool in the topology read (`GET /admin/v1/pools`). Summary shape today: name + the member
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

/// A model lane in the topology read (`GET /admin/v1/models`): the config key + its upstream
/// provider. No credentials, ever.
#[derive(Debug, Clone, Serialize)]
pub(crate) struct ModelView {
    pub(crate) model: String,
    pub(crate) provider: String,
}

/// A provider in the topology read (`GET /admin/v1/providers`): the provider name + how many model
/// lanes route through it.
#[derive(Debug, Clone, Serialize)]
pub(crate) struct ProviderView {
    pub(crate) provider: String,
    pub(crate) model_count: usize,
}

/// A hook definition in the registry read (`GET /admin/v1/hooks`, `GET /admin/v1/hooks/{name}`) — the
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
    /// Gate fallback on timeout/error/abstain: `"weighted"` | `"reject"` | `"first"`.
    pub(crate) on_error: &'static str,
    /// Gate decision deadline in milliseconds.
    pub(crate) timeout_ms: u64,
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

/// One plugin in the plugin catalog (`GET /admin/v1/plugins?type=`). A plugin is either
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

/// The ingress auth chain read (`GET /admin/v1/auth`): the ordered module names that authenticate
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
    /// A single-page result (no further pages). The topology reads are small and unpaginated today;
    /// keys/audit/versions get real cursoring as they land.
    pub(crate) fn single(items: Vec<T>) -> Self {
        Self {
            items,
            next_cursor: None,
        }
    }
}
