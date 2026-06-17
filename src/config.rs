// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Matthew Jackson

use std::collections::HashMap;
use std::fmt;

use serde::Deserialize;

// Re-export status_class_from_str for config validation
pub(crate) use crate::breaker::status_class_from_str;

/// Reject an env-var value that could break out of the surrounding YAML scalar when substituted
/// into the raw config text BEFORE parsing. `interpolate_env` splices each value in verbatim, so a
/// value carrying a YAML-structural control character — most critically a NEWLINE or carriage
/// return — can close the quoted scalar it sits inside and inject sibling YAML nodes (e.g. an extra
/// `client_tokens` entry, or a rewritten `admin_token`). Since both `client_tokens` and
/// `admin_token` are interpolated from env vars inside double-quoted scalars in the shipped
/// `config.yaml`, whoever controls those env vars (a CI pipeline, secret store, orchestrator) could
/// otherwise silently widen the auth allowlist without editing the config file.
///
/// No legitimate secret, token, URL, or path value contains a raw control character, so blocking
/// the entire C0 control range (plus DEL and the C1 NEL/LS/PS line-breaks YAML also treats as line
/// boundaries) closes the structural-injection vector with effectively zero false positives. A
/// double-quote or `#` on its own is harmless without a line break to terminate the current scalar,
/// and YAML's own quoting handles them, so we do not over-reject those.
fn reject_yaml_unsafe_value(var_name: &str, value: &str) -> Result<(), String> {
    if let Some(bad) = value.chars().find(|c| {
        // C0 controls (incl. \n, \r, \t, NUL) and DEL, plus the Unicode line/paragraph separators
        // and NEL that YAML treats as line breaks (U+0085 NEL, U+2028 LS, U+2029 PS).
        c.is_control() || matches!(c, '\u{2028}' | '\u{2029}')
    }) {
        return Err(format!(
            "environment variable '{var_name}' contains a control character (U+{:04X}) that could \
             inject YAML structure during config interpolation; remove it",
            bad as u32
        ));
    }
    Ok(())
}

/// Expand ${VAR} tokens from environment. Unset var → error (fail loud). A substituted value that
/// carries a YAML-structural control character is rejected (see `reject_yaml_unsafe_value`) so an
/// env var cannot break out of the quoted scalar it lands in and inject extra YAML nodes.
pub(crate) fn interpolate_env(s: &str) -> Result<String, String> {
    let mut result = String::with_capacity(s.len());
    let mut chars = s.chars().peekable();

    while let Some(ch) = chars.next() {
        if ch == '$' && chars.peek() == Some(&'{') {
            chars.next(); // consume '{'
            let mut var_name = String::new();
            let mut closed = false;
            for ch in chars.by_ref() {
                if ch == '}' {
                    closed = true;
                    break;
                }
                var_name.push(ch);
            }
            // The inner loop also exits when the iterator is exhausted, so a token with no closing
            // brace (e.g. `${FOO`) would otherwise be treated as `${FOO}` — silently succeeding if
            // FOO happens to be set, or reporting a misleading "unset variable" if it is not. Reject
            // the malformed token loudly instead so config typos surface at boot.
            if !closed {
                return Err(format!(
                    "unclosed variable reference starting at '${{{var_name}'"
                ));
            }
            if var_name.is_empty() {
                return Err("empty variable name in ${}".into());
            }
            let value = std::env::var(&var_name)
                .map_err(|_| format!("unset environment variable: {}", var_name))?;
            // Reject a structurally-unsafe value BEFORE splicing it in, so it cannot break out of
            // the surrounding YAML scalar and inject sibling nodes (e.g. extra client_tokens).
            reject_yaml_unsafe_value(&var_name, &value)?;
            result.push_str(&value);
        } else {
            result.push(ch);
        }
    }

    Ok(result)
}

/// The fully-resolved runtime config. NOT deserialized from YAML: the on-disk shape is `DeployCfg`
/// (+ provider definitions), and `RootCfg` is constructed exclusively by [`resolve`]. It therefore
/// carries no `Deserialize` derive and no field-level serde defaults — those would be inert, and
/// implying a YAML parse path here would mislead a reader into reasoning about defaults that never
/// fire.
#[derive(Debug)]
pub(crate) struct RootCfg {
    pub(crate) listen: String,
    /// Optional native inbound TLS. `None` ⇒ plain HTTP (today's path, byte-for-byte).
    pub(crate) tls: Option<TlsCfg>,
    pub(crate) auth: Option<AuthCfg>,
    pub(crate) providers: HashMap<String, ProviderCfg>,
    pub(crate) models: HashMap<String, ModelCfg>,
    pub(crate) pools: HashMap<String, PoolCfg>,
    /// Operator-supplied additions to the hardcoded cloud-metadata denylist (see
    /// [`SecurityCfg::blocked_metadata_hosts`]). Resolved from `DeployCfg.security`; empty when no
    /// `security:` block is present. Threaded into `config_validate::validate` so a provider
    /// `base_url` (and any path-override composition) targeting one of these hosts is rejected at
    /// boot unless that host is carved out by an allow-override.
    pub(crate) blocked_metadata_hosts: Vec<String>,
    /// Global SURGICAL allow-override: cloud-metadata hosts/IPs to UNBLOCK for ALL providers
    /// (`security.allow_metadata_hosts`). Unioned with each provider's own `allow_metadata_hosts`
    /// when the guard runs; a host on the denylist is permitted iff it appears in this union (or
    /// `allow_all_metadata` is set). Matched with the same canonicalization as the block check (an IP
    /// entry unblocks all its spellings). Default empty.
    pub(crate) allow_metadata_hosts: Vec<String>,
    /// Nuclear override (`security.allow_all_metadata`): when true the metadata SSRF guard is fully
    /// DISABLED — every cloud-metadata endpoint is reachable by every provider. Logs a startup WARN.
    /// Default false.
    pub(crate) allow_all_metadata: bool,
}

/// Native inbound TLS configuration for the client↔Busbar hop. Absent (`Config.tls == None`) ⇒
/// Busbar serves plain HTTP exactly as before. Present ⇒ Busbar terminates TLS itself; if
/// `client_ca_file` is also set, it additionally requires and verifies a client certificate (mTLS).
/// All three paths are PEM files on the operator's host; they are loaded once at startup and any
/// load/parse error is fatal (`die`). Key bytes are never logged.
#[derive(Deserialize, Clone, Debug)]
pub(crate) struct TlsCfg {
    /// PEM certificate chain, leaf first (e.g. fullchain.pem).
    pub(crate) cert_file: String,
    /// PEM private key matching the leaf cert (PKCS#8, PKCS#1, or SEC1).
    pub(crate) key_file: String,
    /// PEM CA bundle to verify client certs against. `Some` ⇒ mTLS required: a client must present
    /// a cert chaining to this CA to complete the handshake at all. `None` ⇒ server-only TLS.
    #[serde(default)]
    pub(crate) client_ca_file: Option<String>,
}

#[derive(Deserialize, Clone)]
pub(crate) struct AuthCfg {
    #[serde(default = "default_auth_mode")]
    pub(crate) mode: String,
    #[deprecated(since = "0.1.0", note = "use client_tokens allowlist instead")]
    #[serde(rename = "token", default)]
    pub(crate) _legacy_token: Option<String>,
    #[serde(default)]
    pub(crate) client_tokens: Vec<String>,
}

// MANUAL Debug that REDACTS every credential field. A derived `Debug` would print every entry of
// `client_tokens` AND the deprecated `_legacy_token` in PLAINTEXT — a latent credential leak the
// moment an `AuthCfg` (or any struct that embeds it, e.g. `RootCfg`/`DeployCfg`) is debug-logged.
// Print only the COUNT of allowlist tokens and presence of the legacy token, never the values (and
// never any prefix/suffix, which would be a partial-secret oracle). Mirrors `auth::AuthMiddleware`.
impl fmt::Debug for AuthCfg {
    #[allow(deprecated)] // reading the deprecated field solely to redact it
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AuthCfg")
            .field("mode", &self.mode)
            .field(
                "_legacy_token",
                &if self._legacy_token.is_some() {
                    "<redacted; present>"
                } else {
                    "<absent>"
                },
            )
            .field(
                "client_tokens",
                &format_args!("<redacted; {} configured>", self.client_tokens.len()),
            )
            .finish()
    }
}

impl AuthCfg {
    /// Normalize legacy single-token format into allowlist.
    #[allow(deprecated)] // accessing deprecated field for normalization logic
    pub(crate) fn normalize(mut self) -> Self {
        if let Some(tok) = self._legacy_token.take() {
            // If client_tokens is empty and we have legacy token, promote it.
            if self.client_tokens.is_empty() {
                self.client_tokens.push(tok);
            } else {
                // Both the deprecated `token` and the `client_tokens` allowlist were
                // supplied. The allowlist wins and the legacy token is discarded; warn
                // so the operator notices their `token:` is being ignored rather than
                // silently merged (which could otherwise mask a stale credential).
                // `normalize` returns Self with no error channel, so we warn rather
                // than fail.
                tracing::warn!(
                    "auth config specifies both the deprecated `token` and a non-empty \
                     `client_tokens` allowlist; the legacy `token` is being ignored. Remove \
                     `token:` and add its value to `client_tokens` if it should remain valid."
                );
            }
        }
        self
    }

    /// Create a default AuthCfg for initialization.
    #[allow(deprecated)] // accessing deprecated field in constructor
    pub(crate) fn default_none() -> Self {
        Self {
            mode: crate::auth::AuthMode::NONE.to_string(),
            _legacy_token: None,
            client_tokens: vec![],
        }
    }
}

fn default_auth_mode() -> String {
    crate::auth::AuthMode::NONE.to_string()
}

#[derive(Deserialize)]
pub(crate) struct ProviderCfg {
    #[serde(default = "default_protocol")]
    pub(crate) protocol: String,
    pub(crate) base_url: String,
    pub(crate) api_key_env: String,
    /// Active health-probe settings for this provider's lanes (mode + interval + timeout).
    #[serde(default)]
    pub(crate) health: Option<HealthCfg>,
    // error_map is REQUIRED on every provider — NO default (fail loud if missing)
    pub(crate) error_map: HashMap<String, String>,
    /// Optional upstream request-path override (see ProviderDef::path).
    #[serde(default)]
    pub(crate) path: Option<String>,
    /// Optional auth-style override (see ProviderDef::auth).
    #[serde(default)]
    pub(crate) auth: Option<String>,
    /// Per-provider SURGICAL escape hatch: the cloud-metadata hosts/IPs to UNBLOCK for THIS
    /// provider's `base_url` (and path-override composition) only. Each entry carves a single
    /// exception out of the metadata denylist (hardcoded ∪ `security.blocked_metadata_hosts`) — e.g.
    /// `allow_metadata_hosts: ["169.254.169.254"]` lets only this provider reach IMDS while every
    /// OTHER metadata endpoint (and every other provider) stays blocked. An entry is matched with the
    /// SAME canonicalization as the block check, so an IP entry also unblocks its obfuscated spellings
    /// (decimal-int, IPv4-mapped IPv6, trailing-dot). For an everywhere-unblock use
    /// `security.allow_metadata_hosts`; for a full disable use `security.allow_all_metadata`.
    /// Loopback / RFC-1918 / CGNAT / public targets are allowed regardless — a client never chooses a
    /// provider URL (model NAME → operator pool → operator URL), so private upstreams pose no
    /// client-driven SSRF and local models (Ollama / vLLM) "just work" with no entry. Default empty
    /// (all metadata blocked).
    #[serde(default)]
    pub(crate) allow_metadata_hosts: Vec<String>,
    // Future fields (parse and be inert):
    #[serde(default, rename = "api_key")]
    pub(crate) _legacy_api_key: Option<String>,
}

// MANUAL Debug that REDACTS the legacy inline API key. A derived `Debug` would print
// `_legacy_api_key` in PLAINTEXT — a latent credential leak if a `ProviderCfg` (or `RootCfg`, which
// holds them) is debug-logged. `api_key_env` is only the NAME of an env var, not the secret, so it
// stays. Print presence only for the legacy key, never the value.
impl fmt::Debug for ProviderCfg {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ProviderCfg")
            .field("protocol", &self.protocol)
            .field("base_url", &self.base_url)
            .field("api_key_env", &self.api_key_env)
            .field("health", &self.health)
            .field("error_map", &self.error_map)
            .field("path", &self.path)
            .field("auth", &self.auth)
            .field("allow_metadata_hosts", &self.allow_metadata_hosts)
            .field(
                "_legacy_api_key",
                &if self._legacy_api_key.is_some() {
                    "<redacted; present>"
                } else {
                    "<absent>"
                },
            )
            .finish()
    }
}

fn default_protocol() -> String {
    "anthropic".to_string()
}

/// Active health-probe mode for a provider's lanes.
#[derive(Debug, Deserialize, Clone, Copy, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub(crate) enum HealthMode {
    /// No active probing. Health is inferred purely from organic traffic (the breaker trips on
    /// real failures and recovers via the half-open probe). This is the default.
    #[default]
    None,
    /// Periodically re-probe ONLY lanes that are currently tripped (Open/HalfOpen), so a recovered
    /// upstream is picked back up promptly instead of waiting for organic traffic to probe it.
    Dead,
    /// Periodically probe EVERY lane, so a silently-dead upstream is tripped out before real
    /// traffic hits it. Sends a tiny billable request per interval — opt-in.
    Active,
}

#[derive(Debug, Deserialize, Clone)]
pub(crate) struct HealthCfg {
    /// Probing strategy (see `HealthMode`). Defaults to `none` — a `health:` block with only an
    /// interval does nothing until a mode is chosen.
    #[serde(default)]
    pub(crate) mode: HealthMode,
    /// Seconds between probes for this provider's lanes (default 30, floored at 1).
    #[serde(default)]
    pub(crate) interval_secs: Option<u64>,
    /// Per-probe request timeout in seconds (default 5, floored at 1).
    #[serde(default)]
    pub(crate) timeout_secs: Option<u64>,
}

#[derive(Debug, Deserialize, Clone)]
pub(crate) struct ModelCfg {
    #[serde(default = "neg1")]
    pub(crate) max_requests: i64,
    pub(crate) provider: String,
    pub(crate) max_concurrent: usize,
    /// Default max output tokens injected when a cross-protocol translation targets a backend that
    /// REQUIRES `max_tokens` (Anthropic Messages) and the source request omitted it (legal for
    /// OpenAI). Unset falls back to `crate::proto::DEFAULT_MAX_TOKENS`. Must be > 0 when set.
    #[serde(default)]
    pub(crate) default_max_tokens: Option<u32>,
}

fn neg1() -> i64 {
    -1
}

#[derive(Debug, Clone)]
pub(crate) struct PoolCfg {
    pub(crate) members: Vec<PoolMember>,
    /// Per-pool breaker settings (resolved into `store::BreakerCfg` at startup; drives trip
    /// thresholds and cooldown backoff for this pool's lanes).
    pub(crate) breaker: Option<BreakerCfg>,
    pub(crate) failover: Option<FailoverCfg>,
    pub(crate) on_exhausted: Option<OnExhaustedCfg>,
    pub(crate) affinity: Option<AffinityCfg>,
    /// Routing transport for this pool. `weighted` (the default, also the absent case) is today's
    /// SWRR with ZERO added cost — no `RoutingPolicy` object is constructed and the hot path is
    /// byte-identical to the pre-feature behavior. Any other value resolves a pluggable policy that
    /// runs ONCE before the failover loop to produce a ranked member preference.
    ///
    /// Populated by [`PoolCfg`]'s manual `Deserialize`, which also desugars the NATIVE SHORTHANDS:
    /// `route: cheapest` / `fastest` / `least_busy` / `usage` all map to `RouteKind::Native` with the
    /// policy name folded into `policy.name` (see below), so the long form (`route: native` +
    /// `policy.name: cheapest`) and the short form are byte-identical after load. `route: weighted`
    /// (long or short) stays plain `RouteKind::Weighted` (the zero-cost default), NOT a native object.
    pub(crate) route: RouteKind,
    /// Per-transport policy configuration (URL/script/native-name/timeout/on_error). Inert when
    /// `route: weighted`. For a native shorthand the resolved `name` is synthesized here so the
    /// native registry lookup in `routing::resolve_policy` sees a single canonical shape.
    pub(crate) policy: Option<PolicyCfg>,
}

/// Manual `Deserialize` for [`PoolCfg`] so the `route:` key accepts the NATIVE SHORTHANDS in
/// addition to the long transport names. A bare `route: cheapest` (or `fastest` / `least_busy` /
/// `usage`) desugars to `RouteKind::Native` with `policy.name` set to that shorthand, so the rest of
/// the codebase only ever sees the canonical `(route: native, policy.name: <native>)` shape — the
/// long form keeps working unchanged. `route: weighted` (long or short) stays `RouteKind::Weighted`
/// (the zero-cost default); `webhook` / `script` / `native` keep their existing meaning. An explicit
/// `policy.name` is never overwritten by the shorthand (a long-form config wins).
impl<'de> Deserialize<'de> for PoolCfg {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        // Raw mirror of the on-disk shape. `route` is captured as a free string so we can recognize
        // the native shorthands that `RouteKind`'s snake_case enum cannot express on its own.
        #[derive(Deserialize)]
        struct RawPoolCfg {
            #[serde(default)]
            members: Vec<PoolMember>,
            #[serde(default)]
            breaker: Option<BreakerCfg>,
            #[serde(default)]
            failover: Option<FailoverCfg>,
            #[serde(default)]
            on_exhausted: Option<OnExhaustedCfg>,
            #[serde(default)]
            affinity: Option<AffinityCfg>,
            #[serde(default)]
            route: Option<String>,
            #[serde(default)]
            policy: Option<PolicyCfg>,
        }

        let raw = RawPoolCfg::deserialize(deserializer)?;
        // Desugar `route:` into `(RouteKind, Option<native shorthand name>)`. Unknown values are a
        // hard error (matching serde's enum behavior), so a typo in `route:` still fails loudly.
        let (route, shorthand_name): (RouteKind, Option<&'static str>) = match raw.route.as_deref()
        {
            None | Some("weighted") => (RouteKind::Weighted, None),
            Some("webhook") => (RouteKind::Webhook, None),
            Some("script") => (RouteKind::Script, None),
            Some("native") => (RouteKind::Native, None),
            // Native shorthands: a bare policy name in `route:` ⇒ Native + that name in policy.name.
            Some("cheapest") => (RouteKind::Native, Some("cheapest")),
            Some("fastest") => (RouteKind::Native, Some("fastest")),
            Some("least_busy") => (RouteKind::Native, Some("least_busy")),
            Some("usage") => (RouteKind::Native, Some("usage")),
            Some(other) => {
                return Err(serde::de::Error::custom(format!(
                    "unknown route '{other}': expected one of weighted, webhook, script, native, \
                     or a native shorthand (cheapest, fastest, least_busy, usage)"
                )));
            }
        };

        // Fold the shorthand name into `policy.name` so downstream resolution sees one canonical
        // shape. An explicit long-form `policy.name` always wins (never overwritten).
        let mut policy = raw.policy;
        if let Some(name) = shorthand_name {
            // NOTE: `PolicyCfg::default()` leaves `timeout_ms = 0` because serde's
            // `default = "default_policy_timeout_ms"` only fires on the deserialize path, never on a
            // code-built struct. A shorthand pool (`route: cheapest`) has no `policy:` block on disk,
            // so without this the desugared cfg would carry a 0ms policy timeout → an instant
            // deadline at `resolve_policy`. Stamp the real default on a freshly-synthesized cfg.
            let needs_default_timeout = policy.is_none();
            let p = policy.get_or_insert_with(PolicyCfg::default);
            if needs_default_timeout {
                p.timeout_ms = DEFAULT_POLICY_TIMEOUT_MS;
            }
            if p.name.is_none() {
                p.name = Some(name.to_string());
            }
        }

        Ok(PoolCfg {
            members: raw.members,
            breaker: raw.breaker,
            failover: raw.failover,
            on_exhausted: raw.on_exhausted,
            affinity: raw.affinity,
            route,
            policy,
        })
    }
}

/// The routing transport for a pool. Resolved ONCE at config load into a runtime policy enum so the
/// hot path never branches on a string; the default `Weighted` arm builds no policy object at all.
#[derive(Debug, Deserialize, Clone, Default, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub(crate) enum RouteKind {
    /// Today's smooth-weighted-round-robin (SWRR). Default and also the absent case. Zero added cost.
    #[default]
    Weighted,
    /// An operator-run HTTP sidecar that returns a ranked member preference.
    Webhook,
    /// An embedded Rhai script (behind the `script-policy` cargo feature) returning a ranked order.
    Script,
    /// A Busbar-native policy selected by `policy.name` (e.g. `cheapest`/`fastest`/`least_busy`/
    /// `usage`/`weighted`).
    Native,
}

/// Behavior when a policy times out, errors, abstains, or saturates. `Weighted` (default) is the
/// non-negotiable safety stance: a broken/slow policy is indistinguishable from no policy and NEVER
/// blocks or fails a request. `Reject` is fail-closed (503). `First` uses the configured member
/// order (a deterministic degraded pick).
#[derive(Debug, Deserialize, Clone, Default, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub(crate) enum PolicyOnError {
    #[default]
    Weighted,
    Reject,
    First,
}

/// Per-pool policy configuration. All transports share `timeout_ms`/`on_error`; the transport-specific
/// fields (`url`, `script`/`script_file`, `name`) are validated against `route` at startup.
// The transport-specific fields (`url`, `script`/`script_file`, `name`) are consumed by
// `routing::resolve_policy` at config load to construct the matching transport, and validated against
// `route` at startup.
#[derive(Debug, Deserialize, Clone, Default)]
pub(crate) struct PolicyCfg {
    // ── webhook transport ────────────────────────────────────────────────────────────────────────
    /// The operator sidecar URL. Validated by the routing-URL SSRF guard (loopback allowed, IMDS/
    /// RFC1918/CGNAT/metadata blocked — the OTLP precedent). Required when `route: webhook`.
    #[serde(default)]
    pub(crate) url: Option<String>,
    // ── shared ───────────────────────────────────────────────────────────────────────────────────
    /// Hard wall-clock deadline for the policy decision, in milliseconds (default 150). On timeout
    /// the decision is coerced to `on_error`.
    #[serde(default = "default_policy_timeout_ms")]
    pub(crate) timeout_ms: u64,
    /// Fallback behavior on timeout/error/abstain/saturation (default `weighted`).
    #[serde(default)]
    pub(crate) on_error: PolicyOnError,
    // ── script transport ─────────────────────────────────────────────────────────────────────────
    /// Inline Rhai source. Exactly one of `script`/`script_file` is required when `route: script`.
    /// Read by `routing::resolve_policy`'s script arm, which is gated on the `script-policy` feature;
    /// the default build parses the field (configs round-trip) but compiles out the only reader.
    #[serde(default)]
    #[cfg_attr(not(feature = "script-policy"), allow(dead_code))]
    pub(crate) script: Option<String>,
    /// Path to a Rhai script file. Alternative to inline `script`. Same `script-policy`-gated reader.
    #[serde(default)]
    #[cfg_attr(not(feature = "script-policy"), allow(dead_code))]
    pub(crate) script_file: Option<String>,
    // ── native transport ─────────────────────────────────────────────────────────────────────────
    /// Native policy name (`weighted`/`cheapest`/`fastest`/`least_busy`/`usage`). Required when
    /// `route: native`.
    #[serde(default)]
    pub(crate) name: Option<String>,
}

/// The default hard wall-clock deadline for a policy decision, in milliseconds. Used by serde's
/// `default = "default_policy_timeout_ms"` AND applied explicitly to code-built `PolicyCfg`s (the
/// native-shorthand desugar, where `PolicyCfg::default()` would otherwise leave `timeout_ms = 0`
/// because serde defaults only fire on deserialize). Also the single source of truth consumed at the
/// resolution sites in `routing/mod.rs`.
pub(crate) const DEFAULT_POLICY_TIMEOUT_MS: u64 = 150;

fn default_policy_timeout_ms() -> u64 {
    DEFAULT_POLICY_TIMEOUT_MS
}

#[derive(Debug, Deserialize, Clone)]
pub(crate) struct PoolMember {
    pub(crate) target: String,
    #[serde(default = "default_weight")]
    pub(crate) weight: u32,
    #[serde(default)]
    pub(crate) context_max: Option<usize>,
    /// Operator-declared routing tier (e.g. `"large"`/`"small"`/`"primary"`/`"overflow"`). Projected
    /// into the routing `Candidate` (via `MemberMeta`) and read by webhook/script policies.
    #[serde(default)]
    pub(crate) tier: Option<String>,
    /// Operator-declared cost in currency-units per million tokens. Drives the native `cheapest`
    /// policy and is exposed to webhook/script policies. Inert when unset.
    #[serde(default)]
    pub(crate) cost_per_mtok: Option<f64>,
    /// Free-form operator tags (e.g. `["opus"]`) a policy can match on. Projected into the routing
    /// `Candidate` and read by webhook/script policies.
    #[serde(default)]
    pub(crate) tags: Vec<String>,
}

fn default_weight() -> u32 {
    1
}

/// Trip mode for breaker configuration.
#[derive(Debug, Deserialize, Clone, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub(crate) enum BreakerTripMode {
    #[default]
    ErrorRate,
    Consecutive,
}

/// Trip configuration parameters (ADR-0002 defaults).
#[derive(Debug, Deserialize, Clone, Default)]
pub(crate) struct BreakerTripConfig {
    #[serde(default = "default_trip_mode")]
    pub(crate) mode: BreakerTripMode,
    #[serde(default = "default_window_s")]
    pub(crate) window_s: u64,
    #[serde(default = "default_threshold")]
    pub(crate) threshold: f64,
    #[serde(default = "default_min_requests")]
    pub(crate) min_requests: usize,
    /// Consecutive-failure threshold for `BreakerTripMode::Consecutive`. Field name kept as `n` to
    /// preserve the operator config schema (`trip.n`) — do not rename.
    #[serde(default = "default_consecutive_n")]
    pub(crate) n: u32,
}

fn default_trip_mode() -> BreakerTripMode {
    BreakerTripMode::ErrorRate
}

fn default_window_s() -> u64 {
    30
}

fn default_threshold() -> f64 {
    0.5
}

fn default_min_requests() -> usize {
    5
}

fn default_consecutive_n() -> u32 {
    3
}

/// Breaker configuration per pool with full trip settings (ADR-0002).
#[derive(Debug, Deserialize, Clone)]
pub(crate) struct BreakerCfg {
    #[serde(default = "default_cooldown")]
    pub(crate) base_cooldown_secs: u64,
    #[serde(default = "default_max_cooldown")]
    pub(crate) max_cooldown_secs: u64,
    #[serde(default)]
    pub(crate) trip: Option<BreakerTripConfig>,
}

impl Default for BreakerCfg {
    fn default() -> Self {
        // Delegate to the serde-default fns so the `breaker:`-omitted path (this `Default`) and the
        // per-field-omitted path (`#[serde(default = ...)]`) share a single source of truth for the
        // cooldown literals and cannot drift. See `breaker_cfg_default_matches_serde_default_fns`.
        Self {
            base_cooldown_secs: default_cooldown(),
            max_cooldown_secs: default_max_cooldown(),
            trip: Some(BreakerTripConfig::default()),
        }
    }
}

fn default_cooldown() -> u64 {
    // Single source of truth for the base cooldown: both `BreakerCfg::default()` (used when a pool
    // omits the `breaker:` block) and `#[serde(default = "default_cooldown")]` (used when the block
    // is present but omits `base_cooldown_secs`) route through here, so the value is a consistent
    // 15s on every path.
    15
}

fn default_max_cooldown() -> u64 {
    120
}

#[derive(Debug, Deserialize, Clone)]
pub(crate) struct FailoverCfg {
    #[serde(default = "default_failover_deadline")]
    pub(crate) deadline_secs: u64,
    /// Member model names excluded from this pool's candidate set — never selected (primary or
    /// failover). A per-pool blocklist for temporarily benching a member without editing `members`.
    #[serde(default)]
    pub(crate) exclusions: Option<Vec<String>>,
    #[serde(default = "default_cap")]
    pub(crate) cap: usize,
}

/// Default failover wall-clock budget (seconds) when a pool doesn't set `failover.deadline_secs`.
pub(crate) const DEFAULT_FAILOVER_DEADLINE_SECS: u64 = 120;
/// Default maximum failover hops per request when a pool doesn't set `failover.cap`.
pub(crate) const DEFAULT_FAILOVER_CAP: usize = 3;

fn default_failover_deadline() -> u64 {
    DEFAULT_FAILOVER_DEADLINE_SECS
}

fn default_cap() -> usize {
    DEFAULT_FAILOVER_CAP
}

#[derive(Debug, Deserialize, Clone)]
pub(crate) struct OnExhaustedCfg {
    #[serde(default = "default_on_exhausted_action")]
    pub(crate) action: String,
}

fn default_on_exhausted_action() -> String {
    "reject".to_string()
}

/// Pool exhaustion mode configuration.
/// Maps from config string `action` field to executable behavior when all members are tripped/excluded.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum OnExhausted {
    /// Status503: return 503 Service Unavailable with Retry-After header
    /// set to the soonest member's cooldown expiry.
    Status503,
    /// FallbackPool(name): route to a configured fallback pool by name.
    /// Guard against loops via depth cap (max 1) or visited pool tracking.
    FallbackPool(String),
    /// LeastBad: send to the member with soonest cooldown expiry even though Open.
    /// Log loudly that this is a degraded path.
    LeastBad,
}

impl OnExhausted {
    /// Parse an action string from config into an OnExhausted variant.
    /// Returns Err(String) for unknown actions - NO bare _ => allowed.
    pub(crate) fn parse(action: &str) -> Result<Self, String> {
        match action {
            "reject" | "503" | "status_503" => Ok(OnExhausted::Status503),
            "fallback_pool" => Err("fallback_pool requires a pool name argument".into()),
            "least_bad" | "least-bad" | "leastbad" => Ok(OnExhausted::LeastBad),
            // FallbackPool with name - parse as "fallback_pool:<pool_name>" format
            s if s.starts_with("fallback_pool:") => {
                let pool_name = &s["fallback_pool:".len()..];
                if pool_name.is_empty() {
                    Err("fallback_pool requires a non-empty pool name".into())
                } else {
                    Ok(OnExhausted::FallbackPool(pool_name.to_string()))
                }
            }
            // Explicit handling of common typos/variants for clarity
            "status503" => Ok(OnExhausted::Status503),
            "fallback" | "failover" => Err(format!(
                "'{}' is not a valid on_exhausted action; use 'fallback_pool:<pool_name>'",
                action
            )),
            // Unknown actions - explicit error, NO _ => catch-all
            unknown => Err(format!(
                "unknown on_exhausted action '{}': valid values are 'reject', '503', 'status_503', 'fallback_pool:<name>', or 'least_bad'",
                unknown
            )),
        }
    }
}

#[derive(Debug, Deserialize, Clone)]
pub(crate) struct AffinityCfg {
    /// Affinity mode. `session` (the default and only supported mode) pins a session to a lane
    /// using the header named by `header_name`.
    #[serde(default = "default_affinity_mode")]
    pub(crate) mode: String,
    /// Request header carrying the session id (defaults to `x-session-id` when unset).
    #[serde(default)]
    pub(crate) header_name: Option<String>,
}

fn default_affinity_mode() -> String {
    "session".to_string()
}

fn default_listen() -> String {
    "0.0.0.0:8080".into()
}

/// Provider definition - vetted knowledge shipped in providers.yaml (no keys).
#[derive(Debug, Deserialize, Clone)]
pub(crate) struct ProviderDef {
    pub(crate) protocol: String,
    pub(crate) base_url: String,
    #[serde(default)]
    pub(crate) error_map: HashMap<String, String>,
    #[serde(default)]
    pub(crate) health: Option<HealthCfg>,
    /// Optional override of the upstream request path appended to `base_url`. Defaults to the
    /// protocol's standard path. Use it for OpenAI-compatible providers that embed the API version
    /// in `base_url` and serve `/chat/completions` (no `/v1`), e.g. `base_url: .../api/paas/v4` +
    /// `path: /chat/completions`.
    #[serde(default)]
    pub(crate) path: Option<String>,
    /// Optional auth-style override. Defaults to the protocol's native auth (bearer for
    /// openai/anthropic/responses, `x-goog-api-key` for gemini, SigV4 for bedrock). Set to
    /// `api-key` for backends that authenticate with an `api-key: <key>` header instead of a
    /// bearer token — e.g. Azure OpenAI (which also carries `?api-version=` and the deployment in
    /// its `path`). Recognized values: `bearer` (default) | `api-key`.
    #[serde(default)]
    pub(crate) auth: Option<String>,
    /// Catalog default for the per-provider metadata allow-override (see
    /// `ProviderCfg::allow_metadata_hosts`). A deployment's `allow_metadata_hosts` (`Some`) replaces
    /// this; `None` falls back to the catalog list. Default empty (all metadata blocked).
    #[serde(default)]
    pub(crate) allow_metadata_hosts: Vec<String>,
}

/// Provider deployment - operator config in config.yaml (names provider + supplies key).
#[derive(Deserialize, Clone, Default)]
pub(crate) struct ProviderDeploy {
    pub(crate) api_key_env: String,
    #[serde(default)]
    pub(crate) protocol: Option<String>,
    #[serde(default)]
    pub(crate) base_url: Option<String>,
    #[serde(default)]
    pub(crate) error_map: Option<HashMap<String, String>>,
    /// Optional upstream request-path override (see ProviderDef::path).
    #[serde(default)]
    pub(crate) path: Option<String>,
    /// Optional auth-style override (see ProviderDef::auth).
    #[serde(default)]
    pub(crate) auth: Option<String>,
    /// Per-provider metadata allow-override (see `ProviderCfg::allow_metadata_hosts`). `Some` REPLACES
    /// the catalog default; `None` falls back to the catalog's `allow_metadata_hosts`.
    #[serde(default)]
    pub(crate) allow_metadata_hosts: Option<Vec<String>>,
    /// Optional active health-probe settings (see ProviderDef::health). Overrides the catalog's
    /// `health` when set; this is the block the shipped `config.yaml` documents under a provider.
    #[serde(default)]
    pub(crate) health: Option<HealthCfg>,
    /// Legacy inline `api_key:` under a provider. Captured ONLY so an operator who sets it (the
    /// field name invites the mistake) gets a loud boot warning that inline keys are unsupported and
    /// `api_key_env` must be used — rather than the value being silently dropped by serde with no
    /// signal. busbar never reads a key from here; `resolve()` warns and discards it.
    #[serde(default, rename = "api_key")]
    pub(crate) _legacy_api_key: Option<String>,
}

// MANUAL Debug that REDACTS the legacy inline API key. A derived `Debug` would print
// `_legacy_api_key` in PLAINTEXT — a latent credential leak if a `ProviderDeploy` (or `DeployCfg`,
// which holds them) is debug-logged. `api_key_env` is only the NAME of an env var, not the secret,
// so it stays. Print presence only for the legacy key, never the value.
impl fmt::Debug for ProviderDeploy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ProviderDeploy")
            .field("api_key_env", &self.api_key_env)
            .field("protocol", &self.protocol)
            .field("base_url", &self.base_url)
            .field("error_map", &self.error_map)
            .field("path", &self.path)
            .field("auth", &self.auth)
            .field("allow_metadata_hosts", &self.allow_metadata_hosts)
            .field("health", &self.health)
            .field(
                "_legacy_api_key",
                &if self._legacy_api_key.is_some() {
                    "<redacted; present>"
                } else {
                    "<absent>"
                },
            )
            .finish()
    }
}

/// Deployment configuration - operator-owned config.yaml structure.
#[derive(Debug, Deserialize)]
pub(crate) struct DeployCfg {
    #[serde(default = "default_listen")]
    pub(crate) listen: String,
    /// Optional native inbound TLS / mTLS. Absent ⇒ plain HTTP (unchanged default).
    #[serde(default)]
    pub(crate) tls: Option<TlsCfg>,
    pub(crate) auth: Option<AuthCfg>,
    pub(crate) providers: HashMap<String, ProviderDeploy>,
    pub(crate) models: HashMap<String, ModelCfg>,
    /// Pools are optional: a deployment can route to models directly (`/<model>/v1/messages`)
    /// without defining any pool.
    #[serde(default)]
    pub(crate) pools: HashMap<String, PoolCfg>,
    /// Optional observability sinks (OTLP traces + request-log webhook). Metrics
    /// (`/metrics`) are always on and need no config.
    #[serde(default)]
    pub(crate) observability: Option<ObservabilityCfg>,
    /// optional governance (virtual keys, budgets, rate limits). Absent = disabled.
    #[serde(default)]
    pub(crate) governance: Option<GovernanceCfg>,
    /// Optional security controls. Today this carries only `blocked_metadata_hosts`, the operator
    /// extension to the hardcoded cloud-metadata SSRF denylist. Absent ⇒ only the hardcoded denylist
    /// applies.
    #[serde(default)]
    pub(crate) security: Option<SecurityCfg>,
}

/// Operator-owned security controls (config.yaml `security:` block).
#[derive(Debug, Deserialize, Clone, Default)]
pub(crate) struct SecurityCfg {
    /// Additional hosts/IPs APPENDED to the hardcoded cloud-metadata denylist. A provider `base_url`
    /// resolving to any of these is rejected at boot (unless carved out by an allow-override),
    /// exactly like the built-in metadata endpoints. This is the answer to "an unknown cloud's
    /// metadata IP/hostname is not in the built-in list" — add it here. Entries may be IP literals
    /// (matched against the resolved host, including the obfuscation-decoded forms) or DNS hostnames
    /// (matched case-insensitively, trailing dot stripped). Default empty.
    #[serde(default)]
    pub(crate) blocked_metadata_hosts: Vec<String>,
    /// Global SURGICAL allow-override: hosts/IPs to UNBLOCK from the cloud-metadata denylist for ALL
    /// providers. Carves a single exception out of the denylist everywhere (the everywhere-scoped
    /// twin of per-provider `allow_metadata_hosts`). An IP entry also unblocks its obfuscated
    /// spellings, mirroring how a block entry blocks all spellings. Default empty.
    #[serde(default)]
    pub(crate) allow_metadata_hosts: Vec<String>,
    /// Nuclear override: when true the cloud-metadata SSRF guard is FULLY DISABLED for every provider
    /// (every metadata/IMDS endpoint becomes reachable). Logs a startup WARNING. Default false.
    #[serde(default)]
    pub(crate) allow_all_metadata: bool,
}

/// Governance config. When present + enabled, callers authenticate with virtual keys
/// (not the static auth token) and are subject to per-key allowed-pools / budgets / rate limits.
#[derive(Deserialize, Clone, Default)]
pub(crate) struct GovernanceCfg {
    #[serde(default)]
    pub(crate) enabled: bool,
    /// SQLite database path for the durable governance store. Defaults to `busbar-governance.db`.
    #[serde(default = "default_gov_db_path")]
    pub(crate) db_path: String,
    /// Flat cents charged per request for budget accounting. Defaults to 1.
    #[serde(default = "default_price_per_request_cents")]
    pub(crate) price_per_request_cents: i64,
    /// Cents charged per 1000 tokens (input + output), accrued from response usage. Defaults to 0.
    /// Total budget spend per request = price_per_request_cents + tokens/1000 * price_per_1k_tokens_cents.
    #[serde(default)]
    pub(crate) price_per_1k_tokens_cents: i64,
    /// bearer token guarding the /admin management API. None = admin API disabled.
    #[serde(default)]
    pub(crate) admin_token: Option<String>,
    /// Behavior when the budget store errors during the atomic admission check-and-charge (fix 2b).
    /// `allow` (default) fails OPEN — the request proceeds, preserving availability on a telemetry-
    /// store hiccup (today's behavior). `deny` fails CLOSED — the request is rejected, the strict
    /// stance for security/regulated deployments that want a hard budget guarantee. Only the store-
    /// ERROR path is affected; a definitive over-budget result always rejects regardless.
    #[serde(default)]
    pub(crate) budget_on_store_error: BudgetOnStoreError,
}

/// Fail-mode for the budget check on a store error (fix 2b). Default `allow` (fail-open) preserves
/// today's availability-first behavior.
#[derive(Debug, Deserialize, Clone, Copy, Default, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub(crate) enum BudgetOnStoreError {
    /// Fail OPEN: on a store error during the budget check, proceed (availability). Today's behavior.
    #[default]
    Allow,
    /// Fail CLOSED: on a store error during the budget check, reject (hard budget guarantee).
    Deny,
}

// MANUAL Debug that REDACTS the admin bearer token. A derived `Debug` would print `admin_token` in
// PLAINTEXT — a latent credential leak if a `GovernanceCfg` (or `DeployCfg`, which holds it) is
// debug-logged. Print presence only, never the value.
impl fmt::Debug for GovernanceCfg {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("GovernanceCfg")
            .field("enabled", &self.enabled)
            .field("db_path", &self.db_path)
            .field("price_per_request_cents", &self.price_per_request_cents)
            .field("price_per_1k_tokens_cents", &self.price_per_1k_tokens_cents)
            .field(
                "admin_token",
                &if self.admin_token.is_some() {
                    "<redacted; present>"
                } else {
                    "<absent>"
                },
            )
            .field("budget_on_store_error", &self.budget_on_store_error)
            .finish()
    }
}

fn default_gov_db_path() -> String {
    "busbar-governance.db".to_string()
}

fn default_price_per_request_cents() -> i64 {
    1
}

/// Observability sinks. All fields optional; absent = that sink is disabled.
#[derive(Debug, Deserialize, Clone, Default)]
pub(crate) struct ObservabilityCfg {
    /// OTLP/HTTP traces endpoint (e.g. `http://localhost:4318/v1/traces`). When set, busbar
    /// installs an OpenTelemetry tracer + exports spans.
    #[serde(default)]
    pub(crate) otlp_endpoint: Option<String>,
    /// When set, busbar fires a best-effort (fire-and-forget) JSON request-log POST per request
    /// to this URL.
    #[serde(default)]
    pub(crate) request_log_webhook_url: Option<String>,
}

/// Resolve DeployCfg + ProviderDef map into resolved RootCfg.
/// For each deployed provider, look up its definition by name; produce a resolved ProviderCfg
/// = def's protocol/base_url/error_map (with any config.yaml override applied) + the deployment's api_key_env.
pub(crate) fn resolve(
    deploy: &DeployCfg,
    defs: &HashMap<String, ProviderDef>,
) -> Result<RootCfg, Vec<String>> {
    let mut errors = Vec::new();
    let mut resolved_providers: HashMap<String, ProviderCfg> = HashMap::new();

    for (deploy_name, deploy_cfg) in &deploy.providers {
        // Look up the provider definition by name
        let def = match defs.get(deploy_name) {
            Some(d) => d,
            None => {
                errors.push(format!(
                    "provider '{}' referenced in config.yaml not found in providers.yaml",
                    deploy_name
                ));
                continue;
            }
        };

        // Apply overrides from deployment (rarely used)
        let protocol = deploy_cfg
            .protocol
            .clone()
            .unwrap_or_else(|| def.protocol.clone());
        let base_url = deploy_cfg
            .base_url
            .clone()
            .unwrap_or_else(|| def.base_url.clone());

        // A legacy inline `api_key:` under a provider is NOT supported — keys come only from
        // `api_key_env`. Warn loudly and discard it (rather than letting serde drop it silently),
        // so an operator who set it learns why their key isn't taking effect.
        if deploy_cfg._legacy_api_key.is_some() {
            tracing::warn!(
                provider = %deploy_name,
                "inline `api_key:` under a provider is unsupported and ignored; set the key in the \
                 environment variable named by `api_key_env` instead"
            );
        }

        // Merge error_map: def's map with deployment override taking precedence
        let mut error_map = def.error_map.clone();
        if let Some(override_map) = &deploy_cfg.error_map {
            for (code, class) in override_map {
                error_map.insert(code.clone(), class.clone());
            }
        }

        resolved_providers.insert(
            deploy_name.clone(),
            ProviderCfg {
                protocol,
                base_url,
                api_key_env: deploy_cfg.api_key_env.clone(),
                // Deployment health config wins over the catalog default (mirrors path/auth), so
                // the `health:` block documented in config.yaml actually takes effect.
                health: deploy_cfg.health.clone().or_else(|| def.health.clone()),
                error_map,
                // deployment override wins over the catalog default
                path: deploy_cfg.path.clone().or_else(|| def.path.clone()),
                auth: deploy_cfg.auth.clone().or_else(|| def.auth.clone()),
                // deployment override (Some) replaces the catalog default
                allow_metadata_hosts: deploy_cfg
                    .allow_metadata_hosts
                    .clone()
                    .unwrap_or_else(|| def.allow_metadata_hosts.clone()),
                _legacy_api_key: None,
            },
        );
    }

    // Governance is read from `DeployCfg` (it does not land on the resolved `RootCfg`, so
    // `config_validate::validate(&RootCfg)` cannot see it). Validate it here, on `resolve`'s
    // existing fail-loud error channel, so an enabled-but-admin-token-less governance block (which
    // silently locks the /admin API) is rejected at boot rather than discovered at runtime.
    if let Some(governance) = &deploy.governance {
        if let Err(gov_errors) =
            crate::config_validate::validate_governance(governance, deploy.auth.as_ref())
        {
            errors.extend(gov_errors);
        }
    }

    if errors.is_empty() {
        Ok(RootCfg {
            listen: deploy.listen.clone(),
            tls: deploy.tls.clone(),
            auth: deploy.auth.clone().map(|a| a.normalize()),
            providers: resolved_providers,
            models: deploy.models.clone(),
            pools: deploy.pools.clone(),
            blocked_metadata_hosts: deploy
                .security
                .as_ref()
                .map(|s| s.blocked_metadata_hosts.clone())
                .unwrap_or_default(),
            allow_metadata_hosts: deploy
                .security
                .as_ref()
                .map(|s| s.allow_metadata_hosts.clone())
                .unwrap_or_default(),
            allow_all_metadata: deploy
                .security
                .as_ref()
                .map(|s| s.allow_all_metadata)
                .unwrap_or(false),
        })
    } else {
        Err(errors)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Serializes tests that touch the *shared* `BUSBAR_CLIENT_TOKEN` env var. Env vars are
    /// process-global, and `cargo test` runs tests in parallel by default, so two tests that
    /// `set_var`/`remove_var` the same name race: one can wipe the value mid-flight of the other,
    /// causing a spurious "unset variable" interpolation failure. Renaming is not viable because the
    /// shipped `config.yaml` hard-references `${BUSBAR_CLIENT_TOKEN}`; instead, every test that
    /// drives that var must hold this lock for the whole set/interpolate/remove sequence.
    ///
    /// Per-test vars use unique `BUSBAR_T_*` names and so do not need this guard.
    static CLIENT_TOKEN_ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    /// A `tracing::Layer` that records the messages of WARN-level events it sees, so a test can
    /// assert a particular `tracing::warn!` fired.
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

    /// Construct an `AuthCfg` directly for normalization tests (the deprecated `_legacy_token`
    /// field is only settable inside the crate with the deprecation lint suppressed).
    #[allow(deprecated)]
    fn auth_cfg(legacy_token: Option<&str>, client_tokens: &[&str]) -> AuthCfg {
        AuthCfg {
            mode: "token".to_string(),
            _legacy_token: legacy_token.map(str::to_string),
            client_tokens: client_tokens.iter().map(|s| s.to_string()).collect(),
        }
    }

    /// When only the deprecated `token` is supplied (no `client_tokens`), normalize promotes it
    /// into the allowlist — the legacy single-token format keeps working.
    #[test]
    fn test_normalize_promotes_legacy_token_when_allowlist_empty() {
        let normalized = auth_cfg(Some("sk-bb-legacy"), &[]).normalize();
        assert_eq!(
            normalized.client_tokens,
            vec!["sk-bb-legacy".to_string()],
            "a lone legacy `token` must be promoted into client_tokens"
        );
    }

    /// REGRESSION (LOW #33, config.rs:113-121): when BOTH the deprecated `token` and a non-empty
    /// `client_tokens` allowlist are supplied, `normalize` discards the legacy token (the allowlist
    /// wins) — but that drop MUST be observable via a `tracing::warn!`, not silent. This captures
    /// WARN events: against the old (silent) code it FAILS (no warning), and passes once the warn!
    /// is emitted. It also asserts the allowlist is left untouched (no merge).
    #[test]
    fn test_normalize_dropping_legacy_token_warns() {
        use tracing_subscriber::layer::SubscriberExt as _;

        let cap = WarnCapture::default();
        let subscriber = tracing_subscriber::registry().with(cap.clone());

        let normalized = tracing::subscriber::with_default(subscriber, || {
            auth_cfg(Some("sk-bb-legacy-dropped"), &["sk-bb-allowlisted"]).normalize()
        });

        // The legacy token is NOT merged into the existing allowlist.
        assert_eq!(
            normalized.client_tokens,
            vec!["sk-bb-allowlisted".to_string()],
            "an existing client_tokens allowlist must win and not absorb the legacy token"
        );

        let msgs = cap.0.lock().unwrap();
        assert!(
            msgs.iter().any(|m| m.contains("`token`")),
            "dropping the legacy `token` when client_tokens is non-empty must emit an observable \
             warn!, got: {msgs:?}"
        );
    }

    /// A minimal config without a `pools:` section parses fine — pools are optional (direct
    /// model routing). Only providers + models are required.
    #[test]
    fn test_config_without_pools_parses() {
        let yaml = r#"
listen: "0.0.0.0:8080"
providers:
  anthropic:
    api_key_env: ANTHROPIC_KEY
models:
  claude:
    provider: anthropic
    max_concurrent: 10
"#;
        let deploy: DeployCfg =
            serde_yaml::from_str(yaml).expect("config without pools must parse");
        assert!(deploy.pools.is_empty());
        assert!(deploy.models.contains_key("claude"));
    }

    /// A provider's `path` override flows from the catalog (and a deployment override wins) into
    /// the resolved ProviderCfg — the knob that fixes version-in-base-url providers.
    #[test]
    fn test_provider_path_override_resolves() {
        let mut defs = HashMap::new();
        defs.insert(
            "zai-payg".to_string(),
            ProviderDef {
                protocol: "openai".to_string(),
                base_url: "https://api.z.ai/api/paas/v4".to_string(),
                error_map: HashMap::new(),
                health: None,
                path: Some("/chat/completions".to_string()),
                auth: None,
                allow_metadata_hosts: Vec::new(),
            },
        );
        let mut providers = HashMap::new();
        providers.insert(
            "zai-payg".to_string(),
            ProviderDeploy {
                api_key_env: "ZAI_KEY".to_string(),
                protocol: None,
                base_url: None,
                error_map: None,
                path: None, // inherit the catalog override
                auth: None,
                // Deployment-side health (the block config.yaml documents under a provider).
                health: Some(HealthCfg {
                    mode: HealthMode::Dead,
                    interval_secs: Some(5),
                    timeout_secs: None,
                }),
                _legacy_api_key: None,
                allow_metadata_hosts: None,
            },
        );
        let deploy = DeployCfg {
            listen: "0.0.0.0:8080".into(),
            tls: None,
            auth: None,
            providers,
            models: HashMap::new(),
            pools: HashMap::new(),
            observability: None,
            governance: None,
            security: None,
        };
        let cfg = resolve(&deploy, &defs).expect("resolve");
        assert_eq!(
            cfg.providers["zai-payg"].path.as_deref(),
            Some("/chat/completions"),
            "catalog path override must resolve into ProviderCfg"
        );
        // Deployment-side health must survive resolve (regression: it was silently dropped).
        assert_eq!(
            cfg.providers["zai-payg"].health.as_ref().map(|h| h.mode),
            Some(HealthMode::Dead),
            "config.yaml provider health must resolve into ProviderCfg"
        );
    }

    /// The shipped example config.yaml must parse and resolve cleanly against providers.yaml
    /// (every referenced provider/model exists; the example stays a working starting point).
    #[test]
    fn test_shipped_example_config_resolves() {
        // Hold the shared-env lock across the whole set/interpolate/remove sequence so a sibling test
        // that also drives BUSBAR_CLIENT_TOKEN cannot wipe it mid-flight (recover on poison: a panic
        // in another holder must not block this test).
        let _env_guard = CLIENT_TOKEN_ENV_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        // The example references env-var placeholders via `${...}` interpolation, which scans the
        // whole file — including commented blocks. ONLY the active (uncommented) `auth.client_tokens`
        // entry uses the brace form, so only BUSBAR_CLIENT_TOKEN must be set. The commented
        // governance `admin_token` deliberately uses the no-brace `$BUSBAR_ADMIN_TOKEN` form, which
        // interpolate_env does NOT expand, so booting the default config must NOT require
        // BUSBAR_ADMIN_TOKEN to be set (regression: the brace form forced a mandatory boot failure
        // even with governance disabled). We intentionally do NOT set BUSBAR_ADMIN_TOKEN here.
        std::env::set_var("BUSBAR_CLIENT_TOKEN", "example-token");
        std::env::remove_var("BUSBAR_ADMIN_TOKEN");
        let providers_raw =
            std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/providers.yaml"))
                .unwrap();
        let defs: HashMap<String, ProviderDef> =
            serde_yaml::from_str(&providers_raw).expect("parse providers.yaml");

        let config_raw =
            std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/config.yaml")).unwrap();
        let expanded = interpolate_env(&config_raw).expect("expand ${ENV} in example config.yaml");
        let deploy: DeployCfg = serde_yaml::from_str(&expanded).expect("parse example config.yaml");

        let cfg = resolve(&deploy, &defs).expect("example config.yaml must resolve");
        // Spot-check the progressively-complex pools all wired up.
        assert!(cfg.pools.contains_key("smart"));
        assert!(cfg.pools.contains_key("overflow"));
        assert!(cfg.models.contains_key("claude-sonnet"));

        // Env vars are process-global and tests run in parallel; clean up so this test cannot
        // leave BUSBAR_CLIENT_TOKEN set for the rest of the run (which could mask an "unset
        // variable" assertion in another test).
        std::env::remove_var("BUSBAR_CLIENT_TOKEN");
    }

    /// Regression (#23): booting the shipped default config.yaml must NOT require BUSBAR_ADMIN_TOKEN
    /// to be set. `interpolate_env` expands `${...}` anywhere in the raw text — including comments —
    /// so a commented `admin_token: "${BUSBAR_ADMIN_TOKEN}"` example would make an unset
    /// BUSBAR_ADMIN_TOKEN a MANDATORY boot failure even when governance is disabled. The commented
    /// example uses the no-brace `$BUSBAR_ADMIN_TOKEN` form, which interpolate_env leaves verbatim.
    /// This test interpolates the default config with BUSBAR_ADMIN_TOKEN guaranteed-unset and asserts
    /// success; it fails against the old `${...}` comment (unset-variable boot error).
    #[test]
    fn test_default_config_boots_without_admin_token_env() {
        // Serialize with the sibling that shares BUSBAR_CLIENT_TOKEN (see CLIENT_TOKEN_ENV_LOCK).
        let _env_guard = CLIENT_TOKEN_ENV_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        std::env::set_var("BUSBAR_CLIENT_TOKEN", "example-token");
        std::env::remove_var("BUSBAR_ADMIN_TOKEN");

        let config_raw =
            std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/config.yaml")).unwrap();

        // No active OR commented `${...}` token in the shipped config may reference an admin token:
        // the only legitimate brace-form interpolation is the active client-tokens entry.
        assert!(
            !config_raw.contains("${BUSBAR_ADMIN_TOKEN}"),
            "the commented admin_token example must use the no-brace $BUSBAR_ADMIN_TOKEN form so it \
             does not force a mandatory boot failure on unset BUSBAR_ADMIN_TOKEN"
        );

        let expanded = interpolate_env(&config_raw)
            .expect("default config.yaml must interpolate with BUSBAR_ADMIN_TOKEN unset");
        // The no-brace form is passed through verbatim (interpolate_env only expands `${...}`).
        assert!(
            expanded.contains("$BUSBAR_ADMIN_TOKEN"),
            "the no-brace admin_token example must survive interpolation untouched"
        );

        std::env::remove_var("BUSBAR_CLIENT_TOKEN");
    }

    /// Regression (#20): the two integration tests above share the process-global
    /// `BUSBAR_CLIENT_TOKEN` env var with a set → interpolate → remove sequence. Under the default
    /// parallel test runner, an unguarded sibling could `remove_var` between this test's `set_var`
    /// and `interpolate_env`, making interpolation fail with an "unset variable" error. This test
    /// reproduces that race deterministically by hammering the exact sequence from many threads, and
    /// asserts that holding `CLIENT_TOKEN_ENV_LOCK` across the whole sequence keeps every
    /// interpolation succeeding. Run against the old (unguarded) sequence it flakes/fails; with the
    /// guard it is stable.
    #[test]
    fn test_client_token_env_lock_serializes_set_interpolate_remove() {
        const THREADS: usize = 8;
        const ITERS: usize = 200;
        let failures = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let mut handles = Vec::with_capacity(THREADS);
        for _ in 0..THREADS {
            let failures = std::sync::Arc::clone(&failures);
            handles.push(std::thread::spawn(move || {
                for _ in 0..ITERS {
                    // The guard makes set/interpolate/remove atomic w.r.t. other lock holders.
                    let _g = CLIENT_TOKEN_ENV_LOCK
                        .lock()
                        .unwrap_or_else(|p| p.into_inner());
                    std::env::set_var("BUSBAR_CLIENT_TOKEN", "race-token");
                    let r = interpolate_env("tok: \"${BUSBAR_CLIENT_TOKEN}\"");
                    if r.as_deref() != Ok("tok: \"race-token\"") {
                        failures.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    }
                    std::env::remove_var("BUSBAR_CLIENT_TOKEN");
                }
            }));
        }
        for h in handles {
            h.join().expect("interpolation thread must not panic");
        }
        assert_eq!(
            failures.load(std::sync::atomic::Ordering::Relaxed),
            0,
            "guarded set/interpolate/remove of BUSBAR_CLIENT_TOKEN must never observe an unset var"
        );
    }

    /// Native SHORTHAND desugaring: `route: cheapest` (a bare native name) must parse to
    /// `RouteKind::Native` with `policy.name` folded in — byte-identical to the long form
    /// `route: native` + `policy.name: cheapest`. Covers every shorthand.
    #[test]
    fn test_route_native_shorthand_desugars() {
        for name in ["cheapest", "fastest", "least_busy", "usage"] {
            let yaml = format!("route: {name}\nmembers: []\n");
            let pool: PoolCfg = serde_yaml::from_str(&yaml).expect("shorthand must parse");
            assert_eq!(pool.route, RouteKind::Native, "{name} desugars to Native");
            assert_eq!(
                pool.policy.as_ref().and_then(|p| p.name.as_deref()),
                Some(name),
                "{name} shorthand must fold into policy.name"
            );
            // C1 / CH3: a desugared shorthand has no `policy:` block on disk, so its synthesized
            // `PolicyCfg` must carry the REAL default timeout (150), NOT the 0 that
            // `PolicyCfg::default()` leaves behind (serde field-defaults don't fire on code-built
            // structs). A 0 here becomes an instant 0ms policy deadline at resolution.
            assert_eq!(
                pool.policy.as_ref().map(|p| p.timeout_ms),
                Some(DEFAULT_POLICY_TIMEOUT_MS),
                "{name} shorthand must inherit the default {DEFAULT_POLICY_TIMEOUT_MS}ms policy timeout, not 0"
            );
        }
    }

    /// `route: weighted` (shorthand or absent) stays the zero-cost `Weighted` default — it must NOT
    /// be turned into a native policy object.
    #[test]
    fn test_route_weighted_and_absent_stay_default() {
        let absent: PoolCfg = serde_yaml::from_str("members: []\n").expect("absent route parses");
        assert_eq!(absent.route, RouteKind::Weighted);
        assert!(absent.policy.is_none());

        let explicit: PoolCfg =
            serde_yaml::from_str("route: weighted\nmembers: []\n").expect("weighted parses");
        assert_eq!(explicit.route, RouteKind::Weighted);
    }

    /// The LONG form still works and an explicit `policy.name` is never overwritten by a shorthand.
    #[test]
    fn test_route_long_form_and_explicit_name_preserved() {
        let long: PoolCfg =
            serde_yaml::from_str("route: native\nmembers: []\npolicy:\n  name: fastest\n")
                .expect("long form parses");
        assert_eq!(long.route, RouteKind::Native);
        assert_eq!(long.policy.unwrap().name.as_deref(), Some("fastest"));

        // webhook / script keep their kind.
        let wh: PoolCfg =
            serde_yaml::from_str("route: webhook\nmembers: []\npolicy:\n  url: http://x\n")
                .expect("webhook parses");
        assert_eq!(wh.route, RouteKind::Webhook);
    }

    /// An unknown `route:` value fails loudly (no silent degrade to weighted at parse time).
    #[test]
    fn test_route_unknown_value_errors() {
        let err = serde_yaml::from_str::<PoolCfg>("route: bogus\nmembers: []\n");
        assert!(err.is_err(), "unknown route must be a parse error");
        let msg = format!("{}", err.unwrap_err());
        assert!(
            msg.contains("bogus"),
            "error must name the bad value, got: {msg}"
        );
    }

    /// fix 2b: `governance.budget_on_store_error` parses `allow`/`deny`, defaults to `allow` (fail-
    /// open, today's behavior), and rejects an unknown value (typed enum, not a free string).
    #[test]
    fn test_budget_on_store_error_parses() {
        use crate::config::BudgetOnStoreError;
        // Default (field absent) is Allow.
        let g: GovernanceCfg = serde_yaml::from_str("enabled: true\n").expect("parse");
        assert_eq!(
            g.budget_on_store_error,
            BudgetOnStoreError::Allow,
            "default is allow"
        );
        // Explicit allow / deny.
        let g: GovernanceCfg =
            serde_yaml::from_str("budget_on_store_error: allow\n").expect("parse allow");
        assert_eq!(g.budget_on_store_error, BudgetOnStoreError::Allow);
        let g: GovernanceCfg =
            serde_yaml::from_str("budget_on_store_error: deny\n").expect("parse deny");
        assert_eq!(g.budget_on_store_error, BudgetOnStoreError::Deny);
        // Unknown value is a parse error (no silent degrade).
        assert!(
            serde_yaml::from_str::<GovernanceCfg>("budget_on_store_error: maybe\n").is_err(),
            "unknown budget_on_store_error must fail to parse"
        );
    }

    /// The shipped providers.yaml catalog must parse, name only known protocols, and use HTTPS.
    #[test]
    fn test_shipped_providers_catalog_valid() {
        let path = concat!(env!("CARGO_MANIFEST_DIR"), "/providers.yaml");
        let raw = std::fs::read_to_string(path).expect("read providers.yaml");
        let defs: HashMap<String, ProviderDef> =
            serde_yaml::from_str(&raw).expect("parse providers.yaml");
        assert!(defs.len() >= 10, "catalog should be non-trivial");
        let registry = crate::proto::ProtocolRegistry::with_builtins();
        for (name, def) in &defs {
            assert!(
                registry.get(&def.protocol).is_some(),
                "provider '{name}' names unknown protocol '{}'",
                def.protocol
            );
            assert!(
                def.base_url.starts_with("https://"),
                "provider '{name}' base_url must be https"
            );
        }
    }

    // NOTE: env vars are process-global; tests run in parallel. Use UNIQUE per-test var
    // names so they cannot race each other (the old shared HOST/USER raced + USER even
    // collided with the real shell var). Do not reintroduce shared names.
    #[test]
    fn test_interpolate_env_simple() {
        let input = "https://${BUSBAR_T_SIMPLE_HOST}/api";
        std::env::set_var("BUSBAR_T_SIMPLE_HOST", "example.com");
        let result = interpolate_env(input).unwrap();
        assert_eq!(result, "https://example.com/api");
        std::env::remove_var("BUSBAR_T_SIMPLE_HOST");
    }

    #[test]
    fn test_interpolate_env_multiple() {
        let input =
            "${BUSBAR_T_MULTI_PROTO}://${BUSBAR_T_MULTI_USER}@${BUSBAR_T_MULTI_HOST}:${BUSBAR_T_MULTI_PORT}/";
        std::env::set_var("BUSBAR_T_MULTI_PROTO", "https");
        std::env::set_var("BUSBAR_T_MULTI_USER", "admin");
        std::env::set_var("BUSBAR_T_MULTI_HOST", "localhost");
        std::env::set_var("BUSBAR_T_MULTI_PORT", "8080");
        let result = interpolate_env(input).unwrap();
        assert_eq!(result, "https://admin@localhost:8080/");
        std::env::remove_var("BUSBAR_T_MULTI_PROTO");
        std::env::remove_var("BUSBAR_T_MULTI_USER");
        std::env::remove_var("BUSBAR_T_MULTI_HOST");
        std::env::remove_var("BUSBAR_T_MULTI_PORT");
    }

    #[test]
    fn test_interpolate_env_unset_fails() {
        let input = "https://${UNSET_VAR}/api";
        let result = interpolate_env(input);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), "unset environment variable: UNSET_VAR");
    }

    #[test]
    fn test_interpolate_env_empty_var() {
        let input = "${}";
        let result = interpolate_env(input);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), "empty variable name in ${}");
    }

    #[test]
    fn test_interpolate_env_no_vars() {
        let input = "plain-text-no-vars";
        let result = interpolate_env(input).unwrap();
        assert_eq!(result, "plain-text-no-vars");
    }

    /// Regression (YAML-structure injection): an env value containing a NEWLINE (the structural
    /// break that closes a quoted YAML scalar) must be rejected, not spliced into the raw config
    /// text. The exploit shape from the finding — a value that ends a quoted `client_tokens` entry
    /// and injects an extra list item — must fail loudly at interpolation time. Uses a unique
    /// per-test var name (process-global env, parallel tests).
    #[test]
    fn test_interpolate_env_rejects_newline_yaml_injection() {
        // The double-quote/newline breakout payload the finding calls out for client_tokens.
        std::env::set_var("BUSBAR_T_INJECT_NL", "real-tok\"\n    - \"injected-tok");
        let input = "client_tokens:\n    - \"${BUSBAR_T_INJECT_NL}\"";
        let result = interpolate_env(input);
        std::env::remove_var("BUSBAR_T_INJECT_NL");
        assert!(
            result.is_err(),
            "an env value with a newline must be rejected to prevent YAML injection"
        );
        let err = result.unwrap_err();
        assert!(
            err.contains("control character") && err.contains("BUSBAR_T_INJECT_NL"),
            "error must name the offending variable and the control-character reason, got: {err}"
        );
    }

    /// A bare carriage return is also a YAML line break and must be rejected on the same grounds.
    #[test]
    fn test_interpolate_env_rejects_carriage_return() {
        std::env::set_var("BUSBAR_T_INJECT_CR", "tok\r- injected");
        let result = interpolate_env("x: \"${BUSBAR_T_INJECT_CR}\"");
        std::env::remove_var("BUSBAR_T_INJECT_CR");
        assert!(
            result.is_err(),
            "an env value with a carriage return must be rejected"
        );
    }

    /// The guard must NOT over-reject: ordinary token / URL values (including ones with `:`, `/`,
    /// `@`, `.`, `-`, and even an embedded double-quote or `#`, which are harmless without a line
    /// break) interpolate cleanly. This keeps real opaque API keys working.
    #[test]
    fn test_interpolate_env_allows_ordinary_values_with_punctuation() {
        std::env::set_var("BUSBAR_T_OK_TOK", "sk-bb-aB3#9/x.y@z:1234567890abcdef");
        let result = interpolate_env("token: \"${BUSBAR_T_OK_TOK}\"").unwrap();
        std::env::remove_var("BUSBAR_T_OK_TOK");
        assert_eq!(result, "token: \"sk-bb-aB3#9/x.y@z:1234567890abcdef\"");
    }

    /// End-to-end: an env value carrying a newline-based injection must NOT smuggle an extra
    /// `client_tokens` entry into the parsed config. The interpolation rejects it before serde ever
    /// sees the malformed YAML, so the allowlist cannot be silently widened via a compromised env
    /// var.
    #[test]
    fn test_env_injection_cannot_widen_client_tokens_allowlist() {
        std::env::set_var(
            "BUSBAR_T_ALLOWLIST_INJECT",
            "legit\"\n    - \"smuggled-admin-token",
        );
        let yaml = "auth:\n  mode: token\n  client_tokens:\n    - \"${BUSBAR_T_ALLOWLIST_INJECT}\"";
        let result = interpolate_env(yaml);
        std::env::remove_var("BUSBAR_T_ALLOWLIST_INJECT");
        assert!(
            result.is_err(),
            "newline injection into client_tokens must be rejected at interpolation, not parsed"
        );
    }

    /// An unclosed `${FOO` (missing `}`) must fail loudly with an "unclosed" error rather than be
    /// treated as `${FOO}` — regardless of whether FOO is set in the environment. Uses a unique
    /// per-test var name (process-global env, parallel tests) and a guaranteed-unset name.
    #[test]
    fn test_interpolate_env_unclosed_brace_fails() {
        // Unset variable, missing brace: must report "unclosed", NOT "unset environment variable".
        let result = interpolate_env("prefix-${BUSBAR_T_UNCLOSED_UNSET");
        assert!(result.is_err(), "unclosed token must error");
        let err = result.unwrap_err();
        assert!(
            err.contains("unclosed"),
            "error must mention 'unclosed', got: {err}"
        );
        assert!(
            !err.contains("unset environment variable"),
            "must not misreport as an unset-variable error, got: {err}"
        );

        // Set variable, missing brace: must STILL error (not silently interpolate the value).
        std::env::set_var("BUSBAR_T_UNCLOSED_SET", "leaked-value");
        let result2 = interpolate_env("https://${BUSBAR_T_UNCLOSED_SET/api");
        std::env::remove_var("BUSBAR_T_UNCLOSED_SET");
        assert!(
            result2.is_err(),
            "unclosed token must error even when the var is set"
        );
        let err2 = result2.unwrap_err();
        assert!(
            err2.contains("unclosed"),
            "error must mention 'unclosed', got: {err2}"
        );
    }

    // Two-file (providers.yaml + config.yaml) resolution tests

    #[test]
    fn test_resolve_provider_from_def() {
        // DeployCfg referencing z.ai + providers.yaml def -> resolved ProviderCfg has protocol/base_url/error_map from def
        let mut defs = HashMap::new();
        let mut error_map = HashMap::new();
        error_map.insert("1113".to_string(), "billing".to_string());
        error_map.insert("1302".to_string(), "rate_limit".to_string());

        defs.insert(
            "z.ai".to_string(),
            ProviderDef {
                protocol: "anthropic".to_string(),
                base_url: "https://api.z.ai/api/anthropic".to_string(),
                error_map,
                health: None,
                path: None,
                auth: None,
                allow_metadata_hosts: Vec::new(),
            },
        );

        let mut providers = HashMap::new();
        providers.insert(
            "z.ai".to_string(),
            ProviderDeploy {
                api_key_env: "ZAI_KEY".to_string(),
                protocol: None,
                base_url: None,
                error_map: None,
                path: None,
                auth: None,
                health: None,
                _legacy_api_key: None,
                allow_metadata_hosts: None,
            },
        );

        let deploy = DeployCfg {
            listen: "0.0.0.0:8080".into(),
            tls: None,
            auth: None,
            providers,
            models: HashMap::new(),
            pools: HashMap::new(),
            observability: None,
            governance: None,
            security: None,
        };

        let result = resolve(&deploy, &defs).expect("resolve should succeed");

        let provider_cfg = result
            .providers
            .get("z.ai")
            .expect("z.ai should be in resolved providers");
        assert_eq!(provider_cfg.protocol, "anthropic");
        assert_eq!(provider_cfg.base_url, "https://api.z.ai/api/anthropic");
        assert_eq!(provider_cfg.api_key_env, "ZAI_KEY");
        assert_eq!(
            provider_cfg.error_map.get("1113"),
            Some(&"billing".to_string())
        );
        assert_eq!(
            provider_cfg.error_map.get("1302"),
            Some(&"rate_limit".to_string())
        );
    }

    /// A legacy inline `api_key:` under a provider in config.yaml must parse onto
    /// `ProviderDeploy._legacy_api_key` (so resolve can warn on it) rather than being silently
    /// dropped by serde, and must NOT leak into the resolved ProviderCfg (keys come only from env).
    #[test]
    fn test_inline_api_key_parsed_and_ignored() {
        let yaml = r#"
listen: "0.0.0.0:8080"
providers:
  myprov:
    api_key_env: MYPROV_KEY
    api_key: "sk-inline-should-be-ignored"
models: {}
"#;
        let deploy: DeployCfg =
            serde_yaml::from_str(yaml).expect("config with inline api_key must parse");
        let dep = deploy.providers.get("myprov").expect("myprov present");
        assert_eq!(
            dep._legacy_api_key.as_deref(),
            Some("sk-inline-should-be-ignored"),
            "inline api_key must be captured on ProviderDeploy, not silently dropped"
        );

        // resolve() discards it (and warns); the resolved ProviderCfg never carries the inline key.
        let mut defs = HashMap::new();
        defs.insert(
            "myprov".to_string(),
            ProviderDef {
                protocol: "anthropic".to_string(),
                base_url: "https://api.example.com".to_string(),
                error_map: HashMap::new(),
                health: None,
                path: None,
                auth: None,
                allow_metadata_hosts: Vec::new(),
            },
        );
        let cfg = resolve(&deploy, &defs).expect("resolve");
        assert_eq!(
            cfg.providers["myprov"]._legacy_api_key, None,
            "inline api_key must never reach the resolved ProviderCfg"
        );
        assert_eq!(cfg.providers["myprov"].api_key_env, "MYPROV_KEY");
    }

    #[test]
    fn test_resolve_rejects_enabled_governance_without_admin_token() {
        // resolve() is the boot-time fail-loud channel for the governance block (which never lands
        // on RootCfg, so config_validate::validate cannot see it). An enabled governance block with
        // no admin_token silently locks the /admin API — resolve must reject it.
        let defs = HashMap::new();
        let deploy = DeployCfg {
            listen: "0.0.0.0:8080".into(),
            tls: None,
            auth: None,
            providers: HashMap::new(),
            models: HashMap::new(),
            pools: HashMap::new(),
            observability: None,
            governance: Some(GovernanceCfg {
                enabled: true,
                db_path: "busbar-governance.db".to_string(),
                price_per_request_cents: 1,
                price_per_1k_tokens_cents: 0,
                admin_token: None,
                budget_on_store_error: Default::default(),
            }),
            security: None,
        };
        let errs = resolve(&deploy, &defs)
            .expect_err("enabled governance without admin_token must fail resolution");
        assert!(
            errs.iter().any(|e| e.contains("governance.admin_token")),
            "expected an admin-token lockout error; got: {errs:?}"
        );
    }

    #[test]
    fn test_resolve_accepts_enabled_governance_with_admin_token() {
        let defs = HashMap::new();
        let deploy = DeployCfg {
            listen: "0.0.0.0:8080".into(),
            tls: None,
            auth: None,
            providers: HashMap::new(),
            models: HashMap::new(),
            pools: HashMap::new(),
            observability: None,
            governance: Some(GovernanceCfg {
                enabled: true,
                db_path: "busbar-governance.db".to_string(),
                price_per_request_cents: 1,
                price_per_1k_tokens_cents: 0,
                admin_token: Some("operator-secret".to_string()),
                budget_on_store_error: Default::default(),
            }),
            security: None,
        };
        assert!(
            resolve(&deploy, &defs).is_ok(),
            "enabled governance WITH an admin_token must resolve"
        );
    }

    #[test]
    fn test_resolve_unknown_provider_error() {
        // config.yaml references nope not in providers.yaml -> resolve returns error naming nope
        let defs = HashMap::new();

        let mut providers = HashMap::new();
        providers.insert(
            "nope".to_string(),
            ProviderDeploy {
                api_key_env: "NOPE_KEY".to_string(),
                protocol: None,
                base_url: None,
                error_map: None,
                path: None,
                auth: None,
                health: None,
                _legacy_api_key: None,
                allow_metadata_hosts: None,
            },
        );

        let deploy = DeployCfg {
            listen: "0.0.0.0:8080".into(),
            tls: None,
            auth: None,
            providers,
            models: HashMap::new(),
            pools: HashMap::new(),
            observability: None,
            governance: None,
            security: None,
        };

        let result = resolve(&deploy, &defs);
        assert!(result.is_err());
        let errs = result.unwrap_err();
        assert_eq!(errs.len(), 1);
        assert!(errs[0].contains("nope"));
        assert!(errs[0].contains("not found in providers.yaml"));
    }

    #[test]
    fn test_resolve_override_wins() {
        // config.yaml provider with a base_url override wins over the def
        let mut defs = HashMap::new();
        let error_map = HashMap::new();

        defs.insert(
            "custom".to_string(),
            ProviderDef {
                protocol: "anthropic".to_string(),
                base_url: "https://default.example.com".to_string(),
                error_map,
                health: None,
                path: None,
                auth: None,
                allow_metadata_hosts: Vec::new(),
            },
        );

        let mut providers = HashMap::new();
        let mut override_error_map = HashMap::new();
        override_error_map.insert("9999".to_string(), "client_error".to_string());

        providers.insert(
            "custom".to_string(),
            ProviderDeploy {
                api_key_env: "CUSTOM_KEY".to_string(),
                protocol: Some("openai".to_string()), // Override protocol
                base_url: Some("https://override.example.com".to_string()), // Override base_url
                error_map: Some(override_error_map),  // Override error_map
                path: None,
                auth: None,
                health: None,
                _legacy_api_key: None,
                allow_metadata_hosts: None,
            },
        );

        let deploy = DeployCfg {
            listen: "0.0.0.0:8080".into(),
            tls: None,
            auth: None,
            providers,
            models: HashMap::new(),
            pools: HashMap::new(),
            observability: None,
            governance: None,
            security: None,
        };

        let result = resolve(&deploy, &defs).expect("resolve should succeed");

        let provider_cfg = result
            .providers
            .get("custom")
            .expect("custom should be in resolved providers");
        assert_eq!(
            provider_cfg.protocol, "openai",
            "protocol override should win"
        );
        assert_eq!(
            provider_cfg.base_url, "https://override.example.com",
            "base_url override should win"
        );
        assert_eq!(provider_cfg.api_key_env, "CUSTOM_KEY");
        assert_eq!(
            provider_cfg.error_map.get("9999"),
            Some(&"client_error".to_string())
        );
    }

    #[test]
    fn test_resolve_empty_error_map_allowed_in_def() {
        // A def can have empty error_map; validation will catch it later if required
        let mut defs = HashMap::new();
        defs.insert(
            "minimal".to_string(),
            ProviderDef {
                protocol: "anthropic".to_string(),
                base_url: "https://api.example.com".to_string(),
                error_map: HashMap::new(), // Empty but valid for resolution
                health: None,
                path: None,
                auth: None,
                allow_metadata_hosts: Vec::new(),
            },
        );

        let mut providers = HashMap::new();
        providers.insert(
            "minimal".to_string(),
            ProviderDeploy {
                api_key_env: "MINIMAL_KEY".to_string(),
                protocol: None,
                base_url: None,
                error_map: None,
                path: None,
                auth: None,
                health: None,
                _legacy_api_key: None,
                allow_metadata_hosts: None,
            },
        );

        let deploy = DeployCfg {
            listen: "0.0.0.0:8080".into(),
            tls: None,
            auth: None,
            providers,
            models: HashMap::new(),
            pools: HashMap::new(),
            observability: None,
            governance: None,
            security: None,
        };

        let result = resolve(&deploy, &defs).expect("resolve should succeed");
        let provider_cfg = result
            .providers
            .get("minimal")
            .expect("minimal should exist");
        assert!(provider_cfg.error_map.is_empty());
    }

    // OnExhausted mode parsing tests
    #[test]
    fn test_on_exhausted_parse_status_503_variants() {
        // Test all Status503 variants
        assert_eq!(
            OnExhausted::parse("reject").unwrap(),
            OnExhausted::Status503
        );
        assert_eq!(OnExhausted::parse("503").unwrap(), OnExhausted::Status503);
        assert_eq!(
            OnExhausted::parse("status_503").unwrap(),
            OnExhausted::Status503
        );
        assert_eq!(
            OnExhausted::parse("status503").unwrap(),
            OnExhausted::Status503
        );
    }

    #[test]
    fn test_on_exhausted_parse_least_bad_variants() {
        // Test all LeastBad variants
        assert_eq!(
            OnExhausted::parse("least_bad").unwrap(),
            OnExhausted::LeastBad
        );
        assert_eq!(
            OnExhausted::parse("least-bad").unwrap(),
            OnExhausted::LeastBad
        );
        assert_eq!(
            OnExhausted::parse("leastbad").unwrap(),
            OnExhausted::LeastBad
        );
    }

    #[test]
    fn test_on_exhausted_parse_fallback_pool() {
        // Test FallbackPool with colon syntax
        let result = OnExhausted::parse("fallback_pool:drain").unwrap();
        assert_eq!(result, OnExhausted::FallbackPool("drain".to_string()));

        let result2 = OnExhausted::parse("fallback_pool:backup").unwrap();
        assert_eq!(result2, OnExhausted::FallbackPool("backup".to_string()));
    }

    #[test]
    fn test_on_exhausted_parse_unknown_action() {
        // Test that unknown actions produce clear error messages (exhaustive match)
        let result = OnExhausted::parse("invalid_mode");
        assert!(result.is_err());
        let err_msg = result.unwrap_err();
        assert!(err_msg.contains("unknown on_exhausted action"));
        assert!(err_msg.contains("invalid_mode"));

        let result2 = OnExhausted::parse("fallback");
        assert!(result2.is_err());
        let err_msg2 = result2.unwrap_err();
        assert!(err_msg2.contains("'fallback' is not a valid on_exhausted action"));
    }

    #[test]
    fn test_on_exhausted_parse_empty_fallback_pool_name() {
        // Test that empty fallback pool name produces error
        let result = OnExhausted::parse("fallback_pool:");
        assert!(result.is_err());
        let err_msg = result.unwrap_err();
        assert!(err_msg.contains("fallback_pool requires a non-empty pool name"));
    }

    #[test]
    fn breaker_cfg_default_matches_serde_default_fns() {
        // `BreakerCfg::default()` (used when a pool omits the whole `breaker:` block) and the
        // `#[serde(default = ...)]` fns (used when individual fields are omitted) must agree on the
        // cooldown literals; otherwise the same pool would get different cooldowns depending on
        // whether the block is present. `Default` now delegates to these fns, so this guards against
        // the two ever drifting again.
        let d = BreakerCfg::default();
        assert_eq!(
            d.base_cooldown_secs,
            default_cooldown(),
            "base_cooldown_secs default diverged from default_cooldown()"
        );
        assert_eq!(
            d.max_cooldown_secs,
            default_max_cooldown(),
            "max_cooldown_secs default diverged from default_max_cooldown()"
        );
    }

    /// REGRESSION (LOW #15/#16, SECURITY): every config struct that carries a secret must REDACT it
    /// in `Debug`, not print it in plaintext. A derived `Debug` (the pre-R24 state for AuthCfg,
    /// GovernanceCfg, ProviderCfg, ProviderDeploy) would leak the literal token/api_key the moment
    /// the struct — or any struct that embeds it (RootCfg/DeployCfg) — is debug-logged. Against the
    /// old derived impls these assertions FAIL (the secret appears); they pass once the manual
    /// redacting impls are in place. The secret values are deliberately distinctive so a substring
    /// search is decisive.
    #[test]
    #[allow(deprecated)] // constructing the deprecated `_legacy_token` field solely to verify redaction
    fn test_debug_redacts_all_config_secrets() {
        // AuthCfg: client_tokens + the deprecated _legacy_token.
        let auth = AuthCfg {
            mode: "token".to_string(),
            _legacy_token: Some("SECRET-legacy-auth-token-xyz".to_string()),
            client_tokens: vec![
                "SECRET-client-token-aaa".to_string(),
                "SECRET-client-token-bbb".to_string(),
            ],
        };
        let dbg = format!("{auth:?}");
        assert!(
            !dbg.contains("SECRET-legacy-auth-token-xyz"),
            "AuthCfg Debug leaked the legacy token: {dbg}"
        );
        assert!(
            !dbg.contains("SECRET-client-token-aaa") && !dbg.contains("SECRET-client-token-bbb"),
            "AuthCfg Debug leaked a client token: {dbg}"
        );
        assert!(
            dbg.contains("2 configured"),
            "AuthCfg Debug should report the allowlist COUNT: {dbg}"
        );

        // GovernanceCfg: admin_token.
        let gov = GovernanceCfg {
            enabled: true,
            db_path: "x.db".to_string(),
            price_per_request_cents: 1,
            price_per_1k_tokens_cents: 0,
            admin_token: Some("SECRET-admin-bearer-token-qqq".to_string()),
            budget_on_store_error: Default::default(),
        };
        let dbg = format!("{gov:?}");
        assert!(
            !dbg.contains("SECRET-admin-bearer-token-qqq"),
            "GovernanceCfg Debug leaked admin_token: {dbg}"
        );
        assert!(
            dbg.contains("<redacted; present>"),
            "GovernanceCfg Debug should mark admin_token present-but-redacted: {dbg}"
        );

        // ProviderCfg: inline _legacy_api_key.
        let prov = ProviderCfg {
            protocol: "anthropic".to_string(),
            base_url: "https://example".to_string(),
            api_key_env: "PROV_KEY".to_string(),
            health: None,
            error_map: HashMap::new(),
            path: None,
            auth: None,
            allow_metadata_hosts: Vec::new(),
            _legacy_api_key: Some("SECRET-inline-provider-key-www".to_string()),
        };
        let dbg = format!("{prov:?}");
        assert!(
            !dbg.contains("SECRET-inline-provider-key-www"),
            "ProviderCfg Debug leaked the inline api_key: {dbg}"
        );
        assert!(
            dbg.contains("PROV_KEY"),
            "ProviderCfg Debug should still show the api_key_env NAME (not a secret): {dbg}"
        );

        // ProviderDeploy: inline _legacy_api_key.
        let deploy = ProviderDeploy {
            api_key_env: "DEPLOY_KEY".to_string(),
            _legacy_api_key: Some("SECRET-inline-deploy-key-zzz".to_string()),
            ..ProviderDeploy::default()
        };
        let dbg = format!("{deploy:?}");
        assert!(
            !dbg.contains("SECRET-inline-deploy-key-zzz"),
            "ProviderDeploy Debug leaked the inline api_key: {dbg}"
        );
        assert!(
            dbg.contains("DEPLOY_KEY"),
            "ProviderDeploy Debug should still show the api_key_env NAME (not a secret): {dbg}"
        );
    }

    /// REGRESSION (LOW #15/#16, SECURITY): the redaction must hold TRANSITIVELY — a derived `Debug`
    /// on an embedding struct (DeployCfg) delegates to each field's `Debug`, so the redacting impls
    /// above are what protect the whole-config dump an operator is most likely to log. This builds a
    /// DeployCfg containing every secret and asserts none survive its Debug output.
    #[test]
    #[allow(deprecated)]
    fn test_debug_redacts_secrets_transitively_through_deploycfg() {
        let mut providers = HashMap::new();
        providers.insert(
            "myprov".to_string(),
            ProviderDeploy {
                api_key_env: "DEPLOY_KEY".to_string(),
                _legacy_api_key: Some("SECRET-embedded-deploy-key".to_string()),
                ..ProviderDeploy::default()
            },
        );
        let deploy = DeployCfg {
            listen: "127.0.0.1:8080".to_string(),
            tls: None,
            auth: Some(AuthCfg {
                mode: "token".to_string(),
                _legacy_token: Some("SECRET-embedded-legacy-token".to_string()),
                client_tokens: vec!["SECRET-embedded-client-token".to_string()],
            }),
            providers,
            models: HashMap::new(),
            pools: HashMap::new(),
            observability: None,
            governance: Some(GovernanceCfg {
                enabled: true,
                db_path: "x.db".to_string(),
                price_per_request_cents: 1,
                price_per_1k_tokens_cents: 0,
                admin_token: Some("SECRET-embedded-admin-token".to_string()),
                budget_on_store_error: Default::default(),
            }),
            security: None,
        };
        let dbg = format!("{deploy:?}");
        for secret in [
            "SECRET-embedded-deploy-key",
            "SECRET-embedded-legacy-token",
            "SECRET-embedded-client-token",
            "SECRET-embedded-admin-token",
        ] {
            assert!(
                !dbg.contains(secret),
                "DeployCfg Debug leaked a nested secret ({secret}): {dbg}"
            );
        }
    }
}
