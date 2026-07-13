// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use std::collections::HashMap;
use std::fmt;

use serde::{Deserialize, Serialize};

/// The busbar-owned config overlay (persistence substrate for API-applied hook changes).
pub(crate) mod overlay;

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
    /// The top-level hook registry (`hooks:`). Each entry is a named tap or gate; pools reference a
    /// gate by name via `hook:`, and `global_hooks` names those firing on every request. Empty when
    /// no `hooks:` block is present.
    pub(crate) hooks: HashMap<String, HookCfg>,
    /// The ADMIN auth chain (`admin_auth:`) — ordered module names gating `/admin/v1/*` (the
    /// parallel of `auth.chain` for the operator surface). Default `[admin-tokens]` (the single
    /// operator admin token, exactly 1.2.1 behavior). `[]` = OPEN admin (dev only; loud boot
    /// warning). Each name must resolve to a compiled-in admin auth module.
    pub(crate) admin_auth: Vec<String>,
    /// `group_map:` — principal GROUPS (returned by external auth modules) → operator-owned
    /// policy. Policy stays in config, never asserted by a plugin (design-hooks-v2 §2.3): a
    /// module says WHO, this map says WHAT THEY MAY DO. Multiple groups union; the most
    /// permissive `admin_scope` wins; unmapped groups grant NOTHING (fail closed).
    pub(crate) group_map: HashMap<String, GroupMapEntry>,
    /// Names of hooks that fire on EVERY request (`global_hooks:` plus any hook with inline
    /// `global: true`, deduped). Validated to reference registry entries at boot.
    pub(crate) global_hooks: Vec<String>,
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
    /// Fully-resolved operational limits ("NEVER CODED CAPS"), projected from the `limits:` /
    /// `observability:` / `governance:` / `metrics:` / `health:` / `routing:` config sections. Every
    /// value defaults to its historical hardcoded const, so an all-default config is unchanged. Read
    /// by `config_validate::validate`, threaded into the store/client/TLS/App at startup, and
    /// installed into the process-wide `crate::limits` statics for the deep call-stack use sites.
    pub(crate) limits: LimitsResolved,
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
#[serde(deny_unknown_fields)]
pub(crate) struct AuthCfg {
    /// The authentication CHAIN — ordered module names (e.g. `[tokens]`). Empty (the default) is the
    /// open front door (the old `mode: none`). Replaces `mode:` — a stale `mode:` key is a loud boot
    /// error (deny_unknown_fields). Each name must resolve to a compiled-in auth module.
    #[serde(default)]
    pub(crate) chain: Vec<String>,
    /// Upstream-credential mode: `own` (default — busbar's configured lane key) or `passthrough`
    /// (forward the caller's credential upstream; the old `mode: passthrough`).
    #[serde(default)]
    pub(crate) upstream_credentials: crate::auth::UpstreamCreds,
    /// The `tokens` module's allowlist. Inert unless `tokens` is in `chain`.
    #[serde(default)]
    pub(crate) client_tokens: Vec<String>,
}

// MANUAL Debug that REDACTS every credential field. A derived `Debug` would print every entry of
// `client_tokens` in PLAINTEXT — a latent credential leak the moment an `AuthCfg` (or any struct
// that embeds it, e.g. `RootCfg`/`DeployCfg`) is debug-logged. Print only the COUNT of allowlist
// tokens, never the values (and never any prefix/suffix, which would be a partial-secret oracle).
// Mirrors `auth::AuthMiddleware`.
impl fmt::Debug for AuthCfg {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AuthCfg")
            .field("chain", &self.chain)
            .field("upstream_credentials", &self.upstream_credentials)
            .field(
                "client_tokens",
                &format_args!("<redacted; {} configured>", self.client_tokens.len()),
            )
            .finish()
    }
}

impl AuthCfg {
    /// Create a default (open front door) AuthCfg for initialization.
    pub(crate) fn default_none() -> Self {
        Self {
            chain: vec![],
            upstream_credentials: crate::auth::UpstreamCreds::Own,
            client_tokens: vec![],
        }
    }
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
    pub(crate) auth: Option<ProviderAuth>,
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

/// Default provider protocol when not specified. Wire-contract: providers.yaml catalog entries
/// and un-overridden deployments use this protocol for the dispatch registry lookup.
const DEFAULT_PROTOCOL: &str = "anthropic";

fn default_protocol() -> String {
    DEFAULT_PROTOCOL.to_string()
}

/// Per-provider auth-style override. Closed set: the request is signed with the protocol's native
/// auth (`bearer`) unless `api-key` selects an `api-key: <key>` header (Azure OpenAI). The wire
/// strings are unchanged from the pre-enum `Option<String>` field (`bearer` / `api-key`), so an
/// unknown spelling is now a deserialize error instead of a hand-checked validation error.
#[derive(Debug, Deserialize, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ProviderAuth {
    #[serde(rename = "bearer")]
    Bearer,
    #[serde(rename = "api-key")]
    ApiKey,
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
#[serde(deny_unknown_fields)]
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
#[serde(deny_unknown_fields)]
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
    /// Optional upstream model name override. When set, this value is sent to the provider as the
    /// model identifier in the request body and URL path, instead of the config key. Useful when
    /// the provider expects a different model string (e.g. Bedrock model IDs).
    #[serde(default)]
    pub(crate) upstream_model: Option<String>,
    /// Per-ATTEMPT time-to-response-headers cap (ms). If this lane has not returned response headers
    /// within the budget, the attempt is abandoned (transient → breaker) and the request FAILS OVER
    /// to the next member — the hang detector. Model-level default; a pool member's
    /// `attempt_timeout_ms` overrides it per workload. Absent = bounded only by the request budget.
    #[serde(default)]
    pub(crate) attempt_timeout_ms: Option<u64>,
    /// Operator declaration that THIS model accepts reasoning/thinking request parameters
    /// (Anthropic `thinking`, Gemini `thinkingConfig`, OpenAI `reasoning_effort`). Capability is
    /// per-MODEL, not per-provider (Sonnet takes `thinking`, Haiku 400s on it), and busbar keeps no
    /// model database — this flag is the operator asserting what they deployed, in the same family
    /// as `context_max`/`cost_per_mtok`. When absent/false, a cross-protocol reasoning ask is
    /// DROPPED at the seam with a warn (never sent, so a non-reasoning model can never 400 from
    /// translation). A pool member's `reasoning` overrides this per pool. Same-protocol passthrough
    /// is byte-exact and ignores the flag.
    #[serde(default)]
    pub(crate) reasoning: Option<bool>,
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
    /// The pool's native ranking STRATEGY (a strategy name in `hooks: [...]`). `weighted`
    /// (default / absent) is today's SWRR
    /// with ZERO added cost — no `RoutingPolicy` object, byte-identical hot path. `cheapest`/`fastest`/
    /// `least_busy`/`usage` resolve a native ordering policy that runs once before the failover loop.
    /// This is the pool's ranking FLOOR.
    pub(crate) policy: PoolPolicy,
    /// The pool's GATES (the non-strategy names in `hooks: [...]`). Each names an entry in the
    /// top-level `hooks:` registry; validated to be `kind: gate` at startup.
    /// Empty = no per-pool gate (pure native ordering). Config order is preserved — it is the
    /// phase-2 chain order (order last-wins; reject/restrict commute).
    pub(crate) gates: Vec<String>,
    /// Whether the pool EXPLICITLY named its base ordering strategy (a strategy name in
    /// `hooks: [...]`), vs leaving it defaulted. `false` (defaulted) is the pool that INHERITS the
    /// `default:` hook when one is registered (else the compiled-in `weighted` backstop); `true` means
    /// the operator picked a base, so the `default:` hook does NOT override it. `policy` alone can't
    /// carry this — it defaults to `Weighted` indistinguishably from an explicit `weighted`.
    pub(crate) base_named: bool,
}

/// Manual `Deserialize` for [`PoolCfg`] so retired config keys become CLEAN-BREAK migration errors
/// instead of silent surprises: the removed 1.2.1 `route:` pool key AND the retired transitional
/// `policy:`/`hook:` pair each fail loudly with the exact fix. `hooks: [...]` is THE pool form —
/// one list naming an optional ordering strategy and any gates (everything is a hook).
impl<'de> Deserialize<'de> for PoolCfg {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
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
            /// RETIRED transitional key — captured only to emit a migration error naming the fix.
            #[serde(default)]
            policy: Option<serde::de::IgnoredAny>,
            /// RETIRED transitional key — captured only to emit a migration error naming the fix.
            #[serde(default)]
            hook: Option<serde::de::IgnoredAny>,
            /// THE pool form (everything-is-a-hook): a pool names the hooks it wants — an ordering
            /// strategy (weighted/cheapest/…) and/or gates — in ONE list. Desugars into the internal
            /// (base policy, gates) representation.
            #[serde(default)]
            hooks: Option<Vec<String>>,
            /// REMOVED in 1.3 — captured only to emit a migration error naming the fix.
            #[serde(default)]
            route: Option<String>,
        }

        // Is `name` one of the native ordering strategies (an ordering hook), vs a gate reference?
        // The strategy set is fixed + known at parse time, so `hooks: [...]` classifies without the
        // (not-yet-available) registry: a strategy name sets the base ordering; anything else is a gate.
        fn is_strategy_name(name: &str) -> bool {
            matches!(
                name,
                "weighted" | "cheapest" | "fastest" | "least_busy" | "usage"
            )
        }

        let raw = RawPoolCfg::deserialize(deserializer)?;

        // The `route:` pool key is GONE in 1.3 (a pool names its hooks in one `hooks: [...]` list;
        // `route` now means only the HTTP router). Name the fix per legacy value.
        if let Some(route) = raw.route.as_deref() {
            let msg = match route {
                "weighted" | "cheapest" | "fastest" | "least_busy" | "usage" | "native" => {
                    "the `route:` pool key was removed in 1.3; a pool names its ordering strategy \
                     in its `hooks:` list — write `hooks: [<name>]` (e.g. `hooks: [cheapest]`)."
                }
                "socket" | "webhook" => {
                    "the `route: socket|webhook` transport was removed in 1.3; define the hook once \
                     under top-level `hooks:` (e.g. `hooks: { my-hook: { kind: gate, socket: ... } }`) \
                     and name it in the pool's list: `hooks: [my-hook]`."
                }
                "script" => {
                    "route: script (the embedded Rhai transport) was removed in 1.3. Define an \
                     out-of-process gate under top-level `hooks:` (kind: gate, socket:) and name it \
                     in the pool's `hooks: [...]` list. See the 1.2.x -> 1.3 migration guide."
                }
                _ => {
                    "the `route:` pool key was removed in 1.3. Name the pool's ordering strategy \
                     and/or gates in its `hooks: [...]` list (definitions live under top-level \
                     `hooks:`)."
                }
            };
            return Err(serde::de::Error::custom(msg));
        }

        // The transitional `policy:`/`hook:` pool keys are RETIRED — `hooks: [...]` is the one form.
        if raw.policy.is_some() {
            return Err(serde::de::Error::custom(
                "the `policy:` pool key was retired in 1.3; a pool names its ordering strategy in \
                 its `hooks:` list — write `hooks: [<strategy>]` (e.g. `hooks: [cheapest]`).",
            ));
        }
        if raw.hook.is_some() {
            return Err(serde::de::Error::custom(
                "the `hook:` pool key was retired in 1.3; name the gate in the pool's `hooks:` \
                 list — write `hooks: [my-gate]` (an ordering strategy may share the list, e.g. \
                 `hooks: [cheapest, my-gate]`).",
            ));
        }

        fn parse_strategy<E: serde::de::Error>(name: &str) -> Result<PoolPolicy, E> {
            match name {
                "weighted" => Ok(PoolPolicy::Weighted),
                "cheapest" => Ok(PoolPolicy::Cheapest),
                "fastest" => Ok(PoolPolicy::Fastest),
                "least_busy" => Ok(PoolPolicy::LeastBusy),
                "usage" => Ok(PoolPolicy::Usage),
                other => Err(serde::de::Error::custom(format!(
                    "unknown pool policy '{other}': expected weighted, cheapest, fastest, \
                     least_busy, or usage"
                ))),
            }
        }

        // Resolve the internal (base policy, gates) representation from the `hooks: [...]` list.
        let (policy, gates, base_named) = if let Some(names) = raw.hooks {
            // Partition the list: ordering strategies set the base ranking; anything else is a gate ref
            // (validated against the registry at startup). At most one strategy (a pool has ONE base
            // ordering); ANY number of gates, keeping list order — that is the phase-2 chain
            // tie-break order (reject/restrict commute; order last-wins; `priority` sorts first).
            let mut policy: Option<PoolPolicy> = None;
            let mut gates: Vec<String> = Vec::new();
            for name in names {
                if is_strategy_name(&name) {
                    if policy.is_some() {
                        return Err(serde::de::Error::custom(
                            "a pool `hooks:` list names more than one ordering strategy; a pool has \
                             one base ordering",
                        ));
                    }
                    policy = Some(parse_strategy(&name)?);
                } else {
                    gates.push(name);
                }
            }
            // No strategy named ⇒ the base is the default (resolved at startup: the `default:` hook if
            // one exists, else the compiled-in `weighted` backstop). Placeholder is `weighted` here;
            // `base_named` records whether a strategy WAS named so resolution knows to inherit or not.
            let base_named = policy.is_some();
            (policy.unwrap_or_default(), gates, base_named)
        } else {
            // No `hooks:` list ⇒ the defaults: weighted-placeholder base (base NOT named, so the
            // `default:` hook — if registered — becomes the base at resolution), no gates.
            (PoolPolicy::default(), Vec::new(), false)
        };

        Ok(PoolCfg {
            members: raw.members,
            breaker: raw.breaker,
            failover: raw.failover,
            on_exhausted: raw.on_exhausted,
            affinity: raw.affinity,
            policy,
            gates,
            base_named,
        })
    }
}

/// A pool's native ranking STRATEGY — the `policy:` key. `weighted` (default / absent) is today's
/// smooth-weighted-round-robin: ZERO added cost, no policy object constructed, the byte-identical hot
/// path. The others resolve a Busbar-native ordering policy that runs once before the failover loop.
/// This is the pool's ranking FLOOR; an optional `hook:` gate can override it per-request.
#[derive(Debug, Deserialize, Clone, Default, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub(crate) enum PoolPolicy {
    /// Smooth-weighted-round-robin (SWRR). Default and also the absent case. Zero added cost.
    #[default]
    Weighted,
    Cheapest,
    Fastest,
    LeastBusy,
    Usage,
}

impl PoolPolicy {
    /// The ranking-registry name for this strategy (`plugins::hooks::ranking::native_policy`).
    /// `weighted` returns `None` — it IS the zero-cost inline-SWRR default and constructs no policy
    /// object. String literals (not the ranking plugin's constants) so this stays engine-level and
    /// compiles when the `hooks-ranking` plugin is removed; the plugin matches the same names.
    pub(crate) fn native_name(&self) -> Option<&'static str> {
        match self {
            PoolPolicy::Weighted => None,
            PoolPolicy::Cheapest => Some("cheapest"),
            PoolPolicy::Fastest => Some("fastest"),
            PoolPolicy::LeastBusy => Some("least_busy"),
            PoolPolicy::Usage => Some("usage"),
        }
    }
}

/// A hook's MODE — the `kind:` key. A hook is one thing; `tap`/`gate` just say whether busbar waits
/// for a reply. `tap` = fire-and-forget (watch). `gate` = fire-and-wait (decide: nothing / reject /
/// restrict / order / rewrite). Only a gate can influence dispatch; a pool's `hook:` must name a gate.
#[derive(Debug, Deserialize, Serialize, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub(crate) enum HookKind {
    Tap,
    Gate,
}

/// A hook's PROMPT access grant (`prompt:`) — the trust ladder for request content, monotonic
/// `no ⊂ ro ⊂ rw`. DEFAULT `no` (shape-only; no prompt text leaves the process). `ro` sends the
/// prompt for READ-ONLY inspection (PII screening, guardrails, audit). `rw` additionally lets a GATE
/// return a `rewrite` arm that mutates the body (compression, redaction) — rewrite REQUIRES read, so
/// it is the top rung of the SAME ladder, not a separate flag. Immutable after registration.
#[derive(Debug, Deserialize, Serialize, Clone, Copy, Default, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub(crate) enum PromptAccess {
    #[default]
    No,
    Ro,
    Rw,
}

impl PromptAccess {
    /// Whether the prompt projection is built + sent (both `ro` and `rw`).
    pub(crate) fn sends_prompt(self) -> bool {
        !matches!(self, PromptAccess::No)
    }
    /// Whether the hook may return a `rewrite` arm (only `rw`). Wired in the slice-4 seam.
    #[allow(dead_code)]
    pub(crate) fn can_rewrite(self) -> bool {
        matches!(self, PromptAccess::Rw)
    }
}

/// A hook's caller-IDENTITY access grant (`user:`). `no` (default) = no identity in the payload; `ro`
/// = the governance key id/name (NEVER the secret) + the body end-user field. No `rw`: identity is
/// established by the auth plugin and hooks never rewrite it. Immutable after registration.
#[derive(Debug, Deserialize, Serialize, Clone, Copy, Default, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub(crate) enum UserAccess {
    #[default]
    No,
    Ro,
}

impl UserAccess {
    /// Whether the caller-identity projection is built + sent (`ro`).
    pub(crate) fn sends_user(self) -> bool {
        matches!(self, UserAccess::Ro)
    }
}

/// The pipeline stage a TAP observes (`at:`). Parsed now; the seam that fires taps at each stage
/// lands in a later slice. Inert on a gate.
#[derive(Debug, Deserialize, Serialize, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub(crate) enum HookStage {
    Request,
    Route,
    Attempt,
    Completion,
}

/// A resolved on_error/on_empty TERMINAL. `Weighted` (default) is the non-negotiable safety
/// stance: a broken/slow policy is indistinguishable from no policy and NEVER blocks or fails a
/// request. `Reject` is fail-closed (503). `First` uses the configured member order (a
/// deterministic degraded pick). The `on_error` CONFIG field is a free string (a fallback chain of
/// hook names bottoming out on one of these three reserved terminals); `on_empty` parses this enum
/// directly.
#[derive(Debug, Deserialize, Serialize, Clone, Default, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub(crate) enum PolicyOnError {
    #[default]
    Weighted,
    Reject,
    First,
}

/// The serde default for a hook's `on_error` — `nothing` (Matthew's ruling): a failing gate
/// DOES NOT PARTICIPATE by default — it cannot steer, and it cannot displace another gate's
/// verdict. Security gates opt into `reject`; ordering gates name `weighted` explicitly.
fn default_on_error() -> String {
    ON_ERROR_NOTHING.to_string()
}

/// The RESERVED on_error terminal names — every fallback chain must bottom out on one.
pub(crate) const ON_ERROR_WEIGHTED: &str = "weighted";
pub(crate) const ON_ERROR_REJECT: &str = "reject";
pub(crate) const ON_ERROR_FIRST: &str = "first";
/// The explicit DO-NOT-PARTICIPATE terminal: the failing gate simply drops out of the decision —
/// it cannot steer, and it cannot displace any OTHER gate's verdict (in the concurrent reconcile a
/// non-participating outcome is skipped by every pass). The right posture for a gate whose job is
/// orthogonal to routing (e.g. a compressor): its failure should never reshape traffic. Internally
/// identical to the `weighted` terminal — "didn't participate" and "busbar's normal ordering" are
/// the same behavior — but the NAME teaches the correct mental model.
pub(crate) const ON_ERROR_NOTHING: &str = "nothing";

/// Map an `on_error` NAME to its reserved terminal, if it is one. `None` = the name is a fallback
/// hook reference (a ranking strategy or a registry gate), resolved by routing / validated at boot.
pub(crate) fn on_error_terminal(name: &str) -> Option<PolicyOnError> {
    match name {
        ON_ERROR_WEIGHTED | ON_ERROR_NOTHING => Some(PolicyOnError::Weighted),
        ON_ERROR_REJECT => Some(PolicyOnError::Reject),
        ON_ERROR_FIRST => Some(PolicyOnError::First),
        _ => None,
    }
}

/// The serde default for `admin_auth:` — the built-in `admin-tokens` module (the single operator
/// admin token; byte-identical to the pre-chain behavior).
fn default_admin_auth() -> Vec<String> {
    vec!["admin-tokens".to_string()]
}

/// One `group_map:` entry — the operator-owned policy granted to a principal GROUP. Additive
/// surface: governance fields (allowed_pools, budgets, rate limits) land here next; today it
/// carries the admin authorization scope.
#[derive(Debug, Deserialize, Serialize, Clone)]
#[serde(deny_unknown_fields)]
pub(crate) struct GroupMapEntry {
    /// The ADMIN scope this group grants: `read-only` | `hooks-register` | `full`. Absent = no
    /// admin access from this group. Validated at boot; the most permissive of a principal's
    /// mapped groups wins.
    #[serde(default)]
    pub(crate) admin_scope: Option<String>,
}

/// A named entry in the top-level `hooks:` registry — a single hook (tap or gate) and its transport.
/// One transport per hook: exactly one of `socket` (Unix domain socket, ~8us) or `webhook` (HTTPS
/// sidecar). Shared runtime knobs carry over from the 1.2.1 policy block. A pool references a GATE by
/// name via its `hook:` key; global taps/gates via `global_hooks:` (or inline `global: true`).
#[derive(Debug, Deserialize, Serialize, Clone)]
#[serde(deny_unknown_fields)]
pub(crate) struct HookCfg {
    /// The hook's MODE: `tap` (fire-and-forget) or `gate` (fire-and-wait, returns a reply arm).
    pub(crate) kind: HookKind,
    // ── transport (exactly one) ──────────────────────────────────────────────────────────────────
    /// Unix domain socket path of the operator-run hook binary. Lazy connect (the hook may start
    /// after busbar). Unix-only. Mutually exclusive with `webhook`.
    #[serde(default)]
    pub(crate) socket: Option<String>,
    /// HTTPS sidecar URL. Validated by the routing-URL SSRF guard (loopback allowed; IMDS/RFC1918/
    /// CGNAT/metadata blocked — the OTLP precedent). Mutually exclusive with `socket`.
    #[serde(default)]
    pub(crate) webhook: Option<String>,
    // ── shared runtime knobs ─────────────────────────────────────────────────────────────────────
    /// Hard wall-clock deadline for a gate decision, in milliseconds (default 1). Co-located socket
    /// ~8us, webhook ~34us, so 1ms is 20x+ headroom; RAISE it for a hook that hits a DB/network/model.
    /// On timeout the decision is coerced to `on_error` and the request proceeds.
    #[serde(default = "default_policy_timeout_ms")]
    pub(crate) timeout_ms: u64,
    /// Fallback when a GATE times out/errors/saturates — a NAME resolved against the same registry
    /// as any hook (default `weighted` = proceed as busbar normally would). Reserved terminals:
    /// `nothing` (do not participate — a failing gate drops out and cannot displace another gate's
    /// verdict; the posture for non-routing gates like compressors) | `weighted` (same behavior,
    /// named as the ordering floor) | `reject` (fail closed — security gates set this) | `first`.
    /// Any other name is a
    /// fallback HOOK (a built-in ranking strategy or another gate) fired when this one fails; its
    /// own `on_error` chains further, and boot validation proves every chain terminates (unknown
    /// names, taps, and cycles are boot errors).
    #[serde(default = "default_on_error")]
    pub(crate) on_error: String,
    /// PROMPT access grant: `no` (default, shape-only) | `ro` (read prompt content) | `rw` (read +
    /// may `rewrite` the body). The single trust ladder for request content; `rw` is how a gate is
    /// granted rewrite. Immutable after registration. `rw` on a tap is a config error.
    #[serde(default)]
    pub(crate) prompt: PromptAccess,
    /// Caller-IDENTITY access grant: `no` (default) | `ro` (governance key id/name — never the secret
    /// — + body end-user field). Enables route-by-who gates. Immutable after registration.
    #[serde(default)]
    pub(crate) user: UserAccess,
    /// Hook ordering key (default 0). Orders the rewrite transform chain and the phase-2 decision
    /// chain (which reject surfaces; which order is "last" — see design-hooks-v2 §3.2). Ascending;
    /// ties keep globals before pool gates, then config order.
    #[serde(default)]
    pub(crate) priority: u16,
    /// TAP observation stage (`request`/`route`/`attempt`/`completion`; unset = `request`).
    /// `request` observes the (post-rewrite) request; `route` the post-reconcile candidate set;
    /// `attempt` every dispatch attempt (the failover story); `completion` the outcome — including
    /// the SYNTHETIC rejected completion, so audit taps see denials. Inert on a gate.
    #[serde(default)]
    pub(crate) at: Option<HookStage>,
    /// GATE restrict empty-intersection behavior (default `reject`, fail-closed; `weighted` is the
    /// advisory escape — the gate's restriction is skipped). Applied per gate in the phase-2
    /// reconcile.
    #[serde(default)]
    pub(crate) on_empty: Option<PolicyOnError>,
    /// OPAQUE settings map pushed to the hook via the `configure` wire message (D2): sent as the
    /// first line on every socket connection and re-pushed (commit-on-ack) by
    /// `PATCH /admin/v1/hooks/{name}/settings`. Busbar never interprets the contents.
    #[serde(default)]
    pub(crate) settings: serde_json::Map<String, serde_json::Value>,
    /// Fire on EVERY request — inline sugar for adding this name to `global_hooks:`. Default false.
    #[serde(default)]
    pub(crate) global: bool,
    /// Mark this hook as THE default — the base a pool inherits when it names no hook of its own.
    /// REPLACEMENT semantics (unlike `global:`, which is an overlay ON TOP of the base): a `default`
    /// hook becomes the base, so the compiled-in backstop (`weighted`) is not used. Exactly like
    /// `auth: [sso]` means the built-in `tokens` is not loaded. AT MOST ONE hook may set `default:
    /// true` (boot AND every admin apply → error naming both); 0 ⇒ the compiled-in backstop. Only an
    /// ordering hook (one that returns `order`) is a meaningful default. Default false. Resolution:
    /// `routing::resolve_pool_ordering` gives this hook to every pool whose base is unnamed.
    #[serde(default)]
    pub(crate) default: bool,
}

/// The default hard wall-clock deadline for a gate decision, in milliseconds. Used by serde's
/// `default = "default_policy_timeout_ms"`. Also the single source of truth consumed at the
/// resolution sites in `routing/mod.rs`.
pub(crate) const DEFAULT_POLICY_TIMEOUT_MS: u64 = 1;

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
    /// into the routing `Candidate` (via `MemberMeta`) and read by webhook/socket policies.
    #[serde(default)]
    pub(crate) tier: Option<String>,
    /// Per-ATTEMPT time-to-response-headers cap (ms) for THIS member in THIS pool — overrides the
    /// model-level `attempt_timeout_ms`, so one model can be patient in an image pool (10000) and
    /// ruthless in a realtime pool (50). See `ModelCfg::attempt_timeout_ms` for semantics.
    #[serde(default)]
    pub(crate) attempt_timeout_ms: Option<u64>,
    /// Per-pool override of the model-level `reasoning` capability flag (member wins), so the same
    /// lane can allow thinking in a research pool and refuse it in a latency-critical one. See
    /// `ModelCfg::reasoning` for semantics.
    #[serde(default)]
    pub(crate) reasoning: Option<bool>,
    /// Operator-declared cost in currency-units per million tokens. Drives the native `cheapest`
    /// policy and is exposed to webhook/socket policies. Inert when unset.
    #[serde(default)]
    pub(crate) cost_per_mtok: Option<f64>,
    /// Free-form operator tags (e.g. `["opus"]`) a policy can match on. Projected into the routing
    /// `Candidate` and read by webhook/socket policies.
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
#[serde(deny_unknown_fields)]
pub(crate) struct BreakerTripConfig {
    #[serde(default = "default_trip_mode")]
    pub(crate) mode: BreakerTripMode,
    /// Sliding-window length in seconds. Renamed from `window_s` in 1.0.0; the old key is still
    /// accepted via the serde alias so existing configs keep loading.
    #[serde(default = "default_window_secs", alias = "window_s")]
    pub(crate) window_secs: u64,
    #[serde(default = "default_threshold")]
    pub(crate) threshold: f64,
    #[serde(default = "default_min_requests")]
    pub(crate) min_requests: usize,
    /// Consecutive-failure threshold for `BreakerTripMode::Consecutive`. Renamed from `n` in 1.0.0;
    /// the old key is still accepted via the serde alias so existing configs keep loading.
    #[serde(default = "default_consecutive_n", alias = "n")]
    pub(crate) consecutive_n: u32,
}

fn default_trip_mode() -> BreakerTripMode {
    BreakerTripMode::ErrorRate
}

/// Default sliding-window length in seconds for the breaker trip evaluation (ADR-0002).
const DEFAULT_BREAKER_WINDOW_SECS: u64 = 30;
/// Default error-rate threshold for tripping the breaker (fraction in (0.0, 1.0]).
const DEFAULT_BREAKER_THRESHOLD: f64 = 0.5;
/// Default minimum request count before the error-rate breaker can trip.
const DEFAULT_BREAKER_MIN_REQUESTS: usize = 5;
/// Default consecutive-failure streak length for `BreakerTripMode::Consecutive`.
const DEFAULT_BREAKER_CONSECUTIVE_N: u32 = 3;

fn default_window_secs() -> u64 {
    DEFAULT_BREAKER_WINDOW_SECS
}

fn default_threshold() -> f64 {
    DEFAULT_BREAKER_THRESHOLD
}

fn default_min_requests() -> usize {
    DEFAULT_BREAKER_MIN_REQUESTS
}

fn default_consecutive_n() -> u32 {
    DEFAULT_BREAKER_CONSECUTIVE_N
}

/// Breaker configuration per pool with full trip settings (ADR-0002).
#[derive(Debug, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
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

/// Default base cooldown (seconds) for the escalating breaker back-off (ADR-0002). Single source
/// of truth for both `BreakerCfg::default()` and the `#[serde(default)]` path.
const DEFAULT_BREAKER_BASE_COOLDOWN_SECS: u64 = 15;
/// Default maximum cooldown (seconds) for the escalating breaker back-off (ADR-0002).
const DEFAULT_BREAKER_MAX_COOLDOWN_SECS: u64 = 120;

fn default_cooldown() -> u64 {
    // Single source of truth for the base cooldown: both `BreakerCfg::default()` (used when a pool
    // omits the `breaker:` block) and `#[serde(default = "default_cooldown")]` (used when the block
    // is present but omits `base_cooldown_secs`) route through here, so the value is a consistent
    // 15s on every path.
    DEFAULT_BREAKER_BASE_COOLDOWN_SECS
}

fn default_max_cooldown() -> u64 {
    DEFAULT_BREAKER_MAX_COOLDOWN_SECS
}

#[derive(Debug, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub(crate) struct FailoverCfg {
    /// Failover wall-clock budget in seconds. Renamed from `deadline_secs` in 1.0.0; the old key is
    /// still accepted via the serde alias so existing configs keep loading.
    #[serde(default = "default_failover_timeout", alias = "deadline_secs")]
    pub(crate) timeout_secs: u64,
    /// Member model names excluded from this pool's candidate set — never selected (primary or
    /// failover). A per-pool blocklist for temporarily benching a member without editing `members`.
    #[serde(default)]
    pub(crate) exclusions: Option<Vec<String>>,
    /// Maximum failover hops per request. Renamed from `cap` in 1.0.0; the old key is still accepted
    /// via the serde alias so existing configs keep loading.
    #[serde(default = "default_max_hops", alias = "cap")]
    pub(crate) max_hops: usize,
}

/// Default failover wall-clock budget (seconds) when a pool doesn't set `failover.timeout_secs`.
pub(crate) const DEFAULT_FAILOVER_DEADLINE_SECS: u64 = 120;
/// Default maximum failover hops per request when a pool doesn't set `failover.max_hops`.
pub(crate) const DEFAULT_FAILOVER_CAP: usize = 3;

fn default_failover_timeout() -> u64 {
    DEFAULT_FAILOVER_DEADLINE_SECS
}

fn default_max_hops() -> usize {
    DEFAULT_FAILOVER_CAP
}

#[derive(Debug, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub(crate) struct OnExhaustedCfg {
    #[serde(default = "default_on_exhausted_action")]
    pub(crate) action: String,
}

/// Default on_exhausted action: return 503 Service Unavailable when all pool members are exhausted.
const DEFAULT_ON_EXHAUSTED: &str = "reject";

fn default_on_exhausted_action() -> String {
    DEFAULT_ON_EXHAUSTED.to_string()
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

/// Prefix for the `fallback_pool:<name>` on_exhausted action. Used for BOTH the `starts_with`
/// guard AND the slice offset so the prefix literal and the offset are ALWAYS coupled.
const FALLBACK_POOL_PREFIX: &str = "fallback_pool:";

impl OnExhausted {
    /// Parse an action string from config into an OnExhausted variant.
    /// Returns Err(String) for unknown actions - NO bare _ => allowed.
    pub(crate) fn parse(action: &str) -> Result<Self, String> {
        match action {
            "reject" | "503" | "status_503" => Ok(OnExhausted::Status503),
            "fallback_pool" => Err("fallback_pool requires a pool name argument".into()),
            "least_bad" | "least-bad" | "leastbad" => Ok(OnExhausted::LeastBad),
            // FallbackPool with name - parse as "fallback_pool:<pool_name>" format
            s if s.starts_with(FALLBACK_POOL_PREFIX) => {
                let pool_name = &s[FALLBACK_POOL_PREFIX.len()..];
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

/// Affinity mode. `session` is the default and only supported mode. Modelled as a (currently
/// single-variant) enum so an unrecognized spelling (e.g. `sticky`) is a deserialize error rather
/// than a silently-accepted value that degrades to default behaviour. The wire string (`session`)
/// is unchanged from the pre-enum `String` field.
#[derive(Debug, Deserialize, Clone, Copy, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub(crate) enum AffinityMode {
    #[default]
    Session,
}

#[derive(Debug, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub(crate) struct AffinityCfg {
    /// Affinity mode. `session` (the default and only supported mode) pins a session to a lane
    /// using the header named by `header_name`.
    #[serde(default)]
    pub(crate) mode: AffinityMode,
    /// Request header carrying the session id (defaults to `x-session-id` when unset).
    #[serde(default)]
    pub(crate) header_name: Option<String>,
}

/// Default listen address for the inbound HTTP server.
pub(crate) const DEFAULT_LISTEN_ADDR: &str = "0.0.0.0:8080";

fn default_listen() -> String {
    DEFAULT_LISTEN_ADDR.into()
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
    pub(crate) auth: Option<ProviderAuth>,
    /// Catalog default for the per-provider metadata allow-override (see
    /// `ProviderCfg::allow_metadata_hosts`). A deployment's `allow_metadata_hosts` (`Some`) replaces
    /// this; `None` falls back to the catalog list. Default empty (all metadata blocked).
    #[serde(default)]
    pub(crate) allow_metadata_hosts: Vec<String>,
}

/// Provider deployment - operator config in config.yaml (names provider + supplies key).
#[derive(Deserialize, Clone, Default)]
#[serde(deny_unknown_fields)]
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
    pub(crate) auth: Option<ProviderAuth>,
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
    /// The top-level hook registry (`hooks:`) — named taps + gates. Optional; absent = empty.
    #[serde(default)]
    pub(crate) hooks: HashMap<String, HookCfg>,
    /// The ADMIN auth chain (`admin_auth:`). Absent ⇒ the default `[admin-tokens]`.
    #[serde(default = "default_admin_auth")]
    pub(crate) admin_auth: Vec<String>,
    /// `group_map:` — principal groups → operator-owned policy. Optional; absent = empty.
    #[serde(default)]
    pub(crate) group_map: HashMap<String, GroupMapEntry>,
    /// Hooks that fire on every request (`global_hooks:`). Optional; unioned at resolve with any hook
    /// carrying inline `global: true`.
    #[serde(default)]
    pub(crate) global_hooks: Vec<String>,
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
    /// Operator-tunable global operational limits ("NEVER CODED CAPS"). Whole block optional; each
    /// field defaults to its historical hardcoded value (absent = today's behavior).
    #[serde(default)]
    pub(crate) limits: LimitsCfg,
    /// Process-wide metrics tunables.
    #[serde(default)]
    pub(crate) metrics: MetricsCfg,
    /// Process-wide active-probe fallbacks (per-lane overrides still win).
    #[serde(default)]
    pub(crate) health: HealthDefaultsCfg,
    /// Routing global default policy timeout (per-policy override still wins).
    #[serde(default)]
    pub(crate) routing: RoutingCfg,
}

/// Operator-owned security controls (config.yaml `security:` block).
#[derive(Debug, Deserialize, Clone, Default)]
#[serde(deny_unknown_fields)]
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
// deny_unknown_fields: a typo in a security-relevant governance key (e.g. `admin_tokn:`) must be a
// loud startup error, not a silent default (which would leave the admin API unreachable / a budget
// unset). Mirrors the same guard on AuthCfg.
#[derive(Deserialize, Clone)]
#[serde(deny_unknown_fields)]
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
    /// Behavior when the budget store errors during the atomic admission check-and-charge.
    /// `allow` (default) fails OPEN — the request proceeds, preserving availability on a telemetry-
    /// store hiccup (today's behavior). `deny` fails CLOSED — the request is rejected, the strict
    /// stance for security/regulated deployments that want a hard budget guarantee. Only the store-
    /// ERROR path is affected; a definitive over-budget result always rejects regardless.
    #[serde(default)]
    pub(crate) budget_on_store_error: BudgetOnStoreError,
    /// SQLite `busy_timeout` (ms) applied to each governance connection (default 5000).
    #[serde(default = "default_sqlite_busy_timeout_ms")]
    pub(crate) sqlite_busy_timeout_ms: i64,
    /// Amortization interval for the rate-limiter stale-entry sweep: every Nth `check_rate` pays the
    /// full retain (default 256).
    #[serde(default = "default_rate_sweep_interval")]
    pub(crate) rate_sweep_interval: u32,
}

impl Default for GovernanceCfg {
    fn default() -> Self {
        // Route the limit fields through the serde-default fns; the non-limit fields keep their
        // historical zero/disabled defaults (governance is off unless `enabled` is set).
        Self {
            enabled: false,
            db_path: default_gov_db_path(),
            price_per_request_cents: default_price_per_request_cents(),
            price_per_1k_tokens_cents: 0,
            admin_token: None,
            budget_on_store_error: BudgetOnStoreError::default(),
            sqlite_busy_timeout_ms: default_sqlite_busy_timeout_ms(),
            rate_sweep_interval: default_rate_sweep_interval(),
        }
    }
}

/// Fail-mode for the budget check on a store error. Default `allow` (fail-open) preserves
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

/// Default SQLite database path for the governance store.
const DEFAULT_GOVERNANCE_DB: &str = "busbar-governance.db";

fn default_gov_db_path() -> String {
    DEFAULT_GOVERNANCE_DB.to_string()
}

fn default_price_per_request_cents() -> i64 {
    1
}

/// Observability sinks. All fields optional; absent = that sink is disabled.
#[derive(Debug, Deserialize, Clone)]
pub(crate) struct ObservabilityCfg {
    /// OTLP/HTTP traces endpoint (e.g. `http://localhost:4318/v1/traces`). When set, busbar
    /// installs an OpenTelemetry tracer + exports spans.
    #[serde(default)]
    pub(crate) otlp_endpoint: Option<String>,
    /// When set, busbar fires a best-effort (fire-and-forget) JSON request-log POST per request
    /// to this URL.
    #[serde(default)]
    pub(crate) request_log_webhook_url: Option<String>,
    /// Max concurrent webhook deliveries (default 64). Bounds the fan-out of a slow webhook sink.
    #[serde(default = "default_max_inflight_webhook_deliveries")]
    pub(crate) max_inflight_webhook_deliveries: usize,
    /// Per-delivery webhook timeout (seconds, default 2).
    #[serde(default = "default_webhook_delivery_timeout_secs")]
    pub(crate) webhook_delivery_timeout_secs: u64,
    /// Emit the `Server-Timing: busbar;dur=<ms>` response header (default `false`). The header is a
    /// useful latency probe, but it is also an in-band busbar fingerprint on an otherwise
    /// anti-fingerprinting gateway — and it is the one fingerprint observable by an UNAUTHENTICATED
    /// client on every response — so it defaults OFF to preserve backend-facing indistinguishability.
    /// Operators who want the latency probe (and accept the product tell) opt IN by setting `true`.
    #[serde(default = "default_emit_server_timing")]
    pub(crate) emit_server_timing: bool,
}

impl Default for ObservabilityCfg {
    fn default() -> Self {
        // Route the limit fields through the serde-default fns so the omitted-block path and the
        // omitted-field path share one source of truth (the URL sinks stay disabled by default).
        Self {
            otlp_endpoint: None,
            request_log_webhook_url: None,
            max_inflight_webhook_deliveries: default_max_inflight_webhook_deliveries(),
            webhook_delivery_timeout_secs: default_webhook_delivery_timeout_secs(),
            emit_server_timing: default_emit_server_timing(),
        }
    }
}

/// `Server-Timing: busbar` header is SUPPRESSED by default (indistinguishability); operators opt IN.
pub(crate) const DEFAULT_EMIT_SERVER_TIMING: bool = false;
fn default_emit_server_timing() -> bool {
    DEFAULT_EMIT_SERVER_TIMING
}

// ───────────────────────────────────────────────────────────────────────────────────────────────
// Operator-tunable operational limits ("NEVER CODED CAPS"). Every field defaults — via a
// `default = "fn"` whose body is the historical hardcoded const — to today's behavior, so an absent
// key (the common case) is byte-for-byte unchanged. Each section struct is itself `#[serde(default)]`
// at its `DeployCfg` field, so omitting the whole block is valid. The resolved values are projected
// onto `LimitsResolved` (on `RootCfg`) and threaded/installed at startup (see `crate::limits`).
// ───────────────────────────────────────────────────────────────────────────────────────────────

/// Default upstream per-request timeout (seconds). Single source of truth for both serde's
/// `default = "..."` and the resolved-default fallback. Mirrors the historical `main.rs` const.
const DEFAULT_UPSTREAM_REQUEST_TIMEOUT_SECS: u64 = 300;
/// Default maximum accepted request body size (bytes). Couples to the egress translate-body cap
/// (`crate::limits::translate_body_max_bytes`): a body the gateway accepts inbound must also be
/// buffer-translatable on egress, so ONE knob (`limits.request_body_max_bytes`) drives both.
pub(crate) const DEFAULT_REQUEST_BODY_MAX_BYTES: usize = 32 * 1024 * 1024;
/// Hard floor on `request_body_max_bytes` — a too-small cap would reject legitimate multi-turn /
/// multimodal requests with no recourse. 64 KiB comfortably holds a minimal request.
pub(crate) const REQUEST_BODY_MAX_BYTES_FLOOR: usize = 64 * 1024;
/// Hard ceiling on `request_body_max_bytes` — the body is buffered per request, so an absurd value
/// is a memory-exhaustion foot-gun. 1 GiB is far above any legitimate completion payload.
pub(crate) const REQUEST_BODY_MAX_BYTES_CEIL: usize = 1024 * 1024 * 1024;
/// Default max idle keep-alive connections the upstream client pools per host. Mirrors `main.rs`.
const DEFAULT_POOL_MAX_IDLE_PER_HOST: usize = 64;
/// Default inbound concurrency limit. `0` = unlimited (today's behavior — NO layer added).
pub(crate) const DEFAULT_MAX_INBOUND_CONCURRENT: usize = 0;
/// Default hard-down sticky cooldown (seconds). Mirrors `store.rs`.
pub(crate) const DEFAULT_HARD_DOWN_COOLDOWN_SECS: u64 = 1800;
/// Default ceiling on a honored upstream `Retry-After` (seconds). Mirrors `store.rs` (24h).
pub(crate) const DEFAULT_MAX_HONORED_RETRY_AFTER_SECS: u64 = 86_400;
/// Default cap on a buffered upstream ERROR / verbatim-relay body (bytes). Mirrors `forward.rs`.
pub(crate) const DEFAULT_UPSTREAM_ERROR_BODY_MAX_BYTES: usize = 256 * 1024;
/// Default TLS handshake wall-clock bound (seconds). Mirrors `tls.rs`.
pub(crate) const DEFAULT_TLS_HANDSHAKE_TIMEOUT_SECS: u64 = 10;
/// Default global fallback for the translation-injected `max_tokens` (mirrors `proto::DEFAULT_MAX_TOKENS`).
pub(crate) const DEFAULT_DEFAULT_MAX_TOKENS: u32 = 4096;
/// Default max concurrent webhook deliveries. Mirrors `observability.rs`.
pub(crate) const DEFAULT_MAX_INFLIGHT_WEBHOOK_DELIVERIES: usize = 64;
/// Default per-webhook delivery timeout (seconds). Mirrors `observability.rs`.
pub(crate) const DEFAULT_WEBHOOK_DELIVERY_TIMEOUT_SECS: u64 = 2;
/// Default max per-key gauge series emitted per scrape. Mirrors `metrics.rs`.
pub(crate) const DEFAULT_KEY_GAUGE_LIMIT: usize = 2000;
/// Default SQLite `busy_timeout` (ms) for the governance store. Mirrors `governance.rs`.
pub(crate) const DEFAULT_SQLITE_BUSY_TIMEOUT_MS: i64 = 5_000;
/// Default rate-sweep amortization interval. Mirrors `governance.rs`.
pub(crate) const DEFAULT_RATE_SWEEP_INTERVAL: u32 = 256;
/// Default active-probe interval (seconds) — the process-wide fallback for the per-lane override.
pub(crate) const DEFAULT_PROBE_INTERVAL_SECS: u64 = 30;
/// Default active-probe timeout (seconds) — the process-wide fallback for the per-lane override.
pub(crate) const DEFAULT_PROBE_TIMEOUT_SECS: u64 = 5;

fn default_upstream_request_timeout_secs() -> u64 {
    DEFAULT_UPSTREAM_REQUEST_TIMEOUT_SECS
}
fn default_request_body_max_bytes() -> usize {
    DEFAULT_REQUEST_BODY_MAX_BYTES
}
fn default_pool_max_idle_per_host() -> usize {
    DEFAULT_POOL_MAX_IDLE_PER_HOST
}
fn default_max_inbound_concurrent() -> usize {
    DEFAULT_MAX_INBOUND_CONCURRENT
}
fn default_hard_down_cooldown_secs() -> u64 {
    DEFAULT_HARD_DOWN_COOLDOWN_SECS
}
fn default_max_honored_retry_after_secs() -> u64 {
    DEFAULT_MAX_HONORED_RETRY_AFTER_SECS
}
fn default_upstream_error_body_max_bytes() -> usize {
    DEFAULT_UPSTREAM_ERROR_BODY_MAX_BYTES
}
fn default_tls_handshake_timeout_secs() -> u64 {
    DEFAULT_TLS_HANDSHAKE_TIMEOUT_SECS
}
fn default_default_max_tokens() -> u32 {
    DEFAULT_DEFAULT_MAX_TOKENS
}
fn default_max_inflight_webhook_deliveries() -> usize {
    DEFAULT_MAX_INFLIGHT_WEBHOOK_DELIVERIES
}
fn default_webhook_delivery_timeout_secs() -> u64 {
    DEFAULT_WEBHOOK_DELIVERY_TIMEOUT_SECS
}
fn default_key_gauge_limit() -> usize {
    DEFAULT_KEY_GAUGE_LIMIT
}
fn default_sqlite_busy_timeout_ms() -> i64 {
    DEFAULT_SQLITE_BUSY_TIMEOUT_MS
}
fn default_rate_sweep_interval() -> u32 {
    DEFAULT_RATE_SWEEP_INTERVAL
}
fn default_probe_interval_secs() -> u64 {
    DEFAULT_PROBE_INTERVAL_SECS
}
fn default_probe_timeout_secs() -> u64 {
    DEFAULT_PROBE_TIMEOUT_SECS
}

/// The `limits:` block — global operational caps. Each field defaults to its historical hardcoded
/// value, so an absent field (or an absent block) is today's behavior.
#[derive(Debug, Deserialize, Clone)]
pub(crate) struct LimitsCfg {
    #[serde(default = "default_upstream_request_timeout_secs")]
    pub(crate) upstream_request_timeout_secs: u64,
    /// Max accepted inbound body (bytes). COUPLED: also drives the egress translate-body cap
    /// (`crate::limits::translate_body_max_bytes`) — one knob feeds both so an accepted request is
    /// always buffer-translatable on egress.
    #[serde(default = "default_request_body_max_bytes")]
    pub(crate) request_body_max_bytes: usize,
    #[serde(default = "default_pool_max_idle_per_host")]
    pub(crate) pool_max_idle_per_host: usize,
    /// Inbound concurrency cap. `0` (default) = unlimited: NO layer is added (a true no-op). When
    /// `>0`, a `tower` global concurrency limit wraps the router as the outermost layer.
    #[serde(default = "default_max_inbound_concurrent")]
    pub(crate) max_inbound_concurrent: usize,
    #[serde(default = "default_hard_down_cooldown_secs")]
    pub(crate) hard_down_cooldown_secs: u64,
    #[serde(default = "default_upstream_error_body_max_bytes")]
    pub(crate) upstream_error_body_max_bytes: usize,
    #[serde(default = "default_tls_handshake_timeout_secs")]
    pub(crate) tls_handshake_timeout_secs: u64,
    #[serde(default = "default_max_honored_retry_after_secs")]
    pub(crate) max_honored_retry_after_secs: u64,
    #[serde(default = "default_default_max_tokens")]
    pub(crate) default_max_tokens: u32,
    /// Effort-word → thinking-token-budget table for the cross-protocol reasoning carry: what
    /// OpenAI's `reasoning_effort` words mean in tokens when projected onto Anthropic
    /// `thinking.budget_tokens` / Gemini `thinkingBudget` (and, inverted, the bucket thresholds
    /// when a numeric budget is projected onto an effort word). "Medium" is a cost decision, so
    /// operators can override it; defaults 1024/4096/8192/16384.
    #[serde(default)]
    pub(crate) reasoning_effort_budgets: ReasoningEffortBudgets,
}

/// The `minimal/low/medium/high` → token-budget table (see `LimitsCfg::reasoning_effort_budgets`).
#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq)]
pub(crate) struct ReasoningEffortBudgets {
    #[serde(default = "default_reasoning_minimal")]
    pub(crate) minimal: u32,
    #[serde(default = "default_reasoning_low")]
    pub(crate) low: u32,
    #[serde(default = "default_reasoning_medium")]
    pub(crate) medium: u32,
    #[serde(default = "default_reasoning_high")]
    pub(crate) high: u32,
}

impl Default for ReasoningEffortBudgets {
    fn default() -> Self {
        Self {
            minimal: default_reasoning_minimal(),
            low: default_reasoning_low(),
            medium: default_reasoning_medium(),
            high: default_reasoning_high(),
        }
    }
}

fn default_reasoning_minimal() -> u32 {
    1024
}
fn default_reasoning_low() -> u32 {
    4096
}
fn default_reasoning_medium() -> u32 {
    8192
}
fn default_reasoning_high() -> u32 {
    16384
}

impl Default for LimitsCfg {
    fn default() -> Self {
        // Route every field through the serde-default fn so the omitted-block path (this `Default`)
        // and the omitted-field path share one source of truth and cannot drift.
        Self {
            upstream_request_timeout_secs: default_upstream_request_timeout_secs(),
            request_body_max_bytes: default_request_body_max_bytes(),
            pool_max_idle_per_host: default_pool_max_idle_per_host(),
            max_inbound_concurrent: default_max_inbound_concurrent(),
            hard_down_cooldown_secs: default_hard_down_cooldown_secs(),
            upstream_error_body_max_bytes: default_upstream_error_body_max_bytes(),
            tls_handshake_timeout_secs: default_tls_handshake_timeout_secs(),
            max_honored_retry_after_secs: default_max_honored_retry_after_secs(),
            default_max_tokens: default_default_max_tokens(),
            reasoning_effort_budgets: ReasoningEffortBudgets::default(),
        }
    }
}

/// The `metrics:` block.
#[derive(Debug, Deserialize, Clone)]
pub(crate) struct MetricsCfg {
    #[serde(default = "default_key_gauge_limit")]
    pub(crate) key_gauge_limit: usize,
}

impl Default for MetricsCfg {
    fn default() -> Self {
        Self {
            key_gauge_limit: default_key_gauge_limit(),
        }
    }
}

/// The `health:` block — process-wide active-probe fallbacks (per-lane `health.interval_secs` /
/// `timeout_secs` still override these).
#[derive(Debug, Deserialize, Clone)]
pub(crate) struct HealthDefaultsCfg {
    #[serde(default = "default_probe_interval_secs")]
    pub(crate) default_probe_interval_secs: u64,
    #[serde(default = "default_probe_timeout_secs")]
    pub(crate) default_probe_timeout_secs: u64,
}

impl Default for HealthDefaultsCfg {
    fn default() -> Self {
        Self {
            default_probe_interval_secs: default_probe_interval_secs(),
            default_probe_timeout_secs: default_probe_timeout_secs(),
        }
    }
}

/// The `routing:` block — the global default policy timeout (per-policy `policy.timeout_ms` still
/// overrides).
#[derive(Debug, Deserialize, Clone)]
pub(crate) struct RoutingCfg {
    #[serde(default = "default_policy_timeout_ms")]
    pub(crate) default_policy_timeout_ms: u64,
}

impl Default for RoutingCfg {
    fn default() -> Self {
        Self {
            default_policy_timeout_ms: default_policy_timeout_ms(),
        }
    }
}

/// Fully-resolved operational limits, projected onto `RootCfg` by `resolve`. Grouped here so the
/// startup wiring (`crate::limits::install` + the explicit main.rs/store threading) reads a flat
/// struct rather than re-walking optional config sections.
#[derive(Debug, Clone)]
pub(crate) struct LimitsResolved {
    pub(crate) upstream_request_timeout_secs: u64,
    pub(crate) request_body_max_bytes: usize,
    pub(crate) pool_max_idle_per_host: usize,
    pub(crate) max_inbound_concurrent: usize,
    pub(crate) hard_down_cooldown_secs: u64,
    pub(crate) upstream_error_body_max_bytes: usize,
    pub(crate) tls_handshake_timeout_secs: u64,
    pub(crate) max_honored_retry_after_secs: u64,
    pub(crate) default_max_tokens: u32,
    pub(crate) reasoning_effort_budgets: ReasoningEffortBudgets,
    pub(crate) max_inflight_webhook_deliveries: usize,
    pub(crate) webhook_delivery_timeout_secs: u64,
    pub(crate) key_gauge_limit: usize,
    pub(crate) sqlite_busy_timeout_ms: i64,
    pub(crate) rate_sweep_interval: u32,
    pub(crate) default_probe_interval_secs: u64,
    pub(crate) default_probe_timeout_secs: u64,
    pub(crate) default_policy_timeout_ms: u64,
}

impl Default for LimitsResolved {
    fn default() -> Self {
        Self::from_sections(
            &LimitsCfg::default(),
            &ObservabilityCfg::default(),
            &GovernanceCfg::default(),
            &MetricsCfg::default(),
            &HealthDefaultsCfg::default(),
            &RoutingCfg::default(),
        )
    }
}

impl LimitsResolved {
    fn from_sections(
        limits: &LimitsCfg,
        obs: &ObservabilityCfg,
        gov: &GovernanceCfg,
        metrics: &MetricsCfg,
        health: &HealthDefaultsCfg,
        routing: &RoutingCfg,
    ) -> Self {
        Self {
            upstream_request_timeout_secs: limits.upstream_request_timeout_secs,
            request_body_max_bytes: limits.request_body_max_bytes,
            pool_max_idle_per_host: limits.pool_max_idle_per_host,
            max_inbound_concurrent: limits.max_inbound_concurrent,
            hard_down_cooldown_secs: limits.hard_down_cooldown_secs,
            upstream_error_body_max_bytes: limits.upstream_error_body_max_bytes,
            tls_handshake_timeout_secs: limits.tls_handshake_timeout_secs,
            max_honored_retry_after_secs: limits.max_honored_retry_after_secs,
            default_max_tokens: limits.default_max_tokens,
            reasoning_effort_budgets: limits.reasoning_effort_budgets,
            max_inflight_webhook_deliveries: obs.max_inflight_webhook_deliveries,
            webhook_delivery_timeout_secs: obs.webhook_delivery_timeout_secs,
            key_gauge_limit: metrics.key_gauge_limit,
            sqlite_busy_timeout_ms: gov.sqlite_busy_timeout_ms,
            rate_sweep_interval: gov.rate_sweep_interval,
            default_probe_interval_secs: health.default_probe_interval_secs,
            default_probe_timeout_secs: health.default_probe_timeout_secs,
            default_policy_timeout_ms: routing.default_policy_timeout_ms,
        }
    }
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
                auth: deploy_cfg.auth.or(def.auth),
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
            auth: deploy.auth.clone(),
            providers: resolved_providers,
            models: deploy.models.clone(),
            pools: deploy.pools.clone(),
            hooks: deploy.hooks.clone(),
            admin_auth: deploy.admin_auth.clone(),
            group_map: deploy.group_map.clone(),
            // global_hooks = explicit `global_hooks:` list UNIONed with any hook carrying inline
            // `global: true`, deduped, order-stable (explicit list first, then inline in registry
            // iteration order). Dangling refs are caught by config_validate.
            global_hooks: {
                let mut names = deploy.global_hooks.clone();
                for (name, hook) in &deploy.hooks {
                    if hook.global && !names.iter().any(|n| n == name) {
                        names.push(name.clone());
                    }
                }
                names
            },
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
            // Project the operational-limit sections onto a flat resolved struct. The `observability:`
            // and `governance:` blocks are optional; absent ⇒ their section defaults (which are the
            // historical hardcoded values, via the manual `Default` impls).
            limits: LimitsResolved::from_sections(
                &deploy.limits,
                &deploy.observability.clone().unwrap_or_default(),
                &deploy.governance.clone().unwrap_or_default(),
                &deploy.metrics,
                &deploy.health,
                &deploy.routing,
            ),
        })
    } else {
        Err(errors)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The hook config types are round-trippable (Deserialize + Serialize) — the foundation for the
    /// config-overlay persistence that will let a runtime-registered hook survive a restart. A
    /// `HookCfg` deserialized from JSON re-serializes + re-parses to an identical shape, exercising the
    /// snake_case enums (kind/prompt/user) + the transport + the ordering/stage fields.
    #[test]
    fn hook_cfg_round_trips_for_overlay_persistence() {
        let src = serde_json::json!({
            "kind": "gate",
            "webhook": "http://127.0.0.1:8900/",
            "prompt": "rw",
            "user": "ro",
            "priority": 7,
            "on_error": "reject",
            "global": true,
            "timeout_ms": 25
        });
        let cfg: HookCfg = serde_json::from_value(src).expect("HookCfg deserializes");
        // Serialize -> re-deserialize -> re-serialize: the two JSON forms must be identical (stable).
        let once = serde_json::to_value(&cfg).expect("HookCfg serializes");
        let cfg2: HookCfg = serde_json::from_value(once.clone()).expect("re-deserializes");
        let twice = serde_json::to_value(&cfg2).expect("re-serializes");
        assert_eq!(once, twice, "HookCfg round-trips stably");
        // Spot-check the snake_case enum projection survives.
        assert_eq!(once["kind"], "gate");
        assert_eq!(once["prompt"], "rw");
        assert_eq!(once["user"], "ro");
        assert_eq!(once["on_error"], "reject");
    }

    /// Serializes tests that touch the *shared* `BUSBAR_CLIENT_TOKEN` env var. Env vars are
    /// process-global, and `cargo test` runs tests in parallel by default, so two tests that
    /// `set_var`/`remove_var` the same name race: one can wipe the value mid-flight of the other,
    /// causing a spurious "unset variable" interpolation failure. Renaming is not viable because the
    /// shipped `config.yaml` hard-references `${BUSBAR_CLIENT_TOKEN}`; instead, every test that
    /// drives that var must hold this lock for the whole set/interpolate/remove sequence.
    ///
    /// Per-test vars use unique `BUSBAR_T_*` names and so do not need this guard.
    static CLIENT_TOKEN_ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    /// 1.0.0 MIGRATION: the legacy single-token `token:` key was REMOVED. `AuthCfg` is now
    /// `#[serde(deny_unknown_fields)]`, so a config still setting `token:` is REJECTED AT PARSE with
    /// serde's "unknown field `token`, expected one of `mode`, `client_tokens`" — a hard, clear
    /// migration error, never a silent credential drop. (Previously the key deserialized into a
    /// tombstone field and was caught later at validate time; that mechanism was removed.)
    #[test]
    fn test_legacy_token_key_is_rejected_at_parse() {
        let yaml = "mode: token\ntoken: \"sk-bb-legacy\"\nclient_tokens: []";
        let err = serde_yaml::from_str::<AuthCfg>(yaml)
            .expect_err("legacy `token:` must be rejected at parse, not deserialize");
        let msg = err.to_string();
        assert!(
            msg.contains("unknown field") && msg.contains("token"),
            "expected serde's unknown-field error naming `token`; got: {msg}"
        );
        // The rejected secret value is NEVER echoed back in the parse error.
        assert!(
            !msg.contains("sk-bb-legacy"),
            "the parse error must not leak the configured token value; got: {msg}"
        );
    }

    /// 1.0.0 KEY RENAMES — back-compat: every renamed key still loads from its OLD spelling via a
    /// serde alias, and the new spelling loads too. Pins the alias surface so a future field rename
    /// can't silently drop the alias (which would break a deployed pre-1.0 config on upgrade).
    #[test]
    fn test_renamed_keys_accept_old_and_new_spellings() {
        // breaker trip: window_s → window_secs, n → consecutive_n
        let old: BreakerTripConfig =
            serde_yaml::from_str("mode: consecutive\nwindow_s: 42\nn: 7").expect("old trip keys");
        assert_eq!(old.window_secs, 42);
        assert_eq!(old.consecutive_n, 7);
        let new: BreakerTripConfig =
            serde_yaml::from_str("mode: consecutive\nwindow_secs: 42\nconsecutive_n: 7")
                .expect("new trip keys");
        assert_eq!(new.window_secs, 42);
        assert_eq!(new.consecutive_n, 7);

        // failover: deadline_secs → timeout_secs, cap → max_hops
        let old: FailoverCfg =
            serde_yaml::from_str("deadline_secs: 30\ncap: 5").expect("old failover keys");
        assert_eq!(old.timeout_secs, 30);
        assert_eq!(old.max_hops, 5);
        let new: FailoverCfg =
            serde_yaml::from_str("timeout_secs: 30\nmax_hops: 5").expect("new failover keys");
        assert_eq!(new.timeout_secs, 30);
        assert_eq!(new.max_hops, 5);
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
            listen: DEFAULT_LISTEN_ADDR.into(),
            tls: None,
            auth: None,
            providers,
            models: HashMap::new(),
            pools: HashMap::new(),
            hooks: HashMap::new(),
            admin_auth: vec!["admin-tokens".to_string()],
            group_map: HashMap::new(),
            global_hooks: Vec::new(),
            observability: None,
            governance: None,
            security: None,
            limits: LimitsCfg::default(),
            metrics: MetricsCfg::default(),
            health: HealthDefaultsCfg::default(),
            routing: RoutingCfg::default(),
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

    /// The `hooks: [...]` list parses each native strategy name as the base; absent defaults to
    /// weighted with base NOT named (so the `default:` hook can replace it at resolution).
    #[test]
    fn test_pool_policy_strategies_parse() {
        for (name, expected) in [
            ("cheapest", PoolPolicy::Cheapest),
            ("fastest", PoolPolicy::Fastest),
            ("least_busy", PoolPolicy::LeastBusy),
            ("usage", PoolPolicy::Usage),
            ("weighted", PoolPolicy::Weighted),
        ] {
            let yaml = format!("hooks: [{name}]\nmembers: []\n");
            let pool: PoolCfg = serde_yaml::from_str(&yaml).expect("strategy name must parse");
            assert_eq!(pool.policy, expected, "{name} must parse to its strategy");
            assert!(pool.gates.is_empty());
            assert!(pool.base_named, "a named strategy names the base");
        }
        // Absent hooks: defaults to the zero-cost weighted strategy; base NOT named ⇒ inherits default:
        let absent: PoolCfg = serde_yaml::from_str("members: []\n").expect("absent parses");
        assert_eq!(absent.policy, PoolPolicy::Weighted);
        assert!(absent.gates.is_empty());
        assert!(!absent.base_named, "an absent hooks: did not name the base");
    }

    /// RETIRED transitional keys: the `policy:`/`hook:` pool pair each fail with a migration error
    /// pointing at the `hooks: [...]` list.
    #[test]
    fn test_pool_policy_and_hook_keys_retired() {
        let e = serde_yaml::from_str::<PoolCfg>("policy: cheapest\nmembers: []\n")
            .expect_err("policy: must be a retirement error");
        assert!(
            e.to_string().contains("retired") && e.to_string().contains("hooks: [cheapest]"),
            "policy: must point at the hooks list — got: {e}"
        );
        let e = serde_yaml::from_str::<PoolCfg>("hook: smart-router\nmembers: []\n")
            .expect_err("hook: must be a retirement error");
        assert!(
            e.to_string().contains("retired") && e.to_string().contains("hooks: [my-gate]"),
            "hook: must point at the hooks list — got: {e}"
        );
        // The block form of the retired key errors the same way (IgnoredAny swallows any shape).
        let e = serde_yaml::from_str::<PoolCfg>("members: []\npolicy:\n  socket: /s\n")
            .expect_err("policy block must be a retirement error");
        assert!(e.to_string().contains("retired"), "{e}");
    }

    /// The unified `hooks: [...]` pool form desugars into the internal (base policy, gate) rep: an
    /// ordering-strategy name sets the base ranking, any other name is a gate reference.
    #[test]
    fn test_pool_hooks_list_desugars() {
        // strategy + gate ⇒ base explicitly named
        let pool: PoolCfg = serde_yaml::from_str("hooks: [cheapest, smart-router]\nmembers: []\n")
            .expect("hooks list must parse");
        assert_eq!(pool.policy, PoolPolicy::Cheapest);
        assert_eq!(pool.gates, ["smart-router"]);
        assert!(pool.base_named, "a named strategy sets base_named");

        // gate only ⇒ base stays default (weighted placeholder); base NOT named ⇒ inherits default:
        let g: PoolCfg = serde_yaml::from_str("hooks: [pii-guard]\nmembers: []\n")
            .expect("gate-only list parses");
        assert_eq!(g.policy, PoolPolicy::Weighted);
        assert_eq!(g.gates, ["pii-guard"]);
        assert!(
            !g.base_named,
            "a gate-only pool did not name its base ordering"
        );

        // strategy only ⇒ base set, no gate, base named
        let s: PoolCfg =
            serde_yaml::from_str("hooks: [fastest]\nmembers: []\n").expect("strategy-only parses");
        assert_eq!(s.policy, PoolPolicy::Fastest);
        assert!(s.gates.is_empty());
        assert!(s.base_named);
    }

    /// A `hooks:` list may name SEVERAL gates — they fire concurrently in the phase-2 reconcile.
    /// List order is preserved (the chain tie-break within equal `priority`).
    #[test]
    fn test_pool_hooks_list_accepts_multiple_gates() {
        let pool: PoolCfg =
            serde_yaml::from_str("hooks: [cheapest, pii-guard, compliance]\nmembers: []\n")
                .expect("multi-gate list must parse");
        assert_eq!(pool.policy, PoolPolicy::Cheapest);
        assert_eq!(pool.gates, ["pii-guard", "compliance"]);
        assert!(pool.base_named);
    }

    /// The retired keys error even alongside a valid `hooks:` list (the retirement check fires
    /// before desugar — no silent half-migration).
    #[test]
    fn test_pool_hooks_and_legacy_pair_conflict() {
        let e =
            serde_yaml::from_str::<PoolCfg>("hooks: [cheapest]\npolicy: fastest\nmembers: []\n")
                .expect_err("a retired key alongside hooks: must error");
        assert!(e.to_string().contains("retired"), "{e}");
    }

    /// Two ordering strategies in one `hooks:` list is an error (a pool has one base ordering).
    #[test]
    fn test_pool_hooks_two_strategies_error() {
        let e = serde_yaml::from_str::<PoolCfg>("hooks: [cheapest, fastest]\nmembers: []\n")
            .expect_err("two strategies must error");
        assert!(
            e.to_string().contains("more than one ordering strategy"),
            "{e}"
        );
    }

    /// Any `policy:` value — known strategy or not — is the same retirement error (the key is gone).
    #[test]
    fn test_pool_policy_unknown_value_errors() {
        let err = serde_yaml::from_str::<PoolCfg>("policy: bogus\nmembers: []\n")
            .expect_err("the retired policy: key must be a parse error");
        assert!(err.to_string().contains("retired"), "{err}");
    }

    /// CLEAN-BREAK migration errors: the removed `route:` pool key names its replacement per value —
    /// every arm points at the `hooks: [...]` pool list.
    #[test]
    fn test_legacy_keys_are_migration_errors() {
        // route: <native> -> hooks: [<name>]
        let e = serde_yaml::from_str::<PoolCfg>("route: cheapest\nmembers: []\n")
            .expect_err("route: <native> must error");
        assert!(
            e.to_string().contains("hooks: [cheapest]"),
            "route:<native> must point at the hooks list — got: {e}"
        );
        // route: socket|webhook -> hooks: registry + pool hooks: [name]
        let e = serde_yaml::from_str::<PoolCfg>("route: socket\nmembers: []\n")
            .expect_err("route: socket must error");
        assert!(
            e.to_string().contains("hooks: [my-hook]"),
            "route: socket must point at the hooks registry + list — got: {e}"
        );
        // route: script -> gate under hooks:
        let e = serde_yaml::from_str::<PoolCfg>("route: script\nmembers: []\n")
            .expect_err("route: script must error");
        assert!(
            e.to_string().contains("removed in 1.3"),
            "route: script must name the removal — got: {e}"
        );
    }

    /// A hook's `prompt:` / `user:` grants parse the trust ladder; absent defaults to `no`.
    #[test]
    fn test_hook_access_grants_parse() {
        let hook: HookCfg = serde_yaml::from_str("kind: gate\nsocket: /s\nprompt: rw\nuser: ro\n")
            .expect("grants must parse");
        assert_eq!(hook.prompt, PromptAccess::Rw);
        assert!(hook.prompt.sends_prompt() && hook.prompt.can_rewrite());
        assert_eq!(hook.user, UserAccess::Ro);
        assert!(hook.user.sends_user());

        let bare: HookCfg =
            serde_yaml::from_str("kind: tap\nsocket: /s\n").expect("bare hook must parse");
        assert_eq!(bare.prompt, PromptAccess::No, "prompt defaults to no");
        assert_eq!(bare.user, UserAccess::No, "user defaults to no");
        assert!(!bare.prompt.sends_prompt());
    }

    /// `governance.budget_on_store_error` parses `allow`/`deny`, defaults to `allow` (fail-
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
                protocol: DEFAULT_PROTOCOL.to_string(),
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
            listen: DEFAULT_LISTEN_ADDR.into(),
            tls: None,
            auth: None,
            providers,
            models: HashMap::new(),
            pools: HashMap::new(),
            hooks: HashMap::new(),
            admin_auth: vec!["admin-tokens".to_string()],
            group_map: HashMap::new(),
            global_hooks: Vec::new(),
            observability: None,
            governance: None,
            security: None,
            limits: LimitsCfg::default(),
            metrics: MetricsCfg::default(),
            health: HealthDefaultsCfg::default(),
            routing: RoutingCfg::default(),
        };

        let result = resolve(&deploy, &defs).expect("resolve should succeed");

        let provider_cfg = result
            .providers
            .get("z.ai")
            .expect("z.ai should be in resolved providers");
        assert_eq!(provider_cfg.protocol, DEFAULT_PROTOCOL);
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
                protocol: DEFAULT_PROTOCOL.to_string(),
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
            listen: DEFAULT_LISTEN_ADDR.into(),
            tls: None,
            auth: None,
            providers: HashMap::new(),
            models: HashMap::new(),
            pools: HashMap::new(),
            hooks: HashMap::new(),
            admin_auth: vec!["admin-tokens".to_string()],
            group_map: HashMap::new(),
            global_hooks: Vec::new(),
            observability: None,
            governance: Some(GovernanceCfg {
                enabled: true,
                db_path: DEFAULT_GOVERNANCE_DB.to_string(),
                price_per_request_cents: 1,
                price_per_1k_tokens_cents: 0,
                admin_token: None,
                budget_on_store_error: Default::default(),
                sqlite_busy_timeout_ms: crate::config::DEFAULT_SQLITE_BUSY_TIMEOUT_MS,
                rate_sweep_interval: crate::config::DEFAULT_RATE_SWEEP_INTERVAL,
            }),
            security: None,
            limits: LimitsCfg::default(),
            metrics: MetricsCfg::default(),
            health: HealthDefaultsCfg::default(),
            routing: RoutingCfg::default(),
        };
        let errs = resolve(&deploy, &defs)
            .expect_err("enabled governance without admin_token must fail resolution");
        assert!(
            errs.iter().any(|e| e.contains("governance.admin_token")),
            "expected an admin-token lockout error; got: {errs:?}"
        );
    }

    // Admin-token behavior — requires the compile-removable `admin-tokens` module.
    #[cfg(feature = "auth-admin-tokens")]
    #[test]
    fn test_resolve_accepts_enabled_governance_with_admin_token() {
        let defs = HashMap::new();
        let deploy = DeployCfg {
            listen: DEFAULT_LISTEN_ADDR.into(),
            tls: None,
            auth: None,
            providers: HashMap::new(),
            models: HashMap::new(),
            pools: HashMap::new(),
            hooks: HashMap::new(),
            admin_auth: vec!["admin-tokens".to_string()],
            group_map: HashMap::new(),
            global_hooks: Vec::new(),
            observability: None,
            governance: Some(GovernanceCfg {
                enabled: true,
                db_path: DEFAULT_GOVERNANCE_DB.to_string(),
                price_per_request_cents: 1,
                price_per_1k_tokens_cents: 0,
                admin_token: Some("operator-secret".to_string()),
                budget_on_store_error: Default::default(),
                sqlite_busy_timeout_ms: crate::config::DEFAULT_SQLITE_BUSY_TIMEOUT_MS,
                rate_sweep_interval: crate::config::DEFAULT_RATE_SWEEP_INTERVAL,
            }),
            security: None,
            limits: LimitsCfg::default(),
            metrics: MetricsCfg::default(),
            health: HealthDefaultsCfg::default(),
            routing: RoutingCfg::default(),
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
            listen: DEFAULT_LISTEN_ADDR.into(),
            tls: None,
            auth: None,
            providers,
            models: HashMap::new(),
            pools: HashMap::new(),
            hooks: HashMap::new(),
            admin_auth: vec!["admin-tokens".to_string()],
            group_map: HashMap::new(),
            global_hooks: Vec::new(),
            observability: None,
            governance: None,
            security: None,
            limits: LimitsCfg::default(),
            metrics: MetricsCfg::default(),
            health: HealthDefaultsCfg::default(),
            routing: RoutingCfg::default(),
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
                protocol: DEFAULT_PROTOCOL.to_string(),
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
            listen: DEFAULT_LISTEN_ADDR.into(),
            tls: None,
            auth: None,
            providers,
            models: HashMap::new(),
            pools: HashMap::new(),
            hooks: HashMap::new(),
            admin_auth: vec!["admin-tokens".to_string()],
            group_map: HashMap::new(),
            global_hooks: Vec::new(),
            observability: None,
            governance: None,
            security: None,
            limits: LimitsCfg::default(),
            metrics: MetricsCfg::default(),
            health: HealthDefaultsCfg::default(),
            routing: RoutingCfg::default(),
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
                protocol: DEFAULT_PROTOCOL.to_string(),
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
            listen: DEFAULT_LISTEN_ADDR.into(),
            tls: None,
            auth: None,
            providers,
            models: HashMap::new(),
            pools: HashMap::new(),
            hooks: HashMap::new(),
            admin_auth: vec!["admin-tokens".to_string()],
            group_map: HashMap::new(),
            global_hooks: Vec::new(),
            observability: None,
            governance: None,
            security: None,
            limits: LimitsCfg::default(),
            metrics: MetricsCfg::default(),
            health: HealthDefaultsCfg::default(),
            routing: RoutingCfg::default(),
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

    /// REGRESSION: every config struct that carries a secret must REDACT it
    /// in `Debug`, not print it in plaintext. A derived `Debug` for AuthCfg,
    /// GovernanceCfg, ProviderCfg, and ProviderDeploy would leak the literal token/api_key the moment
    /// the struct — or any struct that embeds it (RootCfg/DeployCfg) — is debug-logged. Against the
    /// old derived impls these assertions FAIL (the secret appears); they pass once the manual
    /// redacting impls are in place. The secret values are deliberately distinctive so a substring
    /// search is decisive.
    #[test]
    fn test_debug_redacts_all_config_secrets() {
        // AuthCfg: client_tokens (the 1.0.0 `token` field was removed — setting it is now a parse
        // error, so it can no longer reach `Debug`).
        let auth = AuthCfg {
            chain: vec!["tokens".to_string()],
            upstream_credentials: crate::auth::UpstreamCreds::Own,
            client_tokens: vec![
                "SECRET-client-token-aaa".to_string(),
                "SECRET-client-token-bbb".to_string(),
            ],
        };
        let dbg = format!("{auth:?}");
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
            sqlite_busy_timeout_ms: crate::config::DEFAULT_SQLITE_BUSY_TIMEOUT_MS,
            rate_sweep_interval: crate::config::DEFAULT_RATE_SWEEP_INTERVAL,
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
            protocol: DEFAULT_PROTOCOL.to_string(),
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

    /// REGRESSION: the redaction must hold TRANSITIVELY — a derived `Debug`
    /// on an embedding struct (DeployCfg) delegates to each field's `Debug`, so the redacting impls
    /// above are what protect the whole-config dump an operator is most likely to log. This builds a
    /// DeployCfg containing every secret and asserts none survive its Debug output.
    #[test]
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
                chain: vec!["tokens".to_string()],
                upstream_credentials: crate::auth::UpstreamCreds::Own,
                client_tokens: vec!["SECRET-embedded-client-token".to_string()],
            }),
            providers,
            models: HashMap::new(),
            pools: HashMap::new(),
            hooks: HashMap::new(),
            admin_auth: vec!["admin-tokens".to_string()],
            group_map: HashMap::new(),
            global_hooks: Vec::new(),
            observability: None,
            governance: Some(GovernanceCfg {
                enabled: true,
                db_path: "x.db".to_string(),
                price_per_request_cents: 1,
                price_per_1k_tokens_cents: 0,
                admin_token: Some("SECRET-embedded-admin-token".to_string()),
                budget_on_store_error: Default::default(),
                sqlite_busy_timeout_ms: crate::config::DEFAULT_SQLITE_BUSY_TIMEOUT_MS,
                rate_sweep_interval: crate::config::DEFAULT_RATE_SWEEP_INTERVAL,
            }),
            security: None,
            limits: LimitsCfg::default(),
            metrics: MetricsCfg::default(),
            health: HealthDefaultsCfg::default(),
            routing: RoutingCfg::default(),
        };
        let dbg = format!("{deploy:?}");
        for secret in [
            "SECRET-embedded-deploy-key",
            "SECRET-embedded-client-token",
            "SECRET-embedded-admin-token",
        ] {
            assert!(
                !dbg.contains(secret),
                "DeployCfg Debug leaked a nested secret ({secret}): {dbg}"
            );
        }
    }

    // ── operational limits ("NEVER CODED CAPS") ──────────────────────────────────────────────────

    /// A config that OMITS the whole `limits:` block (and every other limit section) must resolve to
    /// the HISTORICAL hardcoded defaults — the common case, and the guarantee that nothing changes
    /// for existing deployments. Asserts every resolved limit equals its `DEFAULT_*` const.
    #[test]
    fn test_limits_absent_block_yields_historical_defaults() {
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
            serde_yaml::from_str(yaml).expect("config without a limits block must parse");
        let l = LimitsResolved::from_sections(
            &deploy.limits,
            &deploy.observability.clone().unwrap_or_default(),
            &deploy.governance.clone().unwrap_or_default(),
            &deploy.metrics,
            &deploy.health,
            &deploy.routing,
        );
        assert_eq!(
            l.upstream_request_timeout_secs,
            DEFAULT_UPSTREAM_REQUEST_TIMEOUT_SECS
        );
        assert_eq!(l.request_body_max_bytes, DEFAULT_REQUEST_BODY_MAX_BYTES);
        assert_eq!(l.pool_max_idle_per_host, DEFAULT_POOL_MAX_IDLE_PER_HOST);
        assert_eq!(l.max_inbound_concurrent, DEFAULT_MAX_INBOUND_CONCURRENT);
        assert_eq!(
            l.max_inbound_concurrent, 0,
            "default must be the unlimited no-op"
        );
        assert_eq!(l.hard_down_cooldown_secs, DEFAULT_HARD_DOWN_COOLDOWN_SECS);
        assert_eq!(
            l.upstream_error_body_max_bytes,
            DEFAULT_UPSTREAM_ERROR_BODY_MAX_BYTES
        );
        assert_eq!(
            l.tls_handshake_timeout_secs,
            DEFAULT_TLS_HANDSHAKE_TIMEOUT_SECS
        );
        assert_eq!(
            l.max_honored_retry_after_secs,
            DEFAULT_MAX_HONORED_RETRY_AFTER_SECS
        );
        assert_eq!(l.default_max_tokens, DEFAULT_DEFAULT_MAX_TOKENS);
        assert_eq!(l.default_max_tokens, crate::proto::DEFAULT_MAX_TOKENS);
        assert_eq!(
            l.max_inflight_webhook_deliveries,
            DEFAULT_MAX_INFLIGHT_WEBHOOK_DELIVERIES
        );
        assert_eq!(
            l.webhook_delivery_timeout_secs,
            DEFAULT_WEBHOOK_DELIVERY_TIMEOUT_SECS
        );
        assert_eq!(l.key_gauge_limit, DEFAULT_KEY_GAUGE_LIMIT);
        assert_eq!(l.sqlite_busy_timeout_ms, DEFAULT_SQLITE_BUSY_TIMEOUT_MS);
        assert_eq!(l.rate_sweep_interval, DEFAULT_RATE_SWEEP_INTERVAL);
        assert_eq!(l.default_probe_interval_secs, DEFAULT_PROBE_INTERVAL_SECS);
        assert_eq!(l.default_probe_timeout_secs, DEFAULT_PROBE_TIMEOUT_SECS);
        assert_eq!(l.default_policy_timeout_ms, DEFAULT_POLICY_TIMEOUT_MS);
    }

    /// `LimitsResolved::default()` (the omitted-everything path) must equal the per-field defaults —
    /// the two ways of getting "today's behavior" cannot drift.
    #[test]
    fn test_limits_resolved_default_matches_from_sections_defaults() {
        let a = LimitsResolved::default();
        let b = LimitsResolved::from_sections(
            &LimitsCfg::default(),
            &ObservabilityCfg::default(),
            &GovernanceCfg::default(),
            &MetricsCfg::default(),
            &HealthDefaultsCfg::default(),
            &RoutingCfg::default(),
        );
        assert_eq!(a.request_body_max_bytes, b.request_body_max_bytes);
        assert_eq!(
            a.upstream_request_timeout_secs,
            b.upstream_request_timeout_secs
        );
        assert_eq!(a.sqlite_busy_timeout_ms, b.sqlite_busy_timeout_ms);
        assert_eq!(a.default_policy_timeout_ms, b.default_policy_timeout_ms);
        assert_eq!(a.key_gauge_limit, b.key_gauge_limit);
    }

    /// A SET limit value (across several sections) OVERRIDES the default; an unset SIBLING field in
    /// the same block still defaults. Exercises the per-field `#[serde(default = "...")]` wiring.
    #[test]
    fn test_limits_set_value_overrides_default() {
        let yaml = r#"
listen: "0.0.0.0:8080"
providers:
  anthropic:
    api_key_env: ANTHROPIC_KEY
models:
  claude:
    provider: anthropic
    max_concurrent: 10
limits:
  upstream_request_timeout_secs: 42
  max_inbound_concurrent: 256
  request_body_max_bytes: 1048576
metrics:
  key_gauge_limit: 9
governance:
  sqlite_busy_timeout_ms: 1234
health:
  default_probe_interval_secs: 7
routing:
  default_policy_timeout_ms: 99
"#;
        let deploy: DeployCfg = serde_yaml::from_str(yaml).expect("limits override must parse");
        let l = LimitsResolved::from_sections(
            &deploy.limits,
            &deploy.observability.clone().unwrap_or_default(),
            &deploy.governance.clone().unwrap_or_default(),
            &deploy.metrics,
            &deploy.health,
            &deploy.routing,
        );
        assert_eq!(l.upstream_request_timeout_secs, 42);
        assert_eq!(l.max_inbound_concurrent, 256);
        assert_eq!(l.request_body_max_bytes, 1_048_576);
        assert_eq!(l.key_gauge_limit, 9);
        assert_eq!(l.sqlite_busy_timeout_ms, 1234);
        assert_eq!(l.default_probe_interval_secs, 7);
        assert_eq!(l.default_policy_timeout_ms, 99);
        // Unset SIBLING fields still default (pool_max_idle in the same `limits:` block, probe
        // TIMEOUT in the same `health:` block):
        assert_eq!(l.pool_max_idle_per_host, DEFAULT_POOL_MAX_IDLE_PER_HOST);
        assert_eq!(l.default_probe_timeout_secs, DEFAULT_PROBE_TIMEOUT_SECS);
        assert_eq!(l.hard_down_cooldown_secs, DEFAULT_HARD_DOWN_COOLDOWN_SECS);
    }

    /// The body-size COUPLING: `limits.request_body_max_bytes` is the SINGLE knob; the resolved value
    /// the inbound `DefaultBodyLimit` uses IS the same value the egress translate-body cap reads
    /// (`crate::limits::translate_body_max_bytes` returns `request_body_max_bytes`). So an accepted
    /// request is always buffer-translatable on egress.
    #[test]
    fn test_request_body_size_couples_ingress_and_translate() {
        let d = LimitsResolved::default();
        assert_eq!(d.request_body_max_bytes, DEFAULT_REQUEST_BODY_MAX_BYTES);

        let yaml = r#"
listen: "0.0.0.0:8080"
providers:
  anthropic:
    api_key_env: ANTHROPIC_KEY
models:
  claude:
    provider: anthropic
    max_concurrent: 10
limits:
  request_body_max_bytes: 5242880
"#;
        let deploy: DeployCfg = serde_yaml::from_str(yaml).expect("parse");
        let l = LimitsResolved::from_sections(
            &deploy.limits,
            &ObservabilityCfg::default(),
            &GovernanceCfg::default(),
            &MetricsCfg::default(),
            &HealthDefaultsCfg::default(),
            &RoutingCfg::default(),
        );
        assert_eq!(l.request_body_max_bytes, 5 * 1024 * 1024);
    }
}
