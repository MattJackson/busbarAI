// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use std::collections::HashMap;
use std::fmt;

use serde::{Deserialize, Serialize};

/// The busbar-owned config overlay (persistence substrate for API-applied hook changes).
pub(crate) mod overlay;

/// The top-level `groups:` limit tree (S3): GroupCfg + the generic limit shape.
pub(crate) mod groups;
/// The 1.4.x -> 1.5.0 config migrator + the loud fail-closed 1.x detector (P9).
pub(crate) mod migrate;
/// The secret-reference type (C2): `{ module, settings }` + the `{env}`/`{file}` sugar.
pub(crate) mod secret;

pub(crate) use groups::{GroupCfg, LimitCfg};
pub(crate) use secret::SecretRef;

// Re-export status_class_from_str for config validation
pub(crate) use crate::breaker::status_class_from_str;
use crate::proto::PROTO_ANTHROPIC;

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

/// How [`interpolate_env_with`] treats a `${VAR}` whose environment variable is unset.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum EnvSubst {
    /// Boot / reload: an unset variable is a hard error (fail loud — a real deployment must have its
    /// secrets present before it serves traffic).
    Strict,
    /// `busbar --validate`: an unset variable is substituted with a placeholder (its own name) and
    /// recorded, so config STRUCTURE can be validated without secrets present (CI, pre-reload dry runs).
    Lenient,
}

/// Expand `${VAR}` tokens from the environment (see [`EnvSubst`] for unset-variable behavior). A
/// substituted value carrying a YAML-structural control character is rejected (`reject_yaml_unsafe_value`)
/// so an env var cannot break out of the quoted scalar it lands in and inject extra YAML nodes.
pub(crate) fn interpolate_env(s: &str) -> Result<String, String> {
    interpolate_env_with(s, EnvSubst::Strict, &mut Vec::new())
}

/// See [`interpolate_env`]. In [`EnvSubst::Lenient`] mode each unset variable name is pushed into
/// `unset` (first-seen, deduped) and a placeholder substituted; in `Strict` mode `unset` is untouched.
pub(crate) fn interpolate_env_with(
    s: &str,
    mode: EnvSubst,
    unset: &mut Vec<String>,
) -> Result<String, String> {
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
            let value = match std::env::var(&var_name) {
                Ok(v) => v,
                Err(_) => match mode {
                    EnvSubst::Strict => {
                        return Err(format!("unset environment variable: {}", var_name));
                    }
                    EnvSubst::Lenient => {
                        if !unset.contains(&var_name) {
                            unset.push(var_name.clone());
                        }
                        var_name.clone() // placeholder: a non-empty, YAML-safe scalar
                    }
                },
            };
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
    /// Separate admin listen address — the admin API is served ONLY here, never on the data
    /// listener. Defaults to loopback (`127.0.0.1:8081`).
    pub(crate) admin_listen: String,
    /// TLS/mTLS for the admin listener (only meaningful with `admin_listen`).
    pub(crate) admin_tls: Option<TlsCfg>,
    pub(crate) auth: Option<AuthCfg>,
    pub(crate) providers: HashMap<String, ProviderCfg>,
    pub(crate) models: HashMap<String, ModelCfg>,
    pub(crate) pools: HashMap<String, PoolCfg>,
    /// The RUNTIME hook registry, SYNTHESIZED by `resolve` from the inline hook refs in
    /// `pools.<p>.hooks` and `global_hooks` (S9: there is no `hooks:` config block; instances are
    /// named where they run). Admin-registered hooks land here too.
    pub(crate) hooks: HashMap<String, HookCfg>,
    /// The ADMIN auth chain module names (from `auth.admin_auth:`, in order) gating
    /// `/api/v1/admin/*`. Default `[admin-tokens]`. `[]` = OPEN admin (dev only; loud boot
    /// warning).
    pub(crate) admin_auth: Vec<String>,
    /// The top-level `groups:` limit tree (S3).
    pub(crate) groups: std::collections::BTreeMap<String, GroupCfg>,
    /// The top-level `rate_card:` - the ONLY cost source (S5). See `DeployCfg::rate_card`.
    pub(crate) rate_card: Option<std::collections::BTreeMap<String, RateEntryCfg>>,
    /// Flat cents charged per request (default 0).
    pub(crate) per_request_fee: i64,
    /// The `store:` block as configured; `None` = the block was ABSENT (ephemeral RAM store,
    /// presence-driven governance stays off unless another governance signal is present).
    pub(crate) store: Option<StoreCfg>,
    /// Names of hooks that fire on EVERY request - the registry names synthesized from the
    /// `global_hooks:` inline refs, in order.
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
/// `client_ca` is also set, it additionally requires and verifies a client certificate (mTLS).
/// All three values are SECRET REFERENCES (C2: `{ file: … }` / `{ env: … }` / a secret module)
/// resolving to PEM bytes; they are resolved once at startup and any resolve/parse error is fatal
/// (`die`). Key bytes are never logged.
// deny_unknown_fields (M8): a typo under `tls:` - e.g. `client_c:` for `client_ca:` - would
// otherwise be SILENTLY IGNORED, leaving mTLS DISABLED while the operator believes it is on
// (a security downgrade with no diagnostic). Reject any unknown key here so the typo fails boot.
#[derive(Deserialize, Serialize, Clone, Debug)]
#[serde(deny_unknown_fields)]
pub(crate) struct TlsCfg {
    /// PEM certificate chain, leaf first (e.g. fullchain.pem), as a secret reference.
    pub(crate) cert: SecretRef,
    /// PEM private key matching the leaf cert (PKCS#8, PKCS#1, or SEC1), as a secret reference.
    pub(crate) key: SecretRef,
    /// PEM CA bundle to verify client certs against. `Some` ⇒ mTLS required: a client must present
    /// a cert chaining to this CA to complete the handshake at all. `None` ⇒ server-only TLS.
    #[serde(default)]
    pub(crate) client_ca: Option<SecretRef>,
}

/// One entry in an auth chain (`auth.chain:` / `auth.admin_auth:`) - an ORDERED-LIST module entry
/// (C2b/C2c): a bare module NAME for a module needing no config (`- keys`), or a single-key map
/// whose key is the module name and whose value carries the busbar-TYPED fields alongside the
/// module's own opaque `settings:`:
///
/// ```yaml
/// chain:
///   - keys
///   - ad: { max_admin_scope: full, settings: { server: "ldaps://corp" } }
/// admin_auth:
///   - admin-tokens: { token: { env: BUSBAR_ADMIN_TOKEN } }
/// ```
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct AuthChainEntry {
    /// The module name (built-in `keys` / `admin-tokens`, or a `kind: auth` plugin name/alias).
    pub(crate) module: String,
    /// Ceiling on the ADMIN scope obtainable through this module, regardless of what
    /// `role_bindings:` grants: `read-only` | `hooks-register` | `mint` | `full`. Absent =
    /// `read-only` for every module except the built-in `admin-tokens` operator credential (full by
    /// definition and exempt) - `full` from an external chain is an explicit opt-in.
    pub(crate) max_admin_scope: Option<String>,
    /// The operator ADMIN credential, for the built-in `admin-tokens` module (a secret reference).
    /// Meaningless on other modules (validated).
    pub(crate) token: Option<SecretRef>,
    /// The module's own opaque settings (pushed to an auth plugin verbatim).
    pub(crate) settings: serde_json::Map<String, serde_json::Value>,
}

impl AuthChainEntry {
    /// A bare, config-less entry (the `- keys` form).
    pub(crate) fn bare(module: impl Into<String>) -> Self {
        Self {
            module: module.into(),
            max_admin_scope: None,
            token: None,
            settings: serde_json::Map::new(),
        }
    }
}

/// The typed body of a configured chain entry (`{ <module>: { …this… } }`).
#[derive(Debug, Deserialize, Clone, Default)]
#[serde(deny_unknown_fields)]
struct AuthChainEntryBody {
    #[serde(default)]
    max_admin_scope: Option<String>,
    #[serde(default)]
    token: Option<SecretRef>,
    #[serde(default)]
    settings: serde_json::Map<String, serde_json::Value>,
}

impl<'de> Deserialize<'de> for AuthChainEntry {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct EntryVisitor;

        impl<'de> serde::de::Visitor<'de> for EntryVisitor {
            type Value = AuthChainEntry;

            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(
                    "an auth chain entry: a bare module name (`- keys`) or a single-key map \
                     `- <module>: { max_admin_scope?, token?, settings? }`",
                )
            }

            fn visit_str<E>(self, v: &str) -> Result<AuthChainEntry, E>
            where
                E: serde::de::Error,
            {
                if v.trim().is_empty() {
                    return Err(E::custom(
                        "an auth chain entry module name must be non-empty",
                    ));
                }
                Ok(AuthChainEntry::bare(v))
            }

            fn visit_map<A>(self, mut map: A) -> Result<AuthChainEntry, A::Error>
            where
                A: serde::de::MapAccess<'de>,
            {
                let Some((module, body)) = map.next_entry::<String, AuthChainEntryBody>()? else {
                    return Err(serde::de::Error::custom(
                        "an auth chain map entry needs exactly one key (the module name)",
                    ));
                };
                if map.next_key::<String>()?.is_some() {
                    return Err(serde::de::Error::custom(
                        "an auth chain map entry takes exactly ONE module key; write each module \
                         as its own list item",
                    ));
                }
                if module.trim().is_empty() {
                    return Err(serde::de::Error::custom(
                        "an auth chain entry module name must be non-empty",
                    ));
                }
                Ok(AuthChainEntry {
                    module,
                    max_admin_scope: body.max_admin_scope,
                    token: body.token,
                    settings: body.settings,
                })
            }
        }

        deserializer.deserialize_any(EntryVisitor)
    }
}

/// One `auth.role_bindings.<module>.<role>` entry - the operator-owned PURE-AUTH policy granted to
/// a ROLE asserted by that specific module (S4: bindings are NESTED BY MODULE, so `ad.platform`
/// and `oidc.platform` are distinct grants and a module can never ride another module's binding).
/// An unbound role grants NOTHING (fail closed). Limits live on the bound `group`, never here.
#[derive(Debug, Deserialize, Serialize, Clone, Default, PartialEq)]
#[serde(deny_unknown_fields)]
pub(crate) struct RoleBindingCfg {
    /// DATA-PLANE grant: pools this role may target. OMITTED = ALL pools (C6);
    /// an explicit `[]` = NO pools (empty list is the empty set).
    #[serde(default)]
    pub(crate) allowed_pools: Option<Vec<String>>,
    /// The `groups:` bucket this role's principals charge through. Absent = no group (unlimited).
    #[serde(default)]
    pub(crate) group: Option<String>,
    /// The ADMIN scope this role grants: `read-only` | `hooks-register` | `mint` | `full`. Absent =
    /// no admin access from this role. The most permissive of a principal's bound roles wins (by the
    /// `Scope` ordinal), ceilinged by the asserting module's `max_admin_scope`.
    #[serde(default)]
    pub(crate) admin_scope: Option<String>,
}

/// `role_bindings:` - module name -> role name -> grant.
pub(crate) type RoleBindings =
    std::collections::BTreeMap<String, std::collections::BTreeMap<String, RoleBindingCfg>>;

#[derive(Debug, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub(crate) struct AuthCfg {
    /// The key-signing key (S2): a SECRET REFERENCE resolving to the ed25519 signing key busbar
    /// mints virtual-key tokens with. Fleet-shared (every node verifying the same tokens resolves
    /// the same key). Absent ⇒ busbar GENERATES a keypair on first boot and persists it 0600
    /// (dev zero-config). Rotating it revokes every outstanding key.
    #[serde(default)]
    pub(crate) signing_key: Option<SecretRef>,
    /// Upstream-credential mode: `own` (default — busbar's configured lane key) or `passthrough`
    /// (forward the caller's credential upstream; the old `mode: passthrough`).
    #[serde(default)]
    pub(crate) upstream_credentials: crate::auth::UpstreamCreds,
    /// The DATA-PLANE authentication CHAIN - ordered module entries. Empty (the default) is the
    /// open front door. `keys` is the built-in signed-key verifier.
    #[serde(default)]
    pub(crate) chain: Vec<AuthChainEntry>,
    /// The ADMIN auth chain gating `/api/v1/admin/*` (the parallel of `chain` for the operator
    /// surface). Default `[admin-tokens]`. `[]` = OPEN admin (dev only; loud boot warning).
    #[serde(default = "default_admin_auth")]
    pub(crate) admin_auth: Vec<AuthChainEntry>,
    /// Role -> policy bindings, NESTED BY MODULE (see [`RoleBindingCfg`]).
    #[serde(default)]
    pub(crate) role_bindings: RoleBindings,
}

impl AuthCfg {
    /// Create a default (open front door, default admin chain) AuthCfg for initialization.
    pub(crate) fn default_none() -> Self {
        Self {
            signing_key: None,
            upstream_credentials: crate::auth::UpstreamCreds::Own,
            chain: vec![],
            admin_auth: default_admin_auth(),
            role_bindings: RoleBindings::new(),
        }
    }

    /// The `admin-tokens` operator-credential secret reference, if configured.
    pub(crate) fn admin_token_ref(&self) -> Option<&SecretRef> {
        self.admin_auth
            .iter()
            .chain(self.chain.iter())
            .find(|e| e.module == ADMIN_TOKENS_MODULE)
            .and_then(|e| e.token.as_ref())
    }
}

/// The built-in signed-key verifier module name (`auth.chain: [keys]`).
pub(crate) const KEYS_MODULE: &str = "keys";
/// The built-in operator admin-token module name (`auth.admin_auth: [admin-tokens]`).
pub(crate) const ADMIN_TOKENS_MODULE: &str = "admin-tokens";

/// Append a targeted migration hint to a config-deserialize error when it is the removed 1.3.0
/// `auth.mode:` key (rejected by `AuthCfg`'s `deny_unknown_fields`), so an upgrading operator gets
/// actionable guidance instead of serde's bare "unknown field `mode`, expected one of …". Additive:
/// any other error is returned verbatim. (1.4.0 audit, config-compat — the key was renamed to
/// `auth.chain:` / `auth.upstream_credentials:` but the failure gave no upgrade breadcrumb.)
pub(crate) fn augment_config_error(err: impl std::fmt::Display) -> String {
    let msg = err.to_string();
    if msg.contains("unknown field `mode`") {
        format!(
            "{msg}\n  hint: the `auth.mode:` key was removed in favor of `auth.chain:` — `mode: none` \
             maps to an empty/omitted chain, `mode: token` or `mode: apikey` to `chain: [tokens]`, and \
             `mode: passthrough` to `auth.upstream_credentials: passthrough`"
        )
    } else {
        msg
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)] // M8: a typo'd provider key must fail boot, not be silently ignored.
pub(crate) struct ProviderCfg {
    #[serde(default = "default_protocol")]
    pub(crate) protocol: String,
    pub(crate) base_url: String,
    /// The provider credential as a SECRET REFERENCE (C2) - `{ env: VAR }`, `{ file: … }`, or a
    /// secret module. Resolved once at startup; the resolved value never appears in config or logs.
    pub(crate) api_key: SecretRef,
    /// Active health-probe settings for this provider's lanes (mode + interval + timeout).
    #[serde(default)]
    pub(crate) health: Option<HealthCfg>,
    // error_map is REQUIRED on every provider — NO default (fail loud if missing)
    pub(crate) error_map: HashMap<String, String>,
    /// Optional upstream request-path override (see ProviderDef::path).
    #[serde(default)]
    pub(crate) path: Option<String>,
    /// Optional path-BASE override (see ProviderDef::path_base) — replaces a URL-model protocol's
    /// hardcoded base segment so the per-request `/{model}:verb` suffix is appended to it (Vertex AI).
    #[serde(default)]
    pub(crate) path_base: Option<String>,
    /// OAuth token endpoint for `auth: oauth-client-credentials` (see ProviderDef::token_url).
    #[serde(default)]
    pub(crate) token_url: Option<String>,
    /// OAuth scope for `auth: oauth-client-credentials` (see ProviderDef::scope).
    #[serde(default)]
    pub(crate) scope: Option<String>,
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
}

/// Default provider protocol when not specified. Wire-contract: providers.yaml catalog entries
/// and un-overridden deployments use this protocol for the dispatch registry lookup.
const DEFAULT_PROTOCOL: &str = PROTO_ANTHROPIC;

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
    /// OAuth 2.0 JWT-bearer grant (RFC 7523): the provider's credential is a signing key (delivered as
    /// a Google service-account JSON in `api_key_env`), which busbar uses to mint + auto-refresh a
    /// short-lived bearer token per lane. Generic — Vertex AI is the first provider to select it. The
    /// token minting/refresh lives in `crate::egress_auth::jwt_bearer`; this is only the selector.
    #[serde(rename = "jwt-bearer")]
    JwtBearer,
    /// OAuth 2.0 client-credentials grant (RFC 6749 §4.4): `api_key_env` carries
    /// `client_id:client_secret`, and the provider's `token_url` + `scope` complete the exchange for
    /// an auto-refreshed bearer. Generic — Azure OpenAI via Microsoft Entra ID is the first consumer.
    /// The token minting/refresh lives in `crate::egress_auth::oauth_client_credentials`.
    #[serde(rename = "oauth-client-credentials")]
    OAuthClientCredentials,
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
    /// Per-lane concurrency limiter: the max number of in-flight requests admitted to this lane at
    /// once (excess requests park on the lane's semaphore until a slot frees or the request budget
    /// expires). OPTIONAL — omitted means UNBOUNDED (no concurrency cap), the same opt-in-limiter
    /// posture as `max_requests` (default -1 = unlimited). Set a positive integer to opt into a cap;
    /// `0` is rejected at boot (`config_validate`) as a lane that admits nothing. Unbounded is
    /// realized as a `Semaphore` seeded with `tokio::sync::Semaphore::MAX_PERMITS` (see main.rs) —
    /// "effectively unbounded"; a literal `usize::MAX` would panic (tokio caps permits at
    /// `MAX_PERMITS`).
    #[serde(default)]
    pub(crate) max_concurrent: Option<usize>,
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
    /// Operator declaration that THIS model accepts prompt-cache markers on dialects where the
    /// marker is model-gated (Bedrock Converse `cachePoint`: Claude accepts it, Amazon Nova
    /// hard-rejects it with 400 "extraneous key"). Same family as `reasoning` — busbar keeps no
    /// model database, the operator asserts what they deployed. When absent/false, cross-protocol
    /// `cache_control` breakpoints headed to such a dialect are DROPPED at the seam with a warn
    /// (the request proceeds uncached — fail-safe, never a translation-induced 400). Dialects
    /// whose cache form is universally accepted (Anthropic `cache_control`) ignore this flag, as
    /// does same-protocol passthrough (byte-exact).
    #[serde(default)]
    pub(crate) prompt_caching: Option<bool>,
}

fn neg1() -> i64 {
    -1
}

/// One inline HOOK reference (S9): where a hook RUNS is where it is named - in a pool's
/// `hooks: [...]` (ordered) or the top-level `global_hooks: [...]` (ordered). Two spellings:
///
/// ```yaml
/// hooks:
///   - cheapest                                    # bare BUILT-IN (an ordering strategy)
///   - { module: my-hook-plugin, settings: { url: "https://sidecar/hook" }, on_error: reject }
/// ```
///
/// A bare name is ONLY a built-in (weighted | cheapest | fastest | least_busy | usage); everything
/// else is a module ref naming a `kind: hook` plugin (by signed-manifest name/alias).
#[derive(Debug, Clone, PartialEq)]
pub(crate) enum HookRefEntry {
    /// A bare built-in name.
    Builtin(String),
    /// A `{ module: …, settings: …, …typed }` module instance.
    Module(HookModuleRef),
}

/// The map form of an inline hook reference: the module name + its opaque `settings:` plus the
/// busbar-TYPED per-instance fields (C2c: typed fields sit ALONGSIDE settings, never inside).
#[derive(Debug, Deserialize, Clone, PartialEq)]
#[serde(deny_unknown_fields)]
pub(crate) struct HookModuleRef {
    /// The hook module: a `kind: hook` plugin's signed-manifest name/alias.
    pub(crate) module: String,
    /// The module's own opaque settings (busbar never interprets them; pushed to the plugin via
    /// `configure`).
    #[serde(default)]
    pub(crate) settings: serde_json::Map<String, serde_json::Value>,
    /// The hook's MODE: `gate` (fire-and-wait; the default for an inline ref - it was named where
    /// decisions happen) or `tap` (fire-and-forget).
    #[serde(default)]
    pub(crate) kind: Option<HookKind>,
    /// Gate decision deadline in ms (default 1).
    #[serde(default)]
    pub(crate) timeout_ms: Option<u64>,
    /// Gate failure posture (C1: keyword bare, a reference is `{ hook: … }` - parsed by the
    /// existing on_error chain machinery). Default `nothing`.
    #[serde(default)]
    pub(crate) on_error: Option<OnErrorCfg>,
    /// Gate restrict empty-intersection behavior.
    #[serde(default)]
    pub(crate) on_empty: Option<PolicyOnError>,
    /// TAP observation stage.
    #[serde(default)]
    pub(crate) at: Option<HookStage>,
    /// PROMPT access grant (`no` | `ro` | `rw`).
    #[serde(default)]
    pub(crate) prompt: Option<PromptAccess>,
    /// Caller-identity access grant (`no` | `ro`).
    #[serde(default)]
    pub(crate) user: Option<UserAccess>,
    /// Ordering key (default 0).
    #[serde(default)]
    pub(crate) priority: Option<u16>,
}

impl<'de> Deserialize<'de> for HookRefEntry {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        // A YAML scalar is a bare built-in name; a map is the module-ref form. serde_yaml's
        // untagged support struggles with nested opaque maps, so branch on the raw value shape.
        let value = serde_yaml::Value::deserialize(deserializer)?;
        match value {
            serde_yaml::Value::String(name) => {
                if name.trim().is_empty() {
                    return Err(serde::de::Error::custom(
                        "a bare hook reference must be a non-empty built-in name",
                    ));
                }
                Ok(HookRefEntry::Builtin(name))
            }
            v @ serde_yaml::Value::Mapping(_) => {
                let r: HookModuleRef =
                    serde_yaml::from_value(v).map_err(serde::de::Error::custom)?;
                Ok(HookRefEntry::Module(r))
            }
            _ => Err(serde::de::Error::custom(
                "a hook reference is a bare built-in name (weighted | cheapest | fastest | \
                 least_busy | usage) or a `{ module: …, settings: … }` map",
            )),
        }
    }
}

/// A structured `on_error:` value (C1): a reserved keyword stays BARE
/// (`nothing` | `weighted` | `reject` | `first`); a fallback-hook reference is `{ hook: <name> }`.
#[derive(Debug, Clone, PartialEq)]
pub(crate) enum OnErrorCfg {
    /// One of the reserved terminals (see [`on_error_terminal`]).
    Terminal(String),
    /// A fallback hook reference.
    Hook(String),
}

impl OnErrorCfg {
    /// The flat NAME the existing on_error chain machinery resolves (terminal word or hook name).
    pub(crate) fn as_name(&self) -> &str {
        match self {
            OnErrorCfg::Terminal(s) | OnErrorCfg::Hook(s) => s,
        }
    }
}

impl<'de> Deserialize<'de> for OnErrorCfg {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct HookRefBody {
            hook: String,
        }

        let value = serde_yaml::Value::deserialize(deserializer)?;
        match value {
            serde_yaml::Value::String(word) => {
                if on_error_terminal(&word).is_some() {
                    Ok(OnErrorCfg::Terminal(word))
                } else {
                    Err(serde::de::Error::custom(format!(
                        "on_error keyword '{word}' is not one of the reserved terminals \
                         (nothing | weighted | reject | first); a fallback HOOK is referenced \
                         structured: `on_error: {{ hook: {word} }}`"
                    )))
                }
            }
            v @ serde_yaml::Value::Mapping(_) => {
                let body: HookRefBody =
                    serde_yaml::from_value(v).map_err(serde::de::Error::custom)?;
                if body.hook.trim().is_empty() {
                    return Err(serde::de::Error::custom(
                        "on_error: { hook: … } must name a non-empty hook",
                    ));
                }
                Ok(OnErrorCfg::Hook(body.hook))
            }
            _ => Err(serde::de::Error::custom(
                "on_error is a bare terminal (nothing | weighted | reject | first) or a \
                 structured hook reference `{ hook: <name> }`",
            )),
        }
    }
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
    /// The pool's inline MODULE hook refs (`hooks: [...]` map entries), in config order. Projected
    /// into the internal hook registry by `resolve` (which fills `gates` with the synthesized
    /// registry names).
    pub(crate) module_hooks: Vec<HookModuleRef>,
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

/// Manual `Deserialize` for [`PoolCfg`]: the `hooks: [...]` list is THE pool form - one ORDERED
/// list naming an optional built-in ordering strategy (bare name) and any module hook instances
/// (inline `{ module: … }` refs, S9). Desugars into the internal (base policy, module refs)
/// representation; `resolve` projects the module refs into the runtime hook registry.
impl<'de> Deserialize<'de> for PoolCfg {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        // M8: deny unknown keys so a typo'd pool key fails boot.
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
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
            /// The pool's hooks - an ordering strategy (bare built-in name) and/or inline module
            /// hook instances - in ONE ordered list.
            #[serde(default)]
            hooks: Option<Vec<HookRefEntry>>,
        }

        // Is `name` one of the native ordering strategies? The strategy set is fixed + known at
        // parse time: a strategy name sets the base ordering; any other bare name is an error
        // (out-of-process hooks are inline `{ module: … }` refs, never bare names).
        fn is_strategy_name(name: &str) -> bool {
            matches!(
                name,
                ON_ERROR_WEIGHTED
                    | STRATEGY_CHEAPEST
                    | STRATEGY_FASTEST
                    | STRATEGY_LEAST_BUSY
                    | STRATEGY_USAGE
            )
        }

        fn parse_strategy(name: &str) -> PoolPolicy {
            match name {
                STRATEGY_CHEAPEST => PoolPolicy::Cheapest,
                STRATEGY_FASTEST => PoolPolicy::Fastest,
                STRATEGY_LEAST_BUSY => PoolPolicy::LeastBusy,
                STRATEGY_USAGE => PoolPolicy::Usage,
                _ => PoolPolicy::Weighted,
            }
        }

        let raw = RawPoolCfg::deserialize(deserializer)?;

        // Resolve the internal (base policy, module refs) representation from the `hooks:` list.
        let (policy, module_hooks, base_named) = if let Some(entries) = raw.hooks {
            let mut policy: Option<PoolPolicy> = None;
            let mut module_hooks: Vec<HookModuleRef> = Vec::new();
            for entry in entries {
                match entry {
                    HookRefEntry::Builtin(name) if is_strategy_name(&name) => {
                        if policy.is_some() {
                            return Err(serde::de::Error::custom(
                                "a pool `hooks:` list names more than one ordering strategy; a \
                                 pool has one base ordering",
                            ));
                        }
                        policy = Some(parse_strategy(&name));
                    }
                    HookRefEntry::Builtin(name) => {
                        return Err(serde::de::Error::custom(format!(
                            "unknown built-in hook '{name}' in a pool `hooks:` list; the bare \
                             built-ins are weighted | cheapest | fastest | least_busy | usage - \
                             a plugin hook is an inline module ref naming a `kind: hook` plugin, \
                             e.g. `{{ module: my-hook-plugin, settings: {{ … }} }}`"
                        )));
                    }
                    HookRefEntry::Module(r) => module_hooks.push(r),
                }
            }
            let base_named = policy.is_some();
            (policy.unwrap_or_default(), module_hooks, base_named)
        } else {
            (PoolPolicy::default(), Vec::new(), false)
        };

        Ok(PoolCfg {
            members: raw.members,
            breaker: raw.breaker,
            failover: raw.failover,
            on_exhausted: raw.on_exhausted,
            affinity: raw.affinity,
            module_hooks,
            policy,
            gates: Vec::new(),
            base_named,
        })
    }
}

/// A pool's native ranking STRATEGY — the base ordering strategy named in a pool's `hooks:` list
/// (the retired `policy:` key). `weighted` (default / absent) is today's smooth-weighted-round-robin:
/// ZERO added cost, no policy object constructed, the byte-identical hot path. The others resolve a
/// Busbar-native ordering policy that runs once before the failover loop. This is the pool's ranking
/// FLOOR; a gate named in the pool's `hooks:` list can override it per-request.
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
    /// object. Engine-level `STRATEGY_*` consts (not the ranking plugin's constants) so this
    /// compiles when the `hooks-ranking` plugin is removed; the plugin matches the same names.
    pub(crate) fn native_name(&self) -> Option<&'static str> {
        match self {
            PoolPolicy::Weighted => None,
            PoolPolicy::Cheapest => Some(STRATEGY_CHEAPEST),
            PoolPolicy::Fastest => Some(STRATEGY_FASTEST),
            PoolPolicy::LeastBusy => Some(STRATEGY_LEAST_BUSY),
            PoolPolicy::Usage => Some(STRATEGY_USAGE),
        }
    }
}

/// A hook's MODE — the `kind:` key. A hook is one thing; `tap`/`gate` just say whether busbar waits
/// for a reply. `tap` = fire-and-forget (watch). `gate` = fire-and-wait (decide: nothing / reject /
/// restrict / order / rewrite). Only a gate can influence dispatch; a gate named in a pool's `hooks:`
/// list must be `kind: gate`.
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

/// The serde default for a hook's `on_error` — `nothing`: a failing gate
/// DOES NOT PARTICIPATE by default — it cannot steer, and it cannot displace another gate's
/// verdict. Security gates opt into `reject`; ordering gates name `weighted` explicitly.
fn default_on_error() -> String {
    ON_ERROR_NOTHING.to_string()
}

/// The native ranking-strategy names — shared by the pool `hooks:` classifier/parser,
/// `PoolPolicy::native_name`, `RESERVED_HOOK_NAMES`, and the config validator's built-in-strategy
/// check, so the vocabulary cannot drift. `weighted` is NOT listed here: it is the zero-cost
/// inline-SWRR floor and its name is owned by `ON_ERROR_WEIGHTED` below.
pub(crate) const STRATEGY_CHEAPEST: &str = "cheapest";
pub(crate) const STRATEGY_FASTEST: &str = "fastest";
pub(crate) const STRATEGY_LEAST_BUSY: &str = "least_busy";
pub(crate) const STRATEGY_USAGE: &str = "usage";

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

/// Names a hook may NOT take, enforced on EVERY hook-write path (boot validation, config apply, and
/// the runtime register/PUT API). Two reasons, one rule:
/// - REGISTRY UNIQUENESS: the native ranking strategies + built-in auth modules already answer to
///   their names — two things can't answer to one name.
/// - UNION DISAMBIGUATION (3rd-party audit #8): `on_error` is a string union of "reserved terminal"
///   vs "fallback hook name". Reserving EVERY terminal word (`weighted`/`reject`/`first`/`nothing`)
///   as an illegal hook name makes the union closed and unambiguous for machine consumers: a value
///   in this set is a terminal; anything else is a hook reference — no hook can ever collide.
pub(crate) const RESERVED_HOOK_NAMES: &[&str] = &[
    // on_error terminals (see ON_ERROR_*) — includes `weighted`, which is ALSO the native floor.
    ON_ERROR_WEIGHTED,
    ON_ERROR_REJECT,
    ON_ERROR_FIRST,
    ON_ERROR_NOTHING,
    // native ranking strategies (PoolPolicy::native_name)
    STRATEGY_CHEAPEST,
    STRATEGY_FASTEST,
    STRATEGY_LEAST_BUSY,
    STRATEGY_USAGE,
    // built-in auth modules (AuthModule::name)
    "tokens",
    "admin-tokens",
];

/// The serde default for `auth.admin_auth:` - the built-in `admin-tokens` module (the single
/// operator admin token; byte-identical to the pre-chain behavior).
fn default_admin_auth() -> Vec<AuthChainEntry> {
    vec![AuthChainEntry::bare(ADMIN_TOKENS_MODULE)]
}

/// A named entry in the top-level `hooks:` registry — a single hook (tap or gate) and the `kind: hook`
/// PLUGIN that backs it. A hook is now a dlopen plugin under the hybrid ABI (the 1.5.0 retirement of
/// the out-of-process socket/webhook transport): exactly ONE `plugin:` reference names the signed
/// plugin (by manifest name/alias), loaded like a store/auth plugin. Shared runtime knobs carry over
/// from the 1.2.1 policy block. A pool references a GATE by name via its `hook:` key; global taps/gates
/// via `global_hooks:` (or inline `global: true`).
#[derive(Debug, Deserialize, Serialize, Clone)]
#[serde(deny_unknown_fields)]
pub(crate) struct HookCfg {
    /// The hook's MODE: `tap` (fire-and-forget) or `gate` (fire-and-wait, returns a reply arm).
    pub(crate) kind: HookKind,
    // ── plugin reference (exactly one, required) ─────────────────────────────────────────────────
    /// The `kind: hook` PLUGIN backing this hook, by signed-manifest name or alias — resolved against
    /// the same validated plugin registry that store/auth plugins load through (fail-closed: an
    /// unresolvable or wrong-kind reference refuses to boot). This REPLACES the retired
    /// `socket`/`webhook` out-of-process transports: a hook now runs in-process behind the frozen
    /// plugin ABI. Required and non-empty.
    pub(crate) plugin: String,
    // ── shared runtime knobs ─────────────────────────────────────────────────────────────────────
    /// Hard wall-clock deadline for a gate decision, in milliseconds (default 1). An in-process gate
    /// is microseconds; RAISE it for a hook plugin that does real work (a DB/network/model call).
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
    /// OPAQUE settings map pushed to the hook via the `configure` op (D2): sent to the plugin at
    /// load and re-pushed (commit-on-ack) by `PATCH /api/v1/admin/hooks/{name}/settings`. Busbar
    /// never interprets the contents.
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
    /// `hooks::resolve_pool_ordering` gives this hook to every pool whose base is unnamed.
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
#[serde(deny_unknown_fields)] // M8: a typo'd pool-member key must fail boot, not be silently ignored.
pub(crate) struct PoolMember {
    /// The member's MODEL (a `models:` key). C4: reference fields name the referenced thing
    /// (renamed from the 1.4.x `target:`).
    pub(crate) model: String,
    #[serde(default = "default_weight")]
    pub(crate) weight: u32,
    #[serde(default)]
    pub(crate) context_max: Option<usize>,
    /// Operator-declared routing tier (e.g. `"large"`/`"small"`/`"primary"`/`"overflow"`). Projected
    /// into the routing `Candidate` (via `MemberMeta`) and read by hook plugin policies.
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
    /// Free-form operator tags (e.g. `["opus"]`) a policy can match on. Projected into the routing
    /// `Candidate` and read by hook plugin policies.
    ///
    /// NOTE: the 1.4.x `cost_per_mtok:` member field is REMOVED (S5): `rate_card` is the ONLY cost
    /// source, and routing (`cheapest`) derives its scalar from the member's model's rate entry.
    #[serde(default)]
    pub(crate) tags: Vec<String>,
}

fn default_weight() -> u32 {
    1
}

/// The routing-scalar projection of a rate entry (abstract units per million tokens), fed to the
/// `cheapest` policy and the hook `Candidate.cost_per_mtok` signal: the blended
/// (input + output) / 2 (1 micro-unit/token == 1 unit/mtok, so no further scaling).
pub(crate) fn rate_entry_per_mtok(r: &RateEntryCfg) -> f64 {
    (r.input_utok + r.output_utok) / 2.0
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
    /// Sliding-window length in seconds (C3: one canonical name; the pre-1.0 `window_s` alias is
    /// GONE - an unknown key fails boot).
    #[serde(default = "default_window_secs")]
    pub(crate) window_secs: u64,
    #[serde(default = "default_threshold")]
    pub(crate) threshold: f64,
    #[serde(default = "default_min_requests")]
    pub(crate) min_requests: usize,
    /// Consecutive-failure threshold for `BreakerTripMode::Consecutive` (C3: one canonical name;
    /// the pre-1.0 `n` alias is GONE).
    #[serde(default = "default_consecutive_n")]
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
    /// Failover wall-clock budget in seconds (C3: one canonical name; the pre-1.0 `deadline_secs`
    /// alias is GONE).
    #[serde(default = "default_failover_timeout")]
    pub(crate) timeout_secs: u64,
    /// Member model names excluded from this pool's candidate set — never selected (primary or
    /// failover). A per-pool blocklist for temporarily benching a member without editing `members`.
    #[serde(default)]
    pub(crate) exclusions: Option<Vec<String>>,
    /// Maximum failover hops per request (C3: one canonical name; the pre-1.0 `cap` alias is GONE).
    #[serde(default = "default_max_hops")]
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

/// A pool's STRUCTURED `on_exhausted:` (C1: a keyword stays bare, a reference is structured):
///
/// ```yaml
/// on_exhausted: reject                     # 503 + Retry-After (the default)
/// on_exhausted: least_bad                  # degraded: soonest-recovering member
/// on_exhausted: { fallback_pool: cold }    # route to another pool
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum OnExhaustedCfg {
    Reject,
    LeastBad,
    FallbackPool(String),
}

impl OnExhaustedCfg {
    /// The executable behavior this config value selects.
    pub(crate) fn to_runtime(&self) -> OnExhausted {
        match self {
            OnExhaustedCfg::Reject => OnExhausted::Status503,
            OnExhaustedCfg::LeastBad => OnExhausted::LeastBad,
            OnExhaustedCfg::FallbackPool(name) => OnExhausted::FallbackPool(name.clone()),
        }
    }
}

impl<'de> Deserialize<'de> for OnExhaustedCfg {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct FallbackBody {
            fallback_pool: String,
        }

        let value = serde_yaml::Value::deserialize(deserializer)?;
        match value {
            serde_yaml::Value::String(word) => match word.as_str() {
                "reject" => Ok(OnExhaustedCfg::Reject),
                "least_bad" => Ok(OnExhaustedCfg::LeastBad),
                other => Err(serde::de::Error::custom(format!(
                    "unknown on_exhausted keyword '{other}': the bare keywords are `reject` | \
                     `least_bad`; a fallback pool is referenced structured: \
                     `on_exhausted: {{ fallback_pool: <pool> }}`"
                ))),
            },
            v @ serde_yaml::Value::Mapping(_) => {
                let body: FallbackBody =
                    serde_yaml::from_value(v).map_err(serde::de::Error::custom)?;
                if body.fallback_pool.trim().is_empty() {
                    return Err(serde::de::Error::custom(
                        "on_exhausted: { fallback_pool: … } must name a non-empty pool",
                    ));
                }
                Ok(OnExhaustedCfg::FallbackPool(body.fallback_pool))
            }
            _ => Err(serde::de::Error::custom(
                "on_exhausted is `reject`, `least_bad`, or `{ fallback_pool: <pool> }`",
            )),
        }
    }
}

/// Pool exhaustion mode - the executable behavior when all members are tripped/excluded.
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

/// Default admin-plane listen address. The admin API (`/api/v1/admin/…`) ALWAYS runs on its own
/// listener, never sharing the data port — the management plane is privileged and stays isolated by
/// default. The default binds LOOPBACK so a zero-config deployment boots (an exposed default would
/// trip the mTLS boot-guard); to manage Busbar off-host, set an exposed `admin_listen` with
/// `admin_tls.client_ca_file` (mTLS) or an explicit `admin_insecure` waiver.
pub(crate) const DEFAULT_ADMIN_LISTEN_ADDR: &str = "127.0.0.1:8081";

fn default_admin_listen() -> String {
    DEFAULT_ADMIN_LISTEN_ADDR.into()
}

/// True iff `addr` (a `host:port` bind string) binds ONLY to the loopback interface, so a service
/// on it is unreachable from off-host. Drives the admin-plane boot-guard: a loopback admin listener
/// is safe without mTLS; anything else is treated as network-exposed. Unclassifiable hostnames fail
/// CLOSED (treated as exposed) so an ambiguous bind never silently waives the mTLS requirement.
pub(crate) fn bind_is_loopback(addr: &str) -> bool {
    // Strip the trailing `:port`. IPv6 literals contain colons, so split from the RIGHT, then peel
    // the `[...]` brackets an IPv6 host carries in `[::1]:8081` form.
    let host = addr.rsplit_once(':').map_or(addr, |(h, _port)| h);
    let host = host.trim_start_matches('[').trim_end_matches(']');
    if host.eq_ignore_ascii_case("localhost") {
        return true;
    }
    match host.parse::<std::net::IpAddr>() {
        Ok(ip) => ip.is_loopback(),
        Err(_) => false, // a hostname we can't resolve here → assume exposed (fail closed)
    }
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
    /// Optional path-BASE override for URL-model protocols (Gemini): replaces the protocol's
    /// hardcoded base segment (`/v1beta/models`) so the per-request `/{model}:verb` suffix is appended
    /// to a different layout. Unlike `path` (a static full path that ignores the model), `path_base`
    /// keeps the model in the URL — e.g. Vertex AI: `path_base:
    /// /v1/projects/{project}/locations/{location}/publishers/google/models`.
    #[serde(default)]
    pub(crate) path_base: Option<String>,
    /// OAuth token endpoint for `auth: oauth-client-credentials` — the URL busbar POSTs the client
    /// credentials to for a bearer. Required for that auth style; ignored otherwise. E.g. Azure Entra:
    /// `https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token`.
    #[serde(default)]
    pub(crate) token_url: Option<String>,
    /// OAuth scope for `auth: oauth-client-credentials`. Required for that auth style; ignored
    /// otherwise. E.g. Azure OpenAI: `https://cognitiveservices.azure.com/.default`.
    #[serde(default)]
    pub(crate) scope: Option<String>,
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
#[derive(Debug, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub(crate) struct ProviderDeploy {
    /// The provider credential as a SECRET REFERENCE (C2). Replaces the removed `api_key_env:`
    /// (`api_key_env: VAR` becomes `api_key: { env: VAR }`).
    pub(crate) api_key: SecretRef,
    #[serde(default)]
    pub(crate) protocol: Option<String>,
    #[serde(default)]
    pub(crate) base_url: Option<String>,
    #[serde(default)]
    pub(crate) error_map: Option<HashMap<String, String>>,
    /// Optional upstream request-path override (see ProviderDef::path).
    #[serde(default)]
    pub(crate) path: Option<String>,
    /// Optional path-BASE override (see ProviderDef::path_base) — replaces a URL-model protocol's
    /// hardcoded base segment so the per-request `/{model}:verb` suffix is appended to it (Vertex AI).
    #[serde(default)]
    pub(crate) path_base: Option<String>,
    /// OAuth token endpoint for `auth: oauth-client-credentials` (see ProviderDef::token_url).
    #[serde(default)]
    pub(crate) token_url: Option<String>,
    /// OAuth scope for `auth: oauth-client-credentials` (see ProviderDef::scope).
    #[serde(default)]
    pub(crate) scope: Option<String>,
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
}

/// Deployment configuration - operator-owned config.yaml structure.
// deny_unknown_fields: a typo'd or unknown TOP-LEVEL key (e.g. `plugin:` for `plugins:`) must be a
// loud startup error, not a silently-ignored block - the fail-closed posture every nested
// security-relevant struct (auth/governance/plugins/security) already enforces.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct DeployCfg {
    #[serde(default = "default_listen")]
    pub(crate) listen: String,
    /// Optional native inbound TLS / mTLS. Absent ⇒ plain HTTP (unchanged default).
    #[serde(default)]
    pub(crate) tls: Option<TlsCfg>,
    /// SEPARATE listen address for the admin API (`/api/v1/admin/*`). The admin surface ALWAYS runs
    /// here and is NEVER mounted on the data `listen` — the management plane stays isolated so it can
    /// carry its own TLS/mTLS, bind, and firewall posture independent of public LLM traffic. Defaults
    /// to loopback (`127.0.0.1:8081`); set an exposed address (+ `admin_tls`) to manage off-host.
    #[serde(default = "default_admin_listen")]
    pub(crate) admin_listen: String,
    /// TLS/mTLS for the admin listener (only meaningful with `admin_listen`). Its own cert + optional
    /// `client_ca_file`, so admin can require client certificates without forcing them on data-plane
    /// clients. A network-exposed `admin_listen` REQUIRES `client_ca_file` here unless `admin_insecure`.
    #[serde(default)]
    pub(crate) admin_tls: Option<TlsCfg>,
    /// Deliberate waiver of the exposed-admin-requires-mTLS boot-guard. `false` (default) ⇒ a
    /// non-loopback `admin_listen` without `admin_tls.client_ca_file` REFUSES to boot. `true` ⇒ the
    /// operator accepts a token-only admin plane on an exposed address (e.g. fronted by a mesh that
    /// terminates mTLS). Never silently assumed.
    #[serde(default)]
    pub(crate) admin_insecure: bool,
    pub(crate) auth: Option<AuthCfg>,
    pub(crate) providers: HashMap<String, ProviderDeploy>,
    pub(crate) models: HashMap<String, ModelCfg>,
    /// Pools are optional: a deployment can route to models directly (`/<model>/v1/messages`)
    /// without defining any pool.
    #[serde(default)]
    pub(crate) pools: HashMap<String, PoolCfg>,
    /// Hook instances that fire on EVERY request (`global_hooks:`, ordered) - inline refs, same
    /// shape as a pool's `hooks:` list (S9: there is NO top-level `hooks:` registry block).
    #[serde(default)]
    pub(crate) global_hooks: Vec<HookRefEntry>,
    /// The top-level `groups:` block - THE one limit tree (S3). Optional; absent = no groups.
    #[serde(default)]
    pub(crate) groups: std::collections::BTreeMap<String, GroupCfg>,
    /// The top-level `rate_card:` - the ONLY cost source (S5). Per-model entry; ALL-OR-NOTHING:
    /// absent => token pricing is 0 for every model; present => AUTHORITATIVE and COMPLETE (every
    /// configured model must have an entry or boot/`--validate` FAIL naming the missing models).
    /// The numbers are ABSTRACT cost units (no currency, no FX).
    #[serde(default)]
    pub(crate) rate_card: Option<std::collections::BTreeMap<String, RateEntryCfg>>,
    /// Flat cents (abstract minor units) charged per request for budget accounting. Default 0.
    #[serde(default = "default_per_request_fee")]
    pub(crate) per_request_fee: i64,
    /// The durable store as `{ module, settings }` (S6). Absent = the ephemeral RAM store.
    #[serde(default)]
    pub(crate) store: Option<StoreCfg>,
    /// Internal tuning knobs (the `advanced:` block).
    #[serde(default)]
    pub(crate) advanced: AdvancedCfg,
    /// Optional observability sinks (OTLP traces + request-log webhook). Metrics
    /// (`/metrics`) are always on and need no config.
    #[serde(default)]
    pub(crate) observability: Option<ObservabilityCfg>,
    /// The dynamic plugin subsystem (`plugins:` block, top-level). Absent = disabled (the default
    /// `enabled: false` master switch): no plugin is ever discovered or loaded.
    #[serde(default)]
    pub(crate) plugins: PluginsCfg,
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
#[derive(Debug, Deserialize, Serialize, Clone, Default)]
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

/// The top-level `plugins:` block — the ONLY configuration surface of the dynamic plugin subsystem.
/// A plugin is a plugin: store, auth, and hook plugins share this one block (one directory, one
/// trust model, one master switch); the manifest `kind` inside each signed tarball selects which
/// engine subsystem consumes it.
#[derive(Deserialize, Clone, Debug)]
#[serde(deny_unknown_fields)]
pub(crate) struct PluginsCfg {
    /// MASTER SWITCH, default FALSE. When false (or the whole `plugins:` block is absent), NO
    /// plugin is ever loaded — a tarball dropped into the directory is INERT. Referencing a plugin
    /// while disabled (`store.module:` other than `memory`) is a BOOT ERROR naming this flag.
    #[serde(default)]
    pub(crate) enabled: bool,
    /// Directory the signed plugin tarballs live in. Default `plugins` (relative to the working
    /// directory).
    #[serde(default = "default_plugins_dir")]
    pub(crate) dir: String,
    /// Trust policy for plugin signatures. busbar's OWN release key is EMBEDDED in the binary —
    /// first-party plugins verify with zero configuration; this block is for THIRD-PARTY keys and
    /// the explicit untrusted opt-ins.
    #[serde(default)]
    pub(crate) trust: PluginsTrustCfg,
    /// ANTI-DOWNGRADE floors: plugin canonical `name` -> minimum acceptable `version`. Third-party
    /// only in practice — first-party plugins are automatically floored at the running binary's
    /// version. A floored plugin must prove (trusted signature, version at/above the floor) that it
    /// meets the floor; nothing else loads it. Sibling of `trust` (a version axis, not a trust axis).
    #[serde(default)]
    pub(crate) min_versions: std::collections::BTreeMap<String, String>,
}

impl Default for PluginsCfg {
    fn default() -> Self {
        Self {
            enabled: false,
            dir: default_plugins_dir(),
            trust: PluginsTrustCfg::default(),
            min_versions: std::collections::BTreeMap::new(),
        }
    }
}

/// `plugins.trust` — how the engine treats plugin signatures. A first-party (busbar-signed) plugin
/// verifies against the EMBEDDED release key; a third-party plugin verifies against `publishers`;
/// anything else (unsigned, tampered, unknown publisher) is UNTRUSTED and, by DEFAULT, logged and
/// SKIPPED (never `dlopen`ed) unless the matching opt-in flag is set.
#[derive(Deserialize, Clone, Default, Debug)]
#[serde(deny_unknown_fields)]
pub(crate) struct PluginsTrustCfg {
    /// THIRD-PARTY allowlist: publishers whose signatures mark a plugin TRUSTED. Each maps a
    /// publisher name to a hex ed25519 public key. The first-party `busbar` key is embedded in the
    /// binary and never configured here.
    #[serde(default)]
    pub(crate) publishers: Vec<PluginPublisher>,
    /// EXPLICIT opt-in: load plugins that carry NO valid signature (unsigned / tampered). Default
    /// `false` — an unsigned plugin found in `plugins.dir` is LOGGED and SKIPPED (never `dlopen`ed
    /// / executed), at boot and in the admin catalog.
    #[serde(default)]
    pub(crate) allow_unsigned: bool,
    /// EXPLICIT opt-in: load plugins that ARE validly signed but by a publisher NOT in
    /// `publishers`. Default `false` — a third-party-signed plugin is LOGGED and SKIPPED.
    #[serde(default)]
    pub(crate) allow_third_party: bool,
}

/// One allowlisted plugin publisher: a name and its hex ed25519 public key.
#[derive(Deserialize, Clone, Debug)]
#[serde(deny_unknown_fields)]
pub(crate) struct PluginPublisher {
    pub(crate) name: String,
    pub(crate) public_key: String,
}

impl PluginsCfg {
    /// Resolve into the `busbar-plugin-sign` trust policy: the EMBEDDED first-party release key +
    /// the binary's own version (the automatic first-party anti-downgrade floor) + the configured
    /// third-party publishers/opt-ins/floors. A malformed publisher key is a boot error, not a
    /// silent skip (a skipped trust anchor could wrongly reject a good plugin).
    pub(crate) fn to_policy(&self) -> Result<busbar_plugin_sign::TrustPolicy, String> {
        let mut publishers = std::collections::BTreeMap::new();
        for p in &self.trust.publishers {
            if p.name == busbar_plugin_sign::FIRST_PARTY_PUBLISHER {
                return Err(format!(
                    "plugins.trust.publishers['{}']: the publisher name '{}' is reserved for \
                     busbar's embedded release key and cannot be configured",
                    p.name,
                    busbar_plugin_sign::FIRST_PARTY_PUBLISHER
                ));
            }
            let key = busbar_plugin_sign::public_key_from_hex(&p.public_key)
                .map_err(|e| format!("plugins.trust.publishers['{}']: {e}", p.name))?;
            publishers.insert(p.name.clone(), key);
        }
        Ok(busbar_plugin_sign::TrustPolicy {
            first_party_key: busbar_plugin_sign::embedded_release_pubkey(),
            binary_version: env!("CARGO_PKG_VERSION").to_string(),
            publishers,
            allow_unsigned: self.trust.allow_unsigned,
            allow_third_party: self.trust.allow_third_party,
            min_versions: self.min_versions.clone(),
        })
    }
}

/// The compiled-in store name (`store.module: memory`) - the only store that is not a plugin.
pub(crate) const GOVERNANCE_STORE_MEMORY: &str = "memory";

/// The top-level `store:` block (S6): the durable store as `{ module, settings }` - the same
/// module/settings shape as every other plugin instance (C5). `settings` is the store module's OWN
/// config, passed through verbatim (the built-in sqlite plugin reads `db_path` /
/// `busy_timeout_ms`; postgres/redis read `url`). Absent block = the compiled-in ephemeral RAM
/// store (keys/usage reset on restart).
#[derive(Debug, Deserialize, Serialize, Clone)]
#[serde(deny_unknown_fields)]
pub(crate) struct StoreCfg {
    /// The store module, by plugin ALIAS or CANONICAL NAME. `memory` (default) is the compiled-in
    /// ephemeral RAM store. Anything else names a STORE PLUGIN resolved from the `plugins.*`
    /// registry - the shipped first-party stores (`sqlite` / `postgres` / `redis`, canonically
    /// `busbar-store-<x>`) or a third-party store by its manifest name. A non-`memory` store
    /// REQUIRES `plugins.enabled: true`; anything else is a boot error naming the flag.
    #[serde(default = "default_governance_store")]
    pub(crate) module: String,
    /// The module's own opaque settings, passed through verbatim as its config JSON.
    #[serde(default)]
    pub(crate) settings: serde_json::Map<String, serde_json::Value>,
}

impl Default for StoreCfg {
    fn default() -> Self {
        Self {
            module: default_governance_store(),
            settings: serde_json::Map::new(),
        }
    }
}

fn default_governance_store() -> String {
    GOVERNANCE_STORE_MEMORY.to_string()
}

/// The `advanced:` block - INTERNAL tuning knobs (formerly under `governance:`). Every field
/// defaults to its historical value; the whole block is normally omitted.
#[derive(Debug, Deserialize, Serialize, Clone)]
#[serde(deny_unknown_fields)]
pub(crate) struct AdvancedCfg {
    /// Amortization interval for the rate-limiter stale-entry sweep: every Nth `check_rate` pays
    /// the full retain (default 256).
    #[serde(default = "default_rate_sweep_interval")]
    pub(crate) rate_sweep_interval: u32,
    /// Write-behind flush cadence (ms) for the in-memory usage/budget counters. On an UNGRACEFUL
    /// crash (kill -9 / power loss) at most this many ms of accrued spend/requests can be lost; a
    /// graceful shutdown flushes fully. Default 100.
    #[serde(default = "default_usage_flush_interval_ms")]
    pub(crate) usage_flush_interval_ms: u64,
}

impl Default for AdvancedCfg {
    fn default() -> Self {
        Self {
            rate_sweep_interval: default_rate_sweep_interval(),
            usage_flush_interval_ms: default_usage_flush_interval_ms(),
        }
    }
}

/// The serde default for `per_request_fee:` - 0 (no flat per-request charge; token spend derives
/// from the ledger x rate_card).
fn default_per_request_fee() -> i64 {
    0
}

/// One top-level `rate_card:` entry: the four per-token rates in MICRO-units (1e-6 abstract cost
/// unit) per token, one per pricing tier. A tier omitted in YAML prices at 0 for that tier (e.g. a
/// model with no cache pricing simply omits the cache rates). Values must be finite and >= 0
/// (validated at boot). Floats exist ONLY here at the config boundary: they are converted once at
/// resolve time to integer nano-units per token, and the hot path does pure integer math.
#[derive(Debug, Deserialize, Serialize, Clone, Copy, PartialEq, Default)]
#[serde(deny_unknown_fields)]
pub(crate) struct RateEntryCfg {
    #[serde(default)]
    pub(crate) input_utok: f64,
    #[serde(default)]
    pub(crate) output_utok: f64,
    #[serde(default)]
    pub(crate) cache_read_utok: f64,
    #[serde(default)]
    pub(crate) cache_write_utok: f64,
}

/// Observability sinks. All fields optional; absent = that sink is disabled.
#[derive(Debug, Deserialize, Serialize, Clone)]
#[serde(deny_unknown_fields)] // M8: a typo'd observability key must fail boot, not be silently ignored.
pub(crate) struct ObservabilityCfg {
    /// OTLP/HTTP traces endpoint URL (e.g. `http://localhost:4318/v1/traces`). When set, busbar
    /// installs an OpenTelemetry tracer + exports spans. C7: URL fields end `_url` (renamed from
    /// the 1.4.x `otlp_endpoint`).
    #[serde(default)]
    pub(crate) otlp_url: Option<String>,
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
            otlp_url: None,
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
///
/// Sized for the sustained-throughput regime, not the idle-footprint regime: under an LLM-latency
/// workload the in-flight connection count is `RPS × upstream_latency` (Little's law) — e.g. 40k RPS
/// against a 20 ms upstream needs ~800 sockets held open concurrently. A small idle cap (the former
/// 64) forces reqwest to CLOSE every connection beyond the cap the instant a request completes, so
/// the next request re-pays a full TCP + TLS handshake on the hot path — connection CHURN that both
/// caps sustained RPS and inflates tail latency. 1024 lets the pool retain the working set for a
/// 4-core box saturating a 20 ms upstream without reconnecting, at a bounded idle-socket cost
/// (idle keep-alives are cheap; the OS reclaims them and `pool_idle_timeout`/`tcp_keepalive` bound
/// their lifetime). Operators with many distinct upstream hosts can lower it; high-RPS single-host
/// deployments are the ones this default protects.
const DEFAULT_POOL_MAX_IDLE_PER_HOST: usize = 1024;
/// Default idle keep-alive lifetime (seconds) for pooled upstream connections.
///
/// EXPLICIT 300s, replacing reqwest's implicit 90s default: under a bursty LLM workload the warm
/// working set (`pool_max_idle_per_host` sockets, each carrying an amortized TCP+TLS handshake and
/// — on h2 — an established multiplexed session) should SURVIVE inter-burst gaps of a few minutes
/// instead of being reaped at 90s and re-paid as cold handshakes on the hot path when the next
/// burst lands. Safe to hold that long because `tcp_keepalive(60s)` actively validates every idle
/// socket — a middlebox silently dropping a long-idle connection is detected by the keepalive
/// probe, not discovered as a spurious request failure — so the longer lifetime adds warm-socket
/// retention without adding stale-socket risk. Bounded: the OS reclaims idle sockets under
/// pressure, and `pool_max_idle_per_host` caps the count.
pub(crate) const DEFAULT_POOL_IDLE_TIMEOUT_SECS: u64 = 300;
/// Default inbound concurrency limit. `0` = unlimited (NO layer added).
///
/// Non-zero by default because this is the ONLY global bound on buffered request memory: every
/// request buffers its body (up to `request_body_max_bytes`, default 32 MiB) BEFORE any handler
/// logic can reject it, so peak memory is `(concurrent requests) x (body cap)` — with no admission
/// bound, a hostile connection burst is an OOM, not a slowdown. The limit layer is applied
/// OUTERMOST (see `apply_inbound_concurrency_limit`), so a queued request has NOT yet buffered its
/// body — the bound genuinely caps peak at `limit x body cap`. 8192 is ~4x the highest useful
/// in-flight count measured on a 4-core box (sustained throughput peaks near 1-2k concurrent) —
/// far above any legitimate working set, low enough that the worst case stays bounded. Operators
/// who want the old unlimited posture set `limits.max_inbound_concurrent: 0` explicitly.
pub(crate) const DEFAULT_MAX_INBOUND_CONCURRENT: usize = 8192;
/// Default hard-down sticky cooldown (seconds). Mirrors `store.rs`.
pub(crate) const DEFAULT_HARD_DOWN_COOLDOWN_SECS: u64 = 1800;
/// Default ceiling on a honored upstream `Retry-After` (seconds). Mirrors `store.rs` (24h).
pub(crate) const DEFAULT_MAX_HONORED_RETRY_AFTER_SECS: u64 = 86_400;
/// Default cap on a buffered upstream ERROR / verbatim-relay body (bytes). Mirrors `proxy engine`.
pub(crate) const DEFAULT_UPSTREAM_ERROR_BODY_MAX_BYTES: usize = 256 * 1024;
/// Default TLS handshake wall-clock bound (seconds). Mirrors `tls.rs`.
pub(crate) const DEFAULT_TLS_HANDSHAKE_TIMEOUT_SECS: u64 = 10;
/// Default inbound request-BODY read bound (seconds): the max time allowed BETWEEN inbound body
/// frames before the connection is dropped. Bounds a slow-loris that dribbles the request body one
/// byte at a time (the header-read timeout only covers the header phase). Mirrors `tls.rs`. 30s is
/// far longer than any real client needs to send its next body chunk, so it cannot false-positive on
/// a healthy upload.
pub(crate) const DEFAULT_REQUEST_BODY_READ_TIMEOUT_SECS: u64 = 30;
/// Default global fallback for the translation-injected `max_tokens` (mirrors `proto::DEFAULT_MAX_TOKENS`).
pub(crate) const DEFAULT_DEFAULT_MAX_TOKENS: u32 = 4096;
/// Default max concurrent webhook deliveries. Mirrors `observability.rs`.
pub(crate) const DEFAULT_MAX_INFLIGHT_WEBHOOK_DELIVERIES: usize = 64;
/// Default per-webhook delivery timeout (seconds). Mirrors `observability.rs`.
pub(crate) const DEFAULT_WEBHOOK_DELIVERY_TIMEOUT_SECS: u64 = 2;
/// Default max per-key gauge series emitted per scrape. Mirrors `metrics.rs`.
pub(crate) const DEFAULT_KEY_GAUGE_LIMIT: usize = 2000;
/// Default rate-sweep amortization interval. Mirrors `governance.rs`.
pub(crate) const DEFAULT_RATE_SWEEP_INTERVAL: u32 = 256;
/// Default write-behind flush cadence (ms) for the in-memory governance usage/budget counters.
/// Mirrors `governance.rs`.
pub(crate) const DEFAULT_USAGE_FLUSH_INTERVAL_MS: u64 = 100;
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
fn default_pool_idle_timeout_secs() -> u64 {
    DEFAULT_POOL_IDLE_TIMEOUT_SECS
}
fn default_max_inbound_concurrent() -> usize {
    DEFAULT_MAX_INBOUND_CONCURRENT
}
/// `0` = unlimited keys per group (today's behavior — an absent knob changes nothing).
fn default_max_keys_per_principal() -> usize {
    0
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
fn default_request_body_read_timeout_secs() -> u64 {
    DEFAULT_REQUEST_BODY_READ_TIMEOUT_SECS
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
fn default_plugins_dir() -> String {
    "plugins".to_string()
}
fn default_rate_sweep_interval() -> u32 {
    DEFAULT_RATE_SWEEP_INTERVAL
}
fn default_usage_flush_interval_ms() -> u64 {
    DEFAULT_USAGE_FLUSH_INTERVAL_MS
}
fn default_probe_interval_secs() -> u64 {
    DEFAULT_PROBE_INTERVAL_SECS
}
fn default_probe_timeout_secs() -> u64 {
    DEFAULT_PROBE_TIMEOUT_SECS
}

/// The `limits:` block — global operational caps. Each field defaults to its historical hardcoded
/// value, so an absent field (or an absent block) is today's behavior.
#[derive(Debug, Deserialize, Serialize, Clone)]
#[serde(deny_unknown_fields)] // M8: a typo'd limits key must fail boot, not be silently ignored.
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
    /// Idle keep-alive lifetime (seconds) for pooled upstream connections — see
    /// `DEFAULT_POOL_IDLE_TIMEOUT_SECS` for the 300s (vs reqwest's implicit 90s) rationale.
    #[serde(default = "default_pool_idle_timeout_secs")]
    pub(crate) pool_idle_timeout_secs: u64,
    /// Inbound concurrency cap. `0` (default) = unlimited: NO layer is added (a true no-op). When
    /// `>0`, a `tower` global concurrency limit wraps the router as the outermost layer.
    #[serde(default = "default_max_inbound_concurrent")]
    pub(crate) max_inbound_concurrent: usize,
    /// Cap on how many keys may be BOUND TO ONE GROUP — the anti-sprawl mitigation for self-service
    /// minting (self-service §6a). Because a `user:<sub>` leaf group IS the principal (§5), this is
    /// effectively "max keys per principal": a self-issued mint into a group already holding this
    /// many keys is a `409`. `0` (default) = UNLIMITED (today's behavior — an absent knob changes
    /// nothing). Enforced at `POST /keys` only; keys already present are never retroactively revoked.
    #[serde(default = "default_max_keys_per_principal")]
    pub(crate) max_keys_per_principal: usize,
    #[serde(default = "default_hard_down_cooldown_secs")]
    pub(crate) hard_down_cooldown_secs: u64,
    #[serde(default = "default_upstream_error_body_max_bytes")]
    pub(crate) upstream_error_body_max_bytes: usize,
    #[serde(default = "default_tls_handshake_timeout_secs")]
    pub(crate) tls_handshake_timeout_secs: u64,
    /// Max time (seconds) allowed BETWEEN inbound request-body frames before the connection is
    /// dropped - the slow-loris body defense the header-read timeout does not cover. See
    /// `DEFAULT_REQUEST_BODY_READ_TIMEOUT_SECS`.
    #[serde(default = "default_request_body_read_timeout_secs")]
    pub(crate) request_body_read_timeout_secs: u64,
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
#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
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
            pool_idle_timeout_secs: default_pool_idle_timeout_secs(),
            max_inbound_concurrent: default_max_inbound_concurrent(),
            max_keys_per_principal: default_max_keys_per_principal(),
            hard_down_cooldown_secs: default_hard_down_cooldown_secs(),
            upstream_error_body_max_bytes: default_upstream_error_body_max_bytes(),
            tls_handshake_timeout_secs: default_tls_handshake_timeout_secs(),
            request_body_read_timeout_secs: default_request_body_read_timeout_secs(),
            max_honored_retry_after_secs: default_max_honored_retry_after_secs(),
            default_max_tokens: default_default_max_tokens(),
            reasoning_effort_budgets: ReasoningEffortBudgets::default(),
        }
    }
}

/// The `metrics:` block.
#[derive(Debug, Deserialize, Serialize, Clone)]
#[serde(deny_unknown_fields)] // M8: a typo'd metrics key must fail boot, not be silently ignored.
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
#[derive(Debug, Deserialize, Serialize, Clone)]
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
#[derive(Debug, Deserialize, Serialize, Clone)]
#[serde(deny_unknown_fields)] // M8: a typo'd routing key must fail boot, not be silently ignored.
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
    pub(crate) pool_idle_timeout_secs: u64,
    pub(crate) max_inbound_concurrent: usize,
    /// Max keys bound to one group (0 = unlimited) — the self-service mint anti-sprawl cap (§6a).
    pub(crate) max_keys_per_principal: usize,
    pub(crate) hard_down_cooldown_secs: u64,
    pub(crate) upstream_error_body_max_bytes: usize,
    pub(crate) tls_handshake_timeout_secs: u64,
    pub(crate) request_body_read_timeout_secs: u64,
    pub(crate) max_honored_retry_after_secs: u64,
    pub(crate) default_max_tokens: u32,
    pub(crate) reasoning_effort_budgets: ReasoningEffortBudgets,
    pub(crate) max_inflight_webhook_deliveries: usize,
    pub(crate) webhook_delivery_timeout_secs: u64,
    pub(crate) key_gauge_limit: usize,
    pub(crate) rate_sweep_interval: u32,
    pub(crate) usage_flush_interval_ms: u64,
    pub(crate) default_probe_interval_secs: u64,
    pub(crate) default_probe_timeout_secs: u64,
    pub(crate) default_policy_timeout_ms: u64,
}

impl Default for LimitsResolved {
    fn default() -> Self {
        Self::from_sections(
            &LimitsCfg::default(),
            &ObservabilityCfg::default(),
            &AdvancedCfg::default(),
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
        advanced: &AdvancedCfg,
        metrics: &MetricsCfg,
        health: &HealthDefaultsCfg,
        routing: &RoutingCfg,
    ) -> Self {
        Self {
            upstream_request_timeout_secs: limits.upstream_request_timeout_secs,
            request_body_max_bytes: limits.request_body_max_bytes,
            pool_max_idle_per_host: limits.pool_max_idle_per_host,
            pool_idle_timeout_secs: limits.pool_idle_timeout_secs,
            max_inbound_concurrent: limits.max_inbound_concurrent,
            max_keys_per_principal: limits.max_keys_per_principal,
            hard_down_cooldown_secs: limits.hard_down_cooldown_secs,
            upstream_error_body_max_bytes: limits.upstream_error_body_max_bytes,
            tls_handshake_timeout_secs: limits.tls_handshake_timeout_secs,
            request_body_read_timeout_secs: limits.request_body_read_timeout_secs,
            max_honored_retry_after_secs: limits.max_honored_retry_after_secs,
            default_max_tokens: limits.default_max_tokens,
            reasoning_effort_budgets: limits.reasoning_effort_budgets,
            max_inflight_webhook_deliveries: obs.max_inflight_webhook_deliveries,
            webhook_delivery_timeout_secs: obs.webhook_delivery_timeout_secs,
            key_gauge_limit: metrics.key_gauge_limit,
            rate_sweep_interval: advanced.rate_sweep_interval,
            usage_flush_interval_ms: advanced.usage_flush_interval_ms,
            default_probe_interval_secs: health.default_probe_interval_secs,
            default_probe_timeout_secs: health.default_probe_timeout_secs,
            default_policy_timeout_ms: routing.default_policy_timeout_ms,
        }
    }
}

/// Resolve DeployCfg + ProviderDef map into resolved RootCfg.
/// For each deployed provider, look up its definition by name; produce a resolved ProviderCfg
/// = def's protocol/base_url/error_map (with any config.yaml override applied) + the deployment's api_key_env.
/// Build a runtime [`HookCfg`] registry entry from one inline module ref. `module:` now names the
/// `kind: hook` PLUGIN that backs the hook (by signed-manifest name/alias) — the retired socket/webhook
/// built-in transports are gone. `settings:` stays fully opaque (pushed to the plugin via `configure`);
/// nothing is consumed out of it. The plugin reference must be non-empty; an unresolvable/wrong-kind
/// reference is caught fail-closed at the plugin pre-flight (like a store/auth ref).
fn hook_cfg_from_ref(r: &HookModuleRef, default_kind: HookKind) -> Result<HookCfg, String> {
    let settings = r.settings.clone();
    let plugin = r.module.trim().to_string();
    if plugin.is_empty() {
        return Err("a hook module ref must name a non-empty `kind: hook` plugin".to_string());
    }
    Ok(HookCfg {
        kind: r.kind.unwrap_or(default_kind),
        plugin,
        timeout_ms: r.timeout_ms.unwrap_or(DEFAULT_POLICY_TIMEOUT_MS),
        on_error: r
            .on_error
            .as_ref()
            .map(|o| o.as_name().to_string())
            .unwrap_or_else(default_on_error),
        prompt: r.prompt.unwrap_or_default(),
        user: r.user.unwrap_or_default(),
        priority: r.priority.unwrap_or(0),
        at: r.at,
        on_empty: r.on_empty.clone(),
        settings: settings.clone(),
        global: false,
        default: false,
    })
}

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
                api_key: deploy_cfg.api_key.clone(),
                // Deployment health config wins over the catalog default (mirrors path/auth), so
                // the `health:` block documented in config.yaml actually takes effect.
                health: deploy_cfg.health.clone().or_else(|| def.health.clone()),
                error_map,
                // deployment override wins over the catalog default
                path: deploy_cfg.path.clone().or_else(|| def.path.clone()),
                path_base: deploy_cfg
                    .path_base
                    .clone()
                    .or_else(|| def.path_base.clone()),
                token_url: deploy_cfg
                    .token_url
                    .clone()
                    .or_else(|| def.token_url.clone()),
                scope: deploy_cfg.scope.clone().or_else(|| def.scope.clone()),
                auth: deploy_cfg.auth.or(def.auth),
                // deployment override (Some) replaces the catalog default
                allow_metadata_hosts: deploy_cfg
                    .allow_metadata_hosts
                    .clone()
                    .unwrap_or_else(|| def.allow_metadata_hosts.clone()),
            },
        );
    }

    // S9: project the INLINE hook refs (pool `hooks:` module entries + `global_hooks:`) into the
    // runtime hook registry. Each ref becomes a named registry entry (deterministic names: the
    // module name, suffixed `#N` on collision, iterating pools in sorted order); the pool's
    // `gates` list / the resolved `global_hooks` names carry the synthesized names in config
    // order. A module ref names a `kind: hook` plugin; an unresolvable/wrong-kind reference is a
    // FAIL-CLOSED plugin-preflight error (like a store/auth ref).
    let mut hooks_registry: HashMap<String, HookCfg> = HashMap::new();
    let mut pools = deploy.pools.clone();
    let register = |registry: &mut HashMap<String, HookCfg>,
                    r: &HookModuleRef,
                    where_: &str,
                    default_kind: HookKind,
                    errors: &mut Vec<String>|
     -> Option<String> {
        let cfg = match hook_cfg_from_ref(r, default_kind) {
            Ok(cfg) => cfg,
            Err(e) => {
                errors.push(format!("{where_}: {e}"));
                return None;
            }
        };
        let mut name = r.module.clone();
        let mut n = 1usize;
        while registry.contains_key(&name) {
            n += 1;
            name = format!("{}#{n}", r.module);
        }
        registry.insert(name.clone(), cfg);
        Some(name)
    };
    let mut pool_names: Vec<&String> = pools.keys().collect();
    pool_names.sort();
    let mut pool_gates: HashMap<String, Vec<String>> = HashMap::new();
    for pool_name in pool_names {
        let pool = &deploy.pools[pool_name];
        let mut gates = Vec::new();
        for r in &pool.module_hooks {
            if let Some(name) = register(
                &mut hooks_registry,
                r,
                &format!("pools.{pool_name}.hooks"),
                HookKind::Gate,
                &mut errors,
            ) {
                gates.push(name);
            }
        }
        pool_gates.insert(pool_name.clone(), gates);
    }
    for (pool_name, gates) in pool_gates {
        if let Some(p) = pools.get_mut(&pool_name) {
            p.gates = gates;
        }
    }
    let mut global_hook_names = Vec::new();
    for entry in &deploy.global_hooks {
        match entry {
            HookRefEntry::Builtin(name) => {
                errors.push(format!(
                    "global_hooks entry '{name}': a global hook is an inline module ref naming a \
                     `kind: hook` plugin (`{{ module: my-hook-plugin, settings: {{ … }} }}`); bare \
                     built-in names are pool ordering strategies and have no global meaning"
                ));
            }
            HookRefEntry::Module(r) => {
                if let Some(name) = register(
                    &mut hooks_registry,
                    r,
                    "global_hooks",
                    HookKind::Tap,
                    &mut errors,
                ) {
                    global_hook_names.push(name);
                }
            }
        }
    }

    // ADMIN-PLANE BOOT-GUARD: a network-exposed admin listener MUST require client certificates
    // (mTLS) — the management surface is the highest-value target and must not sit on a public bind
    // behind a bearer token alone. Loopback binds are safe (unreachable off-host); an explicit
    // `admin_insecure: true` waives the guard for operators fronting admin with a mesh that
    // terminates mTLS. Anything else that would expose admin without a client CA refuses to boot.
    {
        let admin_listen = &deploy.admin_listen;
        let exposed = !bind_is_loopback(admin_listen);
        let has_client_mtls = deploy
            .admin_tls
            .as_ref()
            .is_some_and(|t| t.client_ca.is_some());
        if exposed && !has_client_mtls && !deploy.admin_insecure {
            errors.push(format!(
                "admin_listen '{admin_listen}' is network-exposed but the admin plane has no mTLS \
                 (admin_tls.client_ca is unset). Require client certificates by supplying \
                 admin_tls.client_ca, bind admin_listen to loopback, or set admin_insecure: \
                 true to deliberately run a token-only admin plane (e.g. behind a mesh)."
            ));
        }
    }

    if errors.is_empty() {
        Ok(RootCfg {
            listen: deploy.listen.clone(),
            tls: deploy.tls.clone(),
            admin_listen: deploy.admin_listen.clone(),
            admin_tls: deploy.admin_tls.clone(),
            auth: deploy.auth.clone(),
            providers: resolved_providers,
            models: deploy.models.clone(),
            pools,
            hooks: hooks_registry,
            // The admin chain module names, from `auth.admin_auth:` (default `[admin-tokens]`
            // when the whole `auth:` block is absent).
            admin_auth: deploy
                .auth
                .as_ref()
                .map(|a| a.admin_auth.iter().map(|e| e.module.clone()).collect())
                .unwrap_or_else(|| {
                    default_admin_auth()
                        .iter()
                        .map(|e| e.module.clone())
                        .collect()
                }),
            groups: deploy.groups.clone(),
            rate_card: deploy.rate_card.clone(),
            per_request_fee: deploy.per_request_fee,
            store: deploy.store.clone(),
            global_hooks: global_hook_names,
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
            // Project the operational-limit sections onto a flat resolved struct. The
            // `observability:` / `advanced:` blocks are optional; absent ⇒ their section defaults
            // (the historical hardcoded values, via the manual `Default` impls).
            limits: LimitsResolved::from_sections(
                &deploy.limits,
                &deploy.observability.clone().unwrap_or_default(),
                &deploy.advanced,
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
#[path = "tests/tests.rs"]
mod tests;
