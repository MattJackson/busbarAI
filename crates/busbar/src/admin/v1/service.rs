// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The Admin API v1 SERVICE — the application core (the "port").
//!
//! `AdminService` owns every admin OPERATION as a typed async method returning `Result<View,
//! AdminError>`. It holds the shared `App` and knows nothing about HTTP/JSON/MCP: a transport adapter
//! (`super::transport`) drives it and projects the result onto a wire. This is where scope checks,
//! atomicity, and audit live as the surface grows — one place, reused by every transport (REST now;
//! GraphQL/MCP/gRPC later, unchanged).

use std::sync::Arc;

use crate::state::App;

use super::contract::{
    AdminAuthView, AdminError, AuthView, BuildInfo, ConfigValidateView, EffectiveConfigView,
    GroupView, HookHealthView, HookTransportView, HookView, InfoView, KeyUsageView, ModelUsageView,
    ModelView, Page, PluginView, PoolDetailView, PoolMemberStatusView, PoolMemberView, PoolView,
    ProviderView, TopologyInfo, UsageBreakdown, UsageView, UsageWindow,
};
use crate::config::{
    DeployCfg, HookCfg, HookKind, HookStage, PromptAccess, ProviderDef, UserAccess,
};

/// Derive busbar's spend ESTIMATE (micro-units, abstract cost units) for one PER-MODEL metering
/// row from the CURRENT rate card: the row's tier-token split priced at that model's rates, plus
/// the flat per-request fee x requests. Recomputed on every read (reprice-on-read: a rate-card
/// correction changes historical figures on the next read; tokens are the stored truth). Metering
/// rows attribute by the CONFIGURED model name, so the rate lookup goes through the
/// `upstream_model` alias resolution.
fn derive_spend_micros_row(cost: &crate::cost::CostModel, model: &str, b: &UsageBreakdown) -> i64 {
    let tier = busbar_api::TierTokens {
        input: b.tokens_input,
        output: b.tokens_output,
        cache_read: b.tokens_cache_read,
        cache_write: b.tokens_cache_creation,
    };
    let resolved = cost.resolve_model_alias(model);
    cost.derive_spend_micros([(resolved, &tier)].into_iter(), b.requests, true)
}

/// Process start instant, for the `info` uptime read. Stamped ONCE at startup by `mark_start()`.
/// A missing value (never stamped — e.g. a unit test that skips `main`) yields a `None` uptime
/// rather than a panic.
static PROCESS_START: std::sync::OnceLock<std::time::Instant> = std::sync::OnceLock::new();
/// Process start EPOCH (unix seconds) — `info.started_at`, the boot-epoch marker consumers use to
/// detect that process-local counters (config_version, breaker trip counts) reset.
static PROCESS_START_EPOCH: std::sync::OnceLock<u64> = std::sync::OnceLock::new();

/// Stamp the process start instant + epoch for the `info` reads. Idempotent (first `set` wins), so
/// it is safe to call unconditionally at startup.
pub(crate) fn mark_start() {
    let _ = PROCESS_START.set(std::time::Instant::now());
    let _ = PROCESS_START_EPOCH.set(crate::store::now());
}

/// The auth modules COMPILED INTO this binary (feature-gated at compile time — real `#[cfg]` on each
/// array element, so this reflects the ACTUAL binary). The single source for both `info`'s build
/// proof and the `plugins?type=auth` catalog. `keys` (the built-in signed-key verifier) is
/// engine-handled and always present; `admin-tokens` (the operator admin credential) is the
/// removable default-on feature.
fn auth_modules_compiled_in() -> Vec<&'static str> {
    [
        crate::config::KEYS_MODULE,
        #[cfg(feature = "auth-admin-tokens")]
        crate::config::ADMIN_TOKENS_MODULE,
    ]
    .to_vec()
}

/// The removable hook plugins COMPILED INTO this binary (feature-gated). Excludes the always-present,
/// non-removable weighted SWRR floor, which is reported separately (as `weighted_floor` / the
/// `weighted` compiled-in entry).
fn hook_plugins_compiled_in() -> Vec<&'static str> {
    [
        #[cfg(feature = "hooks-ranking")]
        "ranking",
    ]
    .to_vec()
}

/// Longest a plugin filename may be — generous headroom over any real tarball name, guarding the
/// filesystem path we build from admin-supplied input.
const MAX_PLUGIN_FILENAME_LEN: usize = 256;

/// Validate an admin-supplied plugin TARBALL filename and return it owned. Fail-closed against path
/// traversal (a filename is the LAST path component only — no `/`, `\`, `..`, or absolute/rooted
/// path can reach outside the plugins directory) and enforce the `.tar.gz`/`.tgz` extension. This
/// is the one gate every plugin write/delete funnels through, so the plugins directory is the hard
/// boundary. The filename is STORAGE ONLY — plugin identity always comes from the signed manifest.
fn validate_plugin_filename(file: &str) -> Result<String, AdminError> {
    if file.is_empty() || file.len() > MAX_PLUGIN_FILENAME_LEN {
        return Err(AdminError::Validation(format!(
            "plugin filename must be 1..={MAX_PLUGIN_FILENAME_LEN} chars"
        )));
    }
    // Reject anything that isn't a bare filename — the component the OS would treat as a directory
    // separator, a parent ref, or a rooted path lets an admin-supplied name escape the plugins dir.
    if file.contains('/') || file.contains('\\') || file.contains("..") {
        return Err(AdminError::Validation(
            "plugin filename must be a bare filename (no path separators or `..`)".into(),
        ));
    }
    // Belt-and-braces: the parsed path must have exactly one normal component equal to `file` (so a
    // platform-specific rooted form, e.g. a Windows drive prefix, can never slip through).
    let path = std::path::Path::new(file);
    let mut comps = path.components();
    match (comps.next(), comps.next()) {
        (Some(std::path::Component::Normal(c)), None) if c == std::ffi::OsStr::new(file) => {}
        _ => {
            return Err(AdminError::Validation(
                "plugin filename must be a single, normal path component".into(),
            ));
        }
    }
    if !busbar_plugin_loader::tarball::is_plugin_tarball(file) {
        return Err(AdminError::Validation(
            "plugin filename must be a `.tar.gz` (or `.tgz`) signed plugin tarball".into(),
        ));
    }
    Ok(file.to_string())
}

/// Best-effort reachability probe for a hook's backing plugin, for the health read. A hook is now an
/// in-process `kind: hook` plugin (the socket/webhook out-of-process transports are retired), so
/// "reachable" means the referenced plugin RESOLVES to a loadable `kind: hook` plugin in the validated
/// registry. Returns `(reachable, detail)`: `Some(true)` when it resolves, `Some(false)` with the
/// reason when it does not.
async fn probe_transport(
    cfg: &HookCfg,
    env: &crate::hooks::HookEnv,
) -> (Option<bool>, Option<String>) {
    match env.registry.resolve(&cfg.plugin) {
        Some(p) if p.manifest.kind == "hook" => (Some(true), None),
        Some(p) => (
            Some(false),
            Some(format!(
                "plugin '{}' resolves to kind '{}', not 'hook'",
                cfg.plugin, p.manifest.kind
            )),
        ),
        None => (
            Some(false),
            Some(match env.registry.unresolved_reason(&cfg.plugin) {
                Some(sk) => format!(
                    "plugin '{}' present but not loaded: {}",
                    cfg.plugin, sk.reason
                ),
                None => format!("plugin '{}' is not installed", cfg.plugin),
            }),
        ),
    }
}

/// Build the next `App` snapshot with `name` registered/updated to `cfg` in the hook registry — the
/// PURE core of `POST /api/v1/admin/hooks` (runtime hook registration). Validates the definition, clones
/// the current snapshot (sharing the live-state `Arc`s), inserts the hook, updates the global-hook
/// wiring, and RE-RESOLVES the rewrite/tap transports so a `global` hook takes effect immediately on
/// swap. Lanes/store/pools/auth are UNTOUCHED, so the store's per-lane breaker state is preserved (no
/// re-index — the safe, store-constraint-free subset of config apply). The caller `AppHandle::swap`s
/// the returned snapshot. Pure + `Result` → unit-testable without the transport.
/// The `settings` map is persisted VERBATIM into the state file and re-sent to the hook binary on
/// every reconnect, so an unbounded map bloats the durable state and amplifies the reconnect path.
/// These caps are far past any real hook's settings; a compromised `hooks-register` token must not
/// be able to blow them out. Shared by `build_with_hook` (register / PUT) and `patch_hook_settings`
/// (PATCH) so all three write paths enforce ONE limit with no drift.
pub(crate) const MAX_SETTINGS_BYTES: usize = 64 * 1024;
pub(crate) const MAX_SETTINGS_KEYS: usize = 256;
/// Upper bound on a hook name (a registry key persisted to the state file + every audit row).
/// Generous headroom over any real hook name; guards the durable-state/audit/reconnect path.
pub(crate) const MAX_HOOK_NAME_LEN: usize = 256;
/// Upper bound on a group name — same rationale as the hook cap (a registry key persisted to the
/// overlay + every audit row). Generous over any real `org/dept/team/user:<sub>` name.
pub(crate) const MAX_GROUP_NAME_LEN: usize = 256;

/// Fail-closed size check for a hook's `settings` map — see the cap rationale above.
pub(crate) fn validate_hook_settings_size(
    settings: &serde_json::Map<String, serde_json::Value>,
) -> Result<(), AdminError> {
    if settings.len() > MAX_SETTINGS_KEYS {
        return Err(AdminError::Validation(format!(
            "settings has too many keys ({}, max {MAX_SETTINGS_KEYS})",
            settings.len()
        )));
    }
    if let Ok(bytes) = serde_json::to_vec(settings) {
        if bytes.len() > MAX_SETTINGS_BYTES {
            return Err(AdminError::Validation(format!(
                "settings too large ({} bytes, max {MAX_SETTINGS_BYTES})",
                bytes.len()
            )));
        }
    }
    Ok(())
}

pub(crate) fn build_with_hook(current: &App, name: &str, cfg: HookCfg) -> Result<App, AdminError> {
    // ── validate the definition (fail-closed, before any mutation) ──
    if name.trim().is_empty() {
        return Err(AdminError::Validation("hook name must not be empty".into()));
    }
    // Cap the name length. The name is a registry key that gets written VERBATIM into the overlay
    // state file and every audit row (and echoed on the wire); without a bound a `hooks-register`
    // token could POST a name up to the body-size cap (~MB), bloating the durable state / audit /
    // reconnect path — the same defensive posture as the key-id / settings caps. (found: audit c2r4.)
    if name.len() > MAX_HOOK_NAME_LEN {
        return Err(AdminError::Validation(format!(
            "hook name is {} chars; must be <= {MAX_HOOK_NAME_LEN}",
            name.len()
        )));
    }
    // Reserved names — the SAME rule boot validation enforces (config::RESERVED_HOOK_NAMES): a
    // runtime-registered hook can neither shadow a built-in nor collide with an `on_error` terminal
    // word (which would make the on_error string union ambiguous for every consumer). Previously
    // only the boot/apply path checked this — the register API was the one write path missing it.
    if crate::config::RESERVED_HOOK_NAMES.contains(&name) {
        return Err(AdminError::Validation(format!(
            "hook name `{name}` is reserved (a built-in ranking strategy, auth module, or on_error \
             terminal); pick another name"
        )));
    }
    // The `settings` map rides register/PUT too — cap it here so it is bounded on EVERY write path,
    // not just PATCH (found: audit c1r12 — register/PUT were missing the cap PATCH already had).
    validate_hook_settings_size(&cfg.settings)?;
    // A hook must name exactly one `kind: hook` plugin (the retired socket/webhook transports are
    // gone). Emptiness is the structural check here; the plugin's existence/kind is validated against
    // the registry below (register/PUT) and at the plugin pre-flight.
    if cfg.plugin.trim().is_empty() {
        return Err(AdminError::Validation(
            "a hook must name a `kind: hook` plugin via `plugin:`".into(),
        ));
    }
    // `prompt: rw` is a rewrite grant, meaningless (and unsafe) on a fire-and-forget tap.
    if cfg.kind == HookKind::Tap && cfg.prompt == PromptAccess::Rw {
        return Err(AdminError::Validation(
            "`prompt: rw` is invalid on a `kind: tap` hook (a tap cannot rewrite)".into(),
        ));
    }
    // GRANT IMMUTABILITY (§6.4): `kind`/`prompt`/`user` are definition-only and FROZEN after first
    // registration. Re-registering a name with different grants is a `conflict` — delete and
    // re-register to change them. This closes the "register `prompt: no`, wire it in, then escalate to
    // `rw`" exfiltration path: a grant can never widen in place. Re-registering with the SAME grants is
    // allowed (an idempotent re-register / settings refresh).
    if let Some(existing) = current.hook_registry.get(name) {
        if existing.kind != cfg.kind || existing.prompt != cfg.prompt || existing.user != cfg.user {
            return Err(AdminError::Conflict(format!(
                "hook `{name}` already exists with different kind/prompt/user grants; grants are \
                 immutable — delete and re-register to change them"
            )));
        }
    }

    // ── build the next snapshot (clone shares live state; only config-derived fields change) ──
    let mut next = current.clone();
    next.config_version = current.config_version.wrapping_add(1);
    let is_global = cfg.global;
    next.hook_registry.insert(name.to_string(), cfg);
    if is_global {
        if !next.global_hooks.iter().any(|n| n == name) {
            next.global_hooks.push(name.to_string());
        }
    } else {
        // A PUT that REPLACES a prior `global: true` hook with `global: false` must DE-WIRE it from
        // the global fan-out — otherwise the stale membership keeps it firing on every request and
        // `hook_view` keeps reporting `global: true`, so the operator's 200 OK silently no-ops the
        // demotion. Mirrors `build_without_hook`'s DELETE cleanup.
        next.global_hooks.retain(|n| n != name);
    }
    // Re-resolve the FIRED transports from the new registry so a global hook is live after the swap.
    next.rewrite_hooks = crate::hooks::resolve_rewrite_hooks(
        &next.hook_registry,
        &next.global_hooks,
        &next.hook_env,
        next.config_version,
    );
    next.tap_hooks = crate::hooks::resolve_tap_hooks(
        &next.hook_registry,
        &next.global_hooks,
        &next.hook_env,
        next.config_version,
        crate::config::HookStage::Request,
    );
    next.tap_hooks_route = crate::hooks::resolve_tap_hooks(
        &next.hook_registry,
        &next.global_hooks,
        &next.hook_env,
        next.config_version,
        crate::config::HookStage::Route,
    );
    next.tap_hooks_attempt = crate::hooks::resolve_tap_hooks(
        &next.hook_registry,
        &next.global_hooks,
        &next.hook_env,
        next.config_version,
        crate::config::HookStage::Attempt,
    );
    next.tap_hooks_completion = crate::hooks::resolve_tap_hooks(
        &next.hook_registry,
        &next.global_hooks,
        &next.hook_env,
        next.config_version,
        crate::config::HookStage::Completion,
    );
    next.global_gates = crate::hooks::resolve_gate_hooks(
        &next.hook_registry,
        &next.global_hooks,
        &next.hook_env,
        next.config_version,
    );
    Ok(next)
}

/// Build the next `App` snapshot with `name` REMOVED from the hook registry — the pure core of
/// `DELETE /api/v1/admin/hooks/{name}`. `not_found` if the name is unregistered. Clones the current
/// snapshot (sharing live state), drops the hook from the registry + global wiring, and re-resolves
/// the rewrite/tap transports. Lanes/store untouched (breaker state preserved). Same GLOBAL scope as
/// `build_with_hook`: pool-`hook:` references are resolved into `pool_runtime` at startup and are NOT
/// re-resolved here — that (plus the dangling-ref 409) lands with the broader config/apply.
pub(crate) fn build_without_hook(current: &App, name: &str) -> Result<App, AdminError> {
    if !current.hook_registry.contains_key(name) {
        return Err(AdminError::NotFound(format!("hook `{name}`")));
    }
    let mut next = current.clone();
    next.config_version = current.config_version.wrapping_add(1);
    next.hook_registry.remove(name);
    next.global_hooks.retain(|n| n != name);
    next.rewrite_hooks = crate::hooks::resolve_rewrite_hooks(
        &next.hook_registry,
        &next.global_hooks,
        &next.hook_env,
        next.config_version,
    );
    next.tap_hooks = crate::hooks::resolve_tap_hooks(
        &next.hook_registry,
        &next.global_hooks,
        &next.hook_env,
        next.config_version,
        crate::config::HookStage::Request,
    );
    next.tap_hooks_route = crate::hooks::resolve_tap_hooks(
        &next.hook_registry,
        &next.global_hooks,
        &next.hook_env,
        next.config_version,
        crate::config::HookStage::Route,
    );
    next.tap_hooks_attempt = crate::hooks::resolve_tap_hooks(
        &next.hook_registry,
        &next.global_hooks,
        &next.hook_env,
        next.config_version,
        crate::config::HookStage::Attempt,
    );
    next.tap_hooks_completion = crate::hooks::resolve_tap_hooks(
        &next.hook_registry,
        &next.global_hooks,
        &next.hook_env,
        next.config_version,
        crate::config::HookStage::Completion,
    );
    next.global_gates = crate::hooks::resolve_gate_hooks(
        &next.hook_registry,
        &next.global_hooks,
        &next.hook_env,
        next.config_version,
    );
    Ok(next)
}

/// Build the next `App` snapshot with `name` created-or-replaced in the group registry — the pure
/// core of `POST`/`PUT /api/v1/admin/groups`. VALIDATE-AT-THE-DOOR: the mutated registry is run
/// through the SAME `validate_groups` boot uses (parent references exist, the parent chain is
/// acyclic — any depth, the cycle check is the bound), so a bad group (dangling/cyclic parent) is a `400` that
/// changes nothing. On success the enforcement projection is rebuilt via `CostModel::with_groups`
/// (reusing the rate card + fee unchanged) so the new limits are live after the swap; the governance
/// LEDGER survives (it is Arc-shared, not rebuilt), so past accrual is preserved across the change.
pub(crate) fn build_with_group(
    current: &App,
    name: &str,
    cfg: crate::config::GroupCfg,
) -> Result<App, AdminError> {
    if name.trim().is_empty() {
        return Err(AdminError::Validation(
            "group name must not be empty".into(),
        ));
    }
    if name.len() > MAX_GROUP_NAME_LEN {
        return Err(AdminError::Validation(format!(
            "group name is {} chars; must be <= {MAX_GROUP_NAME_LEN}",
            name.len()
        )));
    }
    // Build the candidate registry and validate it WHOLE before mutating the snapshot — a group's
    // legality (parent exists, chain acyclic) is a property of the tree, not the single entry.
    let mut groups = current.groups_registry.clone();
    groups.insert(name.to_string(), cfg);
    let mut errors = Vec::new();
    crate::config::groups::validate_groups(
        &groups,
        &|p| current.pools.contains_key(p),
        &mut errors,
    );
    if !errors.is_empty() {
        return Err(AdminError::Validation(format!(
            "invalid group `{name}`: {}",
            errors.join("; ")
        )));
    }
    let mut next = current.clone();
    next.config_version = current.config_version.wrapping_add(1);
    next.cost = std::sync::Arc::new(next.cost.with_groups(&groups));
    next.groups_registry = groups;
    Ok(next)
}

/// Build the next `App` snapshot with `name` REMOVED from the group registry — the pure core of
/// `DELETE /api/v1/admin/groups/{name}`. `not_found` if unknown. RE-VALIDATES the reduced tree: if
/// another group still names the removed one as its `parent`, the delete is a `409 conflict` (remove
/// or re-parent the children first) rather than silently orphaning them. On success the enforcement
/// projection is rebuilt (the removed group's buckets disappear); the ledger survives the swap.
pub(crate) fn build_without_group(current: &App, name: &str) -> Result<App, AdminError> {
    if !current.groups_registry.contains_key(name) {
        return Err(AdminError::NotFound(format!("group `{name}`")));
    }
    let mut groups = current.groups_registry.clone();
    groups.remove(name);
    // A dangling `parent` after the removal is the only new error a delete can introduce; surface it
    // as a state CONFLICT (something still references this group) so the caller distinguishes it from
    // a malformed request.
    let mut errors = Vec::new();
    crate::config::groups::validate_groups(
        &groups,
        &|p| current.pools.contains_key(p),
        &mut errors,
    );
    if !errors.is_empty() {
        return Err(AdminError::Conflict(format!(
            "cannot delete group `{name}`: {} (re-parent or remove the referencing group first)",
            errors.join("; ")
        )));
    }
    let mut next = current.clone();
    next.config_version = current.config_version.wrapping_add(1);
    next.cost = std::sync::Arc::new(next.cost.with_groups(&groups));
    next.groups_registry = groups;
    Ok(next)
}

/// Build the next `App` snapshot with the whole HOOK SURFACE replaced by a version snapshot — the
/// pure core of `POST /api/v1/admin/config/rollback`. RE-VALIDATES the snapshot against CURRENT reality
/// before any mutation (a snapshot that was valid when recorded may violate an invariant now):
/// per-hook transport XOR + rw-on-tap, at-most-one-default, and no dangling global refs. Clones the
/// current snapshot (sharing live state — lanes/store untouched, breaker state preserved) and
/// re-resolves every global transport. Same restrict-scope as the other builders: pool-resolved
/// hook references are startup-resolved and not re-resolved here.
pub(crate) fn build_with_registry(
    current: &App,
    registry: std::collections::HashMap<String, HookCfg>,
    global_hooks: Vec<String>,
) -> Result<App, AdminError> {
    for (name, cfg) in &registry {
        if cfg.plugin.trim().is_empty() {
            return Err(AdminError::Validation(format!(
                "hook `{name}` must name a `kind: hook` plugin via `plugin:`"
            )));
        }
        if cfg.kind == HookKind::Tap && cfg.prompt == PromptAccess::Rw {
            return Err(AdminError::Validation(format!(
                "hook `{name}` sets `prompt: rw` on a `kind: tap` (a tap cannot rewrite)"
            )));
        }
    }
    let defaults: Vec<&str> = registry
        .iter()
        .filter(|(_, h)| h.default)
        .map(|(n, _)| n.as_str())
        .collect();
    if defaults.len() > 1 {
        return Err(AdminError::Validation(format!(
            "snapshot has more than one `default: true` hook: {}",
            defaults.join(", ")
        )));
    }
    for g in &global_hooks {
        if !registry.contains_key(g) {
            return Err(AdminError::Validation(format!(
                "snapshot wires unknown global hook `{g}`"
            )));
        }
    }
    let mut next = current.clone();
    next.config_version = current.config_version.wrapping_add(1);
    next.hook_registry = registry;
    next.global_hooks = global_hooks;
    next.rewrite_hooks = crate::hooks::resolve_rewrite_hooks(
        &next.hook_registry,
        &next.global_hooks,
        &next.hook_env,
        next.config_version,
    );
    next.tap_hooks = crate::hooks::resolve_tap_hooks(
        &next.hook_registry,
        &next.global_hooks,
        &next.hook_env,
        next.config_version,
        crate::config::HookStage::Request,
    );
    next.tap_hooks_route = crate::hooks::resolve_tap_hooks(
        &next.hook_registry,
        &next.global_hooks,
        &next.hook_env,
        next.config_version,
        crate::config::HookStage::Route,
    );
    next.tap_hooks_attempt = crate::hooks::resolve_tap_hooks(
        &next.hook_registry,
        &next.global_hooks,
        &next.hook_env,
        next.config_version,
        crate::config::HookStage::Attempt,
    );
    next.tap_hooks_completion = crate::hooks::resolve_tap_hooks(
        &next.hook_registry,
        &next.global_hooks,
        &next.hook_env,
        next.config_version,
        crate::config::HookStage::Completion,
    );
    next.global_gates = crate::hooks::resolve_gate_hooks(
        &next.hook_registry,
        &next.global_hooks,
        &next.hook_env,
        next.config_version,
    );
    Ok(next)
}

/// The admin application core. Cheap to construct and clone-free to share (`Arc<App>` inside); a
/// transport builds ONE and hands `Arc<AdminService>` to its routes.
pub(crate) struct AdminService {
    app: Arc<App>,
}

impl AdminService {
    pub(crate) fn new(app: Arc<App>) -> Self {
        Self { app }
    }

    /// `GET /api/v1/admin/info` — version, the COMPILED-IN plugin sets (compliance-by-compilation proof),
    /// uptime, and pool/model/provider topology. Read scope. Infallible today, but returns `Result`
    /// for a uniform transport contract (every op is `Result<View, AdminError>`).
    pub(crate) async fn info(&self) -> Result<InfoView, AdminError> {
        // The compiled-in plugin sets reflect the ACTUAL binary (feature-gated): the `keys` /
        // `admin-tokens` auth builtins plus the ranking hooks. `weighted` is the one baked in
        // (non-removable), so it appears as `weighted_floor` below, not in `hook_plugins`.
        let auth_modules = auth_modules_compiled_in();
        let hook_plugins = hook_plugins_compiled_in();

        let providers: std::collections::BTreeSet<&str> =
            self.app.lanes.iter().map(|l| l.provider.as_str()).collect();

        Ok(InfoView {
            version: env!("CARGO_PKG_VERSION"),
            build: BuildInfo {
                auth_modules,
                hook_plugins,
                weighted_floor: true,
            },
            uptime_seconds: PROCESS_START.get().map(|s| s.elapsed().as_secs()),
            started_at: PROCESS_START_EPOCH.get().copied(),
            topology: TopologyInfo {
                pools: self.app.pools.len(),
                models: self.app.by_model.len(),
                providers: providers.len(),
            },
            config_persistence: self.app.overlay_path.is_some(),
            config_version: self.app.config_version,
        })
    }

    /// `GET /api/v1/admin/pools` — the pool topology (name + member models/weights). Read scope. Sorted
    /// by name for a stable, diff-friendly listing. Live per-member
    /// status is an additive follow-up (§6.9).
    pub(crate) async fn list_pools(&self) -> Result<Page<PoolView>, AdminError> {
        let mut pools: Vec<PoolView> = self
            .app
            .pools
            .iter()
            .map(|(name, members)| PoolView {
                name: name.clone(),
                members: members
                    .iter()
                    .map(|m| PoolMemberView {
                        // `idx` is the stable lane handle; project the lane's model name.
                        model: self.app.lanes[m.idx].model.clone(),
                        weight: m.weight,
                    })
                    .collect(),
            })
            .collect();
        pools.sort_by(|a, b| a.name.cmp(&b.name));
        Ok(Page::single(pools))
    }

    /// `GET /api/v1/admin/pools/{name}` — the LIVE per-member status of one pool (breaker/concurrency/
    /// latency/tallies), from the same store signals the routing seam ranks on. Read scope.
    /// `not_found` if the pool is unknown.
    pub(crate) async fn get_pool(&self, name: &str) -> Result<PoolDetailView, AdminError> {
        let members = self
            .app
            .pools
            .get(name)
            .ok_or_else(|| AdminError::NotFound(format!("pool `{name}`")))?;
        Ok(self.pool_detail(name, members))
    }

    /// Project one pool's LIVE member status — the shared core of `GET /pools/{name}` and
    /// `GET /pools?detail=true` (one projection, two readers — the shapes can never diverge).
    fn pool_detail(&self, name: &str, members: &[crate::state::WeightedLane]) -> PoolDetailView {
        let now = crate::store::now();
        let members = members
            .iter()
            .map(|m| {
                // `snapshot` is the same release-exposed live summary `/stats` reads (usable / cooldown
                // / inflight / tallies / dead); `available_permits` + `lane_latency_ms` round it out.
                let snap = self.app.store.snapshot(m.idx, now);
                PoolMemberStatusView {
                    model: self.app.lanes[m.idx].model.clone(),
                    weight: m.weight,
                    usable: snap.usable,
                    cooldown_remaining_seconds: snap.cooldown_remaining_s,
                    available_concurrency: self.app.store.available_permits(m.idx),
                    inflight: snap.inflight,
                    latency_ms: self.app.store.lane_latency_ms(m.idx),
                    ok: snap.ok,
                    err: snap.err,
                    dead: snap.dead,
                    trip_count: snap.trips,
                    last_trip_at: (snap.last_trip_at > 0).then_some(snap.last_trip_at),
                }
            })
            .collect();
        PoolDetailView {
            name: name.to_string(),
            members,
        }
    }

    /// `GET /api/v1/admin/pools?detail=true` — the WHOLE topology with live member status in ONE
    /// call (audit #7: the summary + per-pool detail split forced an M+1 fan-out per dashboard
    /// refresh). Same row shape as `GET /pools/{name}` via the shared projection. Sorted by name.
    pub(crate) async fn list_pools_detailed(&self) -> Result<Page<PoolDetailView>, AdminError> {
        let mut pools: Vec<PoolDetailView> = self
            .app
            .pools
            .iter()
            .map(|(name, members)| self.pool_detail(name, members))
            .collect();
        pools.sort_by(|a, b| a.name.cmp(&b.name));
        Ok(Page::single(pools))
    }

    /// `GET /api/v1/admin/models` — every model lane + its upstream provider. Read scope. Sorted by
    /// model name. No credentials.
    pub(crate) async fn list_models(&self) -> Result<Page<ModelView>, AdminError> {
        let mut models: Vec<ModelView> = self
            .app
            .lanes
            .iter()
            .map(|l| ModelView {
                model: l.model.clone(),
                provider: l.provider.clone(),
            })
            .collect();
        models.sort_by(|a, b| a.model.cmp(&b.model));
        Ok(Page::single(models))
    }

    /// `GET /api/v1/admin/providers` — distinct upstream providers + the count of model lanes routing
    /// through each. Read scope. Sorted by provider name.
    pub(crate) async fn list_providers(&self) -> Result<Page<ProviderView>, AdminError> {
        let mut counts: std::collections::BTreeMap<&str, usize> = std::collections::BTreeMap::new();
        for lane in &self.app.lanes {
            *counts.entry(lane.provider.as_str()).or_insert(0) += 1;
        }
        let providers = counts
            .into_iter()
            .map(|(provider, model_count)| ProviderView {
                provider: provider.to_string(),
                model_count,
            })
            .collect();
        Ok(Page::single(providers))
    }

    /// `GET /api/v1/admin/hooks` — the hook registry read. Read scope. Each entry
    /// is the DEFINITION (kind/transport/grants/ordering/stage), never a secret. Sorted by name.
    pub(crate) async fn list_hooks(&self) -> Result<Page<HookView>, AdminError> {
        let mut hooks: Vec<HookView> = self
            .app
            .hook_registry
            .iter()
            .map(|(name, cfg)| self.hook_view(name, cfg))
            .collect();
        hooks.sort_by(|a, b| a.name.cmp(&b.name));
        Ok(Page::single(hooks))
    }

    /// `GET /api/v1/admin/hooks/{name}` — one hook definition, or `not_found` if the name is unregistered.
    pub(crate) async fn get_hook(&self, name: &str) -> Result<HookView, AdminError> {
        self.app
            .hook_registry
            .get(name)
            .map(|cfg| self.hook_view(name, cfg))
            .ok_or_else(|| AdminError::NotFound(format!("hook `{name}`")))
    }

    /// `GET /api/v1/admin/groups` — the `groups:` limit tree read. Read scope. Each entry is the
    /// DEFINITION (parent, enabled, limits, `child_default`), never a secret. Sorted by name (the
    /// registry is already a BTreeMap, so iteration is name-ordered).
    pub(crate) async fn list_groups(&self) -> Result<Page<GroupView>, AdminError> {
        let groups: Vec<GroupView> = self
            .app
            .groups_registry
            .iter()
            .map(|(name, cfg)| GroupView::from_cfg(name, cfg))
            .collect();
        Ok(Page::single(groups))
    }

    /// `GET /api/v1/admin/groups/{name}` — one group definition, or `not_found` if the name is unknown.
    pub(crate) async fn get_group(&self, name: &str) -> Result<GroupView, AdminError> {
        self.app
            .groups_registry
            .get(name)
            .map(|cfg| GroupView::from_cfg(name, cfg))
            .ok_or_else(|| AdminError::NotFound(format!("group `{name}`")))
    }

    /// `GET /api/v1/admin/groups/{name}/usage` — the group's derived current-window usage per
    /// enforcement bucket vs its caps (§6d, the self-service dashboard read). Read scope.
    /// `not_found` for an unknown group; governance off = every bucket reads zero (the caps are
    /// still projected — the definition exists even when nothing enforces).
    pub(crate) async fn get_group_usage(
        &self,
        name: &str,
    ) -> Result<crate::admin::v1::contract::GroupUsageView, AdminError> {
        use crate::admin::v1::contract::{GroupBucketUsageView, GroupUsageView};
        let Some(rt) = self.app.cost.group_named(name) else {
            return Err(AdminError::NotFound(format!("group `{name}`")));
        };
        let now = crate::store::now();
        let mut buckets = Vec::with_capacity(rt.buckets.len());
        for b in &rt.buckets {
            let usage = match &self.app.governance {
                Some(gov) => gov
                    .derived_bucket_usage(&self.app.cost, &b.bucket_id, b.window, false, now)
                    .map_err(|e| {
                        tracing::error!(group = name, bucket = %b.bucket_id, err = %e,
                            "group usage read failed");
                        AdminError::Internal
                    })?,
                None => Default::default(),
            };
            buckets.push(GroupBucketUsageView {
                window: b.window,
                pool: b.pool.clone(),
                requests: usage.requests,
                tokens: usage.tokens,
                spend_cents: usage.spend_cents,
                requests_cap: b.requests_cap,
                tokens_cap: b.tokens_cap,
                budget_cap: b.budget_cap,
                budget_remaining_cents: b
                    .budget_cap
                    .map(|cap| cap.saturating_sub(usage.spend_cents).max(0)),
            });
        }
        Ok(GroupUsageView {
            group: name.to_string(),
            enabled: rt.enabled,
            buckets,
            as_of: now,
        })
    }

    /// `GET /api/v1/admin/plugins?type=auth|hooks` — the plugin catalog for one TYPE. Read
    /// scope. Lists COMPILED-IN plugins (feature-gated, from the binary — the same source as `info`'s
    /// build proof) and EXTERNAL plugins (registered over socket/webhook). An unknown/absent `type` is
    /// an `invalid_request` (the two types are distinct engine contracts; a caller must pick one).
    pub(crate) async fn list_plugins(&self, ptype: &str) -> Result<Page<PluginView>, AdminError> {
        let mut plugins: Vec<PluginView> = Vec::new();
        match ptype {
            "auth" => {
                // Compiled-in auth modules (feature-gated). Active = wired into its chain: `keys`
                // is engine-handled (a flag, not a boxed module), `admin-tokens` lives on the
                // ADMIN chain, and anything else is a boxed data-plane chain module.
                let chain = self.app.auth.chain_names();
                for name in auth_modules_compiled_in() {
                    let active = if name == crate::config::KEYS_MODULE {
                        self.app.auth.keys_in_chain
                    } else if name == crate::config::ADMIN_TOKENS_MODULE {
                        self.app.admin_chain.iter().any(|m| m == name)
                    } else {
                        chain.contains(&name)
                    };
                    plugins.push(PluginView::basic(
                        name.to_string(),
                        "auth",
                        "compiled-in",
                        Some(active),
                        None,
                    ));
                }
                // DYNAMIC auth modules: a `kind: auth` plugin loaded over the signed hybrid ABI and
                // boxed into the data-plane chain. Its runtime name (`module.name()`, what
                // `role_bindings.<module>` keys off) appears in `chain_names()` but is NOT
                // compiled-in — report each such module as a loaded plugin, always `active` (it is
                // in the chain by construction).
                let compiled = auth_modules_compiled_in();
                for name in &chain {
                    if !compiled.contains(name) {
                        plugins.push(PluginView::basic(
                            name.to_string(),
                            "auth",
                            "plugin",
                            Some(true),
                            None,
                        ));
                    }
                }
                // External auth modules (runtime-registered over socket/webhook) — none until the
                // auth-module registration endpoint lands (#56); the catalog shape is ready.
            }
            "hooks" => {
                // The weighted SWRR floor is compiled in unconditionally (the non-removable default
                // hook); activation is the per-pool default, not summarized here.
                plugins.push(PluginView::basic(
                    "weighted".to_string(),
                    "hooks",
                    "compiled-in",
                    None,
                    None,
                ));
                for name in hook_plugins_compiled_in() {
                    plugins.push(PluginView::basic(
                        name.to_string(),
                        "hooks",
                        "compiled-in",
                        None,
                        None,
                    ));
                }
                // External hooks = the configured registry entries (socket/webhook). Configured ⇒
                // active; the transport target is projected (operator config, not a secret).
                let mut externals: Vec<PluginView> = self
                    .app
                    .hook_registry
                    .iter()
                    .map(|(name, cfg)| {
                        let target = Some(cfg.plugin.clone());
                        PluginView::basic(name.clone(), "hooks", "external", Some(true), target)
                    })
                    .collect();
                externals.sort_by(|a, b| a.name.cmp(&b.name));
                plugins.append(&mut externals);
            }
            // `store` (alias `db`) — DYNAMIC-LIBRARY plugins in the plugins directory. Always includes
            // the compiled-in `memory` default; then every loadable library present, each vetted (ABI
            // handshake) and its signed sidecar manifest read + re-evaluated against the running trust
            // posture. The store the operator configured (`store.module`) is `active`.
            "store" | "db" => {
                plugins.append(&mut self.store_plugin_catalog());
            }
            other => {
                return Err(AdminError::Validation(format!(
                    "unknown plugin type `{other}`: expected `auth`, `hooks`, or `store`"
                )));
            }
        }
        Ok(Page::single(plugins))
    }

    /// The DYNAMIC plugin catalog (`GET /api/v1/admin/plugins?type=store`): the compiled-in
    /// `memory` default plus every signed plugin tarball in `plugins.dir`, each with its manifest
    /// metadata and a re-evaluated trust verdict. Sorted by filename after the `memory` head.
    ///
    /// MANIFEST-ONLY INSPECTION (security): this endpoint NEVER `dlopen`s ANY plugin. Each tarball
    /// is unpacked in memory, structurally validated, and trust-evaluated against the RUNNING
    /// policy — pure data checks; no plugin code can run from listing the catalog. Pushing/listing
    /// a plugin over the admin API therefore cannot bypass the trust model: loading only ever
    /// happens through the boot pipeline, which re-runs the same three-phase validation.
    fn store_plugin_catalog(&self) -> Vec<PluginView> {
        // The compiled-in RAM default is always present. Which store backend is ACTIVE is a
        // `store.module` config concern (read via `GET /config`), not summarized per-row here,
        // the same posture the compiled-in hook rows take (`active: None`).
        let mut out = vec![PluginView::basic(
            "memory".to_string(),
            "store",
            "compiled-in",
            None,
            None,
        )];
        let Ok(policy) = self.app.plugins_cfg.to_policy() else {
            return out;
        };
        for row in busbar_plugin_loader::inventory_tarballs(&self.app.plugins_dir, &policy) {
            let trust = if row.status == "ready" {
                if row.signature == "first-party" || row.signature.starts_with("publisher:") {
                    Some("trusted")
                } else {
                    Some("unverified")
                }
            } else if row.manifest.is_some() {
                Some("rejected")
            } else {
                None
            };
            let name = row
                .manifest
                .as_ref()
                .map(|m| m.name.clone())
                .unwrap_or_else(|| row.file.clone());
            out.push(PluginView {
                name,
                r#type: "store",
                loader: "dynamic-library",
                active: None,
                target: Some(row.file.clone()),
                version: row.manifest.as_ref().map(|m| m.version.clone()),
                publisher: row.manifest.as_ref().map(|m| m.publisher.clone()),
                interface_version: row.manifest.as_ref().map(|m| m.abi_version),
                trust,
                valid: Some(row.status == "ready"),
                error: (row.status != "ready").then(|| row.status.clone()),
            });
        }
        out
    }

    /// `POST /api/v1/admin/plugins` — INSTALL a plugin: the caller uploads a SIGNED plugin tarball
    /// (`{cdylib + manifest.json}` as one `.tar.gz`); the engine RE-VERIFIES it server-side against
    /// the running `plugins.*` posture (the client is NEVER trusted — the upload may originate
    /// remotely) and atomically writes the tarball into `plugins.dir`. Full scope, audited. The
    /// change takes effect on the next plugin (re)load (restart / config apply), not as a hot swap.
    ///
    /// Verification order (fail-closed, MANIFEST-ONLY — the uploaded code is NEVER `dlopen`ed by
    /// this endpoint, so pushing a plugin over the API cannot execute it and cannot bypass the
    /// trust model; loading only ever happens through the boot pipeline's same three phases):
    /// 1. Filename sanity — a bare `.tar.gz` filename (no path traversal). Storage only; identity
    ///    comes from the signed manifest.
    /// 2. STRUCTURAL — the tarball unpacks in memory; the manifest parses, is complete and
    ///    well-formed, the sha256 binds the library bytes, the abi_version is supported. `400`.
    /// 3. TRUST — signature vs the embedded first-party key / allowlisted publishers, opt-in flags,
    ///    anti-downgrade floors. An untrusted upload is a `409 conflict` (nothing is written).
    /// 4. CONFLICT — the manifest's name/alias must not collide with a DIFFERENT already-installed
    ///    loadable plugin. `409` naming both.
    /// 5. Atomic publish — write to a temp name in the same directory, then rename into place.
    pub(crate) fn install_store_plugin(
        &self,
        file: &str,
        tarball: &[u8],
    ) -> Result<crate::admin::v1::contract::PluginInstallView, AdminError> {
        use busbar_plugin_sign::{evaluate, validate_structure, Verdict};

        // ── 1. filename sanity: a bare tarball filename ──
        let file = validate_plugin_filename(file)?;

        let policy = self
            .app
            .plugins_cfg
            .to_policy()
            .map_err(AdminError::Validation)?;

        // ── 2. STRUCTURAL: in-memory unpack + manifest completeness + integrity + abi ──
        let unpacked = busbar_plugin_loader::tarball::unpack(tarball)
            .map_err(|e| AdminError::Validation(format!("invalid plugin tarball: {e}")))?;
        validate_structure(
            &unpacked.manifest,
            &unpacked.lib_bytes,
            &busbar_plugin_loader::supported_abi,
        )
        .map_err(|e| AdminError::Validation(format!("invalid plugin manifest: {e}")))?;
        let manifest = &unpacked.manifest;

        // ── 3. TRUST re-verify against the RUNNING posture (server-side) ──
        let (trust, publisher) = match evaluate(&unpacked.lib_bytes, manifest, &policy) {
            Ok(Verdict::Trusted { publisher, .. }) => ("trusted", Some(publisher)),
            Ok(Verdict::Allowed { .. }) => ("unverified", Some(manifest.publisher.clone())),
            // An untrusted upload with no matching opt-in is forbidden - a terminal state conflict
            // (retrying the same bytes can't fix it; sign it, or set the opt-in). The `evaluate`
            // reason already names the exact flag to set and is safe to surface.
            Err(rejected) => {
                return Err(AdminError::Conflict(format!(
                    "plugin rejected by the trust policy: {}",
                    rejected.0
                )));
            }
        };

        // ── 4. CONFLICT vs the already-installed loadable set ──
        // M7 (fail-open): a corrupt tarball already in the plugins dir makes scan_and_validate Err.
        // The old `if let Ok(reg)` SILENTLY SKIPPED the conflict check and published anyway. Propagate
        // it as a Conflict so we never admit a plugin whose conflict status we could not determine.
        let reg = busbar_plugin_loader::scan_and_validate(&self.app.plugins_dir, &policy).map_err(
            |errors| {
                AdminError::Conflict(format!(
                    "cannot validate the installed plugin set before publishing (fix or remove the \
                     offending tarball first): {}",
                    errors.join("; ")
                ))
            },
        )?;
        for existing in reg.loadable() {
            if existing.file == file {
                continue; // overwriting the same tarball file is a legitimate upgrade
            }
            let clash = existing.manifest.name == manifest.name
                || existing.manifest.alias == manifest.alias
                || existing.manifest.name == manifest.alias
                || existing.manifest.alias == manifest.name;
            // H2 (bricks next boot): the old gate exempted a SAME-NAME upload under a DIFFERENT
            // filename (`&& existing.manifest.name != manifest.name`). But boot's phase-3
            // conflicts() hard-rejects two loadable plugins with the same name (different files) -
            // admitting one BRICKS the next restart. Reject it here (409) so we never publish a
            // state boot will refuse: a same-name upgrade must REUSE the existing filename (which
            // hits the `existing.file == file` overwrite path above), not add a second file.
            if clash {
                return Err(AdminError::Conflict(format!(
                    "plugin name/alias conflict: uploaded '{}' (alias '{}', file {}) collides with \
                     installed '{}' (alias '{}', file {}); a same-name upgrade must reuse the \
                     existing filename, not add a second file (boot would reject two files claiming \
                     the same plugin name)",
                    manifest.name,
                    manifest.alias,
                    file,
                    existing.manifest.name,
                    existing.manifest.alias,
                    existing.file
                )));
            }
        }

        // ── 5. atomic publish: write a temp name in the SAME directory, rename into place ──
        let dir = &self.app.plugins_dir;
        std::fs::create_dir_all(dir)
            .map_err(|e| AdminError::Validation(format!("cannot create plugins dir: {e}")))?;
        let stamp = format!("{}-{}", std::process::id(), crate::store::now());
        let tmp = dir.join(format!(".{file}.{stamp}.tmp"));
        std::fs::write(&tmp, tarball).map_err(|e| {
            AdminError::Validation(format!("cannot write plugin to plugins dir: {e}"))
        })?;
        let final_path = dir.join(&file);
        if let Err(e) = std::fs::rename(&tmp, &final_path) {
            let _ = std::fs::remove_file(&tmp);
            return Err(AdminError::Validation(format!(
                "cannot publish plugin into plugins dir: {e}"
            )));
        }

        Ok(crate::admin::v1::contract::PluginInstallView {
            file,
            name: manifest.name.clone(),
            interface_version: manifest.abi_version,
            trust,
            version: Some(manifest.version.clone()),
            publisher,
            note:
                "installed durably in the plugins directory; the change takes effect on the next \
                   plugin (re)load (restart or config apply), not as a hot swap",
        })
    }

    /// `DELETE /api/v1/admin/plugins/{file}` — REMOVE a plugin tarball from the plugins directory.
    /// Full scope. `404 not_found` if the file isn't present. A currently-loaded store keeps
    /// running on its already-loaded handle until the next plugin (re)load — removing the file only
    /// affects the NEXT load (folder = source of truth).
    pub(crate) fn remove_store_plugin(
        &self,
        file: &str,
    ) -> Result<crate::admin::v1::contract::PluginRemoveView, AdminError> {
        let file = validate_plugin_filename(file)?;
        let lib_path = self.app.plugins_dir.join(&file);
        if !lib_path.is_file() {
            return Err(AdminError::NotFound(format!("plugin `{file}`")));
        }
        std::fs::remove_file(&lib_path)
            .map_err(|e| AdminError::Validation(format!("cannot remove plugin: {e}")))?;
        Ok(crate::admin::v1::contract::PluginRemoveView {
            file,
            removed: true,
        })
    }

    /// `POST /api/v1/admin/plugins/reload` — re-scan the plugins directory and report the current
    /// dynamic-library inventory (the SAME projection `GET /plugins?type=store` produces, minus the
    /// compiled-in `memory` head). Full scope. Reconciles the reported set to the folder (folder =
    /// source of truth), the exact sibling of `config/reload`. A store change still applies on the
    /// next store (re)load, not as a hot swap.
    pub(crate) fn reload_store_plugins(
        &self,
    ) -> Result<crate::admin::v1::contract::PluginReloadView, AdminError> {
        // Reuse the store catalog projection, dropping the compiled-in `memory` head (reload reports
        // only the on-disk dynamic set it reconciled).
        let plugins: Vec<PluginView> = self
            .store_plugin_catalog()
            .into_iter()
            .filter(|p| p.loader == "dynamic-library")
            .collect();
        Ok(crate::admin::v1::contract::PluginReloadView {
            plugins,
            note:
                "hot-reloaded the plugin layer LIVE: a new plugin registry and new kind:hook \
                   transports are serving with no restart, and the prior shared libraries unmap once \
                   in-flight requests drain. A `store` MODULE change still lands on a dedicated store \
                   swap (the token ledger cannot be re-hydrated under load), not this reload.",
        })
    }

    /// The RESOLUTION half of an EXPLICIT plugin ROLLBACK (`POST /api/v1/admin/plugins/rollback`,
    /// 1.5.0). Validate that `file` is a plugin tarball in the plugins dir, unpack + STRUCTURALLY
    /// validate its manifest, and TRUST-verify it against a policy whose first-party floor is LOWERED to
    /// the target's OWN version — so a validly-signed but OLDER artifact (exactly the rollback case)
    /// clears trust here even though it would be an anti-downgrade reject on the automatic path. This is
    /// where "automatic vs explicit" is made concrete: the rollback deliberately relaxes the floor to
    /// the pinned target and only that target; a lower artifact still fails, and a signature/opt-in
    /// failure is still fatal (a rollback can never launder an untrusted artifact). Returns the target
    /// manifest identity (name/version/publisher) + the MERGED pin map (prior overlay pins with this
    /// plugin's name set to the target version) the caller persists and re-derives the policy from.
    ///
    /// `prior_pins` is the current persisted `plugin_versions` overlay section (empty if none).
    pub(crate) fn resolve_plugin_rollback(
        &self,
        file: &str,
        prior_pins: &std::collections::BTreeMap<String, String>,
    ) -> Result<
        (
            busbar_plugin_sign::Manifest,
            std::collections::BTreeMap<String, String>,
        ),
        AdminError,
    > {
        use busbar_plugin_sign::{evaluate, validate_structure, Verdict};
        let file = validate_plugin_filename(file)?;
        let lib_path = self.app.plugins_dir.join(&file);
        if !lib_path.is_file() {
            return Err(AdminError::NotFound(format!("plugin `{file}`")));
        }
        let bytes = std::fs::read(&lib_path)
            .map_err(|e| AdminError::Validation(format!("cannot read plugin `{file}`: {e}")))?;
        let unpacked = busbar_plugin_loader::tarball::unpack(&bytes)
            .map_err(|e| AdminError::Validation(format!("invalid plugin tarball `{file}`: {e}")))?;
        validate_structure(
            &unpacked.manifest,
            &unpacked.lib_bytes,
            &busbar_plugin_loader::supported_abi,
        )
        .map_err(|e| AdminError::Validation(format!("invalid plugin manifest `{file}`: {e}")))?;
        let manifest = unpacked.manifest;

        // Build the trust policy with the first-party floor LOWERED to the target artifact's own
        // version — the EXPLICIT relaxation. `min_versions` is carried from base config as-is; we
        // additionally lower THIS plugin's configured floor to the target version so a floored
        // third-party plugin can also roll back. Anything the target does NOT satisfy (a broken
        // signature, an un-opted-in third party) still fails: a rollback authenticates the OPERATOR,
        // never the ARTIFACT.
        let mut policy = self
            .app
            .plugins_cfg
            .to_policy_with_floor(&manifest.version)
            .map_err(AdminError::Validation)?;
        policy
            .min_versions
            .insert(manifest.name.clone(), manifest.version.clone());
        match evaluate(&unpacked.lib_bytes, &manifest, &policy) {
            Ok(Verdict::Trusted { .. }) | Ok(Verdict::Allowed { .. }) => {}
            Err(rejected) => {
                return Err(AdminError::Conflict(format!(
                    "rollback target `{file}` is not loadable under the trust policy even with the \
                     floor lowered to its own version {}: {}. A rollback lowers the anti-downgrade \
                     floor for an explicit operator action; it cannot load an untrusted artifact.",
                    manifest.version, rejected.0
                )));
            }
        }

        // Merge: this plugin's pin becomes the target version; other plugins' prior pins are preserved.
        let mut pins = prior_pins.clone();
        pins.insert(manifest.name.clone(), manifest.version.clone());
        Ok((manifest, pins))
    }

    /// `GET /api/v1/admin/config` — the EFFECTIVE running config, composed from the same redacted reads as
    /// the individual endpoints (auth/pools/models/providers/hooks/global-hooks). Read scope. Carries
    /// no secret. For drift detection + one-shot inspection; the base-vs-overlay source annotation
    /// lands with the overlay substrate.
    pub(crate) async fn get_config(&self) -> Result<EffectiveConfigView, AdminError> {
        Ok(EffectiveConfigView {
            version: self.app.config_version,
            auth: self.get_auth().await?,
            pools: self.list_pools().await?.items,
            models: self.list_models().await?.items,
            providers: self.list_providers().await?.items,
            hooks: self.list_hooks().await?.items,
            global_hooks: self.app.global_hooks.clone(),
        })
    }

    /// `POST /api/v1/admin/config/validate` — DRY-RUN a proposed config: resolve (`config.yaml` deploy +
    /// `providers.yaml` defs) then run the full boot-time `config_validate`, collecting every error at
    /// once, WITHOUT applying anything. Always succeeds as an operation (`Result::Ok`) — the verdict is
    /// in the view's `ok`/`errors`; a valid request describing an invalid config is `ok: false`, not an
    /// error. Read scope (no mutation). Env interpolation is out of scope (structure + resolution only).
    pub(crate) async fn validate_config(
        &self,
        deploy: DeployCfg,
        defs: std::collections::HashMap<String, ProviderDef>,
    ) -> Result<ConfigValidateView, AdminError> {
        // Resolve first (cross-references config.yaml providers against providers.yaml defs); if that
        // fails there is no RootCfg to hand to the semantic validator, so return the resolve errors.
        match crate::config::resolve(&deploy, &defs) {
            Err(errors) => Ok(ConfigValidateView { ok: false, errors }),
            Ok(root) => match crate::config_validate::validate(&root) {
                Ok(()) => Ok(ConfigValidateView {
                    ok: true,
                    errors: Vec::new(),
                }),
                Err(errors) => Ok(ConfigValidateView { ok: false, errors }),
            },
        }
    }

    /// `GET /api/v1/admin/admin-auth` — the ADMIN-plane auth config (distinct from the ingress chain).
    /// Read scope. Reports the live `admin_auth` chain — the SAME resource `PUT /api/v1/admin/admin-auth`
    /// writes, so a read-after-write is coherent (previously this hard-coded `["admin-token"]` and
    /// never reflected a PUT). Never a secret.
    pub(crate) async fn get_admin_auth(&self) -> Result<AdminAuthView, AdminError> {
        let modules = self.app.admin_chain.clone();
        Ok(AdminAuthView {
            // An empty chain is the open (anonymous, full-authority) dev posture — NOT configured.
            configured: !modules.is_empty(),
            modules,
        })
    }

    /// `GET /api/v1/admin/usage` — the fleet METERING read (FinOps surface): the current UTC-day
    /// bucket's raw consumption, aggregated per (model, provider) and per key, each row carrying the
    /// full token SPLIT plus a DERIVED `spend_micros` (computed here at read time from the
    /// operator's configured global prices — raw counts are what's stored, so a consumer with its
    /// own price catalog reconstructs cost from the split instead). `requests` counts DELIVERED
    /// responses (the metering tap), not admissions; budget-enforcement state stays on
    /// `GET /keys/{id}/usage`. Read scope. Empty aggregations when governance is disabled. The
    /// store reads run on a blocking thread; never returns a secret — ids/names only.
    /// `window`: a caller-selected PAST bucket start (validated: bucket-aligned, not in the
    /// future); `None` = the current bucket. The response shape is pinned: always one bucket.
    pub(crate) async fn get_usage(&self, window: Option<u64>) -> Result<UsageView, AdminError> {
        let now = crate::store::now();
        let current = crate::governance::metering_bucket(now);
        let bucket = match window {
            None => current,
            Some(w) => {
                if w % crate::governance::METERING_BUCKET_SECS != 0 {
                    return Err(AdminError::Validation(format!(
                        "window must be a UTC-day bucket start (a multiple of {}); got {w}",
                        crate::governance::METERING_BUCKET_SECS
                    )));
                }
                if w > current {
                    return Err(AdminError::Validation("window is in the future".into()));
                }
                w
            }
        };
        let window = UsageWindow {
            start: bucket,
            end: bucket + crate::governance::METERING_BUCKET_SECS,
        };
        let empty = || UsageView {
            window,
            as_of: now,
            currency: (),
            total: UsageBreakdown::default(),
            by_model: Vec::new(),
            by_key: Vec::new(),
            by_key_truncated: false,
            others: None,
        };
        let Some(gov) = self.app.governance.clone() else {
            return Ok(empty());
        };
        type Fetched = (
            Vec<crate::governance::MeteringRow>,
            std::collections::HashMap<String, String>,
        );
        let joined = tokio::task::spawn_blocking(move || -> Result<Fetched, ()> {
            let rows = gov.metering_for(bucket).map_err(|_| ())?;
            // id → display name, for the by_key rows (a deleted key's history keeps its id).
            let names = gov
                .all_keys()
                .map_err(|_| ())?
                .into_iter()
                .map(|k| (k.id, k.name))
                .collect();
            Ok((rows, names))
        })
        .await;
        let cost = self.app.cost.clone();
        let (rows, names) = match joined {
            Ok(Ok(f)) => f,
            // A store failure or a blocking-join failure is an internal error (details logged
            // upstream in the store layer); the caller never sees store internals.
            Ok(Err(())) | Err(_) => return Err(AdminError::Internal),
        };
        // Aggregate in memory — a bucket is bounded by (keys × models) accumulation rows.
        let mut total = UsageBreakdown::default();
        let mut by_model: std::collections::BTreeMap<(String, String), UsageBreakdown> =
            std::collections::BTreeMap::new();
        let mut by_key: std::collections::BTreeMap<String, UsageBreakdown> =
            std::collections::BTreeMap::new();
        for r in &rows {
            // Spend derives PER ROW (the model is known here - the per-model rate applies), then
            // aggregates ADDITIVELY into total/by_model/by_key, so every rollup is exact under a
            // heterogeneous rate card.
            let row_view = UsageBreakdown {
                tokens_input: r.tokens_input,
                tokens_output: r.tokens_output,
                tokens_cache_read: r.tokens_cache_read,
                tokens_cache_creation: r.tokens_cache_creation,
                requests: r.requests,
                spend_micros: 0,
            };
            let row_spend = derive_spend_micros_row(&cost, &r.model, &row_view);
            for b in [
                &mut total,
                by_model
                    .entry((r.model.clone(), r.provider.clone()))
                    .or_default(),
                by_key.entry(r.key_id.clone()).or_default(),
            ] {
                b.tokens_input = b.tokens_input.saturating_add(r.tokens_input);
                b.tokens_output = b.tokens_output.saturating_add(r.tokens_output);
                b.tokens_cache_read = b.tokens_cache_read.saturating_add(r.tokens_cache_read);
                b.tokens_cache_creation = b
                    .tokens_cache_creation
                    .saturating_add(r.tokens_cache_creation);
                b.requests = b.requests.saturating_add(r.requests);
                b.spend_micros = b.spend_micros.saturating_add(row_spend);
            }
        }
        let by_model = by_model
            .into_iter()
            .map(|((model, provider), usage)| ModelUsageView {
                model,
                provider,
                usage,
            })
            .collect();
        let mut by_key: Vec<KeyUsageView> = by_key
            .into_iter()
            .map(|(id, usage)| KeyUsageView {
                name: names.get(&id).cloned(),
                id,
                usage,
            })
            .collect();
        // Bound the response (no memory/latency cliff at fleet scale — 3rd-party review R2 #1):
        // keep the TOP spenders (the rows a FinOps consumer actually wants first), ordered
        // spend-desc then id for determinism, and SAY when the cap fired.
        const BY_KEY_CAP: usize = 1000;
        by_key.sort_by(|a, b| {
            b.usage
                .spend_micros
                .cmp(&a.usage.spend_micros)
                .then_with(|| a.id.cmp(&b.id))
        });
        let by_key_truncated = by_key.len() > BY_KEY_CAP;
        // FinOps completeness: the tail beyond the cap is summed into an `others` bucket, so
        // total == sum(by_key) + others and every unit stays attributable.
        let others = by_key_truncated.then(|| {
            let mut o = UsageBreakdown::default();
            for row in &by_key[BY_KEY_CAP..] {
                o.tokens_input = o.tokens_input.saturating_add(row.usage.tokens_input);
                o.tokens_output = o.tokens_output.saturating_add(row.usage.tokens_output);
                o.tokens_cache_read = o
                    .tokens_cache_read
                    .saturating_add(row.usage.tokens_cache_read);
                o.tokens_cache_creation = o
                    .tokens_cache_creation
                    .saturating_add(row.usage.tokens_cache_creation);
                o.requests = o.requests.saturating_add(row.usage.requests);
                o.spend_micros = o.spend_micros.saturating_add(row.usage.spend_micros);
            }
            o
        });
        by_key.truncate(BY_KEY_CAP);
        Ok(UsageView {
            window,
            as_of: now,
            currency: (),
            total,
            by_model,
            by_key,
            by_key_truncated,
            others,
        })
    }

    /// `GET /api/v1/admin/auth` — the ingress auth chain + upstream-credential mode. Read scope. Never a
    /// secret: only module names and the mode. This is READ-ONLY at runtime — the ingress chain is
    /// mutated through the config-plane write path (`PUT/POST /api/v1/admin/config`), not a dedicated PUT.
    /// (The ADMIN-plane chain, by contrast, has `PUT /api/v1/admin/admin-auth`.)
    pub(crate) async fn get_auth(&self) -> Result<AuthView, AdminError> {
        Ok(AuthView {
            chain: self.app.auth.chain_names(),
            upstream_credentials: match self.app.upstream_creds() {
                crate::auth::UpstreamCreds::Own => "own",
                crate::auth::UpstreamCreds::Passthrough => "passthrough",
            },
            open: self.app.auth.is_open(),
        })
    }

    /// `GET /api/v1/admin/hooks/{name}/health` — best-effort transport reachability for one hook. Read
    /// scope. `not_found` if the name is unregistered. NEVER fires the hook: for a socket it does a
    /// short-timeout connect probe (`reachable = Some(_)`); for a webhook (or on non-unix) it reports
    /// `reachable = None` with a note (webhooks are probed on demand at request time, not here).
    pub(crate) async fn hook_health(&self, name: &str) -> Result<HookHealthView, AdminError> {
        let cfg = self
            .app
            .hook_registry
            .get(name)
            .ok_or_else(|| AdminError::NotFound(format!("hook `{name}`")))?;
        let view = self.hook_view(name, cfg);
        let (reachable, detail) = probe_transport(cfg, &self.app.hook_env).await;
        Ok(HookHealthView {
            name: name.to_string(),
            transport: view.transport,
            reachable,
            detail,
        })
    }

    /// Project a registry `HookCfg` into the wire `HookView` against the LIVE global wiring.
    fn hook_view(&self, name: &str, cfg: &HookCfg) -> HookView {
        project_hook_view(name, cfg, &self.app.global_hooks)
    }
}

/// Project a `HookCfg` into the ONE wire `HookView` shape, against an explicit global-wiring list —
/// shared by the live reads (`self.app.global_hooks`) AND the version-history read (the SNAPSHOT's
/// own wiring), so a hook has exactly one wire representation everywhere (re-audit M6: the versions
/// endpoint previously serialized the raw `HookCfg` file shape — a second, accidental wire schema).
/// `global` is true when the hook is named in the wiring list OR declares inline `global: true`.
pub(crate) fn project_hook_view(name: &str, cfg: &HookCfg, global_hooks: &[String]) -> HookView {
    {
        // A hook's transport is now the in-process `kind: hook` plugin it references (the retired
        // socket/webhook transports are gone); report the plugin name as the target.
        let (transport_kind, target) = if cfg.plugin.trim().is_empty() {
            ("none", None)
        } else {
            ("plugin", Some(cfg.plugin.clone()))
        };
        HookView {
            name: name.to_string(),
            kind: match cfg.kind {
                HookKind::Tap => "tap",
                HookKind::Gate => "gate",
            },
            transport: HookTransportView {
                kind: transport_kind,
                target,
            },
            prompt: match cfg.prompt {
                PromptAccess::No => "no",
                PromptAccess::Ro => "ro",
                PromptAccess::Rw => "rw",
            },
            user: match cfg.user {
                UserAccess::No => "no",
                UserAccess::Ro => "ro",
            },
            priority: cfg.priority,
            at: cfg.at.map(|s| match s {
                HookStage::Request => "request",
                HookStage::Route => "route",
                HookStage::Attempt => "attempt",
                HookStage::Completion => "completion",
            }),
            on_error: cfg.on_error.clone(),
            timeout_ms: cfg.timeout_ms,
            settings: cfg.settings.clone(),
            global: cfg.global || global_hooks.iter().any(|n| n == name),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{HookCfg, HookKind, PromptAccess, UserAccess};
    use crate::test_support::TestApp;

    fn hook(kind: HookKind, global: bool) -> HookCfg {
        HookCfg {
            kind,
            plugin: "test-hook".to_string(),
            timeout_ms: 5,
            on_error: "weighted".to_string(),
            prompt: PromptAccess::No,
            user: UserAccess::No,
            priority: 0,
            at: None,
            settings: serde_json::Map::new(),
            on_empty: None,
            global,
            default: false,
        }
    }

    /// `build_with_hook` registers a GLOBAL tap into the registry + global wiring AND re-resolves it
    /// into the fired tap transports — so after the caller swaps the returned snapshot, the tap is live.
    /// Lanes/store are shared (unchanged), proving the store-constraint-free subset.
    #[test]
    fn build_with_hook_registers_and_wires_global_tap() {
        let Some(env) = crate::test_support::test_hook_env(&["test-hook"], Default::default())
        else {
            eprintln!("skip: hook cdylib not built (run under --workspace)");
            return;
        };
        let app = TestApp::new().hook_env(env).build();
        assert_eq!(app.tap_hooks.len(), 0, "fixture starts with no taps");
        let next = build_with_hook(&app, "logger", hook(HookKind::Tap, true))
            .expect("a valid global tap registers");
        assert!(next.hook_registry.contains_key("logger"));
        assert!(
            next.global_hooks.iter().any(|n| n == "logger"),
            "global tap wired into global_hooks"
        );
        assert_eq!(
            next.tap_hooks.len(),
            1,
            "the global tap re-resolved into the fired tap transports (live after swap)"
        );
        // Live state is shared, not rebuilt: the store Arc is the SAME instance.
        assert!(
            std::sync::Arc::ptr_eq(&app.store, &next.store),
            "the store (live breaker state) is preserved across the apply, not re-indexed"
        );
    }

    /// REGRESSION (audit c1r8): a PUT that REPLACES a `global: true` hook with `global: false` must
    /// DE-WIRE it from the global fan-out — remove it from `global_hooks` AND drop it from the fired
    /// transports — so the demotion actually takes effect. The prior code only ever APPENDED on
    /// `global: true` and never removed, so a demoted hook kept firing on every request and still
    /// reported `global: true`.
    #[test]
    fn build_with_hook_demotes_global_false_removes_wiring() {
        let Some(env) = crate::test_support::test_hook_env(&["test-hook"], Default::default())
        else {
            eprintln!("skip: hook cdylib not built (run under --workspace)");
            return;
        };
        let app = TestApp::new().hook_env(env).build();
        // Register a GLOBAL tap, then PUT the same name with global: false.
        let promoted = build_with_hook(&app, "logger", hook(HookKind::Tap, true))
            .expect("global tap registers");
        assert!(promoted.global_hooks.iter().any(|n| n == "logger"));
        assert_eq!(promoted.tap_hooks.len(), 1, "global tap is live");

        let demoted = build_with_hook(&promoted, "logger", hook(HookKind::Tap, false))
            .expect("demotion to global: false is a valid same-grant replace");
        assert!(
            !demoted.global_hooks.iter().any(|n| n == "logger"),
            "a global: false PUT must REMOVE the hook from global_hooks, not leave it firing"
        );
        assert_eq!(
            demoted.tap_hooks.len(),
            0,
            "the demoted hook must drop out of the fired global tap transports"
        );
        assert!(
            demoted.hook_registry.contains_key("logger"),
            "the hook definition itself survives — only its global membership is dropped"
        );
    }

    /// REGRESSION (audit c1r12): the `settings` map size cap enforced by PATCH must ALSO gate
    /// register/PUT (both funnel through `build_with_hook`) — else an unbounded map could be
    /// registered/replaced, bloating the durable state and the reconnect path the cap protects.
    #[test]
    fn build_with_hook_caps_oversized_settings() {
        let app = TestApp::new().build();
        // Just over the key cap.
        let mut too_many = hook(HookKind::Tap, false);
        for i in 0..=MAX_SETTINGS_KEYS {
            too_many
                .settings
                .insert(format!("k{i}"), serde_json::json!(1));
        }
        assert!(
            matches!(
                build_with_hook(&app, "big", too_many),
                Err(AdminError::Validation(_))
            ),
            "a settings map over the key cap must reject at register/PUT, not just PATCH"
        );

        // Just over the byte cap (few keys, huge value).
        let mut too_big = hook(HookKind::Tap, false);
        too_big.settings.insert(
            "blob".to_string(),
            serde_json::json!("x".repeat(MAX_SETTINGS_BYTES + 1)),
        );
        assert!(matches!(
            build_with_hook(&app, "big", too_big),
            Err(AdminError::Validation(_))
        ));

        // A modest settings map still registers.
        let mut ok = hook(HookKind::Tap, false);
        ok.settings
            .insert("level".to_string(), serde_json::json!("info"));
        assert!(build_with_hook(&app, "fine", ok).is_ok());
    }

    /// REGRESSION (audit c2r4): the hook NAME (a registry key persisted to the state file + every
    /// audit row) must be length-capped, like the key id / settings map — else a `hooks-register`
    /// token could POST a megabyte-long name and bloat the durable state / audit / reconnect path.
    #[test]
    fn build_with_hook_caps_oversized_name() {
        let app = TestApp::new().build();
        let huge = "n".repeat(MAX_HOOK_NAME_LEN + 1);
        assert!(
            matches!(
                build_with_hook(&app, &huge, hook(HookKind::Tap, false)),
                Err(AdminError::Validation(_))
            ),
            "a name over the cap must reject"
        );
        // A name AT the cap is fine.
        let at_cap = "n".repeat(MAX_HOOK_NAME_LEN);
        assert!(build_with_hook(&app, &at_cap, hook(HookKind::Tap, false)).is_ok());
    }

    /// Validation is fail-closed BEFORE any mutation: `prompt: rw` on a tap and a missing transport
    /// both reject with `invalid_request`.
    #[test]
    fn build_with_hook_rejects_invalid_definitions() {
        let app = TestApp::new().build();
        let mut rw_tap = hook(HookKind::Tap, false);
        rw_tap.prompt = PromptAccess::Rw;
        assert!(matches!(
            build_with_hook(&app, "t", rw_tap),
            Err(AdminError::Validation(_))
        ));

        let mut no_transport = hook(HookKind::Gate, false);
        no_transport.plugin = String::new();
        assert!(matches!(
            build_with_hook(&app, "x", no_transport),
            Err(AdminError::Validation(_))
        ));

        let empty_name = hook(HookKind::Gate, false);
        assert!(matches!(
            build_with_hook(&app, "  ", empty_name),
            Err(AdminError::Validation(_))
        ));
    }

    /// GRANT IMMUTABILITY (§6.4): re-registering an existing hook with DIFFERENT kind/prompt/user is a
    /// `conflict`; re-registering with the SAME grants is allowed (idempotent). Closes the escalation
    /// path (register `prompt: no`, then widen to `rw`).
    #[test]
    fn build_with_hook_enforces_grant_immutability() {
        let app = TestApp::new().build();
        // First registration: a gate with prompt: no.
        let after_first = build_with_hook(&app, "g", hook(HookKind::Gate, false)).unwrap();

        // Re-register the SAME name with a WIDENED grant (prompt: rw) → conflict.
        let mut escalated = hook(HookKind::Gate, false);
        escalated.prompt = PromptAccess::Rw;
        assert!(
            matches!(
                build_with_hook(&after_first, "g", escalated),
                Err(AdminError::Conflict(_))
            ),
            "widening a grant in place must be a conflict"
        );

        // Re-register with the SAME grants → allowed (idempotent).
        assert!(
            build_with_hook(&after_first, "g", hook(HookKind::Gate, false)).is_ok(),
            "re-registering with identical grants is allowed"
        );
    }

    // ── plugin admin surface (#13, tarball world) ───────────────────────────────────────────────

    use busbar_plugin_sign::{sign, Manifest, SigningKey};

    /// A unique temp plugins directory for one test (isolated so parallel tests never collide).
    fn tmp_plugins_dir(tag: &str) -> std::path::PathBuf {
        use std::sync::atomic::{AtomicU64, Ordering};
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        let d = std::env::temp_dir().join(format!(
            "busbar-plugin-admin-{}-{n}-{tag}",
            std::process::id(),
        ));
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    /// A well-formed manifest for tests (sha256/signature completed by `sign`).
    fn test_manifest(name: &str, alias: &str, publisher: &str, version: &str) -> Manifest {
        Manifest {
            name: name.into(),
            alias: alias.into(),
            kind: "store".into(),
            version: version.into(),
            publisher: publisher.into(),
            abi_version: *busbar_plugin_loader::supported_abi("store")
                .iter()
                .max()
                .expect("store abi"),
            sha256: String::new(),
            signature: String::new(),
            description: String::new(),
            homepage: String::new(),
            license: String::new(),
            needs: Default::default(),
        }
    }

    /// Package a signed plugin tarball in memory.
    fn signed_tarball(key: &SigningKey, m: Manifest, lib: &[u8]) -> Vec<u8> {
        let m = sign(key, m, lib);
        busbar_plugin_loader::tarball::package(&m, "lib.so", lib).unwrap()
    }

    /// Build a service over an App whose plugins dir + `plugins.*` posture are the given ones.
    fn svc_with(dir: std::path::PathBuf, cfg: crate::config::PluginsCfg) -> AdminService {
        let app = TestApp::new().plugins_dir(dir).plugins_cfg(cfg).build();
        AdminService::new(app)
    }

    /// The STRICT default posture: no publishers, no opt-ins.
    fn strict_posture() -> crate::config::PluginsCfg {
        crate::config::PluginsCfg::default()
    }

    /// A permissive posture (allow_unsigned): an unsigned upload installs "unverified".
    fn unsigned_ok_posture() -> crate::config::PluginsCfg {
        let mut cfg = crate::config::PluginsCfg::default();
        cfg.trust.allow_unsigned = true;
        cfg
    }

    /// A posture that allowlists one third-party publisher key.
    fn publisher_posture(name: &str, key: &SigningKey) -> crate::config::PluginsCfg {
        let mut cfg = crate::config::PluginsCfg::default();
        cfg.trust.publishers = vec![crate::config::PluginPublisher {
            name: name.into(),
            public_key: hex::encode(key.verifying_key().to_bytes()),
        }];
        cfg
    }

    /// Install rejects a filename that isn't a bare `.tar.gz` name (path traversal / wrong
    /// extension) BEFORE any bytes touch disk.
    #[test]
    fn install_rejects_bad_filenames() {
        let dir = tmp_plugins_dir("badname");
        let svc = svc_with(dir.clone(), unsigned_ok_posture());
        for bad in [
            "../escape.tar.gz",
            "sub/dir.tar.gz",
            "no_extension",
            "plain.so",
            "",
        ] {
            assert!(
                matches!(
                    svc.install_store_plugin(bad, b"bytes"),
                    Err(AdminError::Validation(_))
                ),
                "filename `{bad}` must reject"
            );
        }
        // Nothing was written for any rejected name.
        assert_eq!(std::fs::read_dir(&dir).unwrap().count(), 0);
    }

    /// Install rejects an upload that is not a valid plugin tarball, and leaves NOTHING behind.
    #[test]
    fn install_rejects_invalid_tarball() {
        let dir = tmp_plugins_dir("nontarball");
        let svc = svc_with(dir.clone(), unsigned_ok_posture());
        assert!(
            matches!(
                svc.install_store_plugin("x.tar.gz", b"garbage, not a tarball"),
                Err(AdminError::Validation(_))
            ),
            "non-tarball bytes must fail structural validation"
        );
        assert_eq!(std::fs::read_dir(&dir).unwrap().count(), 0);
    }

    /// A VALIDLY-SIGNED but structurally malformed manifest (bad `kind`) is a 400 — structural
    /// validation is independent of trust.
    #[test]
    fn install_rejects_signed_but_malformed_manifest() {
        let dir = tmp_plugins_dir("malformed");
        let key = SigningKey::from_bytes(&[5u8; 32]);
        let mut m = test_manifest("acme-store-x", "x", "acme", "1.0.0");
        m.kind = "widget".into();
        let tarball = signed_tarball(&key, m, b"lib bytes");
        let svc = svc_with(dir.clone(), publisher_posture("acme", &key));
        let err = svc.install_store_plugin("x.tar.gz", &tarball).unwrap_err();
        assert!(
            matches!(&err, AdminError::Validation(msg) if msg.contains("kind")),
            "got {err:?}"
        );
        assert_eq!(std::fs::read_dir(&dir).unwrap().count(), 0);
    }

    /// Under the STRICT default posture, an UNSIGNED upload is rejected as a conflict naming the
    /// opt-in flag, and nothing is written. The endpoint is MANIFEST-ONLY: the (junk) library
    /// bytes are never executed, so pushing over the API cannot bypass the trust model.
    #[test]
    fn install_strict_posture_rejects_unsigned() {
        let dir = tmp_plugins_dir("strict");
        let lib = b"\x7fELF junk that would crash if ever dlopened";
        let mut m = test_manifest("acme-store-x", "x", "acme", "1.0.0");
        m.sha256 = busbar_plugin_sign::sha256_hex(lib);
        let tarball = busbar_plugin_loader::tarball::package(&m, "lib.so", lib).unwrap();
        let svc = svc_with(dir.clone(), strict_posture());
        let err = svc.install_store_plugin("x.tar.gz", &tarball).unwrap_err();
        assert!(
            matches!(&err, AdminError::Conflict(msg) if msg.contains("allow_third_party")
                || msg.contains("allow_unsigned")),
            "the rejection names the opt-in flag: {err:?}"
        );
        assert_eq!(std::fs::read_dir(&dir).unwrap().count(), 0);
    }

    /// End-to-end install of an unsigned tarball under `allow_unsigned`: installs "unverified",
    /// the catalog reports it, reload reports only the dynamic set, and `remove` deletes it.
    /// (No dlopen anywhere — the lib bytes are junk on purpose.)
    #[test]
    fn install_catalog_remove_roundtrip() {
        let dir = tmp_plugins_dir("roundtrip");
        let svc = svc_with(dir.clone(), unsigned_ok_posture());
        let lib = b"junk lib bytes";
        let mut m = test_manifest("acme-store-junk", "junkstore", "acme", "1.0.0");
        m.sha256 = busbar_plugin_sign::sha256_hex(lib);
        let tarball = busbar_plugin_loader::tarball::package(&m, "lib.so", lib).unwrap();

        let view = svc
            .install_store_plugin("junk.tar.gz", &tarball)
            .expect("an unsigned tarball installs under allow_unsigned");
        assert_eq!(view.trust, "unverified");
        assert_eq!(view.name, "acme-store-junk");
        assert!(dir.join("junk.tar.gz").exists(), "tarball published");

        // Catalog: the memory head + our dynamic plugin.
        let cat = svc.store_plugin_catalog();
        assert_eq!(cat[0].name, "memory");
        let dyn_row = cat
            .iter()
            .find(|p| p.loader == "dynamic-library")
            .expect("dynamic plugin in catalog");
        assert_eq!(dyn_row.valid, Some(true));
        assert_eq!(dyn_row.name, "acme-store-junk");
        assert_eq!(dyn_row.target.as_deref(), Some("junk.tar.gz"));
        assert_eq!(dyn_row.trust, Some("unverified"));

        // Reload reports only the dynamic set (no memory head).
        let reload = svc.reload_store_plugins().unwrap();
        assert!(reload.plugins.iter().all(|p| p.loader == "dynamic-library"));
        assert_eq!(reload.plugins.len(), 1);

        // Remove deletes it; a second remove is a 404.
        svc.remove_store_plugin("junk.tar.gz").expect("remove");
        assert!(!dir.join("junk.tar.gz").exists());
        assert!(matches!(
            svc.remove_store_plugin("junk.tar.gz"),
            Err(AdminError::NotFound(_))
        ));
    }

    /// SECURITY: under the DEFAULT (strict) posture, an unsigned tarball present in the plugins dir
    /// is reported present + `rejected` by the catalog WITHOUT ever being `dlopen`ed — the catalog
    /// path is manifest-only (pure data), so the junk library bytes here can never execute.
    #[test]
    fn catalog_does_not_dlopen_an_untrusted_plugin() {
        let dir = tmp_plugins_dir("untrusted-catalog");
        let svc = svc_with(dir.clone(), strict_posture());
        let lib = b"\x7fELF definitely not a loadable library";
        let mut m = test_manifest("acme-store-evil", "evil", "acme", "1.0.0");
        m.sha256 = busbar_plugin_sign::sha256_hex(lib);
        let tarball = busbar_plugin_loader::tarball::package(&m, "lib.so", lib).unwrap();
        std::fs::write(dir.join("evil.tar.gz"), &tarball).unwrap();

        let cat = svc.store_plugin_catalog();
        let row = cat
            .iter()
            .find(|p| p.target.as_deref() == Some("evil.tar.gz"))
            .expect("the untrusted plugin is listed in the catalog");
        assert_eq!(
            row.trust,
            Some("rejected"),
            "an unsigned plugin under the strict default posture is reported rejected"
        );
        assert_eq!(row.valid, Some(false), "and it is not loadable");
        assert!(
            row.error.as_deref().is_some_and(|e| e.contains("SKIPPED")),
            "the exact skip reason is surfaced: {:?}",
            row.error
        );
    }

    /// A SIGNED upload from an allowlisted third-party publisher installs as `trusted`, and the
    /// catalog reports the signed metadata + trusted verdict.
    #[test]
    fn install_signed_is_trusted() {
        let key = SigningKey::from_bytes(&[7u8; 32]);
        let lib = b"signed lib bytes";
        let tarball = signed_tarball(
            &key,
            test_manifest("acme-store-sqlite", "acmesqlite", "acme", "2.1.0"),
            lib,
        );
        let dir = tmp_plugins_dir("signed");
        let svc = svc_with(dir.clone(), publisher_posture("acme", &key));

        let view = svc
            .install_store_plugin("acme.tar.gz", &tarball)
            .expect("a signed, allowlisted upload installs under the strict posture");
        assert_eq!(view.trust, "trusted");
        assert_eq!(view.publisher.as_deref(), Some("acme"));
        assert_eq!(view.version.as_deref(), Some("2.1.0"));
        assert_eq!(view.name, "acme-store-sqlite");

        let cat = svc.store_plugin_catalog();
        let row = cat
            .iter()
            .find(|p| p.loader == "dynamic-library")
            .expect("dynamic plugin");
        assert_eq!(row.trust, Some("trusted"));
        assert_eq!(row.publisher.as_deref(), Some("acme"));
        assert_eq!(row.version.as_deref(), Some("2.1.0"));
        assert_eq!(row.name, "acme-store-sqlite");
    }

    /// ANTI-DOWNGRADE at the ADMIN INSTALL boundary: a `plugins.min_versions` floor rejects a
    /// VALIDLY-SIGNED but older release of the same plugin (keyed on the manifest NAME) — a
    /// rollback/replay is a `409`, nothing is written. The release at/above the floor installs.
    #[test]
    fn install_downgraded_version_is_rejected_by_floor() {
        let key = SigningKey::from_bytes(&[7u8; 32]);
        let lib = b"lib bytes";
        let mut cfg = publisher_posture("acme", &key);
        cfg.min_versions
            .insert("acme-store-sqlite".to_string(), "2.0.0".to_string());
        let dir = tmp_plugins_dir("downgrade");
        let svc = svc_with(dir.clone(), cfg);

        // A validly-signed 1.9.0 is below the 2.0.0 floor -> rejected, nothing published.
        let old = signed_tarball(
            &key,
            test_manifest("acme-store-sqlite", "acmesqlite", "acme", "1.9.0"),
            lib,
        );
        let err = svc.install_store_plugin("old.tar.gz", &old).unwrap_err();
        assert!(
            matches!(&err, AdminError::Conflict(msg) if msg.contains("anti-downgrade")),
            "got {err:?}"
        );
        assert!(!dir.join("old.tar.gz").exists());

        // The current 2.1.0 clears the floor and installs as trusted.
        let cur = signed_tarball(
            &key,
            test_manifest("acme-store-sqlite", "acmesqlite", "acme", "2.1.0"),
            lib,
        );
        let view = svc
            .install_store_plugin("cur.tar.gz", &cur)
            .expect("a signed release at/above the floor installs");
        assert_eq!(view.trust, "trusted");
        assert_eq!(view.version.as_deref(), Some("2.1.0"));
    }

    /// A signed upload whose publisher is NOT allowlisted is untrusted; under the strict default it
    /// is a conflict (rejected), and nothing is written.
    #[test]
    fn install_unknown_publisher_rejected() {
        let key = SigningKey::from_bytes(&[3u8; 32]);
        let tarball = signed_tarball(
            &key,
            test_manifest("stranger-store-x", "strangerx", "stranger", "1.0.0"),
            b"lib",
        );
        let dir = tmp_plugins_dir("unknownpub");
        let svc = svc_with(dir.clone(), strict_posture());
        assert!(matches!(
            svc.install_store_plugin("x.tar.gz", &tarball),
            Err(AdminError::Conflict(_))
        ));
        assert_eq!(std::fs::read_dir(&dir).unwrap().count(), 0);
    }

    /// CONFLICT at the ADMIN INSTALL boundary: an upload whose alias collides with a DIFFERENT
    /// already-installed loadable plugin is a `409` naming both ("can't use redis and a
    /// third-party redis"); overwriting the SAME plugin (same name, same file) is a legal upgrade.
    #[test]
    fn install_alias_conflict_is_rejected() {
        let key = SigningKey::from_bytes(&[9u8; 32]);
        let dir = tmp_plugins_dir("conflict");
        let svc = svc_with(dir.clone(), publisher_posture("acme", &key));

        let first = signed_tarball(
            &key,
            test_manifest("acme-store-redis", "redis", "acme", "1.0.0"),
            b"lib a",
        );
        svc.install_store_plugin("first.tar.gz", &first)
            .expect("first install");

        // A DIFFERENT plugin claiming the same alias -> conflict naming both.
        let clash = signed_tarball(
            &key,
            test_manifest("other-store-redis", "redis", "acme", "1.0.0"),
            b"lib b",
        );
        let err = svc
            .install_store_plugin("clash.tar.gz", &clash)
            .unwrap_err();
        assert!(
            matches!(&err, AdminError::Conflict(msg)
                if msg.contains("acme-store-redis") && msg.contains("other-store-redis")),
            "names both plugins: {err:?}"
        );
        assert!(!dir.join("clash.tar.gz").exists());

        // Upgrading the SAME plugin in place (same name, same file) is allowed.
        let upgrade = signed_tarball(
            &key,
            test_manifest("acme-store-redis", "redis", "acme", "1.1.0"),
            b"lib a v2",
        );
        svc.install_store_plugin("first.tar.gz", &upgrade)
            .expect("same-name overwrite is a legal upgrade");
    }

    // ---- groups read surface (Phase 1, task #100) ----

    use crate::config::groups::{ChildDefault, LimitMetric, LimitWindow};
    use crate::config::{GroupCfg, LimitCfg};

    fn budget(cents: u64, per: LimitWindow) -> LimitCfg {
        LimitCfg {
            metric: LimitMetric::Budget,
            amount: cents,
            per: Some(per),
            pool: None,
            on_exhaust: None,
            downgrade_to: None,
        }
    }

    /// `list_groups` projects every `groups:` entry (name-sorted by the BTreeMap), faithfully
    /// carrying parent, enabled, the ordered limits, and the `child_default` budget template.
    #[tokio::test]
    async fn list_groups_projects_the_limit_tree() {
        let team = GroupCfg {
            limits: vec![budget(20_000, LimitWindow::Month)],
            child_default: Some(ChildDefault {
                limits: vec![budget(2_000, LimitWindow::Month)],
            }),
            ..Default::default()
        };
        let bob = GroupCfg {
            parent: Some("team".into()),
            limits: vec![budget(3_000, LimitWindow::Month)],
            ..Default::default()
        };
        let app = TestApp::new()
            .group("team", team)
            .group("user:bob", bob)
            .build();
        let svc = AdminService::new(app);

        let page = svc.list_groups().await.expect("list ok");
        // BTreeMap order: "team" < "user:bob".
        assert_eq!(page.items.len(), 2);
        let team = &page.items[0];
        assert_eq!(team.name, "team");
        assert_eq!(team.parent, None);
        assert!(team.enabled);
        assert_eq!(team.limits.len(), 1);
        assert_eq!(team.limits[0].metric, "budget");
        assert_eq!(team.limits[0].amount, 20_000);
        assert_eq!(team.limits[0].per, Some("month"));
        // The child_default template projects as an explicit limit list.
        let cd = team.child_default.as_ref().expect("child_default present");
        assert_eq!(cd.len(), 1);
        assert_eq!(cd[0].amount, 2_000);

        let bob = &page.items[1];
        assert_eq!(bob.name, "user:bob");
        assert_eq!(bob.parent.as_deref(), Some("team"));
        assert!(bob.child_default.is_none());
    }

    /// `get_group` returns one entry by name; an unknown name is `not_found`.
    #[tokio::test]
    async fn get_group_by_name_and_not_found() {
        let app = TestApp::new()
            .group(
                "acme",
                GroupCfg {
                    limits: vec![budget(5_000_000, LimitWindow::Month)],
                    ..Default::default()
                },
            )
            .build();
        let svc = AdminService::new(app);

        let g = svc.get_group("acme").await.expect("found");
        assert_eq!(g.name, "acme");
        assert_eq!(g.limits[0].amount, 5_000_000);

        let err = svc.get_group("ghost").await.unwrap_err();
        assert!(
            matches!(&err, AdminError::NotFound(msg) if msg.contains("ghost")),
            "unknown group is not_found: {err:?}"
        );
    }

    /// A team ceiling with a per-user leaf beneath it — the base tree the mutation tests build on.
    fn team_app() -> Arc<App> {
        TestApp::new()
            .group(
                "team",
                GroupCfg {
                    limits: vec![budget(20_000, LimitWindow::Month)],
                    ..Default::default()
                },
            )
            .build()
    }

    /// `build_with_group` creates a valid leaf, bumps the version, and rebuilds the cost model so the
    /// new group's limits are live in the enforcement projection (the "raise a user's budget" path).
    #[test]
    fn build_with_group_creates_leaf_and_rebuilds_cost() {
        let app = team_app();
        let bob = GroupCfg {
            parent: Some("team".into()),
            limits: vec![budget(3_000, LimitWindow::Month)],
            ..Default::default()
        };
        let next = build_with_group(&app, "user:bob", bob).expect("valid leaf");
        assert_eq!(next.config_version, app.config_version.wrapping_add(1));
        assert!(next.groups_registry.contains_key("user:bob"));
        // The rebuilt cost model sees the new leaf AND its parent chain (parent index resolved).
        let leaf = next
            .cost
            .group_named("user:bob")
            .expect("leaf in cost model");
        assert!(leaf.parent.is_some(), "leaf's parent chain resolved");
        // The parent's own ceiling is still present (cost rebuilt the WHOLE tree, not just the leaf).
        assert!(next.cost.group_named("team").is_some());
    }

    /// A group whose `parent` names a nonexistent group is rejected at the door (validate_groups),
    /// changing nothing — a 400 `invalid_request`.
    #[test]
    fn build_with_group_rejects_dangling_parent() {
        let app = team_app();
        let orphan = GroupCfg {
            parent: Some("nonexistent".into()),
            ..Default::default()
        };
        let Err(err) = build_with_group(&app, "orphan", orphan) else {
            panic!("dangling parent must be rejected");
        };
        assert!(
            matches!(&err, AdminError::Validation(m) if m.contains("orphan")),
            "dangling parent is a validation error: {err:?}"
        );
    }

    #[test]
    fn build_with_group_rejects_empty_name() {
        let app = team_app();
        let Err(err) = build_with_group(&app, "   ", GroupCfg::default()) else {
            panic!("empty name must be rejected");
        };
        assert!(matches!(err, AdminError::Validation(_)));
    }

    /// Deleting a leaf removes it from the registry and the rebuilt cost model.
    #[test]
    fn build_without_group_removes_leaf() {
        // Build a tree that already contains the leaf.
        let app = TestApp::new()
            .group(
                "team",
                GroupCfg {
                    limits: vec![budget(20_000, LimitWindow::Month)],
                    ..Default::default()
                },
            )
            .group(
                "user:bob",
                GroupCfg {
                    parent: Some("team".into()),
                    limits: vec![budget(3_000, LimitWindow::Month)],
                    ..Default::default()
                },
            )
            .build();
        let next = build_without_group(&app, "user:bob").expect("leaf removable");
        assert!(!next.groups_registry.contains_key("user:bob"));
        assert!(next.cost.group_named("user:bob").is_none());
        assert!(next.cost.group_named("team").is_some());
    }

    /// Deleting a group that still PARENTS another is a 409 conflict — never silently orphan the child.
    #[test]
    fn build_without_group_conflict_when_still_a_parent() {
        let app = TestApp::new()
            .group(
                "team",
                GroupCfg {
                    limits: vec![budget(20_000, LimitWindow::Month)],
                    ..Default::default()
                },
            )
            .group(
                "user:bob",
                GroupCfg {
                    parent: Some("team".into()),
                    ..Default::default()
                },
            )
            .build();
        let Err(err) = build_without_group(&app, "team") else {
            panic!("deleting a still-referenced parent must conflict");
        };
        assert!(
            matches!(&err, AdminError::Conflict(m) if m.contains("team")),
            "deleting a still-referenced parent is a conflict: {err:?}"
        );
    }

    #[test]
    fn build_without_group_not_found() {
        let app = team_app();
        let Err(err) = build_without_group(&app, "ghost") else {
            panic!("unknown group must be not_found");
        };
        assert!(matches!(&err, AdminError::NotFound(m) if m.contains("ghost")));
    }

    // ---- group usage read (§6d, `GET /groups/{name}/usage`) ----

    use crate::governance::{GovState, MemoryStore, TierTokens, VirtualKey};

    /// The §6d fixture group: a group-wide requests cap (day), a group-wide budget (month), and a
    /// POOL-SCOPED budget on `frontier` (month) — three distinct `(window, pool?)` enforcement
    /// buckets from three limits.
    fn usage_group_cfg() -> GroupCfg {
        let limit = |metric, amount, per, pool: Option<&str>| LimitCfg {
            metric,
            amount,
            per: Some(per),
            pool: pool.map(String::from),
            on_exhaust: None,
            downgrade_to: None,
        };
        GroupCfg {
            limits: vec![
                limit(LimitMetric::Requests, 5, LimitWindow::Day, None),
                limit(LimitMetric::Budget, 1_000, LimitWindow::Month, None),
                limit(
                    LimitMetric::Budget,
                    500,
                    LimitWindow::Month,
                    Some("frontier"),
                ),
            ],
            ..Default::default()
        }
    }

    /// A cost model carrying `groups` and a rate card pricing model `m` at 10 micro-units per
    /// token (in and out) — 1 cent per 1_000 tokens, so the derived-spend assertions are round.
    fn usage_cost(groups: &std::collections::BTreeMap<String, GroupCfg>) -> crate::cost::CostModel {
        let card = std::collections::BTreeMap::from([(
            "m".to_string(),
            crate::config::RateEntryCfg {
                input_utok: 10.0,
                output_utok: 10.0,
                cache_read_utok: 0.0,
                cache_write_utok: 0.0,
            },
        )]);
        crate::cost::CostModel::resolve_parts(Some(&card), 0, groups)
    }

    fn usage_key(group: &str) -> VirtualKey {
        VirtualKey {
            id: "vk_usage_probe".to_string(),
            key_hash: "h:vk_usage_probe".to_string(),
            name: "usage-probe".to_string(),
            allowed_pools: None,
            enabled: true,
            created_at: 0,
            group: Some(group.to_string()),
            labels: Default::default(),
        }
    }

    fn input_toks(n: u64) -> TierTokens {
        TierTokens {
            input: n,
            output: 0,
            cache_read: 0,
            cache_write: 0,
        }
    }

    /// §6d: `get_group_usage` returns ONE row per `(window, pool?)` enforcement bucket. Usage is
    /// driven through the REAL admission/accrual seam (`try_admit` + `record_usage`, the same path
    /// the proxy charges), so the read proves: the pool-scoped bucket accounts ONLY its pool's
    /// traffic, the group-wide buckets account everything, caps are projected from the limits, and
    /// `budget_remaining_cents = cap − derived spend` (ledger × the current rate card).
    #[tokio::test]
    async fn get_group_usage_splits_window_pool_buckets_and_derives_remaining() {
        let groups = std::collections::BTreeMap::from([("acme".to_string(), usage_group_cfg())]);
        let gov = Arc::new(GovState::new(Arc::new(MemoryStore::new()), None).unwrap());
        let app = TestApp::new()
            .group("acme", usage_group_cfg())
            .cost(usage_cost(&groups))
            .governance(gov.clone())
            .build();

        // One request through `frontier` (100k tokens = 100 cents), one through `value` (50k =
        // 50 cents). The frontier bucket must see only the first; the group-wide buckets both.
        let k = usage_key("acme");
        let now = crate::store::now();
        gov.try_admit(&app.cost, &k, "frontier", now)
            .expect("frontier request admits");
        gov.record_usage(&app.cost, &k, "frontier", "m", &input_toks(100_000), now);
        gov.try_admit(&app.cost, &k, "value", now)
            .expect("value request admits");
        gov.record_usage(&app.cost, &k, "value", "m", &input_toks(50_000), now);

        let svc = AdminService::new(app);
        let view = svc.get_group_usage("acme").await.expect("usage read");
        assert_eq!(view.group, "acme");
        assert!(view.enabled);
        assert!(view.as_of >= now, "as_of is the read instant");
        assert_eq!(
            view.buckets.len(),
            3,
            "three (window, pool?) buckets: {:?}",
            view.buckets
        );
        let find = |window: &str, pool: Option<&str>| {
            view.buckets
                .iter()
                .find(|b| b.window == window && b.pool.as_deref() == pool)
                .unwrap_or_else(|| {
                    panic!("bucket ({window}, {pool:?}) missing: {:?}", view.buckets)
                })
        };

        // (day, group-wide) — the requests cap's bucket: both admissions land; no budget cap ⇒
        // no remaining (never a fabricated 0).
        let day = find("day", None);
        assert_eq!(day.requests, 2);
        assert_eq!(day.tokens, 150_000);
        assert_eq!(day.requests_cap, Some(5));
        assert_eq!(day.budget_cap, None);
        assert_eq!(day.budget_remaining_cents, None);

        // (month, group-wide) — EVERY pool's traffic accounts here.
        let month = find("month", None);
        assert_eq!(month.requests, 2);
        assert_eq!(month.tokens, 150_000);
        assert_eq!(month.spend_cents, 150, "150k tokens at 1c/1k tokens");
        assert_eq!(month.budget_cap, Some(1_000));
        assert_eq!(month.budget_remaining_cents, Some(850));

        // (month, frontier) — ONLY the frontier-dispatched request accounts here.
        let frontier = find("month", Some("frontier"));
        assert_eq!(frontier.requests, 1);
        assert_eq!(frontier.tokens, 100_000);
        assert_eq!(frontier.spend_cents, 100);
        assert_eq!(frontier.budget_cap, Some(500));
        assert_eq!(frontier.budget_remaining_cents, Some(400));
    }

    /// An unknown group is `not_found` — the usage read resolves against the enforcement
    /// projection (the cost model), the same truth `try_admit` walks.
    #[tokio::test]
    async fn get_group_usage_unknown_group_not_found() {
        let groups = std::collections::BTreeMap::from([("acme".to_string(), usage_group_cfg())]);
        let app = TestApp::new()
            .group("acme", usage_group_cfg())
            .cost(usage_cost(&groups))
            .build();
        let svc = AdminService::new(app);
        let err = svc.get_group_usage("ghost").await.unwrap_err();
        assert!(
            matches!(&err, AdminError::NotFound(m) if m.contains("ghost")),
            "unknown group is not_found: {err:?}"
        );
    }

    /// Governance OFF: the read still serves the full bucket projection — every bucket present
    /// with ZERO usage, caps projected, remaining = the whole cap. The definition exists even
    /// when nothing enforces (the doc contract on `get_group_usage`).
    #[tokio::test]
    async fn get_group_usage_governance_off_zero_usage_caps_projected() {
        let groups = std::collections::BTreeMap::from([("acme".to_string(), usage_group_cfg())]);
        let app = TestApp::new()
            .group("acme", usage_group_cfg())
            .cost(usage_cost(&groups))
            .build(); // no .governance(..)
        let svc = AdminService::new(app);
        let view = svc.get_group_usage("acme").await.expect("usage read");
        assert_eq!(
            view.buckets.len(),
            3,
            "caps still projected: {:?}",
            view.buckets
        );
        for b in &view.buckets {
            assert_eq!(b.requests, 0, "governance off = zero usage ({b:?})");
            assert_eq!(b.tokens, 0);
            assert_eq!(b.spend_cents, 0);
            assert_eq!(
                b.budget_remaining_cents, b.budget_cap,
                "nothing spent ⇒ the whole cap remains ({b:?})"
            );
        }
        // The caps themselves survived the projection.
        assert!(view.buckets.iter().any(|b| b.requests_cap == Some(5)));
        assert!(view
            .buckets
            .iter()
            .any(|b| b.budget_cap == Some(500) && b.pool.as_deref() == Some("frontier")));
    }
}
