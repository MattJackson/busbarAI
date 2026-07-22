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
    HookHealthView, HookTransportView, HookView, InfoView, KeyUsageView, ModelUsageView, ModelView,
    Page, PluginView, PoolDetailView, PoolMemberStatusView, PoolMemberView, PoolView, ProviderView,
    TopologyInfo, UsageBreakdown, UsageView, UsageWindow, USAGE_CURRENCY,
};
use crate::config::{
    DeployCfg, HookCfg, HookKind, HookStage, PromptAccess, ProviderDef, UserAccess,
};

/// Micro-units of the usage currency per cent (1 cent = 10 000 micro-USD). The `spend_micros`
/// derivation unit — integer math, sub-cent precise, no float drift.
const MICROS_PER_CENT: i64 = 10_000;
/// Micro-units per token per (cent-per-1000-tokens): `MICROS_PER_CENT / 1000` — a price of
/// 1¢ per 1k tokens is exactly 10 micro-USD per token, so per-token spend needs no division.
const TOKEN_MICROS_PER_1K_CENT: i64 = MICROS_PER_CENT / 1_000;

/// Derive busbar's spend ESTIMATE (micro-USD) for one aggregation row from the operator's
/// configured global prices: `requests × per-request-fee + billable-tokens × per-token price`.
/// Billable = input + cache-read + cache-creation + output (the same normalized additive-cache
/// convention `record_tokens` bills budgets with). i128 intermediates clamp — never wrap.
fn derive_spend_micros(b: &UsageBreakdown, (per_request_cents, per_1k_cents): (i64, i64)) -> i64 {
    let billable = b
        .tokens_input
        .saturating_add(b.tokens_cache_read)
        .saturating_add(b.tokens_cache_creation)
        .saturating_add(b.tokens_output);
    let request_fee =
        (b.requests as i128) * (per_request_cents.max(0) as i128) * (MICROS_PER_CENT as i128);
    let token_fee =
        (billable as i128) * (per_1k_cents.max(0) as i128) * (TOKEN_MICROS_PER_1K_CENT as i128);
    i64::try_from(request_fee + token_fee).unwrap_or(i64::MAX)
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
/// array element, so this reflects the ACTUAL binary and empties under `--no-default-features`). The
/// single source for both `info`'s build proof and the `plugins?type=auth` catalog.
fn auth_modules_compiled_in() -> Vec<&'static str> {
    [
        #[cfg(feature = "auth-tokens")]
        "tokens",
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

/// Read + parse a plugin's signed sidecar manifest (`<library>.manifest.json`), if present and valid.
/// Best-effort: a missing or malformed manifest yields `None` (an unsigned plugin has no manifest).
/// This is the DISPLAY read — every field is signature-covered (verification is separate, via
/// [`crate::plugin_trust::verify`]), so the console can render "install X by Y from Z" faithfully.
fn read_sidecar_manifest(lib_path: &std::path::Path) -> Option<busbar_plugin_sign::Manifest> {
    let manifest_path = crate::plugin_trust::manifest_path_for(lib_path);
    let raw = std::fs::read(&manifest_path).ok()?;
    serde_json::from_slice(&raw).ok()
}

/// The platform-native dynamic-library extension for this host — the one an uploaded store plugin's
/// filename must carry (`.so`/`.dll`/`.dylib`). Per-OS artifacts, never one universal file.
fn plugin_lib_extension() -> &'static str {
    if cfg!(target_os = "windows") {
        ".dll"
    } else if cfg!(target_os = "macos") {
        ".dylib"
    } else {
        ".so"
    }
}

/// Longest a plugin filename may be — generous headroom over any real library name, guarding the
/// filesystem path we build from admin-supplied input.
const MAX_PLUGIN_FILENAME_LEN: usize = 256;

/// Validate an admin-supplied plugin FILENAME and return it owned. Fail-closed against path traversal
/// (a filename is the LAST path component only — no `/`, `\`, `..`, or absolute/rooted path can reach
/// outside the plugins directory) and enforce the platform-native library extension. This is the one
/// gate every plugin write/delete funnels through, so the plugins directory is the hard boundary.
fn validate_plugin_filename(file: &str) -> Result<String, AdminError> {
    let ext = plugin_lib_extension();
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
    if !file.ends_with(ext) {
        return Err(AdminError::Validation(format!(
            "plugin filename must be a `{ext}` dynamic library for this platform"
        )));
    }
    Ok(file.to_string())
}

/// Best-effort reachability probe for a hook's transport, for the health read. NEVER sends a hook
/// request — it only checks whether the endpoint accepts a connection. A socket gets a short-timeout
/// `connect` (unix only); a webhook is not probed here (returns `None` with a note — webhooks lazy-
/// connect per request, and a blind GET/HEAD could have side effects). Returns `(reachable, detail)`.
async fn probe_transport(cfg: &HookCfg) -> (Option<bool>, Option<String>) {
    match (&cfg.socket, &cfg.webhook) {
        (Some(path), _) => {
            #[cfg(unix)]
            {
                // Cap the probe so an unresponsive socket can never stall the admin read.
                const PROBE_TIMEOUT: std::time::Duration = std::time::Duration::from_millis(250);
                match tokio::time::timeout(PROBE_TIMEOUT, tokio::net::UnixStream::connect(path))
                    .await
                {
                    Ok(Ok(_stream)) => (Some(true), None),
                    Ok(Err(e)) => (Some(false), Some(format!("connect failed: {}", e.kind()))),
                    Err(_) => (Some(false), Some("connect timed out".to_string())),
                }
            }
            #[cfg(not(unix))]
            {
                let _ = path;
                (
                    None,
                    Some("socket transport is unix-only; not probed on this host".to_string()),
                )
            }
        }
        (None, Some(_url)) => (
            None,
            Some("webhook is probed on demand at request time, not here".to_string()),
        ),
        (None, None) => (
            Some(false),
            Some("hook defines no transport (socket or webhook)".to_string()),
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
    // Exactly one transport: socket XOR webhook.
    if cfg.socket.is_none() == cfg.webhook.is_none() {
        return Err(AdminError::Validation(
            "a hook must set exactly one transport: `socket` or `webhook`".into(),
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
        &next.client,
        next.config_version,
    );
    next.tap_hooks = crate::hooks::resolve_tap_hooks(
        &next.hook_registry,
        &next.global_hooks,
        &next.client,
        next.config_version,
        crate::config::HookStage::Request,
    );
    next.tap_hooks_route = crate::hooks::resolve_tap_hooks(
        &next.hook_registry,
        &next.global_hooks,
        &next.client,
        next.config_version,
        crate::config::HookStage::Route,
    );
    next.tap_hooks_attempt = crate::hooks::resolve_tap_hooks(
        &next.hook_registry,
        &next.global_hooks,
        &next.client,
        next.config_version,
        crate::config::HookStage::Attempt,
    );
    next.tap_hooks_completion = crate::hooks::resolve_tap_hooks(
        &next.hook_registry,
        &next.global_hooks,
        &next.client,
        next.config_version,
        crate::config::HookStage::Completion,
    );
    next.global_gates = crate::hooks::resolve_gate_hooks(
        &next.hook_registry,
        &next.global_hooks,
        &next.client,
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
        &next.client,
        next.config_version,
    );
    next.tap_hooks = crate::hooks::resolve_tap_hooks(
        &next.hook_registry,
        &next.global_hooks,
        &next.client,
        next.config_version,
        crate::config::HookStage::Request,
    );
    next.tap_hooks_route = crate::hooks::resolve_tap_hooks(
        &next.hook_registry,
        &next.global_hooks,
        &next.client,
        next.config_version,
        crate::config::HookStage::Route,
    );
    next.tap_hooks_attempt = crate::hooks::resolve_tap_hooks(
        &next.hook_registry,
        &next.global_hooks,
        &next.client,
        next.config_version,
        crate::config::HookStage::Attempt,
    );
    next.tap_hooks_completion = crate::hooks::resolve_tap_hooks(
        &next.hook_registry,
        &next.global_hooks,
        &next.client,
        next.config_version,
        crate::config::HookStage::Completion,
    );
    next.global_gates = crate::hooks::resolve_gate_hooks(
        &next.hook_registry,
        &next.global_hooks,
        &next.client,
        next.config_version,
    );
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
        if cfg.socket.is_none() == cfg.webhook.is_none() {
            return Err(AdminError::Validation(format!(
                "hook `{name}` must set exactly one transport: `socket` or `webhook`"
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
        &next.client,
        next.config_version,
    );
    next.tap_hooks = crate::hooks::resolve_tap_hooks(
        &next.hook_registry,
        &next.global_hooks,
        &next.client,
        next.config_version,
        crate::config::HookStage::Request,
    );
    next.tap_hooks_route = crate::hooks::resolve_tap_hooks(
        &next.hook_registry,
        &next.global_hooks,
        &next.client,
        next.config_version,
        crate::config::HookStage::Route,
    );
    next.tap_hooks_attempt = crate::hooks::resolve_tap_hooks(
        &next.hook_registry,
        &next.global_hooks,
        &next.client,
        next.config_version,
        crate::config::HookStage::Attempt,
    );
    next.tap_hooks_completion = crate::hooks::resolve_tap_hooks(
        &next.hook_registry,
        &next.global_hooks,
        &next.client,
        next.config_version,
        crate::config::HookStage::Completion,
    );
    next.global_gates = crate::hooks::resolve_gate_hooks(
        &next.hook_registry,
        &next.global_hooks,
        &next.client,
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
        // The compiled-in plugin sets reflect the ACTUAL binary (feature-gated). `default auth =
        // tokens` + `default hook = weighted` are the two OEM-default plugins; weighted is the one
        // baked in (non-removable), so it appears as `weighted_floor` below, not in `hook_plugins`.
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

    /// `GET /api/v1/admin/plugins?type=auth|hooks` — the plugin catalog for one TYPE. Read
    /// scope. Lists COMPILED-IN plugins (feature-gated, from the binary — the same source as `info`'s
    /// build proof) and EXTERNAL plugins (registered over socket/webhook). An unknown/absent `type` is
    /// an `invalid_request` (the two types are distinct engine contracts; a caller must pick one).
    pub(crate) async fn list_plugins(&self, ptype: &str) -> Result<Page<PluginView>, AdminError> {
        let mut plugins: Vec<PluginView> = Vec::new();
        match ptype {
            "auth" => {
                // Compiled-in auth modules (feature-gated). Active = present in the auth chain.
                let chain = self.app.auth.chain_names();
                for name in auth_modules_compiled_in() {
                    plugins.push(PluginView::basic(
                        name.to_string(),
                        "auth",
                        "compiled-in",
                        Some(chain.contains(&name)),
                        None,
                    ));
                }
                // External auth modules (runtime-registered) — none until the auth-module registration
                // endpoint lands (#56); the catalog shape is ready for them.
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
                        let target = cfg.socket.clone().or_else(|| cfg.webhook.clone());
                        PluginView::basic(name.clone(), "hooks", "external", Some(true), target)
                    })
                    .collect();
                externals.sort_by(|a, b| a.name.cmp(&b.name));
                plugins.append(&mut externals);
            }
            // `store` (alias `db`) — DYNAMIC-LIBRARY plugins in the plugins directory. Always includes
            // the compiled-in `memory` default; then every loadable library present, each vetted (ABI
            // handshake) and its signed sidecar manifest read + re-evaluated against the running trust
            // posture. The store the operator configured (`governance.store`) is `active`.
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

    /// The DYNAMIC-LIBRARY store catalog (`GET /api/v1/admin/plugins?type=store`): the compiled-in
    /// `memory` default plus every loadable library in `plugins_dir`, each with its ABI-validity and
    /// signed-manifest metadata + re-evaluated trust verdict. Pure read (no library is `open`ed — the
    /// ABI handshake `dlopen`s to inspect but never constructs a store, and the manifest is a sidecar
    /// file). Sorted by filename after the `memory` head.
    fn store_plugin_catalog(&self) -> Vec<PluginView> {
        // The compiled-in RAM default is always present. Which store backend is ACTIVE is a
        // `governance.store` config concern (read via `GET /config`), not summarized per-row here —
        // the same posture the compiled-in hook rows take (`active: None`).
        let mut out = vec![PluginView::basic(
            "memory".to_string(),
            "store",
            "compiled-in",
            None,
            None,
        )];
        let policy = self.app.plugin_trust.to_policy().ok();
        for info in busbar_plugin_loader::inventory(&self.app.plugins_dir) {
            let lib_path = self.app.plugins_dir.join(&info.file);
            // The signed sidecar manifest (`<lib>.manifest.json`) — the displayed metadata (all
            // signature-covered fields, so the "install X by Y" card can't be spoofed).
            let manifest = read_sidecar_manifest(&lib_path);
            // The trust verdict is re-evaluated server-side against the RUNNING posture (never a
            // stored value): `verify` reads the library bytes + sidecar manifest and judges them. A
            // `halt`-posture rejection reports `"rejected"`; a permissive posture reports
            // `"unverified"`; an allowlisted signature reports `"trusted"`. Unresolvable policy ⇒ None.
            let trust = policy
                .as_ref()
                .map(|p| match crate::plugin_trust::verify(&lib_path, p) {
                    Ok(note) if note.starts_with("signed by") => "trusted",
                    Ok(_) => "unverified",
                    Err(_) => "rejected",
                });
            // The plugin NAME is the manifest name when present, else the library filename.
            let name = manifest
                .as_ref()
                .map(|m| m.name.clone())
                .unwrap_or_else(|| info.file.clone());
            out.push(PluginView {
                name,
                r#type: "store",
                loader: "dynamic-library",
                // A dynamic store is "active" when it is the configured backend AND its plugin
                // filename matches — but the catalog can't cheaply map a filename to a store kind, so
                // activation is left unsummarized here (the configured backend shows on the `memory`
                // row or is inferable from `governance.store`); dynamic rows report `None`.
                active: None,
                target: Some(info.file.clone()),
                version: manifest.as_ref().map(|m| m.version.clone()),
                publisher: manifest.as_ref().map(|m| m.publisher.clone()),
                interface_version: manifest.as_ref().map(|m| m.interface_version),
                trust,
                valid: Some(info.valid),
                error: info.error.clone(),
            });
        }
        out
    }

    /// `POST /api/v1/admin/plugins` — INSTALL a dynamic-library store plugin: the caller uploads the
    /// library bytes (and optionally its signed manifest); the engine RE-VERIFIES them server-side
    /// against the running `governance.trust` posture (the client is NEVER trusted — the upload may
    /// originate remotely), validates the store ABI handshake, and atomically writes the library (+
    /// manifest sidecar) into `plugins_dir`. Full scope. The store change takes effect on the next
    /// store (re)load (restart / `governance.store` apply), not as a hot swap.
    ///
    /// Verification order (fail-closed, nothing written until every gate passes):
    /// 1. Filename sanity — a bare, platform-native library filename (no path traversal, right ext).
    /// 2. TRUST — [`crate::plugin_trust`]-style `evaluate` over the uploaded bytes + manifest against
    ///    the running policy. A `halt`-posture rejection is a `409 conflict` (nothing is written).
    /// 3. ABI — `validate_plugin` on a TEMP copy (never `dlopen` a file already in `plugins_dir` mid-
    ///    write): the library must export the store ABI at a version the engine speaks, else `400`.
    /// 4. Atomic publish — write the temp files, then rename into place (library + manifest sidecar).
    pub(crate) fn install_store_plugin(
        &self,
        file: &str,
        library: &[u8],
        manifest_bytes: Option<&[u8]>,
    ) -> Result<crate::admin::v1::contract::PluginInstallView, AdminError> {
        use busbar_plugin_sign::{evaluate, Manifest, Verdict};

        // ── 1. filename sanity: a bare, platform-native library filename ──
        let file = validate_plugin_filename(file)?;

        // Parse the optional manifest up front (a malformed manifest is a client error, not a silent
        // "unsigned"): the operator MEANT to sign it, so surface the parse failure.
        let manifest: Option<Manifest> =
            match manifest_bytes {
                None => None,
                Some(raw) => Some(serde_json::from_slice(raw).map_err(|e| {
                    AdminError::Validation(format!("malformed plugin manifest: {e}"))
                })?),
            };

        // ── 2. TRUST re-verify against the RUNNING posture (server-side; the client is not trusted) ──
        let policy = self
            .app
            .plugin_trust
            .to_policy()
            .map_err(|_| AdminError::Internal)?;
        // The floor keys on the identity the plugin will be LOADED by, i.e. its published filename
        // (`dir.join(&file)`), not the manifest's self-declared name.
        let (trust, publisher, version) = match evaluate(library, manifest.as_ref(), &file, &policy)
        {
            Ok(Verdict::Trusted { publisher }) => (
                "trusted",
                Some(publisher),
                manifest.as_ref().map(|m| m.version.clone()),
            ),
            Ok(Verdict::Allowed { .. }) => (
                "unverified",
                manifest.as_ref().map(|m| m.publisher.clone()),
                manifest.as_ref().map(|m| m.version.clone()),
            ),
            // `halt` posture forbids an untrusted upload — a terminal state conflict (retrying the same
            // bytes can't fix it; sign it, or relax the posture). The reason is safe to surface.
            Err(rejected) => {
                return Err(AdminError::Conflict(format!(
                    "plugin rejected by the trust policy: {}. Sign it with an allowlisted publisher, \
                     or relax governance.trust.on_untrusted.",
                    rejected.0
                )));
            }
        };

        // ── 3. ABI validate on a TEMP copy (never dlopen a file we're mid-writing in plugins_dir) ──
        let dir = &self.app.plugins_dir;
        std::fs::create_dir_all(dir)
            .map_err(|e| AdminError::Validation(format!("cannot create plugins dir: {e}")))?;
        // A unique temp basename in the SAME directory (so the final rename is same-filesystem atomic).
        let stamp = format!("{}-{}", std::process::id(), crate::store::now());
        let tmp_lib = dir.join(format!(".{file}.{stamp}.tmp"));
        std::fs::write(&tmp_lib, library).map_err(|e| {
            AdminError::Validation(format!("cannot write plugin to plugins dir: {e}"))
        })?;
        let interface_version = match busbar_plugin_loader::validate_plugin(&tmp_lib) {
            Ok(v) => v,
            Err(e) => {
                let _ = std::fs::remove_file(&tmp_lib);
                return Err(AdminError::Validation(format!(
                    "uploaded library is not a loadable busbar store plugin: {e}"
                )));
            }
        };

        // ── 4. atomic publish: rename the library into place, then write the manifest sidecar ──
        let lib_path = dir.join(&file);
        if let Err(e) = std::fs::rename(&tmp_lib, &lib_path) {
            let _ = std::fs::remove_file(&tmp_lib);
            return Err(AdminError::Validation(format!(
                "cannot publish plugin into plugins dir: {e}"
            )));
        }
        let manifest_path = crate::plugin_trust::manifest_path_for(&lib_path);
        if let Some(raw) = manifest_bytes {
            if let Err(e) = std::fs::write(&manifest_path, raw) {
                // The library is published but the sidecar failed — roll the library back so the
                // install is all-or-nothing (a library without its manifest would mis-report trust).
                let _ = std::fs::remove_file(&lib_path);
                return Err(AdminError::Validation(format!(
                    "plugin library written but manifest sidecar failed: {e}"
                )));
            }
        } else {
            // An unsigned re-install over a previously-signed one must not inherit the stale manifest.
            let _ = std::fs::remove_file(&manifest_path);
        }

        Ok(crate::admin::v1::contract::PluginInstallView {
            file,
            name: manifest.as_ref().map(|m| m.name.clone()).unwrap_or_else(|| {
                lib_path
                    .file_name()
                    .and_then(|f| f.to_str())
                    .unwrap_or("plugin")
                    .to_string()
            }),
            interface_version,
            trust,
            version,
            publisher,
            note: "installed durably in the plugins directory; a store change takes effect on the next \
                   store (re)load (restart or governance.store apply), not as a hot swap",
        })
    }

    /// `DELETE /api/v1/admin/plugins/{file}` — REMOVE a dynamic-library plugin: delete the library and
    /// its manifest sidecar from the plugins directory. Full scope. `404 not_found` if the file isn't
    /// present. A currently-loaded store keeps running on its already-`dlopen`ed handle until the next
    /// store (re)load — removing the file only affects the NEXT load (folder = source of truth).
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
        // Best-effort: drop the manifest sidecar too (a missing sidecar is fine).
        let _ = std::fs::remove_file(crate::plugin_trust::manifest_path_for(&lib_path));
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
                "re-scanned the plugins directory; a store change takes effect on the next store \
                   (re)load (restart or governance.store apply), not as a hot swap",
        })
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
            currency: USAGE_CURRENCY,
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
            (i64, i64),
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
            Ok((rows, names, gov.prices()))
        })
        .await;
        let (rows, names, prices) = match joined {
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
            }
        }
        total.spend_micros = derive_spend_micros(&total, prices);
        let by_model = by_model
            .into_iter()
            .map(|((model, provider), mut usage)| {
                usage.spend_micros = derive_spend_micros(&usage, prices);
                ModelUsageView {
                    model,
                    provider,
                    usage,
                }
            })
            .collect();
        let mut by_key: Vec<KeyUsageView> = by_key
            .into_iter()
            .map(|(id, mut usage)| {
                usage.spend_micros = derive_spend_micros(&usage, prices);
                KeyUsageView {
                    name: names.get(&id).cloned(),
                    id,
                    usage,
                }
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
            currency: USAGE_CURRENCY,
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
        let (reachable, detail) = probe_transport(cfg).await;
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
        let (transport_kind, target) = match (&cfg.socket, &cfg.webhook) {
            (Some(path), _) => ("socket", Some(path.clone())),
            (None, Some(url)) => ("webhook", Some(url.clone())),
            (None, None) => ("none", None),
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
            socket: None,
            webhook: Some("http://127.0.0.1:9971/".to_string()),
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
        let app = TestApp::new().build();
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
        let app = TestApp::new().build();
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
        no_transport.webhook = None;
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

    // ── plugin admin surface (#13) ───────────────────────────────────────────────────────────────

    use busbar_plugin_sign::{sign, Manifest, OnUntrusted, SigningKey};

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

    /// The store ABI version the engine speaks (for test manifests; `interface_version` is display
    /// metadata — `evaluate` verifies the signature, not this field).
    const TEST_ABI_VERSION: u32 = 1;

    /// The platform-native filename a store plugin must carry for THIS host.
    fn lib_name(stem: &str) -> String {
        format!("{stem}{}", plugin_lib_extension())
    }

    /// Build a service over an App whose plugins dir + trust posture are the given ones.
    fn svc_with(dir: std::path::PathBuf, trust: crate::config::PluginTrustCfg) -> AdminService {
        let app = TestApp::new().plugins_dir(dir).plugin_trust(trust).build();
        AdminService::new(app)
    }

    /// A permissive (`log`) posture with no publishers — an unsigned upload loads "unverified".
    fn log_posture() -> crate::config::PluginTrustCfg {
        crate::config::PluginTrustCfg {
            on_untrusted: OnUntrusted::Log,
            publishers: Vec::new(),
            ..Default::default()
        }
    }

    /// Locate the real sqlite plugin cdylib in the build's target dir (like the loader tests). `None`
    /// if it wasn't built (a `-p busbar`-only run) — the caller skips.
    fn sqlite_plugin_path() -> Option<std::path::PathBuf> {
        let exe = std::env::current_exe().ok()?;
        let profile_dir = exe.parent()?.parent()?;
        let name = busbar_plugin_loader::plugin_library_filename("busbar_store_sqlite_plugin");
        let candidate = profile_dir.join(&name);
        candidate.exists().then_some(candidate)
    }

    /// Install rejects a filename that isn't a bare, platform-native library name (path traversal /
    /// wrong extension) BEFORE any bytes touch disk.
    #[test]
    fn install_rejects_bad_filenames() {
        let dir = tmp_plugins_dir("badname");
        let svc = svc_with(dir.clone(), log_posture());
        let ext = plugin_lib_extension();
        for bad in [
            format!("../escape{ext}"),
            format!("sub/dir{ext}"),
            "no_extension".to_string(),
            format!("..{ext}"),
        ] {
            assert!(
                matches!(
                    svc.install_store_plugin(&bad, b"bytes", None),
                    Err(AdminError::Validation(_))
                ),
                "filename `{bad}` must reject"
            );
        }
        // Nothing was written for any rejected name.
        assert_eq!(std::fs::read_dir(&dir).unwrap().count(), 0);
    }

    /// Install rejects an upload that is not a loadable busbar store plugin (ABI handshake fails), and
    /// leaves NOTHING in the plugins dir (the temp copy is cleaned up).
    #[test]
    fn install_rejects_non_plugin_bytes() {
        let dir = tmp_plugins_dir("nonplugin");
        let svc = svc_with(dir.clone(), log_posture());
        let file = lib_name("libnope");
        assert!(
            matches!(
                svc.install_store_plugin(&file, b"\x7fELF not really a plugin", None),
                Err(AdminError::Validation(_))
            ),
            "non-plugin bytes must fail ABI validation"
        );
        assert!(
            !dir.join(&file).exists(),
            "no library published on ABI failure"
        );
        // No leftover temp files either.
        assert_eq!(std::fs::read_dir(&dir).unwrap().count(), 0);
    }

    /// Under the `halt` posture, an UNSIGNED upload is rejected as a conflict and nothing is written —
    /// even a real, ABI-valid plugin (trust is checked BEFORE the ABI probe writes any temp copy).
    #[test]
    fn install_halt_posture_rejects_unsigned() {
        let dir = tmp_plugins_dir("halt");
        let trust = crate::config::PluginTrustCfg {
            on_untrusted: OnUntrusted::Halt,
            publishers: Vec::new(),
            ..Default::default()
        };
        let svc = svc_with(dir.clone(), trust);
        let file = lib_name("libanything");
        assert!(
            matches!(
                svc.install_store_plugin(&file, b"whatever", None),
                Err(AdminError::Conflict(_))
            ),
            "halt posture rejects an unsigned upload as a conflict"
        );
        assert_eq!(std::fs::read_dir(&dir).unwrap().count(), 0);
    }

    /// End-to-end install of the REAL sqlite plugin cdylib under a `log` posture: it re-verifies
    /// (unverified — unsigned), passes the ABI handshake, and is published into the plugins dir. Then
    /// the catalog reports it and `remove` deletes it.
    #[test]
    fn install_catalog_remove_roundtrip_real_plugin() {
        let Some(src) = sqlite_plugin_path() else {
            eprintln!("skip: sqlite plugin cdylib not built (run under --workspace)");
            return;
        };
        let bytes = std::fs::read(&src).unwrap();
        let dir = tmp_plugins_dir("roundtrip");
        let svc = svc_with(dir.clone(), log_posture());
        let file = busbar_plugin_loader::plugin_library_filename("busbar_store_sqlite_plugin");

        let view = svc
            .install_store_plugin(&file, &bytes, None)
            .expect("install a real, ABI-valid plugin under the log posture");
        assert_eq!(view.trust, "unverified", "unsigned under log = unverified");
        assert_eq!(view.file, file);
        assert!(dir.join(&file).exists(), "library published");

        // Catalog: the memory head + our dynamic plugin, valid, dynamic-library loader.
        let cat = svc.store_plugin_catalog();
        assert_eq!(cat[0].name, "memory");
        let dyn_row = cat
            .iter()
            .find(|p| p.loader == "dynamic-library")
            .expect("dynamic plugin in catalog");
        assert_eq!(dyn_row.valid, Some(true));
        assert_eq!(dyn_row.target.as_deref(), Some(file.as_str()));

        // Reload reports only the dynamic set (no memory head).
        let reload = svc.reload_store_plugins().unwrap();
        assert!(reload.plugins.iter().all(|p| p.loader == "dynamic-library"));
        assert_eq!(reload.plugins.len(), 1);

        // Remove deletes it; a second remove is a 404.
        svc.remove_store_plugin(&file).expect("remove");
        assert!(!dir.join(&file).exists());
        assert!(matches!(
            svc.remove_store_plugin(&file),
            Err(AdminError::NotFound(_))
        ));
    }

    /// A SIGNED upload from an allowlisted publisher installs as `trusted`, and its manifest sidecar
    /// is written so the catalog reports the signed metadata + trusted verdict.
    #[test]
    fn install_signed_is_trusted_and_manifest_persisted() {
        let Some(src) = sqlite_plugin_path() else {
            eprintln!("skip: sqlite plugin cdylib not built (run under --workspace)");
            return;
        };
        let bytes = std::fs::read(&src).unwrap();
        let key = SigningKey::from_bytes(&[7u8; 32]);
        let manifest = sign(
            &key,
            Manifest {
                name: "sqlite-store".into(),
                version: "2.1.0".into(),
                kind: "store".into(),
                author: "Acme".into(),
                homepage: String::new(),
                source_url: String::new(),
                description: String::new(),
                license: String::new(),
                publisher: "acme".into(),
                interface_version: TEST_ABI_VERSION,
                sha256: String::new(),
                signature: String::new(),
            },
            &bytes,
        );
        let trust = crate::config::PluginTrustCfg {
            on_untrusted: OnUntrusted::Halt,
            publishers: vec![crate::config::PluginPublisher {
                name: "acme".into(),
                public_key: hex::encode(key.verifying_key().to_bytes()),
            }],
            ..Default::default()
        };
        let dir = tmp_plugins_dir("signed");
        let svc = svc_with(dir.clone(), trust);
        let file = busbar_plugin_loader::plugin_library_filename("busbar_store_sqlite_plugin");
        let manifest_bytes = serde_json::to_vec(&manifest).unwrap();

        let view = svc
            .install_store_plugin(&file, &bytes, Some(&manifest_bytes))
            .expect("a signed, allowlisted upload installs even under halt");
        assert_eq!(view.trust, "trusted");
        assert_eq!(view.publisher.as_deref(), Some("acme"));
        assert_eq!(view.version.as_deref(), Some("2.1.0"));
        assert_eq!(view.name, "sqlite-store");

        // The manifest sidecar was persisted; the catalog reports trusted + signed metadata.
        let cat = svc.store_plugin_catalog();
        let row = cat
            .iter()
            .find(|p| p.loader == "dynamic-library")
            .expect("dynamic plugin");
        assert_eq!(row.trust, Some("trusted"));
        assert_eq!(row.publisher.as_deref(), Some("acme"));
        assert_eq!(row.version.as_deref(), Some("2.1.0"));
        assert_eq!(row.name, "sqlite-store");
    }

    /// ANTI-DOWNGRADE at the ADMIN INSTALL boundary: a `min_versions` floor in `governance.trust`
    /// rejects a VALIDLY-SIGNED but older release of the same plugin — a rollback/replay is a `409`,
    /// and nothing is written to `plugins_dir`. The current release (>= floor) still installs.
    #[test]
    fn install_downgraded_version_is_rejected_by_floor() {
        let Some(src) = sqlite_plugin_path() else {
            eprintln!("skip: sqlite plugin cdylib not built (run under --workspace)");
            return;
        };
        let bytes = std::fs::read(&src).unwrap();
        let key = SigningKey::from_bytes(&[7u8; 32]);
        let signed = |version: &str| {
            sign(
                &key,
                Manifest {
                    name: "sqlite-store".into(),
                    version: version.into(),
                    kind: "store".into(),
                    author: String::new(),
                    homepage: String::new(),
                    source_url: String::new(),
                    description: String::new(),
                    license: String::new(),
                    publisher: "acme".into(),
                    interface_version: TEST_ABI_VERSION,
                    sha256: String::new(),
                    signature: String::new(),
                },
                &bytes,
            )
        };
        let mut floors = std::collections::BTreeMap::new();
        floors.insert("sqlite-store".to_string(), "2.0.0".to_string());
        let trust = crate::config::PluginTrustCfg {
            on_untrusted: OnUntrusted::Halt,
            publishers: vec![crate::config::PluginPublisher {
                name: "acme".into(),
                public_key: hex::encode(key.verifying_key().to_bytes()),
            }],
            min_versions: floors,
        };
        let dir = tmp_plugins_dir("downgrade");
        let svc = svc_with(dir.clone(), trust);
        let file = busbar_plugin_loader::plugin_library_filename("busbar_store_sqlite_plugin");

        // A validly-signed 1.9.0 is below the 2.0.0 floor -> rejected, nothing published.
        let old_mb = serde_json::to_vec(&signed("1.9.0")).unwrap();
        assert!(
            matches!(
                svc.install_store_plugin(&file, &bytes, Some(&old_mb)),
                Err(AdminError::Conflict(_))
            ),
            "a signed downgrade below the floor must be a conflict"
        );
        assert!(
            !dir.join(&file).exists(),
            "nothing written on a rejected downgrade"
        );

        // The current 2.1.0 clears the floor and installs as trusted.
        let cur_mb = serde_json::to_vec(&signed("2.1.0")).unwrap();
        let view = svc
            .install_store_plugin(&file, &bytes, Some(&cur_mb))
            .expect("a signed release at/above the floor installs");
        assert_eq!(view.trust, "trusted");
        assert_eq!(view.version.as_deref(), Some("2.1.0"));
    }

    /// A signed upload whose publisher is NOT allowlisted is untrusted; under `halt` it is a conflict
    /// (rejected), and nothing is written.
    #[test]
    fn install_unknown_publisher_halts() {
        let key = SigningKey::from_bytes(&[3u8; 32]);
        let bytes = b"\x7fELF plugin-ish".to_vec();
        let manifest = sign(
            &key,
            Manifest {
                name: "x".into(),
                version: "1.0.0".into(),
                kind: "store".into(),
                author: String::new(),
                homepage: String::new(),
                source_url: String::new(),
                description: String::new(),
                license: String::new(),
                publisher: "stranger".into(),
                interface_version: TEST_ABI_VERSION,
                sha256: String::new(),
                signature: String::new(),
            },
            &bytes,
        );
        let dir = tmp_plugins_dir("unknownpub");
        let trust = crate::config::PluginTrustCfg {
            on_untrusted: OnUntrusted::Halt,
            publishers: Vec::new(),
            ..Default::default()
        };
        let svc = svc_with(dir.clone(), trust);
        let file = lib_name("libx");
        let mb = serde_json::to_vec(&manifest).unwrap();
        assert!(matches!(
            svc.install_store_plugin(&file, &bytes, Some(&mb)),
            Err(AdminError::Conflict(_))
        ));
        assert_eq!(std::fs::read_dir(&dir).unwrap().count(), 0);
    }
}
