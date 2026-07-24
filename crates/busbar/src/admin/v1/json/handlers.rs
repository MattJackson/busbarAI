use super::*;

/// `GET /api/v1/admin/info` — version, compiled-in plugin proof, uptime, topology.
pub(crate) async fn info(State(handle): State<Arc<AppHandle>>) -> Response {
    respond(StatusCode::OK, service(&handle).info().await)
}

/// `GET /api/v1/admin/pools` — pool topology read. `?detail=true` inlines each member's LIVE status
/// (same row shape as `GET /pools/{name}`) so a dashboard reads the whole topology-with-health in
/// ONE call instead of an M+1 fan-out (audit #7).
pub(crate) async fn list_pools(
    State(handle): State<Arc<AppHandle>>,
    Query(q): Query<std::collections::HashMap<String, String>>,
) -> Response {
    match q.get("detail").map(String::as_str) {
        Some("true") => {
            return respond(StatusCode::OK, service(&handle).list_pools_detailed().await)
        }
        // Strict: an unrecognized value is a loud 400, never a silently-ignored flag.
        Some(other) if other != "false" => {
            return err_json(&AdminError::Validation(
                "invalid `detail`: expected true|false".into(),
            ))
        }
        _ => {}
    }
    respond(StatusCode::OK, service(&handle).list_pools().await)
}

/// `GET /api/v1/admin/pools/{name}` — live per-member status of one pool (404 if unknown).
pub(crate) async fn get_pool(
    State(handle): State<Arc<AppHandle>>,
    Path(name): Path<String>,
) -> Response {
    respond(StatusCode::OK, service(&handle).get_pool(&name).await)
}

/// `GET /api/v1/admin/models` — model lanes + providers.
pub(crate) async fn list_models(State(handle): State<Arc<AppHandle>>) -> Response {
    respond(StatusCode::OK, service(&handle).list_models().await)
}

/// `GET /api/v1/admin/providers` — distinct providers + lane counts.
pub(crate) async fn list_providers(State(handle): State<Arc<AppHandle>>) -> Response {
    respond(StatusCode::OK, service(&handle).list_providers().await)
}

/// `GET /api/v1/admin/hooks` — the hook registry read (+ config-plane `ETag` for `If-Match` chaining).
pub(crate) async fn list_hooks(State(handle): State<Arc<AppHandle>>) -> Response {
    let version = handle.load().config_version;
    with_config_etag(
        respond(StatusCode::OK, service(&handle).list_hooks().await),
        version,
    )
}

/// `GET /api/v1/admin/hooks/{name}` — one hook definition (404 if unregistered; + config-plane `ETag`).
pub(crate) async fn get_hook(
    State(handle): State<Arc<AppHandle>>,
    Path(name): Path<String>,
) -> Response {
    let version = handle.load().config_version;
    with_config_etag(
        respond(StatusCode::OK, service(&handle).get_hook(&name).await),
        version,
    )
}

/// `GET /api/v1/admin/groups` — the `groups:` limit-tree read (+ config-plane `ETag` for `If-Match`
/// chaining, so a client reads then mutates without a second round-trip).
pub(crate) async fn list_groups(State(handle): State<Arc<AppHandle>>) -> Response {
    let version = handle.load().config_version;
    with_config_etag(
        respond(StatusCode::OK, service(&handle).list_groups().await),
        version,
    )
}

/// `GET /api/v1/admin/groups/{name}` — one group definition (404 if unknown; + config-plane `ETag`).
pub(crate) async fn get_group(
    State(handle): State<Arc<AppHandle>>,
    Path(name): Path<String>,
) -> Response {
    let version = handle.load().config_version;
    with_config_etag(
        respond(StatusCode::OK, service(&handle).get_group(&name).await),
        version,
    )
}

/// `GET /api/v1/admin/groups/{name}/usage` — the group's derived current-window usage per
/// enforcement bucket vs its caps (§6d, the self-service dashboard read; 404 if unknown).
pub(crate) async fn get_group_usage(
    State(handle): State<Arc<AppHandle>>,
    Path(name): Path<String>,
) -> Response {
    respond(
        StatusCode::OK,
        service(&handle).get_group_usage(&name).await,
    )
}

/// `GET /api/v1/admin/hooks/{name}/health` — best-effort transport reachability (404 if unregistered).
pub(crate) async fn hook_health(
    State(handle): State<Arc<AppHandle>>,
    Path(name): Path<String>,
) -> Response {
    respond(StatusCode::OK, service(&handle).hook_health(&name).await)
}

/// `GET /api/v1/admin/plugins?type=auth|hooks` — the plugin catalog for one type. A missing/unknown
/// `type` is an `invalid_request` (the two types are distinct engine contracts).
pub(crate) async fn list_plugins(
    State(handle): State<Arc<AppHandle>>,
    Query(q): Query<std::collections::HashMap<String, String>>,
) -> Response {
    let ptype = q.get("type").map(String::as_str).unwrap_or("");
    respond(StatusCode::OK, service(&handle).list_plugins(ptype).await)
}

/// The `POST /api/v1/admin/plugins` request body: install a SIGNED plugin tarball. The tarball
/// bytes ride as base64 (`tarball_b64`) — a plugin artifact is opaque binary, so base64 keeps it a
/// clean JSON field. The engine RE-VERIFIES the contained signed manifest server-side against the
/// running `plugins.*` trust posture (the client is never trusted). `file` is the bare `.tar.gz`
/// filename to store it under (storage only — identity comes from the signed manifest inside).
#[derive(serde::Deserialize)]
pub(crate) struct InstallPluginReq {
    file: String,
    tarball_b64: String,
}

/// `POST /api/v1/admin/plugins` — INSTALL a signed plugin tarball (Full scope). Decodes the upload,
/// unpacks + structurally validates it IN MEMORY, RE-VERIFIES trust against the running `plugins.*`
/// posture, checks name/alias conflicts, and atomically writes the tarball into the plugins
/// directory. The uploaded code is NEVER executed by this endpoint (manifest-only inspection).
/// `201 Created` with the install result. The change takes effect on the next plugin (re)load,
/// not as a hot swap. Every attempt (success AND failure) is audited.
pub(crate) async fn install_plugin(
    State(handle): State<Arc<AppHandle>>,
    axum::Extension(principal): axum::Extension<crate::auth::AuthPrincipal>,
    body: axum::body::Bytes,
) -> Response {
    use base64::Engine as _;
    let actor = principal.actor_id().to_string();
    let req: InstallPluginReq = match serde_json::from_slice(&body) {
        Ok(r) => r,
        Err(e) => {
            audit::AUDIT.record_by(
                "plugin.install",
                "plugin:?",
                audit::OUTCOME_REJECTED,
                &actor,
            );
            return err_json(&AdminError::Validation(format!(
                "malformed plugin body: {e}"
            )));
        }
    };
    let resource = format!("plugin:{}", req.file);
    let tarball = match base64::engine::general_purpose::STANDARD.decode(req.tarball_b64.as_bytes())
    {
        Ok(b) => b,
        Err(e) => {
            audit::AUDIT.record_by("plugin.install", &resource, audit::OUTCOME_REJECTED, &actor);
            return err_json(&AdminError::Validation(format!(
                "tarball_b64 is not valid base64: {e}"
            )));
        }
    };
    // The install itself is in-memory verification + filesystem I/O — run it off the async
    // runtime's worker so a slow disk / large tarball can't stall the reactor.
    let svc_handle = handle.clone();
    let file = req.file.clone();
    let result = tokio::task::spawn_blocking(move || {
        service(&svc_handle).install_store_plugin(&file, &tarball)
    })
    .await;
    match result {
        Ok(Ok(view)) => {
            audit::AUDIT.record_by("plugin.install", &resource, audit::OUTCOME_APPLIED, &actor);
            ok_json(StatusCode::CREATED, &view)
        }
        Ok(Err(e)) => {
            audit::AUDIT.record_by("plugin.install", &resource, audit::OUTCOME_REJECTED, &actor);
            err_json(&e)
        }
        Err(_) => {
            audit::AUDIT.record_by("plugin.install", &resource, audit::OUTCOME_REJECTED, &actor);
            err_json(&AdminError::Internal)
        }
    }
}

/// `DELETE /api/v1/admin/plugins/{file}` — REMOVE a dynamic-library plugin (Full scope): delete the
/// library + its manifest sidecar from the plugins directory. `404 not_found` if absent. `204 No
/// Content` on success. A currently-loaded store keeps running until the next store (re)load.
pub(crate) async fn remove_plugin(
    State(handle): State<Arc<AppHandle>>,
    axum::Extension(principal): axum::Extension<crate::auth::AuthPrincipal>,
    Path(file): Path<String>,
) -> Response {
    let actor = principal.actor_id().to_string();
    let resource = format!("plugin:{file}");
    match service(&handle).remove_store_plugin(&file) {
        Ok(_) => {
            audit::AUDIT.record_by("plugin.remove", &resource, audit::OUTCOME_APPLIED, &actor);
            StatusCode::NO_CONTENT.into_response()
        }
        Err(e) => {
            audit::AUDIT.record_by("plugin.remove", &resource, audit::OUTCOME_REJECTED, &actor);
            err_json(&e)
        }
    }
}

/// `POST /api/v1/admin/plugins/reload` — re-scan the plugins directory and report the reconciled
/// dynamic-library inventory (Full scope) — the sibling of `config/reload`. Audited.
pub(crate) async fn reload_plugins(
    State(handle): State<Arc<AppHandle>>,
    axum::Extension(principal): axum::Extension<crate::auth::AuthPrincipal>,
) -> Response {
    let actor = principal.actor_id().to_string();
    match service(&handle).reload_store_plugins() {
        Ok(view) => {
            audit::AUDIT.record_by(
                "plugin.reload",
                "plugin:dir",
                audit::OUTCOME_APPLIED,
                &actor,
            );
            ok_json(StatusCode::OK, &view)
        }
        Err(e) => {
            audit::AUDIT.record_by(
                "plugin.reload",
                "plugin:dir",
                audit::OUTCOME_REJECTED,
                &actor,
            );
            err_json(&e)
        }
    }
}

/// `GET /api/v1/admin/auth` — the ingress auth chain + upstream-credential mode (no secrets).
pub(crate) async fn get_auth(State(handle): State<Arc<AppHandle>>) -> Response {
    respond(StatusCode::OK, service(&handle).get_auth().await)
}

/// `GET /api/v1/admin/admin-auth` — the admin-plane auth config (the admin surface guard;
/// + config-plane `ETag` so a `PUT /api/v1/admin/admin-auth` can chain `If-Match` off this read).
pub(crate) async fn get_admin_auth(State(handle): State<Arc<AppHandle>>) -> Response {
    let version = handle.load().config_version;
    with_config_etag(
        respond(StatusCode::OK, service(&handle).get_admin_auth().await),
        version,
    )
}

/// `GET /api/v1/admin/usage` — the fleet METERING read: current UTC-day bucket, raw token split
/// per (model, provider) and per key + derived spend_micros (see the service/contract docs).
/// `?window=<bucket-start-epoch>` selects a PAST UTC-day bucket (default: current). The response
/// is ALWAYS one bucket — the pinned shape (see the contract doc).
pub(crate) async fn get_usage(
    State(handle): State<Arc<AppHandle>>,
    Query(q): Query<std::collections::HashMap<String, String>>,
) -> Response {
    let window = match q.get("window") {
        None => None,
        Some(v) => match v.parse::<u64>() {
            Ok(w) => Some(w),
            Err(_) => {
                return err_json(&AdminError::Validation(
                    "invalid `window`: expected a UTC-day bucket start epoch".into(),
                ))
            }
        },
    };
    respond(StatusCode::OK, service(&handle).get_usage(window).await)
}

/// `GET /api/v1/admin/config` — the effective running config snapshot (redacted; no secrets;
/// + config-plane `ETag` so apply/rollback callers chain `If-Match` off this read).
pub(crate) async fn get_config(State(handle): State<Arc<AppHandle>>) -> Response {
    let version = handle.load().config_version;
    with_config_etag(
        respond(StatusCode::OK, service(&handle).get_config().await),
        version,
    )
}

/// The `POST /api/v1/admin/hooks` request body: the hook name + its definition. Optimistic concurrency
/// rides the `If-Match` header (H3) — never a body field.
#[derive(serde::Deserialize)]
pub(crate) struct RegisterHookReq {
    name: String,
    config: crate::config::HookCfg,
}

/// The `PUT /api/v1/admin/hooks/{name}` body: the replacement definition (the name rides the path;
/// optimistic concurrency rides `If-Match`).
#[derive(serde::Deserialize)]
pub(crate) struct PutHookReq {
    config: crate::config::HookCfg,
}

/// The `POST /api/v1/admin/groups` request body: the group name + its definition (a `GroupCfg`
/// accepted VERBATIM — paste a `groups:` block from config.yaml). Optimistic concurrency rides the
/// `If-Match` header, never a body field.
#[derive(serde::Deserialize)]
pub(crate) struct RegisterGroupReq {
    name: String,
    config: crate::config::GroupCfg,
}

/// The `PUT /api/v1/admin/groups/{name}` body: the replacement definition (name rides the path;
/// optimistic concurrency rides `If-Match`).
#[derive(serde::Deserialize)]
pub(crate) struct PutGroupReq {
    config: crate::config::GroupCfg,
}

/// The `PATCH /api/v1/admin/groups/{name}` body: a PARTIAL update — only the fields present are
/// changed, the rest preserved from the current definition. The ergonomic "raise Alice's budget"
/// (send just `limits`) and "freeze a group" (send `enabled: false`) verb. `limits`/`child_default`
/// REPLACE their whole list when present (a list can't be field-merged). To CLEAR `parent` or
/// `child_default` (make a group a root / drop its template), use `PUT` with the full definition.
/// `deny_unknown_fields` so a typo'd field is a 400, never a silent no-op.
#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct GroupPatchReq {
    #[serde(default)]
    parent: Option<String>,
    #[serde(default)]
    enabled: Option<bool>,
    #[serde(default)]
    limits: Option<Vec<crate::config::LimitCfg>>,
    #[serde(default)]
    child_default: Option<crate::config::groups::ChildDefault>,
}

/// `POST /api/v1/admin/hooks` — register (or replace) a hook at RUNTIME. Validates the definition, builds
/// the next `App` snapshot with the hook wired + transports re-resolved, atomically `swap`s it in, and
/// returns `201` with the registered hook. A `global` hook is LIVE immediately (new requests see it);
/// in-flight requests finish on the old snapshot. Lanes/store are untouched — live breaker state is
/// preserved. This is the first API-driven config mutation.
pub(crate) async fn register_hook(
    State(handle): State<Arc<AppHandle>>,
    axum::Extension(principal): axum::Extension<crate::auth::AuthPrincipal>,
    axum::Extension(scope): axum::Extension<crate::auth::AdminScope>,
    headers: axum::http::HeaderMap,
    body: axum::body::Bytes,
) -> Response {
    let actor = principal.actor_id().to_string();
    let expected = match if_match_version(&headers) {
        Ok(v) => v,
        Err(resp) => return resp,
    };
    let req: RegisterHookReq = match serde_json::from_slice(&body) {
        Ok(r) => r,
        Err(e) => return err_json(&AdminError::Validation(format!("malformed hook body: {e}"))),
    };
    // §6.3: a hooks-register principal may not register a content-seeing / global (wired) hook.
    if let Some(e) = hooks_register_escalation(scope, &req.config) {
        audit::AUDIT.record_by(
            "hook.register",
            &format!("hook:{}", req.name),
            audit::OUTCOME_REJECTED,
            &actor,
        );
        return err_json(&e);
    }
    let _mlock = CONFIG_MUTATION_LOCK.lock().await;
    let current = handle.load();
    let resource = format!("hook:{}", req.name);
    // A base-config-defined hook may NOT be shadowed/redirected via the API — the same guard PUT
    // and PATCH enforce (put_hook / patch_hook_settings). Without it a narrow hooks-register token
    // could POST a same-shape definition over a base hook's name and silently redirect its
    // transport (e.g. point a base `pii-guard` gate at a hostile socket). Edit config.yaml for base
    // hooks. (found: audit c1r5 — register was the one mutation verb missing this check.)
    if current.base_hook_names.contains(&req.name) {
        audit::AUDIT.record_by("hook.register", &resource, audit::OUTCOME_REJECTED, &actor);
        return err_json(&AdminError::Conflict(format!(
            "hook `{}` is defined in the base config file; edit config.yaml (the API cannot \
             silently shadow operator file config)",
            req.name
        )));
    }
    if let Some(e) = stale_if_match(expected, current.config_version) {
        audit::AUDIT.record_by("hook.register", &resource, audit::OUTCOME_REJECTED, &actor);
        return err_json(&e);
    }
    // Upsert status honesty: 201 only when the name is NEW; a same-grant re-register (an idempotent
    // refresh) is a 200 replace — standard upsert semantics, so POST/PUT overlap is explicit.
    let existed = current.hook_registry.contains_key(&req.name);
    match build_with_hook(&current, &req.name, req.config) {
        Ok(next) => {
            let installed = Arc::new(next);
            handle.swap(installed.clone());
            audit::AUDIT.record_by("hook.register", &resource, audit::OUTCOME_APPLIED, &actor);
            // Persist the new hook state to the overlay (best-effort; no-op when persistence disabled).
            // Clear any tombstone for this name — a re-register un-deletes it.
            let cur = handle.load();
            installed.versions.record(
                installed.config_version,
                &actor,
                &format!("hook.register {resource}"),
                &installed.hook_registry,
                &installed.global_hooks,
            );
            crate::config::overlay::persist(
                cur.overlay_path.as_deref(),
                &cur.hook_registry,
                &cur.global_hooks,
                None,
                Some(&req.name),
            );
            // Project the registered hook from the NEW (post-swap) snapshot for the 201 body; the
            // new config-plane ETag rides along so the caller chains its next If-Match without a read.
            with_config_etag(
                respond(
                    if existed {
                        StatusCode::OK
                    } else {
                        StatusCode::CREATED
                    },
                    service(&handle).get_hook(&req.name).await,
                ),
                installed.config_version,
            )
        }
        Err(e) => {
            audit::AUDIT.record_by("hook.register", &resource, audit::OUTCOME_REJECTED, &actor);
            err_json(&e)
        }
    }
}

/// `PUT /api/v1/admin/hooks/{name}` — REPLACE an existing hook definition at runtime (live, atomic
/// swap). `404 not_found` for an unregistered name (PUT replaces; POST creates). `409 conflict`
/// for a BASE-defined hook (operator file config is edited in the file, never silently shadowed
/// via the API) and for a grant change (`kind`/`prompt`/`user` are immutable — §6.4, enforced in
/// `build_with_hook`). Audited + versioned + overlay-persisted like every mutation.
pub(crate) async fn put_hook(
    State(handle): State<Arc<AppHandle>>,
    axum::Extension(principal): axum::Extension<crate::auth::AuthPrincipal>,
    axum::Extension(scope): axum::Extension<crate::auth::AdminScope>,
    Path(name): Path<String>,
    headers: axum::http::HeaderMap,
    body: axum::body::Bytes,
) -> Response {
    let actor = principal.actor_id().to_string();
    let expected = match if_match_version(&headers) {
        Ok(v) => v,
        Err(resp) => return resp,
    };
    let req: PutHookReq = match serde_json::from_slice(&body) {
        Ok(r) => r,
        Err(e) => return err_json(&AdminError::Validation(format!("malformed hook body: {e}"))),
    };
    // §6.3: a hooks-register principal may not replace a hook into a content-seeing / global form.
    if let Some(e) = hooks_register_escalation(scope, &req.config) {
        audit::AUDIT.record_by(
            "hook.replace",
            &format!("hook:{name}"),
            audit::OUTCOME_REJECTED,
            &actor,
        );
        return err_json(&e);
    }
    let _mlock = CONFIG_MUTATION_LOCK.lock().await;
    let current = handle.load();
    let resource = format!("hook:{name}");
    if !current.hook_registry.contains_key(&name) {
        // Audit the 404 like every other reject in this handler (and like DELETE's 404) — otherwise
        // an attacker can probe which hook names exist via the response code with no audit trail.
        audit::AUDIT.record_by("hook.replace", &resource, audit::OUTCOME_REJECTED, &actor);
        return err_json(&AdminError::NotFound(format!("hook `{name}`")));
    }
    if current.base_hook_names.contains(&name) {
        audit::AUDIT.record_by("hook.replace", &resource, audit::OUTCOME_REJECTED, &actor);
        return err_json(&AdminError::Conflict(format!(
            "hook `{name}` is defined in the base config file; edit config.yaml (the API cannot \
             silently shadow operator file config)"
        )));
    }
    if let Some(e) = stale_if_match(expected, current.config_version) {
        audit::AUDIT.record_by("hook.replace", &resource, audit::OUTCOME_REJECTED, &actor);
        return err_json(&e);
    }
    match build_with_hook(&current, &name, req.config) {
        Ok(next) => {
            let installed = Arc::new(next);
            handle.swap(installed.clone());
            audit::AUDIT.record_by("hook.replace", &resource, audit::OUTCOME_APPLIED, &actor);
            let cur = handle.load();
            installed.versions.record(
                installed.config_version,
                &actor,
                &format!("hook.replace {resource}"),
                &installed.hook_registry,
                &installed.global_hooks,
            );
            crate::config::overlay::persist(
                cur.overlay_path.as_deref(),
                &cur.hook_registry,
                &cur.global_hooks,
                None,
                Some(&name),
            );
            with_config_etag(
                respond(StatusCode::OK, service(&handle).get_hook(&name).await),
                installed.config_version,
            )
        }
        Err(e) => {
            audit::AUDIT.record_by("hook.replace", &resource, audit::OUTCOME_REJECTED, &actor);
            err_json(&e)
        }
    }
}

/// `DELETE /api/v1/admin/hooks/{name}` — remove an API-registered hook at RUNTIME (live). Builds the next
/// snapshot without the hook (dropped from the registry + global wiring, transports re-resolved) and
/// swaps it in. `404 not_found` if the hook is unregistered; `409 conflict` if the hook is
/// base-config-defined (base hooks are file-owned and read-only via the API — the same posture as
/// PUT/PATCH; edit config.yaml to remove one). `204 No Content` on success.
pub(crate) async fn delete_hook(
    State(handle): State<Arc<AppHandle>>,
    axum::Extension(principal): axum::Extension<crate::auth::AuthPrincipal>,
    axum::Extension(scope): axum::Extension<crate::auth::AdminScope>,
    Path(name): Path<String>,
    headers: axum::http::HeaderMap,
) -> Response {
    let actor = principal.actor_id().to_string();
    let expected = match if_match_version(&headers) {
        Ok(v) => v,
        Err(resp) => return resp,
    };
    let _mlock = CONFIG_MUTATION_LOCK.lock().await;
    let current = handle.load();
    let resource = format!("hook:{name}");
    // EXISTENCE before the concurrency guard — the same status precedence PUT/PATCH use, so all
    // three verbs answer a stale guard on a nonexistent hook identically (404, not 409).
    if !current.hook_registry.contains_key(&name) {
        audit::AUDIT.record_by("hook.delete", &resource, audit::OUTCOME_REJECTED, &actor);
        return err_json(&AdminError::NotFound(format!("hook `{name}`")));
    }
    // Optimistic concurrency (H3): DELETE honors `If-Match` like every other config-plane mutation
    // (it previously had NO guard — the one mutation verb missing it).
    if let Some(e) = stale_if_match(expected, current.config_version) {
        audit::AUDIT.record_by("hook.delete", &resource, audit::OUTCOME_REJECTED, &actor);
        return err_json(&e);
    }
    // §6.3 escalation guard, keyed on the EXISTING hook's grants — a non-Full (hooks-register)
    // principal may not DELETE a content-seeing (`prompt`/`user`) or `global: true` gate. Such a
    // hook can only have been created by a Full admin (register/put block a narrow token from wiring
    // one), and DELETING it TEARS DOWN that admin's security gate — the same escalation register /
    // put / patch already forbid. Without this a hooks-register token could remove an operator's
    // global `pii-guard` gate and reach content by the back door. (found: audit c1r13; the sibling
    // c1r6 fix closed the PATCH path — DELETE was the remaining verb missing the guard.)
    if let Some(existing) = current.hook_registry.get(&name) {
        if let Some(e) = hooks_register_escalation(scope, existing) {
            audit::AUDIT.record_by("hook.delete", &resource, audit::OUTCOME_REJECTED, &actor);
            return err_json(&e);
        }
    }
    // A base-config hook is read-only via the API (consistent with put_hook / patch_hook_settings).
    // Without this a narrow hooks-register token could DELETE an operator's base-defined security
    // gate (e.g. `pii-guard`) — an escalation beyond "register" — and the additive overlay can't
    // durably subtract a base hook anyway. Edit config.yaml. (found: audit c1r5.)
    if current.base_hook_names.contains(&name) {
        audit::AUDIT.record_by("hook.delete", &resource, audit::OUTCOME_REJECTED, &actor);
        return err_json(&AdminError::Conflict(format!(
            "hook `{name}` is defined in the base config file; edit config.yaml (the API cannot \
             silently shadow operator file config)"
        )));
    }
    match build_without_hook(&current, &name) {
        Ok(next) => {
            let installed = Arc::new(next);
            handle.swap(installed.clone());
            audit::AUDIT.record_by("hook.delete", &resource, audit::OUTCOME_APPLIED, &actor);
            // Tombstone this name so the deletion survives a restart even if the hook was base-defined.
            let cur = handle.load();
            installed.versions.record(
                installed.config_version,
                &actor,
                &format!("hook.delete {resource}"),
                &installed.hook_registry,
                &installed.global_hooks,
            );
            crate::config::overlay::persist(
                cur.overlay_path.as_deref(),
                &cur.hook_registry,
                &cur.global_hooks,
                Some(&name),
                None,
            );
            // 204 still carries the NEW config-plane ETag — a scripted delete chain needs no re-read.
            with_config_etag(
                StatusCode::NO_CONTENT.into_response(),
                installed.config_version,
            )
        }
        Err(e) => {
            audit::AUDIT.record_by("hook.delete", &resource, audit::OUTCOME_REJECTED, &actor);
            err_json(&e)
        }
    }
}

/// Resolve — and if needed AUTO-PROVISION — the group a `POST /keys` mint binds to (self-service
/// D2, §6a). The mint-time group contract, one place, shared by the key handler:
///
///   - group EXISTS, no `parent` given → bind as-is (`provisioned: false`).
///   - group EXISTS, `parent` given → the given parent MUST equal the group's actual parent, else
///     `409 conflict` (a portal must not silently re-home an existing leaf under a different team).
///   - group MISSING, `parent` given → CREATE it as a leaf under `parent`, limits stamped from the
///     nearest-ancestor `child_default` (inherit-only when none), via the SAME `build_with_group`
///     validate-at-the-door path every group write uses (so validation / cost rebuild / version log
///     / overlay persistence / base-shadow guard all hold), then bind (`provisioned: true`).
///   - group MISSING, no `parent` → today's `400` (an unknown group with nowhere to root it).
///
/// Runs the create under `CONFIG_MUTATION_LOCK` (serialized with every other group/config mutation)
/// and re-loads INSIDE the lock, so a concurrent create of the same leaf is a benign no-op (the
/// second caller sees it exists and binds). Audited + versioned + overlay-persisted exactly like an
/// explicit `POST /groups`. `parent` is capped at `MAX_GROUP_NAME_LEN` (a registry key / audit row).
///
/// Returns `Ok(true)` when a leaf was auto-provisioned for this mint, `Ok(false)` when the group
/// already existed (bind as-is).
pub(crate) async fn resolve_mint_group(
    handle: &Arc<AppHandle>,
    group: &str,
    parent: Option<&str>,
    actor: &str,
) -> Result<bool, AdminError> {
    let current = handle.load();
    // Fast path: the group already exists (existence is the ENFORCEMENT truth — `cost.group_named`,
    // the exact check every request admission uses — so a mint never binds a group the chain can't
    // resolve). If a `parent` was named it must match the existing parent (never silently re-home an
    // existing leaf); the parent value comes from the config registry, which agrees with the cost
    // model in production (both rebuilt together on every apply).
    if current.cost.group_named(group).is_some() {
        if let Some(want) = parent {
            let actual = current
                .groups_registry
                .get(group)
                .and_then(|g| g.parent.clone());
            if actual.as_deref() != Some(want) {
                return Err(AdminError::Conflict(format!(
                    "group `{group}` already exists with parent {}; the mint named parent `{want}` \
                     — a mint cannot re-home an existing group (PATCH the group to re-parent it, or \
                     drop `parent` to bind as-is)",
                    actual
                        .map(|p| format!("`{p}`"))
                        .unwrap_or_else(|| "<root>".into()),
                )));
            }
        }
        return Ok(false);
    }
    // The group does NOT exist. Without a `parent` there is nowhere to root it — today's 400 stands
    // (mirrors the pre-auto-provision message, but points at the self-service `parent:` field).
    let Some(parent) = parent else {
        return Err(AdminError::Validation(format!(
            "group '{group}' does not exist in the top-level groups block; either configure it \
             first, or pass `parent: <existing-group>` to auto-provision it as a leaf (e.g. \
             `parent: team-payments` creates {group} under team-payments and binds the key)"
        )));
    };
    if parent.len() > crate::admin::v1::service::MAX_GROUP_NAME_LEN {
        return Err(AdminError::Validation(format!(
            "parent name is {} chars; must be <= {}",
            parent.len(),
            crate::admin::v1::service::MAX_GROUP_NAME_LEN
        )));
    }
    // AUTO-PROVISION under the mutation lock (serialized with /groups + /config writes). Re-load
    // INSIDE the lock so we build against the freshest tree and a concurrent create of the same leaf
    // is caught (benign: bind to it).
    let _mlock = CONFIG_MUTATION_LOCK.lock().await;
    let current = handle.load();
    if current.cost.group_named(group).is_some() {
        // A racing mint created it between our read and the lock. Honor the same parent-match rule.
        let actual = current
            .groups_registry
            .get(group)
            .and_then(|g| g.parent.clone());
        if actual.as_deref() != Some(parent) {
            return Err(AdminError::Conflict(format!(
                "group `{group}` was concurrently created with a different parent than `{parent}`"
            )));
        }
        return Ok(false);
    }
    // The named parent must exist — build_with_group's validate-at-the-door would reject a dangling
    // parent as a 400, but name it precisely here (the mint's parent, not an opaque tree error).
    // Existence via the enforcement truth (cost), matching the group existence check above.
    if current.cost.group_named(parent).is_none() {
        return Err(AdminError::Validation(format!(
            "cannot auto-provision `{group}`: its `parent: {parent}` does not exist in the \
             top-level groups block; name an existing team/org group"
        )));
    }
    // A base-config group name is file-owned — the additive overlay cannot durably shadow it, so a
    // mint must not materialize one at runtime (mirrors POST /groups). Vanishingly unlikely for a
    // `user:<sub>` leaf, but the guard is uniform across every write path.
    if current.base_group_names.contains(group) {
        return Err(AdminError::Conflict(format!(
            "group `{group}` is defined in the base config file; edit config.yaml (the API cannot \
             silently shadow operator file config)"
        )));
    }
    let leaf = crate::config::groups::provision_child(&current.groups_registry, parent);
    let resource = format!("group:{group}");
    match build_with_group(&current, group, leaf) {
        Ok(next) => {
            let installed = Arc::new(next);
            handle.swap(installed.clone());
            audit::AUDIT.record_by("group.provision", &resource, audit::OUTCOME_APPLIED, actor);
            let cur = handle.load();
            record_group_version(
                &installed,
                actor,
                &format!("group.provision {resource} (auto, parent {parent})"),
            );
            crate::config::overlay::persist_groups(
                cur.overlay_path.as_deref(),
                &cur.groups_registry,
                None,
                Some(group),
            );
            Ok(true)
        }
        Err(e) => {
            audit::AUDIT.record_by("group.provision", &resource, audit::OUTCOME_REJECTED, actor);
            Err(e)
        }
    }
}

/// `POST /api/v1/admin/groups` — create (or replace) a group at RUNTIME. Validate-at-the-door: the
/// mutated tree is re-validated (parent exists, acyclic, depth) — an invalid tree is a `400` that
/// changes nothing. `201` when the name is NEW, `200` on replace (upsert). `409` for a base-config
/// group (edit config.yaml; the API cannot silently shadow file config) or a stale `If-Match`.
/// Live immediately (limits rebuilt into the cost model, swapped in); persisted to the overlay so it
/// survives restart. Full scope (the `/groups` mutation fallthrough); the narrow delegated
/// `group-admin` scope for the self-service tool lands in Phase 2.
pub(crate) async fn register_group(
    State(handle): State<Arc<AppHandle>>,
    axum::Extension(principal): axum::Extension<crate::auth::AuthPrincipal>,
    headers: axum::http::HeaderMap,
    body: axum::body::Bytes,
) -> Response {
    let actor = principal.actor_id().to_string();
    let expected = match if_match_version(&headers) {
        Ok(v) => v,
        Err(resp) => return resp,
    };
    let req: RegisterGroupReq = match serde_json::from_slice(&body) {
        Ok(r) => r,
        Err(e) => {
            return err_json(&AdminError::Validation(format!(
                "malformed group body: {e}"
            )))
        }
    };
    let _mlock = CONFIG_MUTATION_LOCK.lock().await;
    let current = handle.load();
    let resource = format!("group:{}", req.name);
    // A base-config group is file-owned: the additive overlay cannot durably shadow it, and a narrow
    // token must not silently redirect a base group's limits. Edit config.yaml. (Mirrors hooks.)
    if current.base_group_names.contains(&req.name) {
        audit::AUDIT.record_by("group.create", &resource, audit::OUTCOME_REJECTED, &actor);
        return err_json(&AdminError::Conflict(format!(
            "group `{}` is defined in the base config file; edit config.yaml (the API cannot \
             silently shadow operator file config)",
            req.name
        )));
    }
    if let Some(e) = stale_if_match(expected, current.config_version) {
        audit::AUDIT.record_by("group.create", &resource, audit::OUTCOME_REJECTED, &actor);
        return err_json(&e);
    }
    let existed = current.groups_registry.contains_key(&req.name);
    match build_with_group(&current, &req.name, req.config) {
        Ok(next) => {
            let installed = Arc::new(next);
            handle.swap(installed.clone());
            audit::AUDIT.record_by("group.create", &resource, audit::OUTCOME_APPLIED, &actor);
            let cur = handle.load();
            record_group_version(&installed, &actor, &format!("group.create {resource}"));
            // Persist the whole groups section; clear any tombstone for this name (re-create un-deletes).
            crate::config::overlay::persist_groups(
                cur.overlay_path.as_deref(),
                &cur.groups_registry,
                None,
                Some(&req.name),
            );
            with_config_etag(
                respond(
                    if existed {
                        StatusCode::OK
                    } else {
                        StatusCode::CREATED
                    },
                    service(&handle).get_group(&req.name).await,
                ),
                installed.config_version,
            )
        }
        Err(e) => {
            audit::AUDIT.record_by("group.create", &resource, audit::OUTCOME_REJECTED, &actor);
            err_json(&e)
        }
    }
}

/// `PUT /api/v1/admin/groups/{name}` — REPLACE an existing group at runtime (live, atomic swap).
/// `404` for an unknown name (PUT replaces; POST creates). `409` for a base-config group or a stale
/// `If-Match`, `400` if the replacement breaks the tree. Audited + versioned + overlay-persisted.
pub(crate) async fn put_group(
    State(handle): State<Arc<AppHandle>>,
    axum::Extension(principal): axum::Extension<crate::auth::AuthPrincipal>,
    Path(name): Path<String>,
    headers: axum::http::HeaderMap,
    body: axum::body::Bytes,
) -> Response {
    let actor = principal.actor_id().to_string();
    let expected = match if_match_version(&headers) {
        Ok(v) => v,
        Err(resp) => return resp,
    };
    let req: PutGroupReq = match serde_json::from_slice(&body) {
        Ok(r) => r,
        Err(e) => {
            return err_json(&AdminError::Validation(format!(
                "malformed group body: {e}"
            )))
        }
    };
    let _mlock = CONFIG_MUTATION_LOCK.lock().await;
    let current = handle.load();
    let resource = format!("group:{name}");
    if !current.groups_registry.contains_key(&name) {
        audit::AUDIT.record_by("group.replace", &resource, audit::OUTCOME_REJECTED, &actor);
        return err_json(&AdminError::NotFound(format!("group `{name}`")));
    }
    if current.base_group_names.contains(&name) {
        audit::AUDIT.record_by("group.replace", &resource, audit::OUTCOME_REJECTED, &actor);
        return err_json(&AdminError::Conflict(format!(
            "group `{name}` is defined in the base config file; edit config.yaml (the API cannot \
             silently shadow operator file config)"
        )));
    }
    if let Some(e) = stale_if_match(expected, current.config_version) {
        audit::AUDIT.record_by("group.replace", &resource, audit::OUTCOME_REJECTED, &actor);
        return err_json(&e);
    }
    match build_with_group(&current, &name, req.config) {
        Ok(next) => {
            let installed = Arc::new(next);
            handle.swap(installed.clone());
            audit::AUDIT.record_by("group.replace", &resource, audit::OUTCOME_APPLIED, &actor);
            let cur = handle.load();
            record_group_version(&installed, &actor, &format!("group.replace {resource}"));
            crate::config::overlay::persist_groups(
                cur.overlay_path.as_deref(),
                &cur.groups_registry,
                None,
                Some(&name),
            );
            with_config_etag(
                respond(StatusCode::OK, service(&handle).get_group(&name).await),
                installed.config_version,
            )
        }
        Err(e) => {
            audit::AUDIT.record_by("group.replace", &resource, audit::OUTCOME_REJECTED, &actor);
            err_json(&e)
        }
    }
}

/// `PATCH /api/v1/admin/groups/{name}` — PARTIAL update: change only the fields present, preserve
/// the rest (the "raise Alice's budget" / "freeze this team" verb). Merges onto the current
/// definition then routes through the SAME `build_with_group` validation + cost rebuild as PUT, so
/// a partial edit that breaks the tree is a `400` that changes nothing. `404`/`409` semantics match
/// PUT (unknown name / base group / stale `If-Match`). Audited + versioned + overlay-persisted.
pub(crate) async fn patch_group(
    State(handle): State<Arc<AppHandle>>,
    axum::Extension(principal): axum::Extension<crate::auth::AuthPrincipal>,
    Path(name): Path<String>,
    headers: axum::http::HeaderMap,
    body: axum::body::Bytes,
) -> Response {
    let actor = principal.actor_id().to_string();
    let expected = match if_match_version(&headers) {
        Ok(v) => v,
        Err(resp) => return resp,
    };
    let req: GroupPatchReq = match serde_json::from_slice(&body) {
        Ok(r) => r,
        Err(e) => {
            return err_json(&AdminError::Validation(format!(
                "malformed group patch: {e}"
            )))
        }
    };
    let _mlock = CONFIG_MUTATION_LOCK.lock().await;
    let current = handle.load();
    let resource = format!("group:{name}");
    let Some(existing) = current.groups_registry.get(&name) else {
        audit::AUDIT.record_by("group.patch", &resource, audit::OUTCOME_REJECTED, &actor);
        return err_json(&AdminError::NotFound(format!("group `{name}`")));
    };
    if current.base_group_names.contains(&name) {
        audit::AUDIT.record_by("group.patch", &resource, audit::OUTCOME_REJECTED, &actor);
        return err_json(&AdminError::Conflict(format!(
            "group `{name}` is defined in the base config file; edit config.yaml (the API cannot \
             silently shadow operator file config)"
        )));
    }
    if let Some(e) = stale_if_match(expected, current.config_version) {
        audit::AUDIT.record_by("group.patch", &resource, audit::OUTCOME_REJECTED, &actor);
        return err_json(&e);
    }
    // Merge the provided fields onto the current definition; absent fields are preserved.
    let merged = merge_group_patch(
        existing.clone(),
        req.parent,
        req.enabled,
        req.limits,
        req.child_default,
    );
    match build_with_group(&current, &name, merged) {
        Ok(next) => {
            let installed = Arc::new(next);
            handle.swap(installed.clone());
            audit::AUDIT.record_by("group.patch", &resource, audit::OUTCOME_APPLIED, &actor);
            let cur = handle.load();
            record_group_version(&installed, &actor, &format!("group.patch {resource}"));
            crate::config::overlay::persist_groups(
                cur.overlay_path.as_deref(),
                &cur.groups_registry,
                None,
                Some(&name),
            );
            with_config_etag(
                respond(StatusCode::OK, service(&handle).get_group(&name).await),
                installed.config_version,
            )
        }
        Err(e) => {
            audit::AUDIT.record_by("group.patch", &resource, audit::OUTCOME_REJECTED, &actor);
            err_json(&e)
        }
    }
}

/// `DELETE /api/v1/admin/groups/{name}` — remove an API-created group at runtime (live). `404` if
/// unknown; `409` if base-config-defined (edit config.yaml) or if another group still names it as
/// `parent` (re-parent/remove the children first — never silently orphan them). `204` on success;
/// the name is tombstoned so the deletion survives a restart.
pub(crate) async fn delete_group(
    State(handle): State<Arc<AppHandle>>,
    axum::Extension(principal): axum::Extension<crate::auth::AuthPrincipal>,
    Path(name): Path<String>,
    headers: axum::http::HeaderMap,
) -> Response {
    let actor = principal.actor_id().to_string();
    let expected = match if_match_version(&headers) {
        Ok(v) => v,
        Err(resp) => return resp,
    };
    let _mlock = CONFIG_MUTATION_LOCK.lock().await;
    let current = handle.load();
    let resource = format!("group:{name}");
    if !current.groups_registry.contains_key(&name) {
        audit::AUDIT.record_by("group.delete", &resource, audit::OUTCOME_REJECTED, &actor);
        return err_json(&AdminError::NotFound(format!("group `{name}`")));
    }
    if let Some(e) = stale_if_match(expected, current.config_version) {
        audit::AUDIT.record_by("group.delete", &resource, audit::OUTCOME_REJECTED, &actor);
        return err_json(&e);
    }
    if current.base_group_names.contains(&name) {
        audit::AUDIT.record_by("group.delete", &resource, audit::OUTCOME_REJECTED, &actor);
        return err_json(&AdminError::Conflict(format!(
            "group `{name}` is defined in the base config file; edit config.yaml (the API cannot \
             silently shadow operator file config)"
        )));
    }
    match build_without_group(&current, &name) {
        Ok(next) => {
            let installed = Arc::new(next);
            handle.swap(installed.clone());
            audit::AUDIT.record_by("group.delete", &resource, audit::OUTCOME_APPLIED, &actor);
            let cur = handle.load();
            record_group_version(&installed, &actor, &format!("group.delete {resource}"));
            // Tombstone this name so the deletion survives a restart (overlay is additive otherwise).
            crate::config::overlay::persist_groups(
                cur.overlay_path.as_deref(),
                &cur.groups_registry,
                Some(&name),
                None,
            );
            with_config_etag(
                StatusCode::NO_CONTENT.into_response(),
                installed.config_version,
            )
        }
        Err(e) => {
            audit::AUDIT.record_by("group.delete", &resource, audit::OUTCOME_REJECTED, &actor);
            err_json(&e)
        }
    }
}

/// `DELETE /api/v1/admin/overlay/{section}` — DISCARD every overlay mutation for one section and revert
/// it to what base `config.yaml` declares. `section` ∈ {`groups`, `hooks`, `root`}; an unknown name is
/// a `400` `invalid_request`. This is the audited revert-to-config front door (D3: per-section, NOT
/// whole-overlay): it clears that section's overlay entries + tombstones, then rebuilds a complete
/// `App` from base config (disk truth re-read + resolved, the OTHER sections' overlay still merged) and
/// swaps it in — so a `groups` reset restores base group limits (cost model rebuilt), a `hooks` reset
/// restores base hooks (registry/gates/rewrites rebuilt), and a `root` reset restores base single-value
/// config (rate_card/store/security/limits/… — cost model + limits reprojected), each leaving the
/// sibling sections' runtime mutations untouched. Full scope; `If-Match` optimistic concurrency;
/// audited + versioned; the cleared
/// overlay is persisted so the revert survives a restart. A section with NO overlay state is a clean
/// no-op success (idempotent) — nothing changes, the version does not bump. Requires config files on
/// disk (the base truth to revert to); an ephemeral busbar has none, so reset is an `invalid_request`
/// there, exactly like `config/reload`.
pub(crate) async fn reset_overlay_section(
    State(handle): State<Arc<AppHandle>>,
    axum::Extension(principal): axum::Extension<crate::auth::AuthPrincipal>,
    Path(section): Path<String>,
    headers: axum::http::HeaderMap,
) -> Response {
    use crate::config::overlay::OverlaySection;
    let actor = principal.actor_id().to_string();
    // Validate the section name BEFORE the If-Match parse so an unknown section is always a plain
    // 400 (never masked by a header error). Unknown → invalid_request (the taxonomy's 400).
    let Some(section) = OverlaySection::parse(&section) else {
        return err_json(&AdminError::Validation(format!(
            "unknown overlay section `{section}`: expected `groups`, `hooks`, or `root`"
        )));
    };
    let resource = format!("overlay:{}", section.as_str());
    let expected = match if_match_version(&headers) {
        Ok(v) => v,
        Err(resp) => return resp,
    };
    let _mlock = CONFIG_MUTATION_LOCK.lock().await;
    let current = handle.load();
    if let Some(e) = stale_if_match(expected, current.config_version) {
        audit::AUDIT.record_by("overlay.reset", &resource, audit::OUTCOME_REJECTED, &actor);
        return err_json(&e);
    }
    // IDEMPOTENT NO-OP: if this section carries no overlay state (no API-applied entries AND no
    // tombstones), the effective config already equals base for it — a reset changes nothing, so
    // short-circuit a 200 without bumping the version or re-running the boot pipeline. With
    // persistence disabled there is no overlay at all, so every section is definitionally empty.
    let overlay_empty = match current.overlay_path.as_deref() {
        None => true,
        Some(p) => crate::config::overlay::read(p)
            .map(|doc| doc.section_is_empty(section))
            .unwrap_or(true),
    };
    if overlay_empty {
        audit::AUDIT.record_by("overlay.reset", &resource, audit::OUTCOME_APPLIED, &actor);
        return with_config_etag(
            ok_json(
                StatusCode::OK,
                &json!({
                    "reset": section.as_str(),
                    "config_version": current.config_version,
                    "changed": false
                }),
            ),
            current.config_version,
        );
    }
    // Re-run the BOOT disk-load pipeline to recover base `config.yaml` truth, then merge the CURRENT
    // overlay with this section CLEARED — the sibling section's overlay entries/tombstones survive, the
    // reset section reverts to base. This is the exact `config/reload` mechanism, minus one section.
    let (Some(config_path), Some(providers_path)) =
        (current.config_path.clone(), current.providers_path.clone())
    else {
        audit::AUDIT.record_by("overlay.reset", &resource, audit::OUTCOME_REJECTED, &actor);
        return err_json(&AdminError::Validation(
            "this busbar was started without config files (ephemeral mode); a per-section reset has \
             no disk truth to revert to"
                .into(),
        ));
    };
    let outcome = crate::load_config_from_disk(
        &config_path,
        &providers_path,
        false,
        crate::config::EnvSubst::Strict,
    )
    .and_then(|mut loaded| {
        // CLEAR the target section from the persisted overlay FIRST — that slice reverts to base, the
        // other slices stay live. The clear happens before both merge halves so a `root` reset drops
        // its DeployCfg-level overrides pre-resolve, and a `hooks`/`groups` reset drops its registry
        // entries post-resolve.
        let cleared_doc = loaded.overlay_doc.take().map(|mut doc| {
            doc.clear_section(section);
            doc
        });
        // Pre-resolve half: apply the (post-clear) root overrides onto the base DeployCfg, so the
        // limits projection + admin-mTLS boot-guard re-derive over the merged shape.
        if let Some(doc) = cleared_doc.as_ref() {
            crate::config::overlay::apply_root_to_deploy(&mut loaded.deploy, doc);
        }
        let mut cfg = crate::config::resolve(&loaded.deploy, &loaded.defs)
            .map_err(|errs| format!("config errors:\n  - {}", errs.join("\n  - ")))?;
        let base_hook_names: std::collections::HashSet<String> =
            cfg.hooks.keys().cloned().collect();
        let base_group_names: std::collections::HashSet<String> =
            cfg.groups.keys().cloned().collect();
        // Post-resolve half: merge the (post-clear) hooks + groups sections onto the resolved config.
        if let Some(doc) = cleared_doc {
            crate::config::overlay::merge_into(&mut cfg, doc);
        }
        crate::build_app_from_config(
            cfg,
            loaded.deploy.plugins.clone(),
            // Preserve the LIVE overlay path (not the env-derived one `load_config_from_disk`
            // returns) — the reset rewrites the same overlay file the running App uses, exactly as
            // `config/apply` preserves `current.overlay_path`.
            current.overlay_path.clone(),
            base_hook_names,
            base_group_names,
            (Some(config_path), Some(providers_path)),
            Some(&current),
        )
    });
    match outcome {
        Ok(next) => {
            let installed = Arc::new(next);
            handle.swap(installed.clone());
            audit::AUDIT.record_by("overlay.reset", &resource, audit::OUTCOME_APPLIED, &actor);
            let cur = handle.load();
            record_group_version(
                &installed,
                &actor,
                &format!("overlay.reset {} (revert to config.yaml)", section.as_str()),
            );
            // Persist the section-cleared overlay so the revert survives a restart (the sibling
            // section is preserved verbatim by the read-modify-write).
            crate::config::overlay::clear_section(cur.overlay_path.as_deref(), section);
            with_config_etag(
                ok_json(
                    StatusCode::OK,
                    &json!({
                        "reset": section.as_str(),
                        "config_version": cur.config_version,
                        "changed": true
                    }),
                ),
                cur.config_version,
            )
        }
        Err(e) => {
            audit::AUDIT.record_by("overlay.reset", &resource, audit::OUTCOME_REJECTED, &actor);
            err_json(&AdminError::Validation(e))
        }
    }
}

/// Apply a partial group PATCH onto a base definition: a field that is `Some` REPLACES, `None`
/// PRESERVES. `limits`/`child_default` replace their whole list (a list can't be field-merged). The
/// pure, testable core of `patch_group`.
fn merge_group_patch(
    mut base: crate::config::GroupCfg,
    parent: Option<String>,
    enabled: Option<bool>,
    limits: Option<Vec<crate::config::LimitCfg>>,
    child_default: Option<crate::config::groups::ChildDefault>,
) -> crate::config::GroupCfg {
    if let Some(p) = parent {
        base.parent = Some(p);
    }
    if let Some(en) = enabled {
        base.enabled = en;
    }
    if let Some(l) = limits {
        base.limits = l;
    }
    if let Some(cd) = child_default {
        base.child_default = Some(cd);
    }
    base
}

/// Record a config-version entry for a GROUP mutation. The `VersionLog` snapshot payload is the
/// hook surface (its rollback scope today); a group change still bumps `config_version` and lands an
/// audited, timestamped version row (so `GET /config/versions` shows the event honestly). Extending
/// the snapshot + `config/rollback` to restore groups is a tracked follow-up (task #100).
fn record_group_version(installed: &Arc<crate::state::App>, actor: &str, summary: &str) {
    installed.versions.record(
        installed.config_version,
        actor,
        summary,
        &installed.hook_registry,
        &installed.global_hooks,
    );
}

/// `GET /api/v1/admin/audit` — the admin audit log (most-recent-first), every mutation with its outcome.
/// Filters: `?action=hook.register`, `?resource=hook:x`. Paginated by the shared cursor envelope:
/// `?limit=N` (cap 1000) + opaque `?cursor=`, response `{items, next_cursor}` (next_cursor iff more).
pub(crate) async fn get_audit(
    Query(q): Query<std::collections::HashMap<String, String>>,
) -> Response {
    let limit = q
        .get("limit")
        .and_then(|s| s.parse::<usize>().ok())
        .unwrap_or(crate::admin::v1::contract::LIST_LIMIT_DEFAULT)
        .min(crate::admin::v1::contract::LIST_LIMIT_MAX);
    let start = match cursor_offset(&q) {
        Ok(n) => n,
        Err(resp) => return resp,
    };
    let action = q.get("action").map(String::as_str);
    let resource = q.get("resource").map(String::as_str);
    // Fetch one past the page to learn whether a further page exists, then trim to `limit`.
    let mut entries = audit::AUDIT.list_filtered(start, limit + 1, action, resource);
    let next_cursor = page_cursor(&mut entries, start, limit);
    ok_json(
        StatusCode::OK,
        &json!({ "items": entries, "next_cursor": next_cursor }),
    )
}

/// `GET /api/v1/admin/config/versions` — version history metadata, newest first. Paginated by the shared
/// cursor envelope: `?limit=N` (cap 1000) + opaque `?cursor=`, response `{items, next_cursor}`.
pub(crate) async fn list_config_versions(
    State(handle): State<Arc<AppHandle>>,
    Query(q): Query<std::collections::HashMap<String, String>>,
) -> Response {
    let limit = q
        .get("limit")
        .and_then(|s| s.parse::<usize>().ok())
        .unwrap_or(crate::admin::v1::contract::VERSIONS_LIMIT_DEFAULT)
        .min(crate::admin::v1::contract::LIST_LIMIT_MAX);
    let start = match cursor_offset(&q) {
        Ok(n) => n,
        Err(resp) => return resp,
    };
    let mut versions = handle.load().versions.list(start, limit + 1);
    let next_cursor = page_cursor(&mut versions, start, limit);
    ok_json(
        StatusCode::OK,
        &json!({ "items": versions, "next_cursor": next_cursor }),
    )
}

/// `GET /api/v1/admin/config/versions/{v}` — one retained version WITH its hook-surface snapshot.
/// The `{v}` segment is bound as a STRING and parsed here (not `Path<u64>`): a typed extractor
/// rejects a non-numeric segment with axum's OWN plain-text 400, escaping the frozen envelope —
/// parsing in-handler lets a malformed version speak `invalid_request` like every other 400.
pub(crate) async fn get_config_version(
    State(handle): State<Arc<AppHandle>>,
    Path(v): Path<String>,
) -> Response {
    let Ok(v) = v.parse::<u64>() else {
        return err_json(&AdminError::Validation(format!(
            "config version must be a non-negative integer; got `{v}`"
        )));
    };
    match handle.load().versions.get(v) {
        Some(cv) => {
            // Project the snapshot through the ONE wire HookView shape (against the SNAPSHOT's own
            // global wiring) — never the raw HookCfg file shape, so a consumer parses hooks with a
            // single schema whether it reads /hooks or a retained version (re-audit M6).
            let hooks: std::collections::BTreeMap<&String, _> = cv
                .hook_registry
                .iter()
                .map(|(name, cfg)| {
                    (
                        name,
                        crate::admin::v1::service::project_hook_view(name, cfg, &cv.global_hooks),
                    )
                })
                .collect();
            ok_json(
                StatusCode::OK,
                &json!({
                    "version": cv.version,
                    "ts": cv.ts,
                    "principal": cv.principal,
                    "summary": cv.summary,
                    "hooks": hooks,
                    "global_hooks": cv.global_hooks,
                }),
            )
        }
        None => err_json(&AdminError::NotFound(format!(
            "config version {v} (pruned or never recorded)"
        ))),
    }
}

/// `GET /api/v1/admin/config/diff?from=&to=` — structured hook-surface diff between two retained
/// versions: hook names added / removed / changed (definition differs), plus the global wiring of
/// each side when it changed.
pub(crate) async fn config_diff(
    State(handle): State<Arc<AppHandle>>,
    Query(q): Query<std::collections::HashMap<String, String>>,
) -> Response {
    let (Some(from), Some(to)) = (
        q.get("from").and_then(|s| s.parse::<u64>().ok()),
        q.get("to").and_then(|s| s.parse::<u64>().ok()),
    ) else {
        return err_json(&AdminError::Validation(
            "`from` and `to` query params (version numbers) are required".into(),
        ));
    };
    let app = handle.load();
    // Name exactly WHICH version is missing — "and/or" made a consumer re-probe both.
    let a = match app.versions.get(from) {
        Some(v) => v,
        None => {
            return err_json(&AdminError::NotFound(format!(
                "config version {from} (pruned or never recorded)"
            )))
        }
    };
    let b = match app.versions.get(to) {
        Some(v) => v,
        None => {
            return err_json(&AdminError::NotFound(format!(
                "config version {to} (pruned or never recorded)"
            )))
        }
    };
    let mut added: Vec<&String> = b
        .hook_registry
        .keys()
        .filter(|k| !a.hook_registry.contains_key(*k))
        .collect();
    let mut removed: Vec<&String> = a
        .hook_registry
        .keys()
        .filter(|k| !b.hook_registry.contains_key(*k))
        .collect();
    // "Changed" = present in both with a differing definition. HookCfg has no PartialEq (transport
    // objects don't); compare the serialized form — the definition IS its config shape.
    let mut changed: Vec<&String> = a
        .hook_registry
        .iter()
        .filter(|(k, va)| {
            b.hook_registry
                .get(*k)
                .is_some_and(|vb| serde_json::to_value(va).ok() != serde_json::to_value(vb).ok())
        })
        .map(|(k, _)| k)
        .collect();
    added.sort();
    removed.sort();
    changed.sort();
    let mut body = json!({
        "from": from,
        "to": to,
        "hooks": { "added": added, "removed": removed, "changed": changed },
    });
    if a.global_hooks != b.global_hooks {
        body["global_hooks"] = json!({ "from": a.global_hooks, "to": b.global_hooks });
    }
    ok_json(StatusCode::OK, &body)
}

/// The `POST /api/v1/admin/config/rollback` request body. Optimistic concurrency rides `If-Match` (H3).
#[derive(serde::Deserialize)]
pub(crate) struct RollbackReq {
    /// The retained version to restore.
    version: u64,
}

/// `POST /api/v1/admin/config/rollback` — restore a retained version's hook surface. The target is
/// RE-VALIDATED against current reality before the swap (a rollback that no longer resolves is
/// rejected, never blindly applied); the result is a NEW version (history is append-only — rolling
/// back never rewrites it), audited and overlay-persisted.
pub(crate) async fn rollback_config(
    State(handle): State<Arc<AppHandle>>,
    axum::Extension(principal): axum::Extension<crate::auth::AuthPrincipal>,
    headers: axum::http::HeaderMap,
    body: axum::body::Bytes,
) -> Response {
    let actor = principal.actor_id().to_string();
    let expected = match if_match_version(&headers) {
        Ok(v) => v,
        Err(resp) => return resp,
    };
    let req: RollbackReq = match serde_json::from_slice(&body) {
        Ok(r) => r,
        Err(e) => {
            return err_json(&AdminError::Validation(format!(
                "malformed rollback body: {e}"
            )))
        }
    };
    let _mlock = CONFIG_MUTATION_LOCK.lock().await;
    let current = handle.load();
    let resource = format!("config:v{}", req.version);
    if let Some(e) = stale_if_match(expected, current.config_version) {
        audit::AUDIT.record_by(
            "config.rollback",
            &resource,
            audit::OUTCOME_REJECTED,
            &actor,
        );
        return err_json(&e);
    }
    let Some(target) = current.versions.get(req.version) else {
        audit::AUDIT.record_by(
            "config.rollback",
            &resource,
            audit::OUTCOME_REJECTED,
            &actor,
        );
        return err_json(&AdminError::NotFound(format!(
            "config version {} (pruned or never recorded)",
            req.version
        )));
    };
    match build_with_registry(&current, target.hook_registry, target.global_hooks) {
        Ok(next) => {
            let installed = Arc::new(next);
            handle.swap(installed.clone());
            audit::AUDIT.record_by("config.rollback", &resource, audit::OUTCOME_APPLIED, &actor);
            let cur = handle.load();
            installed.versions.record(
                installed.config_version,
                &actor,
                &format!("config.rollback to v{}", req.version),
                &installed.hook_registry,
                &installed.global_hooks,
            );
            // Best-effort overlay persistence of the restored surface (no-op when disabled).
            crate::config::overlay::persist(
                cur.overlay_path.as_deref(),
                &cur.hook_registry,
                &cur.global_hooks,
                None,
                None,
            );
            with_config_etag(
                ok_json(
                    StatusCode::OK,
                    &json!({
                        "restored_version": req.version,
                        // The post-rollback version under the SAME name every other mutation uses.
                        "config_version": cur.config_version,
                    }),
                ),
                cur.config_version,
            )
        }
        Err(e) => {
            audit::AUDIT.record_by(
                "config.rollback",
                &resource,
                audit::OUTCOME_REJECTED,
                &actor,
            );
            err_json(&e)
        }
    }
}

/// `PUT /api/v1/admin/admin-auth` — replace the ADMIN auth chain (`admin_auth:`) at runtime. Pairs with
/// `GET /api/v1/admin/admin-auth`, which reports the same `admin_auth` chain (read-after-write coherent).
/// Body:
/// `{"admin_auth": ["module", ...]}`. Guarded three ways:
/// - every name must be a compiled-in admin module (a typo can never silently drop auth);
/// - optimistic concurrency via `If-Match` (409 `version_conflict` when stale — re-read and retry);
/// - **the D4 DRY-RUN GUARD**: the CALLING request's own credentials are re-evaluated against the
///   CANDIDATE chain, and unless they would still hold FULL scope under it the change is rejected
///   with 409 — you cannot lock yourself out with this endpoint. (A chain broken some other way
///   is fix-config + restart: sub-second, health persists.)
///
/// Applied live and atomically (config-version bump, audited); like `config/apply`, the change is
/// live until the next reload/restart returns to disk truth — persist by updating config.yaml.
pub(crate) async fn put_auth(
    State(handle): State<Arc<AppHandle>>,
    axum::Extension(principal): axum::Extension<crate::auth::AuthPrincipal>,
    headers: axum::http::HeaderMap,
    body: axum::body::Bytes,
) -> Response {
    #[derive(serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    struct PutAuthBody {
        admin_auth: Vec<String>,
    }
    let expected = match if_match_version(&headers) {
        Ok(v) => v,
        Err(resp) => return resp,
    };
    let req: PutAuthBody = match serde_json::from_slice(&body) {
        Ok(b) => b,
        Err(e) => return err_json(&AdminError::Validation(format!("invalid body: {e}"))),
    };
    let _mlock = CONFIG_MUTATION_LOCK.lock().await;
    let current = handle.load();
    if let Some(e) = stale_if_match(expected, current.config_version) {
        // Audit the rejected attempt (§6.7: every mutation attempt leaves a trail — uniform with
        // every other stale-If-Match rejection in this file, and with put_auth's own
        // dry-run-guard rejection below).
        audit::AUDIT.record_by(
            "auth.admin_chain_put",
            "auth:admin_auth",
            audit::OUTCOME_REJECTED,
            principal.actor_id(),
        );
        return err_json(&e);
    }
    // Known-module validation (mirrors the boot rule): `admin-tokens` is the built-in; the
    // test-only stand-in exists in test builds only. An unknown name can never silently drop auth.
    for name in &req.admin_auth {
        let known = name == "admin-tokens" || (cfg!(test) && name == "test-scope-module");
        if !known {
            return err_json(&AdminError::Validation(format!(
                "admin_auth names unknown module '{name}'; the built-in admin module is \
                 `admin-tokens` (external admin modules are registered at compile time)"
            )));
        }
    }
    if req.admin_auth.is_empty() {
        tracing::warn!(
            "PUT /api/v1/admin/admin-auth applied an EMPTY admin_auth chain — the admin API is now the \
             open (anonymous, full-authority) dev posture"
        );
    }
    // Candidate app with the new chain.
    let mut next = (*current).clone();
    next.config_version = current.config_version.wrapping_add(1);
    next.admin_chain = req.admin_auth.clone();
    // D4 DRY-RUN GUARD: this very request's carriers, evaluated under the CANDIDATE chain.
    let bearer = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(crate::auth::AuthMiddleware::extract_bearer_token);
    let header_tok = headers
        .get(crate::auth::X_ADMIN_TOKEN)
        .and_then(|v| v.to_str().ok())
        .filter(|t| !t.is_empty())
        .map(str::to_string);
    let survives = matches!(
        crate::auth::dry_run_admin_scope(&next, bearer.as_deref(), header_tok.as_deref()),
        Some(crate::admin::v1::contract::Scope::Full)
    );
    if !survives {
        audit::AUDIT.record_by(
            "auth.admin_chain_put",
            "auth:admin_auth",
            audit::OUTCOME_REJECTED,
            principal.actor_id(),
        );
        return err_json(&AdminError::Conflict(
            "the new admin_auth chain would not grant THIS caller full scope — refusing to lock \
             you out. Authenticate with a credential the new chain accepts (at full scope) and \
             retry, or change the chain in config.yaml and restart"
                .into(),
        ));
    }
    let installed = Arc::new(next);
    handle.swap(installed.clone());
    audit::AUDIT.record_by(
        "auth.admin_chain_put",
        "auth:admin_auth",
        audit::OUTCOME_APPLIED,
        principal.actor_id(),
    );
    let cur = handle.load();
    installed.versions.record(
        installed.config_version,
        principal.actor_id(),
        "auth.admin_chain_put",
        &installed.hook_registry,
        &installed.global_hooks,
    );
    // The response IS the resource (the same {configured, modules} shape GET /admin-auth returns,
    // so a Terraform provider uses the PUT response as post-state — re-audit M5) + apply metadata.
    with_config_etag(
        ok_json(
            StatusCode::OK,
            &json!({
                "configured": !req.admin_auth.is_empty(),
                "modules": req.admin_auth,
                "applied": true,
                "config_version": cur.config_version,
                "note": "live until the next config reload/restart returns to disk truth; persist by updating config.yaml"
            }),
        ),
        cur.config_version,
    )
}

/// `POST /api/v1/admin/auth/cache/flush` — INSTANT REVOCATION of the credential cache's
/// cached-allow window (design-hooks-v2 §2.5). Body `{"module": "<name>"}` flushes one module's
/// partition; no/empty body flushes everything. The deny path never needed this (`Reject` is
/// never cached); this closes the Identify window when a directory changes NOW.
pub(crate) async fn flush_credential_cache(
    State(handle): State<Arc<AppHandle>>,
    axum::Extension(principal): axum::Extension<crate::auth::AuthPrincipal>,
    body: axum::body::Bytes,
) -> Response {
    let app = handle.load();
    let module: Option<String> = if body.is_empty() {
        None
    } else {
        match serde_json::from_slice::<serde_json::Value>(&body) {
            Ok(v) => match v.get("module") {
                None | Some(serde_json::Value::Null) => None,
                Some(serde_json::Value::String(m)) => Some(m.clone()),
                Some(_) => {
                    return err_json(&AdminError::Validation(
                        "`module` must be a string (the auth module whose partition to flush)"
                            .into(),
                    ))
                }
            },
            Err(_) => return err_json(&AdminError::Validation("body must be JSON".into())),
        }
    };
    let flushed = match module.as_deref() {
        Some(m) => app.credential_cache.flush_module(m),
        None => app.credential_cache.flush_all(),
    };
    audit::AUDIT.record_by(
        "auth.cache_flush",
        module.as_deref().unwrap_or("*"),
        audit::OUTCOME_APPLIED,
        principal.actor_id(),
    );
    ok_json(StatusCode::OK, &json!({ "flushed": flushed }))
}

/// `POST /api/v1/admin/config/reload` — re-run the BOOT disk-load pipeline (config.yaml +
/// providers.yaml + env interpolation from the boot-time environment + overlay merge), validate,
/// build a complete new `App` reusing process-lifetime state (client pool, governance DB, version
/// history, rate windows) with every surviving lane's health RESTORED BY STABLE IDENTITY, and
/// atomically swap it in. A NORMAL admin call under the NORMAL admin auth chain — no second
/// credential path exists (D3). Invalid disk config = `invalid_request`, nothing changes. The
/// GitOps primitive: push config, call reload, no restart, no health amnesia.
pub(crate) async fn reload_config(
    State(handle): State<Arc<AppHandle>>,
    axum::Extension(principal): axum::Extension<crate::auth::AuthPrincipal>,
) -> Response {
    let actor = principal.actor_id().to_string();
    let _mlock = CONFIG_MUTATION_LOCK.lock().await;
    let current = handle.load();
    let (Some(config_path), Some(providers_path)) =
        (current.config_path.clone(), current.providers_path.clone())
    else {
        return err_json(&AdminError::Validation(
            "this busbar was started without config files (ephemeral mode); reload has no disk \
             truth to read"
                .into(),
        ));
    };
    let outcome = crate::load_config_from_disk(
        &config_path,
        &providers_path,
        false,
        crate::config::EnvSubst::Strict,
    )
    .and_then(|mut loaded| {
        // 1.5.0 full-config coverage: apply the overlay's `root` section (single-value config) onto
        // the base `DeployCfg` BEFORE resolve, so the limits projection + admin-mTLS boot-guard
        // re-derive over the merged shape — exactly as boot does. The hooks/groups sections merge
        // POST-resolve below.
        if let Some(doc) = loaded.overlay_doc.as_ref() {
            crate::config::overlay::apply_root_to_deploy(&mut loaded.deploy, doc);
        }
        let mut cfg = crate::config::resolve(&loaded.deploy, &loaded.defs)
            .map_err(|errs| format!("config errors:\n  - {}", errs.join("\n  - ")))?;
        // Base hook + group names = the config-defined registry, pre-overlay (the admin API refuses
        // to PUT-replace / DELETE one); then merge the persisted overlay onto the resolved registry.
        let base_hook_names: std::collections::HashSet<String> =
            cfg.hooks.keys().cloned().collect();
        let base_group_names: std::collections::HashSet<String> =
            cfg.groups.keys().cloned().collect();
        if let Some(doc) = loaded.overlay_doc {
            crate::config::overlay::merge_into(&mut cfg, doc);
        }
        crate::build_app_from_config(
            cfg,
            loaded.deploy.plugins.clone(),
            loaded.overlay_path,
            base_hook_names,
            base_group_names,
            (Some(config_path), Some(providers_path)),
            Some(&current),
        )
    });
    match outcome {
        Ok(next) => {
            let installed = Arc::new(next);
            handle.swap(installed.clone()); // swap re-spawns health probers for the new snapshot
            audit::AUDIT.record_by(
                "config.reload",
                "config:disk",
                audit::OUTCOME_APPLIED,
                &actor,
            );
            let cur = handle.load();
            installed.versions.record(
                installed.config_version,
                &actor,
                "config.reload (from disk)",
                &installed.hook_registry,
                &installed.global_hooks,
            );
            with_config_etag(
                ok_json(
                    StatusCode::OK,
                    &json!({ "reloaded": true, "config_version": cur.config_version }),
                ),
                cur.config_version,
            )
        }
        Err(e) => {
            audit::AUDIT.record_by(
                "config.reload",
                "config:disk",
                audit::OUTCOME_REJECTED,
                &actor,
            );
            err_json(&AdminError::Validation(e))
        }
    }
}

/// The `POST /api/v1/admin/config/apply` body: a full proposed config (validate's exact shape).
/// Optimistic concurrency rides `If-Match` (H3).
#[derive(serde::Deserialize)]
pub(crate) struct ApplyConfigReq {
    /// The deploy config (operator-owned `config.yaml` shape).
    config: crate::config::DeployCfg,
    /// The provider definitions (`providers.yaml` shape). Optional — empty validates/fails loudly
    /// on dangling references.
    #[serde(default)]
    providers: std::collections::HashMap<String, crate::config::ProviderDef>,
}

/// `POST /api/v1/admin/config/apply` — apply a FULL config carried in the request body, atomically:
/// resolve + validate (an invalid config is a 400 that changes nothing), build a complete new
/// `App` reusing process-lifetime state, carry every surviving lane's health BY STABLE IDENTITY
/// (D1), swap. The body-carried twin of `config/reload` (disk) — Terraform/CI push the config they
/// hold instead of writing files. NOTE: an applied config is LIVE but not written to disk — the
/// next reload/restart returns to disk truth (+overlay); the response says so.
pub(crate) async fn apply_config(
    State(handle): State<Arc<AppHandle>>,
    axum::Extension(principal): axum::Extension<crate::auth::AuthPrincipal>,
    headers: axum::http::HeaderMap,
    body: axum::body::Bytes,
) -> Response {
    let actor = principal.actor_id().to_string();
    let expected = match if_match_version(&headers) {
        Ok(v) => v,
        Err(resp) => return resp,
    };
    let req: ApplyConfigReq = match serde_json::from_slice(&body) {
        Ok(r) => r,
        Err(e) => {
            return err_json(&AdminError::Validation(format!(
                "malformed config body: {e}"
            )))
        }
    };
    let _mlock = CONFIG_MUTATION_LOCK.lock().await;
    let current = handle.load();
    if let Some(e) = stale_if_match(expected, current.config_version) {
        audit::AUDIT.record_by(
            "config.apply",
            "config:body",
            audit::OUTCOME_REJECTED,
            &actor,
        );
        return err_json(&e);
    }
    let outcome = crate::config::resolve(&req.config, &req.providers)
        .map_err(|errs| format!("config errors:\n  - {}", errs.join("\n  - ")))
        .and_then(|cfg| {
            // Base hook + group names = the applied config's own (synthesized) registry.
            let base_hook_names: std::collections::HashSet<String> =
                cfg.hooks.keys().cloned().collect();
            let base_group_names: std::collections::HashSet<String> =
                cfg.groups.keys().cloned().collect();
            crate::build_app_from_config(
                cfg,
                req.config.plugins.clone(),
                current.overlay_path.clone(),
                base_hook_names,
                base_group_names,
                (current.config_path.clone(), current.providers_path.clone()),
                Some(&current),
            )
        });
    match outcome {
        Ok(next) => {
            let installed = Arc::new(next);
            handle.swap(installed.clone()); // swap re-spawns health probers for the new snapshot
            audit::AUDIT.record_by(
                "config.apply",
                "config:body",
                audit::OUTCOME_APPLIED,
                &actor,
            );
            let cur = handle.load();
            installed.versions.record(
                installed.config_version,
                &actor,
                "config.apply (request body)",
                &installed.hook_registry,
                &installed.global_hooks,
            );
            with_config_etag(
                ok_json(
                    StatusCode::OK,
                    &json!({
                        "applied": true,
                        "config_version": cur.config_version,
                        "note": "live until the next reload/restart returns to disk truth; persist \
                                 by updating config.yaml",
                    }),
                ),
                cur.config_version,
            )
        }
        Err(e) => {
            audit::AUDIT.record_by(
                "config.apply",
                "config:body",
                audit::OUTCOME_REJECTED,
                &actor,
            );
            err_json(&AdminError::Validation(e))
        }
    }
}

/// Merge a partial `RootSettings` request onto the current overlay root state: a field the request
/// sets (`Some`) REPLACES; a field it omits (`None`) is PRESERVED from the current overlay. The
/// partial-update semantics of `PUT /config/settings` — "raise the per-request fee" sends only
/// `per_request_fee`, leaving every other override untouched. To CLEAR the whole root section, use
/// `DELETE /overlay/root`.
fn merge_root_settings(
    mut base: crate::config::overlay::RootSettings,
    req: crate::config::overlay::RootSettings,
) -> crate::config::overlay::RootSettings {
    if req.listen.is_some() {
        base.listen = req.listen;
    }
    if req.tls.is_some() {
        base.tls = req.tls;
    }
    if req.admin_listen.is_some() {
        base.admin_listen = req.admin_listen;
    }
    if req.admin_tls.is_some() {
        base.admin_tls = req.admin_tls;
    }
    if req.admin_insecure.is_some() {
        base.admin_insecure = req.admin_insecure;
    }
    if req.rate_card.is_some() {
        base.rate_card = req.rate_card;
    }
    if req.per_request_fee.is_some() {
        base.per_request_fee = req.per_request_fee;
    }
    if req.store.is_some() {
        base.store = req.store;
    }
    if req.security.is_some() {
        base.security = req.security;
    }
    if req.limits.is_some() {
        base.limits = req.limits;
    }
    if req.observability.is_some() {
        base.observability = req.observability;
    }
    if req.advanced.is_some() {
        base.advanced = req.advanced;
    }
    if req.metrics.is_some() {
        base.metrics = req.metrics;
    }
    if req.health.is_some() {
        base.health = req.health;
    }
    if req.routing.is_some() {
        base.routing = req.routing;
    }
    base
}

/// The RELOAD-TO-APPLY fields a `PUT /config/settings` REQUEST touched: the process-level binds
/// (`listen`/`admin_listen` socket rebind, `tls`/`admin_tls` bind, `admin_insecure` boot-guard waiver)
/// and the durable `store` backend cannot HOT-SWAP — a live `arc-swap` cannot rebind a socket or
/// migrate an in-flight governance ledger to a new backend — so their new value is DURABLY STORED but
/// takes effect only on the next `POST /config/reload` or restart. Every OTHER field
/// (`rate_card`/`per_request_fee`/`security`/`limits`/…) applies live on the swap. Keyed on the
/// REQUEST (only fields the operator just changed are flagged), so a subsequent live-only edit does
/// not re-flag an already-reloaded bind.
fn reload_to_apply_fields(req: &crate::config::overlay::RootSettings) -> Vec<String> {
    let mut out = Vec::new();
    let mut push = |set: bool, name: &str| {
        if set {
            out.push(name.to_string());
        }
    };
    push(req.listen.is_some(), "listen");
    push(req.tls.is_some(), "tls");
    push(req.admin_listen.is_some(), "admin_listen");
    push(req.admin_tls.is_some(), "admin_tls");
    push(req.admin_insecure.is_some(), "admin_insecure");
    push(req.store.is_some(), "store");
    out
}

/// Read the current overlay `root` section (the operator's API-set single-value overrides), or an
/// empty `RootSettings` when persistence is disabled / the overlay is absent or carries no root
/// section. Shared by the GET/PUT `/config/settings` handlers.
fn current_root_settings(
    overlay_path: Option<&std::path::Path>,
) -> crate::config::overlay::RootSettings {
    overlay_path
        .and_then(crate::config::overlay::read)
        .and_then(|doc| doc.root)
        .unwrap_or_default()
}

/// `GET /api/v1/admin/config/settings` — read the API-set single-value config overlay (the `root`
/// section: `listen`/`tls`/`rate_card`/`store`/`security`/`limits`/…). Reports ONLY the operator's
/// overrides (the fields set via `PUT /config/settings`); base `config.yaml` stands for the rest.
/// Read scope; carries the config-plane `ETag` so a `PUT` can chain `If-Match` off this read. Never a
/// secret in the clear beyond what the operator themselves supplied (TLS refs are secret-references,
/// not raw key bytes).
pub(crate) async fn get_config_settings(State(handle): State<Arc<AppHandle>>) -> Response {
    let current = handle.load();
    let root = current_root_settings(current.overlay_path.as_deref());
    let settings = serde_json::to_value(&root).unwrap_or_else(|_| json!({}));
    with_config_etag(
        ok_json(
            StatusCode::OK,
            &json!({
                "applied": false,
                "config_version": current.config_version,
                "settings": settings,
            }),
        ),
        current.config_version,
    )
}

/// `PUT /api/v1/admin/config/settings` — SET any single-value config section via the API, durably
/// (1.5.0 full-config coverage). The body is a PARTIAL `RootSettings`: only the fields present are
/// changed (merged onto the current overlay root), the rest preserved — so the admin NEVER edits
/// `config.yaml` and persistence is ALWAYS the busbar-owned overlay. The merged root is applied onto
/// the base `DeployCfg` (re-read from disk), re-resolved + re-validated (an invalid result is a `400`
/// that changes NOTHING), built into a new `App`, and swapped in — so `rate_card`/`per_request_fee`/
/// `security`/`limits`/… go LIVE immediately. The process-level binds
/// (`listen`/`admin_listen`/`tls`/`admin_tls`/`admin_insecure`) and the durable `store` backend are
/// stored + flagged RELOAD-TO-APPLY (they cannot hot-swap; `POST /config/reload` or restart makes them
/// live) — the response's `reload_to_apply` names exactly which. Full scope; `If-Match` optimistic
/// concurrency; audited (every attempt) + versioned; overlay-persisted so it survives a restart.
/// Requires config files on disk (the base to merge onto); an ephemeral busbar has none, so this is a
/// `400 invalid_request` there, exactly like `config/reload`.
pub(crate) async fn put_config_settings(
    State(handle): State<Arc<AppHandle>>,
    axum::Extension(principal): axum::Extension<crate::auth::AuthPrincipal>,
    headers: axum::http::HeaderMap,
    body: axum::body::Bytes,
) -> Response {
    let actor = principal.actor_id().to_string();
    let expected = match if_match_version(&headers) {
        Ok(v) => v,
        Err(resp) => return resp,
    };
    let req: crate::config::overlay::RootSettings = match serde_json::from_slice(&body) {
        Ok(r) => r,
        Err(e) => {
            return err_json(&AdminError::Validation(format!(
                "malformed config settings body: {e}"
            )))
        }
    };
    let _mlock = CONFIG_MUTATION_LOCK.lock().await;
    let current = handle.load();
    if let Some(e) = stale_if_match(expected, current.config_version) {
        audit::AUDIT.record_by(
            "config.settings",
            "config:settings",
            audit::OUTCOME_REJECTED,
            &actor,
        );
        return err_json(&e);
    }
    let (Some(config_path), Some(providers_path)) =
        (current.config_path.clone(), current.providers_path.clone())
    else {
        audit::AUDIT.record_by(
            "config.settings",
            "config:settings",
            audit::OUTCOME_REJECTED,
            &actor,
        );
        return err_json(&AdminError::Validation(
            "this busbar was started without config files (ephemeral mode); /config/settings has no \
             disk base to merge onto"
                .into(),
        ));
    };
    // Merge the partial request onto the CURRENT overlay root (partial-update semantics).
    let merged = merge_root_settings(
        current_root_settings(current.overlay_path.as_deref()),
        req.clone(),
    );
    let merged_for_build = merged.clone();
    // Re-run the disk-load pipeline (base truth), apply the MERGED root onto the DeployCfg BEFORE
    // resolve (so the limits projection + admin-mTLS boot-guard re-derive over it), then merge the
    // CURRENT hooks/groups overlay sections POST-resolve — exactly the reload mechanism, with the
    // root section coming from the just-merged desired state rather than the on-disk overlay.
    let outcome = crate::load_config_from_disk(
        &config_path,
        &providers_path,
        false,
        crate::config::EnvSubst::Strict,
    )
    .and_then(|mut loaded| {
        merged_for_build.apply_to_deploy(&mut loaded.deploy);
        let mut cfg = crate::config::resolve(&loaded.deploy, &loaded.defs)
            .map_err(|errs| format!("config errors:\n  - {}", errs.join("\n  - ")))?;
        let base_hook_names: std::collections::HashSet<String> =
            cfg.hooks.keys().cloned().collect();
        let base_group_names: std::collections::HashSet<String> =
            cfg.groups.keys().cloned().collect();
        if let Some(doc) = loaded.overlay_doc {
            crate::config::overlay::merge_into(&mut cfg, doc);
        }
        crate::build_app_from_config(
            cfg,
            loaded.deploy.plugins.clone(),
            current.overlay_path.clone(),
            base_hook_names,
            base_group_names,
            (Some(config_path), Some(providers_path)),
            Some(&current),
        )
    });
    match outcome {
        Ok(next) => {
            let installed = Arc::new(next);
            handle.swap(installed.clone());
            audit::AUDIT.record_by(
                "config.settings",
                "config:settings",
                audit::OUTCOME_APPLIED,
                &actor,
            );
            let cur = handle.load();
            record_group_version(&installed, &actor, "config.settings (root section applied)");
            // Persist the merged root section (best-effort; the sibling hooks/groups sections are
            // preserved verbatim by the read-modify-write).
            crate::config::overlay::persist_root(cur.overlay_path.as_deref(), &merged);
            let reload_to_apply = reload_to_apply_fields(&req);
            let note = if reload_to_apply.is_empty() {
                "applied live".to_string()
            } else {
                format!(
                    "applied live except {} — stored, effective on the next reload/restart (a socket \
                     rebind / TLS bind / store backend cannot hot-swap)",
                    reload_to_apply.join(", ")
                )
            };
            let settings = serde_json::to_value(&merged).unwrap_or_else(|_| json!({}));
            with_config_etag(
                ok_json(
                    StatusCode::OK,
                    &json!({
                        "applied": true,
                        "config_version": cur.config_version,
                        "settings": settings,
                        "reload_to_apply": reload_to_apply,
                        "note": note,
                    }),
                ),
                cur.config_version,
            )
        }
        Err(e) => {
            audit::AUDIT.record_by(
                "config.settings",
                "config:settings",
                audit::OUTCOME_REJECTED,
                &actor,
            );
            err_json(&AdminError::Validation(e))
        }
    }
}

/// The `PATCH /api/v1/admin/hooks/{name}/settings` body. Optimistic concurrency rides `If-Match` (H3).
#[derive(serde::Deserialize)]
pub(crate) struct PatchSettingsReq {
    settings: serde_json::Map<String, serde_json::Value>,
}

/// `PATCH /api/v1/admin/hooks/{name}/settings` — push an opaque settings map to the RUNNING hook and
/// COMMIT ON ACK (D2): busbar sends the `configure` message over the hook's transport, waits for
/// the versioned ack (5s deadline), and only then swaps in the registry update (grants untouched —
/// immutability holds by construction) + persists + audits + versions. A nack/timeout/error
/// commits NOTHING (`invalid_request` names the reason). Base-defined hooks are 409 (edit the
/// file). Socket hooks ALSO receive the committed settings as the configure preamble on every
/// future (re)connection, so a restarted hook never runs blind.
pub(crate) async fn patch_hook_settings(
    State(handle): State<Arc<AppHandle>>,
    axum::Extension(principal): axum::Extension<crate::auth::AuthPrincipal>,
    axum::Extension(scope): axum::Extension<crate::auth::AdminScope>,
    Path(name): Path<String>,
    headers: axum::http::HeaderMap,
    body: axum::body::Bytes,
) -> Response {
    let actor = principal.actor_id().to_string();
    let expected = match if_match_version(&headers) {
        Ok(v) => v,
        Err(resp) => return resp,
    };
    let req: PatchSettingsReq = match serde_json::from_slice(&body) {
        Ok(r) => r,
        Err(e) => {
            return err_json(&AdminError::Validation(format!(
                "malformed settings body: {e}"
            )))
        }
    };
    // BOUND the settings map. It is persisted verbatim into the state file AND re-sent to the hook
    // as the configure preamble on EVERY (re)connection, so an unbounded map amplifies both the
    // snapshot size and per-reconnect wire traffic. Cap the serialized size and the key count as
    // defense-in-depth (admin-gated, but a compromised hooks-register token should not be able to
    // bloat the durable state / reconnect path). The caps are far past any real hook's settings.
    if let Err(e) = crate::admin::v1::service::validate_hook_settings_size(&req.settings) {
        return err_json(&e);
    }
    let current = handle.load();
    let resource = format!("hook:{name}");
    let Some(existing) = current.hook_registry.get(&name) else {
        // Audit the 404 like the other rejects here (and DELETE) — a missing audit row on the
        // unknown-name path lets a narrow token probe which hooks exist by response code alone.
        audit::AUDIT.record_by("hook.settings", &resource, audit::OUTCOME_REJECTED, &actor);
        return err_json(&AdminError::NotFound(format!("hook `{name}`")));
    };
    // §6.3 escalation guard, keyed on the EXISTING hook's grants (PATCH changes settings, not
    // grants). A non-Full (hooks-register) principal may not push settings to a content-seeing
    // (`prompt`/`user`) or `global: true` hook — the same ceiling register_hook/put_hook enforce.
    // Without it a narrow token could retune a `prompt: rw` global gate it can neither create nor
    // replace, reaching a content-seeing hook by the back door. (found: audit c1r6.)
    if let Some(e) = hooks_register_escalation(scope, existing) {
        audit::AUDIT.record_by("hook.settings", &resource, audit::OUTCOME_REJECTED, &actor);
        return err_json(&e);
    }
    if current.base_hook_names.contains(&name) {
        audit::AUDIT.record_by("hook.settings", &resource, audit::OUTCOME_REJECTED, &actor);
        return err_json(&AdminError::Conflict(format!(
            "hook `{name}` is defined in the base config file; edit config.yaml"
        )));
    }
    if let Some(e) = stale_if_match(expected, current.config_version) {
        audit::AUDIT.record_by("hook.settings", &resource, audit::OUTCOME_REJECTED, &actor);
        return err_json(&e);
    }
    let mut updated = existing.clone();
    updated.settings = req.settings;
    let pre_push_version = current.config_version;
    let settings_version = pre_push_version.wrapping_add(1);
    // PUSH first, COMMIT on ack — a hook that never acked never sees committed state it doesn't
    // hold (§6.5: no partial config ever goes live). The hook plugin env is captured here; the load()
    // that feeds the actual swap is re-taken AFTER the await, under the mutation lock.
    let hook_env = current.hook_env.clone();
    if let Err(e) = crate::hooks::push_configure(&updated, &name, settings_version, &hook_env).await
    {
        audit::AUDIT.record_by("hook.settings", &resource, audit::OUTCOME_REJECTED, &actor);
        return err_json(&AdminError::Validation(format!(
            "hook did not acknowledge the settings push: {e}"
        )));
    }
    // COMMIT under the mutation lock, guarding the configure-ack await window: if any config-plane
    // mutation landed while we were awaiting the ack, `current` is stale and swapping on it would
    // clobber that change (and reuse its version number). Re-validate the version under the lock;
    // a change means "config moved during your push" → 409, retry (the ack was for a now-stale
    // snapshot). Version unchanged ⇒ `current` is still the live snapshot, so the build is sound.
    let _mlock = CONFIG_MUTATION_LOCK.lock().await;
    let current = handle.load();
    if current.config_version != pre_push_version {
        audit::AUDIT.record_by("hook.settings", &resource, audit::OUTCOME_REJECTED, &actor);
        return err_json(&AdminError::Conflict(
            "config changed during the settings push; retry".to_string(),
        ));
    }
    match build_with_hook(&current, &name, updated) {
        Ok(next) => {
            let installed = Arc::new(next);
            handle.swap(installed.clone());
            audit::AUDIT.record_by("hook.settings", &resource, audit::OUTCOME_APPLIED, &actor);
            let cur = handle.load();
            installed.versions.record(
                installed.config_version,
                &actor,
                &format!("hook.settings {resource}"),
                &installed.hook_registry,
                &installed.global_hooks,
            );
            crate::config::overlay::persist(
                cur.overlay_path.as_deref(),
                &cur.hook_registry,
                &cur.global_hooks,
                None,
                Some(&name),
            );
            with_config_etag(
                respond(StatusCode::OK, service(&handle).get_hook(&name).await),
                installed.config_version,
            )
        }
        Err(e) => {
            audit::AUDIT.record_by("hook.settings", &resource, audit::OUTCOME_REJECTED, &actor);
            err_json(&e)
        }
    }
}

/// `GET /api/v1/admin/hooks/{name}/schema` — proxy the hook's self-described settings JSON Schema
/// (the `describe` wire message). `{"schema": null}` when the hook/transport doesn't answer.
pub(crate) async fn hook_schema(
    State(handle): State<Arc<AppHandle>>,
    Path(name): Path<String>,
) -> Response {
    let current = handle.load();
    let Some(hook) = current.hook_registry.get(&name) else {
        return err_json(&AdminError::NotFound(format!("hook `{name}`")));
    };
    let schema =
        crate::hooks::fetch_schema(&name, hook, current.config_version, &current.hook_env).await;
    ok_json(StatusCode::OK, &json!({ "name": name, "schema": schema }))
}

/// `GET /api/v1/admin/hooks/{name}/status` — the hook's OBSERVED state, live-queried over its
/// transport: the settings it is actually running + its version (vs busbar's DESIRED registry
/// copy, with a `drift` verdict) and its self-reported metrics (validated + bounded — a hostile
/// hook cannot flood; names/help are charset-enforced/sanitized so no content can ride a metric).
/// `reported: null` when the hook doesn't answer status (fail-open; the desired view still serves).
/// This is the control-plane read: a dashboard built on busbar sees what each plug is doing.
pub(crate) async fn hook_status(
    State(handle): State<Arc<AppHandle>>,
    Path(name): Path<String>,
) -> Response {
    let current = handle.load();
    let Some(hook) = current.hook_registry.get(&name) else {
        return err_json(&AdminError::NotFound(format!("hook `{name}`")));
    };
    let desired_version = current.config_version;
    let reported =
        crate::hooks::fetch_status(&name, hook, desired_version, &current.hook_env).await;
    let as_of = crate::store::now();
    let body = match reported {
        Some(r) => {
            // Drift: the hook runs a different settings version, or a DESIRED key is missing/
            // changed in its observed settings (extra self-managed keys are NOT drift).
            let settings_drift = r
                .settings
                .as_ref()
                .is_some_and(|obs| hook.settings.iter().any(|(k, v)| obs.get(k) != Some(v)));
            let version_drift = r.settings_version.is_some_and(|v| v != desired_version);
            let metrics = r
                .metrics
                .as_ref()
                .map(|m| {
                    crate::hooks::wire::parse_status_metrics(m)
                        .into_iter()
                        .map(|metric| {
                            let mut entry =
                                json!({"name": metric.name, "type": metric.kind, "value": metric.value});
                            // Optional members appear only when the hook sent them (absent ≠ null).
                            for (k, v) in [
                                ("labels", metric.labels.map(|l| json!(l))),
                                ("quantiles", metric.quantiles.map(|q| json!(q))),
                                ("estimated", metric.estimated.map(serde_json::Value::from)),
                                ("ci_low", metric.ci_low.map(serde_json::Value::from)),
                                ("ci_high", metric.ci_high.map(serde_json::Value::from)),
                                ("help", metric.help.map(serde_json::Value::from)),
                                ("label", metric.label.map(serde_json::Value::from)),
                                ("unit", metric.unit.map(serde_json::Value::from)),
                                ("viz", metric.viz.map(serde_json::Value::from)),
                                ("max", metric.max.map(serde_json::Value::from)),
                            ] {
                                if let Some(v) = v {
                                    entry[k] = v;
                                }
                            }
                            entry
                        })
                        .collect::<Vec<_>>()
                })
                .unwrap_or_default();
            json!({
                "name": name,
                "desired": {"settings": hook.settings, "settings_version": desired_version},
                "reported": {"settings": r.settings, "settings_version": r.settings_version},
                "drift": settings_drift || version_drift,
                "metrics": metrics,
                "as_of": as_of,
                "source": "live",
            })
        }
        None => json!({
            "name": name,
            "desired": {"settings": hook.settings, "settings_version": desired_version},
            "reported": serde_json::Value::Null,
            "drift": serde_json::Value::Null,
            // `metrics` is INVARIANTLY an array — `[]` here (not `{}`) so a strict consumer decoding
            // it as an array never has to special-case the no-status branch (busbar-ui review R5).
            "metrics": [],
            "as_of": as_of,
            "source": "live",
            "note": "hook did not answer status (unsupported or unreachable)",
        }),
    };
    ok_json(StatusCode::OK, &body)
}

/// The stable v1 GET endpoints (RELATIVE path, summary), the single source for both the
/// router-mount drift test and the OpenAPI `paths`. Paths are relative to `contract::ADMIN_PREFIX`
/// (no absolute path is hand-written anywhere — the `ap` helper derives them). Templated/POST
/// routes are documented separately in `openapi_doc`. Adding a GET endpoint means adding it here so
/// the doc + the drift guard both see it.
// Consumed by `openapi_doc()` (feature `openapi-schema`) and the router-resolve drift tests (which
// need the default auth features to build a router). In a `--no-default-features` build neither is
// compiled, so the const is genuinely unused there — allow it dead in every config (a plain `allow`
// never warns when it IS used, unlike `expect`).
#[allow(dead_code)]
pub(crate) const V1_GET_PATHS: &[(&str, &str)] = &[
    (
        "/info",
        "Version, compiled-in plugin proof, uptime, topology",
    ),
    (
        "/pools",
        "Pool topology (members + weights). ?detail=true inlines live member status (one call, no N+1)",
    ),
    ("/models", "Model lanes + upstream providers"),
    ("/providers", "Distinct providers + lane counts"),
    (PATH_HOOKS, "Hook registry (definitions)"),
    (
        PATH_GROUPS,
        "Group registry — the limit tree (parent chain, limits, child_default budget template)",
    ),
    (
        "/plugins",
        "Plugin catalog by type (compiled-in + external + dynamic-library)",
    ),
    (
        "/auth",
        "Ingress auth chain + upstream-credential mode",
    ),
    (
        PATH_ADMIN_AUTH,
        "Admin-plane auth config (the admin surface guard)",
    ),
    (
        "/usage",
        "Metering: current UTC-day bucket — {window, as_of, currency, total, by_model, by_key}, raw token split + derived spend_micros",
    ),
    (
        "/config",
        "Effective running config snapshot (redacted)",
    ),
    (
        "/audit",
        "Admin audit log — every mutation with its outcome (newest first). Page: ?limit=, ?cursor=; returns {items, next_cursor}",
    ),
    (
        "/config/versions",
        "Config version history (newest first; id/ts/principal/summary). Page: ?limit=, ?cursor=; returns {items, next_cursor}",
    ),
    ("/openapi.json", "This OpenAPI 3.1 document"),
];

/// Build the OpenAPI 3.1 document describing the v1 JSON-REST surface. Paths + methods + the stable
/// error envelope are the machine-readable contract (tooling generates clients + branches on the error
/// `code`). EVERY operation's success response (200/201) carries a typed body schema — a
/// `$ref` into `components.schemas`, derived by schemars from the real Rust response VIEW types (see
/// `contract` + `contract::schema`) so the schema always matches what serde actually serializes.
///
/// CI-ONLY (`#[cfg(feature = "openapi-schema")]`): schemars is not compiled into the shipped binary.
/// The generated doc is committed as `json/openapi.json` and served verbatim by the live handler
/// (`openapi()` via `include_str!`); the golden/drift test keeps the committed file byte-equal to
/// this function's output, so the static file can never drift from the code.
#[cfg(feature = "openapi-schema")]
// Invoked from the openapi tests + the CI artifact/drift jobs (all test targets); a non-test
// feature-on bin build has no caller, so allow it dead there.
#[cfg_attr(not(test), allow(dead_code))]
pub(crate) fn openapi_doc() -> serde_json::Value {
    let mut paths = serde_json::Map::new();
    for (path, summary) in V1_GET_PATHS {
        paths.insert(
            ap(path),
            json!({
                "get": {
                    "summary": summary,
                    "security": [{"adminToken": []}],
                    "responses": {
                        "200": {"description": "OK"},
                        "401": {"description": "Missing/invalid admin credential"}
                    }
                }
            }),
        );
    }
    // Runtime hook registration: POST on the /hooks collection (merged onto its GET entry above).
    if let Some(obj) = paths
        .get_mut(&ap(PATH_HOOKS))
        .and_then(|p| p.as_object_mut())
    {
        obj.insert(
            "post".to_string(),
            json!({
                "summary": "Register (or replace) a hook at runtime — live immediately",
                "security": [{"adminToken": []}],
                "responses": {
                    "201": {"description": "Registered — the name is NEW (body is the hook definition)"},
                    "200": {"description": "Replaced — the name existed (same-grant re-register; body is the hook definition)"},
                    "400": {"description": "Malformed body or invalid definition (`invalid_request`)"},
                    "403": {"description": "hooks-register principal may not register a content-seeing (`prompt`/`user`) or `global: true` hook (`forbidden`, §6.3)"},
                    "409": {"description": "Base-defined hook (edit config.yaml), grant change on an existing hook, or stale `If-Match` (`version_conflict`, §6.4)"}
                }
            }),
        );
    }
    // Runtime group creation: POST on the /groups collection (merged onto its GET entry above).
    if let Some(obj) = paths
        .get_mut(&ap(PATH_GROUPS))
        .and_then(|p| p.as_object_mut())
    {
        obj.insert(
            "post".to_string(),
            json!({
                "summary": "Create (or replace) a group at runtime — live immediately (upsert)",
                "security": [{"adminToken": []}],
                "responses": {
                    "201": {"description": "Created — the name is NEW (body is the group definition)"},
                    "200": {"description": "Replaced — the name existed (body is the group definition)"},
                    "400": {"description": "Invalid tree — dangling/cyclic parent or depth (`invalid_request`)"},
                    "409": {"description": "Base-defined group (edit config.yaml) or stale `If-Match` (`version_conflict`)"}
                }
            }),
        );
    }
    // Plugin INSTALL: POST on the /plugins collection (merged onto its GET entry above).
    if let Some(obj) = paths
        .get_mut(&ap("/plugins"))
        .and_then(|p| p.as_object_mut())
    {
        obj.insert(
            "post".to_string(),
            json!({
                "summary": "Install a dynamic-library store plugin: upload the library (base64) + optional signed manifest; the engine RE-VERIFIES against the running trust posture, validates the store ABI, and writes it atomically into the plugins directory. Takes effect on the next store (re)load",
                "security": [{"adminToken": []}],
                "responses": {
                    "201": {"description": "Installed — `{file, name, interface_version, trust, version?, publisher?, note}`"},
                    "400": {"description": "Malformed body, bad base64, or the library is not a loadable busbar store plugin (`invalid_request`)"},
                    "409": {"description": "The upload is untrusted and not opted-in (`conflict`) - sign it with an allowlisted publisher, add the publisher to plugins.trust.publishers, or set plugins.trust.allow_unsigned / allow_third_party"}
                }
            }),
        );
    }
    // Plugin RELOAD + REMOVE (templated).
    paths.insert(
        ap("/plugins/reload"),
        json!({
            "post": {
                "summary": "Re-scan the plugins directory and report the reconciled dynamic-library inventory (the sibling of config/reload). A store change takes effect on the next store (re)load",
                "security": [{"adminToken": []}],
                "responses": {
                    "200": {"description": "`{plugins, note}` — the current dynamic-library inventory"}
                }
            }
        }),
    );
    paths.insert(
        ap("/plugins/{file}"),
        json!({
            "delete": {
                "summary": "Remove a dynamic-library plugin (library + manifest sidecar) from the plugins directory. A loaded store keeps running until the next store (re)load",
                "security": [{"adminToken": []}],
                "parameters": [{
                    "name": "file", "in": "path", "required": true,
                    "schema": {"type": "string"}
                }],
                "responses": {
                    "204": {"description": "Removed"},
                    "400": {"description": "Invalid plugin filename (`invalid_request`)"},
                    "404": {"description": "No such plugin file (`not_found`)"}
                }
            }
        }),
    );
    // Templated + non-GET routes.
    paths.insert(
        ap("/hooks/{name}"),
        json!({
            "get": {
                "summary": "One hook definition",
                "security": [{"adminToken": []}],
                "parameters": [{
                    "name": "name", "in": "path", "required": true,
                    "schema": {"type": "string"}
                }],
                "responses": {
                    "200": {"description": "OK"},
                    "404": {"description": "Unknown hook (error code `not_found`)"}
                }
            },
            "put": {
                "summary": "Replace an overlay hook definition — live immediately (grants immutable)",
                "security": [{"adminToken": []}],
                "parameters": [{
                    "name": "name", "in": "path", "required": true,
                    "schema": {"type": "string"}
                }],
                "responses": {
                    "200": {"description": "The replaced hook"},
                    "400": {"description": "Invalid definition (error code `invalid_request`)"},
                    "403": {"description": "A `hooks-register` principal may not replace a hook into a content-seeing (`prompt`/`user`) or `global` form (error code `forbidden`, §6.3)"},
                    "404": {"description": "Unknown hook (error code `not_found`)"},
                    "409": {"description": "Base-defined hook, grant change (`conflict`), or stale `If-Match` (`version_conflict`)"}
                }
            },
            "delete": {
                "summary": "Remove a hook at runtime — live immediately",
                "security": [{"adminToken": []}],
                "parameters": [{
                    "name": "name", "in": "path", "required": true,
                    "schema": {"type": "string"}
                }],
                "responses": {
                    "204": {"description": "Removed"},
                    "403": {"description": "A `hooks-register` principal may not delete a content-seeing (`prompt`/`user`) or `global` hook (error code `forbidden`, §6.3)"},
                    "404": {"description": "Unknown hook (error code `not_found`)"},
                    "409": {"description": "Base-defined hook — read-only via the API; edit config.yaml (error code `conflict`)"}
                }
            }
        }),
    );
    paths.insert(
        ap("/groups/{name}"),
        json!({
            "get": {
                "summary": "One group definition (parent, enabled, limits, child_default)",
                "security": [{"adminToken": []}],
                "parameters": [{
                    "name": "name", "in": "path", "required": true,
                    "schema": {"type": "string"}
                }],
                "responses": {
                    "200": {"description": "OK"},
                    "404": {"description": "Unknown group (error code `not_found`)"}
                }
            },
            "put": {
                "summary": "Replace an overlay group definition — live immediately (limits rebuilt)",
                "security": [{"adminToken": []}],
                "parameters": [{
                    "name": "name", "in": "path", "required": true,
                    "schema": {"type": "string"}
                }],
                "responses": {
                    "200": {"description": "The replaced group"},
                    "400": {"description": "Invalid tree — dangling/cyclic parent or depth (error code `invalid_request`)"},
                    "404": {"description": "Unknown group (error code `not_found`)"},
                    "409": {"description": "Base-defined group (edit config.yaml), or stale `If-Match` (`version_conflict`)"}
                }
            },
            "patch": {
                "summary": "Partial update — change only the fields present (e.g. raise a budget, freeze a group)",
                "security": [{"adminToken": []}],
                "parameters": [{
                    "name": "name", "in": "path", "required": true,
                    "schema": {"type": "string"}
                }],
                "responses": {
                    "200": {"description": "The updated group"},
                    "400": {"description": "Invalid tree after the merge, or unknown patch field (error code `invalid_request`)"},
                    "404": {"description": "Unknown group (error code `not_found`)"},
                    "409": {"description": "Base-defined group, or stale `If-Match` (`version_conflict`)"}
                }
            },
            "delete": {
                "summary": "Remove an overlay group at runtime — live immediately",
                "security": [{"adminToken": []}],
                "parameters": [{
                    "name": "name", "in": "path", "required": true,
                    "schema": {"type": "string"}
                }],
                "responses": {
                    "204": {"description": "Removed"},
                    "404": {"description": "Unknown group (error code `not_found`)"},
                    "409": {"description": "Base-defined group, or another group still names it as parent (error code `conflict`)"}
                }
            }
        }),
    );
    paths.insert(
        ap("/pools/{name}"),
        json!({
            "get": {
                "summary": "Live per-member status of one pool (breaker/concurrency/latency)",
                "security": [{"adminToken": []}],
                "parameters": [{
                    "name": "name", "in": "path", "required": true,
                    "schema": {"type": "string"}
                }],
                "responses": {
                    "200": {"description": "OK"},
                    "404": {"description": "Unknown pool (error code `not_found`)"}
                }
            }
        }),
    );
    paths.insert(
        ap("/groups/{name}/usage"),
        json!({
            "get": {
                "summary": "The group's derived current-window usage per (window, pool) enforcement bucket vs its caps — the self-service dashboard read (spend derives from the token ledger x the CURRENT rate card at read time)",
                "security": [{"adminToken": []}],
                "parameters": [{
                    "name": "name", "in": "path", "required": true,
                    "schema": {"type": "string"}
                }],
                "responses": {
                    "200": {"description": "OK"},
                    "404": {"description": "Unknown group (error code `not_found`)"}
                }
            }
        }),
    );
    paths.insert(
        ap("/hooks/{name}/health"),
        json!({
            "get": {
                "summary": "Best-effort hook transport reachability",
                "security": [{"adminToken": []}],
                "parameters": [{
                    "name": "name", "in": "path", "required": true,
                    "schema": {"type": "string"}
                }],
                "responses": {
                    "200": {"description": "OK (`reachable` may be null for webhook/non-unix)"},
                    "404": {"description": "Unknown hook (error code `not_found`)"}
                }
            }
        }),
    );
    paths.insert(
        ap("/config/diff"),
        json!({
            "get": {
                "summary": "Structured hook-surface diff between two retained versions",
                "security": [{"adminToken": []}],
                "parameters": [
                    {"name": "from", "in": "query", "required": true, "schema": {"type": "integer"}},
                    {"name": "to", "in": "query", "required": true, "schema": {"type": "integer"}}
                ],
                "responses": {
                    "200": {"description": "The diff (hooks added/removed/changed + global-wiring delta)"},
                    "400": {"description": "Missing/non-numeric `from` or `to` (error code `invalid_request`)"},
                    "404": {"description": "Either version pruned or never recorded (error code `not_found`)"},
                    "401": {"description": "Missing/invalid admin credential"}
                }
            }
        }),
    );
    paths.insert(
        ap("/config/versions/{v}"),
        json!({
            "get": {
                "summary": "One retained config version, with its hook-surface snapshot",
                "security": [{"adminToken": []}],
                "parameters": [{
                    "name": "v", "in": "path", "required": true,
                    "schema": {"type": "integer"}
                }],
                "responses": {
                    "200": {"description": "The version (metadata + hooks + global_hooks)"},
                    "404": {"description": "Pruned or never recorded (error code `not_found`)"}
                }
            }
        }),
    );
    paths.insert(
        ap("/hooks/{name}/settings"),
        json!({
            "patch": {
                "summary": "Push an opaque settings map to the running hook; COMMIT ON ACK",
                "security": [{"adminToken": []}],
                "parameters": [{
                    "name": "name", "in": "path", "required": true,
                    "schema": {"type": "string"}
                }],
                "responses": {
                    "200": {"description": "Acked + committed (the updated hook)"},
                    "400": {"description": "Hook did not acknowledge (error code `invalid_request`); nothing committed"},
                    "403": {"description": "A `hooks-register` principal may not push settings to a content-seeing (`prompt`/`user`) or `global` hook (error code `forbidden`, §6.3)"},
                    "404": {"description": "Unknown hook (error code `not_found`)"},
                    "409": {"description": "Base-defined hook (`conflict`) or stale `If-Match` (`version_conflict`)"}
                }
            }
        }),
    );
    paths.insert(
        ap("/hooks/{name}/schema"),
        json!({
            "get": {
                "summary": "The hook's self-described settings JSON Schema (describe proxy)",
                "security": [{"adminToken": []}],
                "parameters": [{
                    "name": "name", "in": "path", "required": true,
                    "schema": {"type": "string"}
                }],
                "responses": {
                    "200": {"description": "`{name, schema}` (`schema` null when the hook doesn't answer describe)"},
                    "404": {"description": "Unknown hook (error code `not_found`)"}
                }
            }
        }),
    );
    paths.insert(
        ap("/hooks/{name}/status"),
        json!({
            "get": {
                "summary": "The hook's OBSERVED state, live-queried: running settings + version (vs busbar's desired copy, with a drift verdict) and self-reported metrics. reported=null when the hook doesn't answer (fail-open)",
                "security": [{"adminToken": []}],
                "parameters": [{
                    "name": "name", "in": "path", "required": true,
                    "schema": {"type": "string"}
                }],
                "responses": {
                    "200": {"description": "`{name, desired, reported, drift, metrics, as_of, source}`"},
                    "404": {"description": "Unknown hook (error code `not_found`)"}
                }
            }
        }),
    );
    paths.insert(
        ap("/config/apply"),
        json!({
            "post": {
                "summary": "Apply a full config from the request body, atomically (live until next reload/restart; health preserved by lane identity)",
                "security": [{"adminToken": []}],
                "responses": {
                    "200": {"description": "`{applied, config_version, note}`"},
                    "400": {"description": "Invalid config (error code `invalid_request`); nothing changed"},
                    "409": {"description": "Stale `If-Match` (error code `version_conflict` — re-read and retry)"}
                }
            }
        }),
    );
    paths.insert(
        ap("/config/reload"),
        json!({
            "post": {
                "summary": "Re-read config.yaml/providers.yaml from disk and apply atomically (health state preserved by lane identity)",
                "security": [{"adminToken": []}],
                "responses": {
                    "200": {"description": "`{reloaded, config_version}`"},
                    "400": {"description": "Disk config invalid or no config files (error code `invalid_request`); nothing changed"}
                }
            }
        }),
    );
    paths.insert(
        ap("/config/settings"),
        json!({
            "get": {
                "summary": "Read the API-set single-value config overlay (root section: listen/tls/rate_card/store/security/limits/…) — only the operator's overrides; base config.yaml stands for the rest",
                "security": [{"adminToken": []}],
                "responses": {
                    "200": {"description": "`{applied:false, config_version, settings}` (settings = the current root overrides)"},
                    "401": {"description": "Missing/invalid admin credential"}
                }
            },
            "put": {
                "summary": "SET any single-value config section durably (1.5.0 full-config coverage): partial RootSettings merged onto the overlay, re-resolved + validated, swapped in. rate_card/per_request_fee/security/limits/… go live; listen/tls/admin_listen/admin_tls/admin_insecure/store are stored + flagged reload-to-apply. NEVER writes config.yaml",
                "security": [{"adminToken": []}],
                "responses": {
                    "200": {"description": "`{applied:true, config_version, settings, reload_to_apply, note}`"},
                    "400": {"description": "Invalid config after the merge, unknown field, or ephemeral busbar with no disk base (error code `invalid_request`); nothing changed"},
                    "409": {"description": "Stale `If-Match` (error code `version_conflict` — re-read and retry)"}
                }
            }
        }),
    );
    if let Some(auth_path) = paths.get_mut(&ap(PATH_ADMIN_AUTH)) {
        auth_path["put"] = json!({
            "summary": "Replace the admin_auth chain at runtime — dry-run guarded (the calling credentials must hold full scope under the NEW chain, else 409). Live until the next reload/restart",
            "security": [{"adminToken": []}],
            "responses": {
                "200": {"description": "The resource + apply metadata: `{configured, modules, applied, config_version, note}`"},
                "400": {"description": "Unknown module / malformed body (error code `invalid_request`)"},
                "409": {"description": "Stale `If-Match` (`version_conflict`), or the new chain would lock the caller out (error code `conflict`)"}
            }
        });
    }
    paths.insert(
        ap("/auth/cache/flush"),
        json!({
            "post": {
                "summary": "Flush the credential cache — one module's partition (`{module}`) or everything (empty body). Instant revocation of the cached-allow window",
                "security": [{"adminToken": []}],
                "responses": {
                    "200": {"description": "`{flushed}` — entries dropped"},
                    "400": {"description": "Malformed body (error code `invalid_request`)"}
                }
            }
        }),
    );
    paths.insert(
        ap("/config/rollback"),
        json!({
            "post": {
                "summary": "Restore a retained version's hook surface (re-validated; a NEW version)",
                "security": [{"adminToken": []}],
                "responses": {
                    "200": {"description": "`{restored_version, config_version}`"},
                    "404": {"description": "Target version not retained (error code `not_found`)"},
                    "409": {"description": "Stale `If-Match` (error code `version_conflict` — re-read and retry)"},
                    "400": {"description": "Snapshot fails re-validation (error code `invalid_request`)"}
                }
            }
        }),
    );
    paths.insert(
        ap("/overlay/{section}"),
        json!({
            "delete": {
                "summary": "DISCARD a section's overlay mutations and revert it to base config.yaml (section ∈ groups|hooks). Per-section reset — the OTHER section's overlay survives. A NEW config version; an already-empty section is an idempotent no-op (changed:false)",
                "security": [{"adminToken": []}],
                "parameters": [{"name": "section", "in": "path", "required": true, "schema": {"type": "string", "enum": ["groups", "hooks"]}}],
                "responses": {
                    "200": {"description": "`{reset, config_version, changed}` — changed:false when the section had no overlay state"},
                    "400": {"description": "Unknown section, or ephemeral busbar with no config files to revert to (error code `invalid_request`)"},
                    "409": {"description": "Stale `If-Match` (error code `version_conflict` — re-read and retry)"}
                }
            }
        }),
    );
    paths.insert(
        ap(PATH_CONFIG_VALIDATE),
        json!({
            "post": {
                "summary": "Dry-run validate a proposed config",
                "security": [{"adminToken": []}],
                "responses": {
                    "200": {"description": "Verdict `{ok, errors}` (even for an invalid config)"},
                    "400": {"description": "Malformed request body (error code `invalid_request`)"}
                }
            }
        }),
    );

    // Virtual-key management (mounted in the v1 router like everything else; handlers live in
    // crate::admin while they migrate into the service). The secret is shown ONCE at create/rotate
    // and never read back.
    paths.insert(
        ap("/keys"),
        json!({
            "get": {
                "summary": "List virtual keys (metadata only; never secrets). Filters: ?enabled=, ?prefix=, ?group= (keys bound to a group — a `user:<sub>` leaf's keys are one person's). Paginate: ?limit=, ?cursor= (opaque)",
                "security": [{"adminToken": []}],
                "responses": {
                    "200": {"description": "`{items, next_cursor}` — the cursor page envelope (next_cursor null at end)"},
                    "400": {"description": "Malformed/foreign pagination cursor (error code `invalid_request`)"},
                    "401": {"description": "Missing/invalid admin credential"}
                }
            },
            "post": {
                "summary": "Mint a virtual key. The secret is returned EXACTLY once. Honors an `Idempotency-Key` header (per-principal ~10min replay)",
                "security": [{"adminToken": []}],
                "responses": {
                    "201": {"description": "Created (body includes the once-shown secret)"},
                    "400": {"description": "Malformed body / invalid budget or rate (error code `invalid_request`)"},
                    "409": {"description": "An Idempotency-Key request is already in flight (error code `conflict`)"}
                }
            }
        }),
    );
    paths.insert(
        ap("/keys/{id}"),
        json!({
            "get": {
                "summary": "One key's metadata + `ETag` (never the secret/hash)",
                "security": [{"adminToken": []}],
                "parameters": [{"name": "id", "in": "path", "required": true, "schema": {"type": "string"}}],
                "responses": {
                    "200": {"description": "Key metadata (+ `ETag` header)"},
                    "404": {"description": "Unknown key (error code `not_found`)"}
                }
            },
            "patch": {
                "summary": "Update budget / rate / enabled. Optional `If-Match` for optimistic concurrency",
                "security": [{"adminToken": []}],
                "parameters": [{"name": "id", "in": "path", "required": true, "schema": {"type": "string"}}],
                "responses": {
                    "200": {"description": "Updated metadata"},
                    "400": {"description": "Invalid budget/rate (error code `invalid_request`)"},
                    "404": {"description": "Unknown key (error code `not_found`)"},
                    "409": {"description": "Stale `If-Match` ETag (error code `version_conflict` — re-read and retry)"}
                }
            },
            "delete": {
                "summary": "Revoke a key — it stops resolving immediately. Optional `If-Match` (the key's ETag)",
                "security": [{"adminToken": []}],
                "parameters": [{"name": "id", "in": "path", "required": true, "schema": {"type": "string"}}],
                "responses": {
                    "204": {"description": "Revoked — No Content"},
                    "400": {"description": "Malformed `If-Match` (error code `invalid_request`)"},
                    "404": {"description": "Unknown key (error code `not_found`)"},
                    "409": {"description": "Stale `If-Match` ETag (error code `version_conflict` — re-read and retry)"}
                }
            }
        }),
    );
    paths.insert(
        ap("/keys/{id}/usage"),
        json!({
            "get": {
                "summary": "Current-window usage for one key (spend / tokens / requests)",
                "security": [{"adminToken": []}],
                "parameters": [{"name": "id", "in": "path", "required": true, "schema": {"type": "string"}}],
                "responses": {
                    "200": {"description": "Budget-window counters + `rate_headroom` (fraction of the tightest RPM/TPM cap left; null = uncapped)"},
                    "404": {"description": "Unknown key (error code `not_found`)"}
                }
            }
        }),
    );
    paths.insert(
        ap("/keys/{id}/rotate"),
        json!({
            "post": {
                "summary": "Mint a fresh secret in place (same id, budgets, usage). The new secret is shown once; the old stops resolving. Honors an `Idempotency-Key` header (per-principal, op+id-scoped, ~10min replay)",
                "security": [{"adminToken": []}],
                "parameters": [{"name": "id", "in": "path", "required": true, "schema": {"type": "string"}}],
                "responses": {
                    "200": {"description": "Rotated (body includes the once-shown new secret; an Idempotency-Key retry replays it verbatim)"},
                    "404": {"description": "Unknown key (error code `not_found`)"},
                    "409": {"description": "An Idempotency-Key request is already in flight (error code `conflict`)"}
                }
            }
        }),
    );

    // Stamp EVERY path+method with its required admin scope (`x-busbar-required-scope`) from the
    // SAME `required_scope` matrix the middleware enforces — the machine-readable authorization
    // matrix (§6.3), drift-proof by construction because both readers share one function. The
    // matrix keys on the literal path shape; templated segments (`{name}`) sit inside the same
    // prefix the matcher tests, so the annotation is exact for every route documented here.
    for (path, methods) in paths.iter_mut() {
        if let Some(obj) = methods.as_object_mut() {
            for (method, op) in obj.iter_mut() {
                let m = match method.as_str() {
                    "get" => axum::http::Method::GET,
                    "post" => axum::http::Method::POST,
                    "put" => axum::http::Method::PUT,
                    "patch" => axum::http::Method::PATCH,
                    "delete" => axum::http::Method::DELETE,
                    _ => continue,
                };
                if let Some(op) = op.as_object_mut() {
                    let scope = crate::admin::v1::contract::required_scope(&m, path);
                    op.insert("x-busbar-required-scope".to_string(), json!(scope.as_str()));
                    // Both accepted credential carriers, on every op (re-audit M8).
                    op.insert(
                        "security".to_string(),
                        json!([{"adminToken": []}, {"bearerAuth": []}]),
                    );
                    // The always-possible responses, stamped algorithmically so no hand-written
                    // entry can forget them (re-audit M7): 401 (bad/missing credential), 403
                    // (authenticated but under-scoped), and 429 on every mutation (the
                    // per-principal mutation budget).
                    if let Some(responses) = op.get_mut("responses").and_then(|r| r.as_object_mut())
                    {
                        responses.entry("401").or_insert(json!(
                            {"description": "Missing/invalid admin credential (error code `unauthorized`)"}
                        ));
                        responses.entry("403").or_insert(json!({"description": format!(
                            "Authenticated but under-scoped: requires `{}` (error code `forbidden`)",
                            scope.as_str()
                        )}));
                        if m != axum::http::Method::GET && m != axum::http::Method::HEAD {
                            responses.entry("429").or_insert(json!(
                                {"description": "Per-principal mutation budget exhausted (error code `rate_limited`; `Retry-After` header)"}
                            ));
                        }
                    }
                }
            }
        }
    }

    // Machine-readable QUERY PARAMETERS for the list/filter GETs (re-audit M7) — previously prose-
    // only, so generated clients had no query surface. Stamped from one table.
    /// (name, description, required) — one documented query parameter.
    type QueryParam = (&'static str, &'static str, bool);
    const QUERY_PARAMS: &[(&str, &[QueryParam])] = &[
        (
            "/keys",
            &[
                ("enabled", "Filter by enabled state (`true`|`false`)", false),
                ("prefix", "Filter by key-id prefix", false),
                ("limit", "Page size (default 200, max 1000)", false),
                (
                    "cursor",
                    "Opaque continuation cursor from `next_cursor`",
                    false,
                ),
            ],
        ),
        (
            "/audit",
            &[
                (
                    "action",
                    "Filter by exact action (e.g. `hook.register`)",
                    false,
                ),
                (
                    "resource",
                    "Filter by exact resource (e.g. `hook:x`)",
                    false,
                ),
                ("limit", "Page size (default 200, max 1000)", false),
                (
                    "cursor",
                    "Opaque continuation cursor from `next_cursor`",
                    false,
                ),
            ],
        ),
        (
            "/config/versions",
            &[
                ("limit", "Page size (default 100, max 1000)", false),
                (
                    "cursor",
                    "Opaque continuation cursor from `next_cursor`",
                    false,
                ),
            ],
        ),
        (
            "/plugins",
            &[(
                "type",
                "Plugin type: `auth` | `hooks` | `store` (required)",
                true,
            )],
        ),
        (
            "/usage",
            &[(
                "window",
                "A PAST UTC-day bucket start epoch (default: current bucket). The response is always ONE bucket; spend_micros is a read-time estimate — bill from the raw token split, never store spend_micros as a ledger charge",
                false,
            )],
        ),
        (
            "/pools",
            &[(
                "detail",
                "`true` inlines each member's live status (same row shape as /pools/{name})",
                false,
            )],
        ),
    ];
    for (path, params) in QUERY_PARAMS {
        if let Some(op) = paths
            .get_mut(&ap(path))
            .and_then(|p| p.get_mut("get"))
            .and_then(|op| op.as_object_mut())
        {
            let list: Vec<serde_json::Value> = params
                .iter()
                .map(|(name, desc, required)| {
                    json!({"name": name, "in": "query", "required": required,
                           "schema": {"type": "string"}, "description": desc})
                })
                .collect();
            match op.get_mut("parameters").and_then(|p| p.as_array_mut()) {
                Some(existing) => existing.extend(list),
                None => {
                    op.insert("parameters".to_string(), json!(list));
                }
            }
        }
    }

    // Stamp the `If-Match` header parameter onto every version-guarded mutation (H3: the ONE
    // optimistic-concurrency mechanism across the surface). Driven by an explicit op list — NOT
    // "every mutation" — because the unguarded ops (validate: stateless dry-run; reload: returns to
    // disk truth unconditionally; cache/flush, key create/rotate: no versioned resource) must not
    // advertise a guard they don't enforce. Keys PATCH/DELETE guard on the KEY's own ETag; the
    // config-plane ops guard on the config-version ETag their reads emit.
    const IF_MATCH_GUARDED: &[(&str, &str)] = &[
        (PATH_HOOKS, "post"),
        ("/hooks/{name}", "put"),
        ("/hooks/{name}", "delete"),
        ("/hooks/{name}/settings", "patch"),
        (PATH_ADMIN_AUTH, "put"),
        ("/config/apply", "post"),
        ("/config/settings", "put"),
        ("/config/rollback", "post"),
        ("/overlay/{section}", "delete"),
        ("/keys/{id}", "patch"),
        ("/keys/{id}", "delete"),
    ];
    for (path, method) in IF_MATCH_GUARDED {
        if let Some(op) = paths
            .get_mut(&ap(path))
            .and_then(|p| p.get_mut(*method))
            .and_then(|op| op.as_object_mut())
        {
            let param = json!({
                "name": "If-Match", "in": "header", "required": false,
                "schema": {"type": "string"},
                "description": "Optimistic concurrency: the resource's ETag from a prior read \
                                (or the ETag returned by the previous mutation). Stale = 409 \
                                `version_conflict` (re-read and retry), nothing changes; absent \
                                or `*` = unconditional."
            });
            match op.get_mut("parameters").and_then(|p| p.as_array_mut()) {
                Some(params) => params.push(param),
                None => {
                    op.insert("parameters".to_string(), json!([param]));
                }
            }
        }
    }

    // ── TYPED RESPONSE SCHEMAS ────────────────────────────────────────────────────────────────
    // Attach a `$ref` body schema to every operation's success response, and collect the referenced
    // component schemas from schemars — derived from the real Rust response VIEW types, so the doc's
    // response shapes always match what serde serializes. Driven by a table keyed on
    // (relative-path, method, status); `attach` resolves the type to a `#/components/schemas/<T>`
    // ref, records it in `gen`, and writes the `content` block.
    use crate::admin::v1::contract::schema as sview;
    let mut gen = schemars::generate::SchemaSettings::draft2020_12()
        .with(|s| {
            // OpenAPI 3.1 keeps component schemas under `#/components/schemas`; strip the per-schema
            // `$schema` meta (OpenAPI carries one document-level dialect, not one per component).
            s.definitions_path = "/components/schemas".into();
            s.meta_schema = None;
        })
        // The doc describes RESPONSES (what busbar SERIALIZES), so generate the serialize-contract
        // schema — this is what makes `skip_serializing_if` fields non-required, matching the wire.
        .for_serialize()
        .into_generator();

    /// Write `content: { application/json: { schema: <schema> } }` onto one operation's `<status>`
    /// response object (creating the response entry if the op didn't already document that status).
    fn set_content(op: &mut serde_json::Value, status: &str, schema: serde_json::Value) {
        let Some(responses) = op.get_mut("responses").and_then(|r| r.as_object_mut()) else {
            return;
        };
        let entry = responses
            .entry(status.to_string())
            .or_insert_with(|| json!({"description": "OK"}));
        if let Some(obj) = entry.as_object_mut() {
            obj.insert(
                "content".to_string(),
                json!({"application/json": {"schema": schema}}),
            );
        }
    }

    // Resolve an operation object (by relative path + method) for schema attachment.
    macro_rules! op {
        ($rel:expr, $method:literal) => {
            paths.get_mut(&ap($rel)).and_then(|p| p.get_mut($method))
        };
    }
    // Attach the `$ref` schema of type `$t` to `<rel>.<method>.responses.<status>`.
    macro_rules! typed {
        ($rel:expr, $method:literal, $status:literal, $t:ty) => {{
            let schema = gen.subschema_for::<$t>();
            let schema = serde_json::to_value(schema).unwrap_or_else(|_| json!({}));
            if let Some(op) = op!($rel, $method) {
                set_content(op, $status, schema);
            }
        }};
    }

    use crate::admin::v1::contract::{
        AdminAuthView, AuthView, ConfigValidateView, EffectiveConfigView, GroupView,
        HookHealthView, HookView, InfoView, ModelView, Page, PluginInstallView, PluginReloadView,
        PluginView, PoolDetailView, PoolView, ProviderView, UsageView,
    };

    // Info & topology.
    typed!("/info", "get", "200", InfoView);
    typed!("/pools", "get", "200", Page<PoolView>);
    typed!("/pools/{name}", "get", "200", PoolDetailView);
    typed!("/models", "get", "200", Page<ModelView>);
    typed!("/providers", "get", "200", Page<ProviderView>);
    // Hooks.
    typed!(PATH_HOOKS, "get", "200", Page<HookView>);
    typed!(PATH_HOOKS, "post", "201", HookView);
    typed!(PATH_HOOKS, "post", "200", HookView);
    typed!("/hooks/{name}", "get", "200", HookView);
    typed!("/hooks/{name}", "put", "200", HookView);
    typed!("/hooks/{name}/settings", "patch", "200", HookView);
    typed!("/hooks/{name}/health", "get", "200", HookHealthView);
    typed!("/hooks/{name}/schema", "get", "200", sview::HookSchemaView);
    typed!("/hooks/{name}/status", "get", "200", sview::HookStatusView);
    // Groups (the limit tree).
    typed!(PATH_GROUPS, "get", "200", Page<GroupView>);
    typed!(PATH_GROUPS, "post", "201", GroupView);
    typed!(PATH_GROUPS, "post", "200", GroupView);
    typed!("/groups/{name}", "get", "200", GroupView);
    typed!("/groups/{name}", "put", "200", GroupView);
    typed!("/groups/{name}", "patch", "200", GroupView);
    typed!(
        "/groups/{name}/usage",
        "get",
        "200",
        crate::admin::v1::contract::GroupUsageView
    );
    // Auth & credentials.
    typed!("/auth", "get", "200", AuthView);
    typed!(PATH_ADMIN_AUTH, "get", "200", AdminAuthView);
    typed!(PATH_ADMIN_AUTH, "put", "200", sview::AdminAuthPutView);
    typed!("/auth/cache/flush", "post", "200", sview::CacheFlushView);
    // Plugins, usage, config.
    typed!("/plugins", "get", "200", Page<PluginView>);
    typed!("/plugins", "post", "201", PluginInstallView);
    typed!("/plugins/reload", "post", "200", PluginReloadView);
    typed!("/usage", "get", "200", UsageView);
    typed!("/config", "get", "200", EffectiveConfigView);
    typed!(PATH_CONFIG_VALIDATE, "post", "200", ConfigValidateView);
    typed!("/config/apply", "post", "200", sview::ConfigApplyView);
    typed!("/config/settings", "get", "200", sview::ConfigSettingsView);
    typed!("/config/settings", "put", "200", sview::ConfigSettingsView);
    typed!("/config/reload", "post", "200", sview::ConfigReloadView);
    typed!("/config/rollback", "post", "200", sview::ConfigRollbackView);
    typed!(
        "/overlay/{section}",
        "delete",
        "200",
        sview::OverlayResetView
    );
    typed!("/config/diff", "get", "200", sview::ConfigDiffView);
    typed!(
        "/config/versions",
        "get",
        "200",
        sview::ConfigVersionPageView
    );
    typed!(
        "/config/versions/{v}",
        "get",
        "200",
        sview::ConfigVersionDetailView
    );
    typed!("/audit", "get", "200", sview::AuditPageView);
    // Virtual keys.
    typed!("/keys", "get", "200", sview::KeyPageView);
    typed!("/keys", "post", "201", sview::CreatedKeyView);
    typed!("/keys/{id}", "get", "200", sview::KeyView);
    typed!("/keys/{id}", "patch", "200", sview::KeyView);
    typed!("/keys/{id}/usage", "get", "200", sview::KeyMeteringView);
    typed!("/keys/{id}/rotate", "post", "200", sview::RotatedKeyView);

    // The discovery endpoint returns THIS very OpenAPI 3.1 document — an arbitrary object. There is
    // no named struct for "an OpenAPI document"; an inline permissive object schema is the honest
    // description (fully modeling the OpenAPI meta-schema is out of scope + circular).
    if let Some(op) = op!("/openapi.json", "get") {
        set_content(
            op,
            "200",
            json!({"type": "object", "description": "An OpenAPI 3.1 document (this document's shape)"}),
        );
    }

    // The stable ERROR envelope. Reference it as the body of every documented ERROR status
    // (4xx/5xx) so a generated client decodes errors with the same typed model it decodes successes.
    // The `Error` component itself is the hand-written schema below (code enum + message), so the
    // schemars `ErrorBody` is NOT registered — we point error responses at `#/components/schemas/Error`.
    let error_ref = json!({"$ref": "#/components/schemas/Error"});
    for methods in paths.values_mut() {
        let Some(methods) = methods.as_object_mut() else {
            continue;
        };
        for (method, op) in methods.iter_mut() {
            if method.starts_with("x-") {
                continue;
            }
            let Some(responses) = op.get_mut("responses").and_then(|r| r.as_object_mut()) else {
                continue;
            };
            for (status, resp) in responses.iter_mut() {
                // 2xx bodies are the typed views attached above; 204 has no body; error statuses
                // (4xx/5xx) all speak the one envelope.
                let is_error = status.starts_with('4') || status.starts_with('5');
                if !is_error {
                    continue;
                }
                if let Some(obj) = resp.as_object_mut() {
                    obj.entry("content".to_string()).or_insert_with(
                        || json!({"application/json": {"schema": error_ref.clone()}}),
                    );
                }
            }
        }
    }

    // The generated component schemas (every `$ref`'d view type), merged with the hand-written
    // `Error` schema. The `Error` schema stays hand-written so its `code` enum is the frozen
    // AdminError taxonomy verbatim (the drift test `openapi_error_enum_matches_admin_error_codes`
    // locks it); schemars fills in every other referenced view.
    let mut schemas = gen.definitions().clone();
    schemas.insert(
        "Error".to_string(),
        json!({
            "type": "object",
            "properties": {
                "error": {
                    "type": "object",
                    "properties": {
                        "code": {"type": "string",
                            "enum": ["not_found", "unauthorized", "method_not_allowed", "forbidden",
                                     "invalid_request", "version_conflict", "conflict",
                                     "rate_limited", "internal"]},
                        "message": {"type": "string"}
                    },
                    "required": ["code", "message"]
                }
            },
            "required": ["error"]
        }),
    );

    json!({
        "openapi": "3.1.0",
        "info": {
            "title": "Busbar Admin API",
            "version": env!("CARGO_PKG_VERSION"),
            "description": "The frozen, additive-only /api/v1/admin surface. Errors use the stable \
                            envelope {\"error\":{\"code\",\"message\"}}; tooling branches on `code`."
        },
        "components": {
            "securitySchemes": {
                "adminToken": {"type": "apiKey", "in": "header", "name": crate::auth::X_ADMIN_TOKEN},
                "bearerAuth": {"type": "http", "scheme": "bearer",
                               "description": "The same operator credential via Authorization: Bearer"}
            },
            "schemas": schemas
        },
        "paths": paths
    })
}

/// The committed, typed OpenAPI 3.1 document — generated from `openapi_doc()` (feature `openapi-schema`)
/// and checked into the tree. The live handler serves THIS static string: schemars is a CI-only
/// dependency, so the release binary cannot regenerate the doc at runtime, and it never needs to —
/// the golden/drift test keeps this file byte-equal to `openapi_doc()`'s output, so serving the
/// static copy is identical to serving a freshly-generated one, minus the schemars code + cost.
pub(crate) const OPENAPI_JSON: &str = include_str!("openapi.json");

/// `GET /api/v1/admin/openapi.json` — the OpenAPI 3.1 schema of the v1 surface (the discovery contract).
/// Serves the committed, typed [`OPENAPI_JSON`] verbatim as `application/json` (no runtime generation —
/// see the constant's doc). Same status/content-type/body shape the generated path always produced.
pub(crate) async fn openapi() -> Response {
    (
        StatusCode::OK,
        [(CONTENT_TYPE, crate::proxy::APPLICATION_JSON)],
        OPENAPI_JSON,
    )
        .into_response()
}

/// The `POST /api/v1/admin/config/validate` request body: a full proposed config — the `config.yaml`
/// deploy block + the `providers.yaml` definitions — mirroring the two files busbar loads at boot.
#[derive(serde::Deserialize)]
pub(crate) struct ValidateConfigReq {
    /// The deploy config (operator-owned `config.yaml` shape).
    config: crate::config::DeployCfg,
    /// The provider definitions (`providers.yaml` shape), keyed by provider name. Optional: a config
    /// that references no providers.yaml entries validates against an empty def set (and reports the
    /// dangling references as errors).
    #[serde(default)]
    providers: std::collections::HashMap<String, crate::config::ProviderDef>,
}

/// `POST /api/v1/admin/config/validate` — dry-run validate a proposed config. A malformed body is an
/// `invalid_request`; a well-formed body always returns 200 with the `{ok, errors}` verdict.
pub(crate) async fn validate_config(
    State(handle): State<Arc<AppHandle>>,
    body: axum::body::Bytes,
) -> Response {
    let req: ValidateConfigReq = match serde_json::from_slice(&body) {
        Ok(r) => r,
        Err(e) => {
            return err_json(&AdminError::Validation(format!(
                "malformed config body: {e}"
            )))
        }
    };
    respond(
        StatusCode::OK,
        service(&handle)
            .validate_config(req.config, req.providers)
            .await,
    )
}

#[cfg(test)]
mod patch_tests {
    use super::merge_group_patch;
    use crate::config::groups::{ChildDefault, LimitMetric, LimitWindow};
    use crate::config::{GroupCfg, LimitCfg};

    fn budget(cents: u64) -> LimitCfg {
        LimitCfg {
            metric: LimitMetric::Budget,
            amount: cents,
            per: Some(LimitWindow::Month),
            pool: None,
            on_exhaust: None,
            downgrade_to: None,
        }
    }

    /// The raise-a-budget path: patching only `limits` replaces them and PRESERVES parent + enabled.
    #[test]
    fn patch_limits_preserves_other_fields() {
        let base = GroupCfg {
            parent: Some("team".into()),
            enabled: true,
            limits: vec![budget(3_000)],
            child_default: None,
        };
        let out = merge_group_patch(base, None, None, Some(vec![budget(5_000)]), None);
        assert_eq!(out.parent.as_deref(), Some("team"));
        assert!(out.enabled);
        assert_eq!(out.limits.len(), 1);
        assert_eq!(out.limits[0].amount, 5_000);
        assert!(out.child_default.is_none());
    }

    /// Freezing a group: patching only `enabled` flips it, leaving limits + parent intact.
    #[test]
    fn patch_enabled_only_freezes_without_touching_limits() {
        let base = GroupCfg {
            parent: Some("team".into()),
            enabled: true,
            limits: vec![budget(3_000)],
            child_default: Some(ChildDefault {
                limits: vec![budget(500)],
            }),
        };
        let out = merge_group_patch(base, None, Some(false), None, None);
        assert!(!out.enabled);
        assert_eq!(out.limits[0].amount, 3_000);
        assert_eq!(out.parent.as_deref(), Some("team"));
        let cd = out.child_default.expect("child_default preserved");
        assert_eq!(cd.limits[0].amount, 500);
    }

    /// An empty patch (all None) is an identity: nothing changes.
    #[test]
    fn empty_patch_is_identity() {
        let base = GroupCfg {
            parent: Some("p".into()),
            enabled: false,
            limits: vec![budget(1)],
            child_default: None,
        };
        let out = merge_group_patch(base.clone(), None, None, None, None);
        assert_eq!(out, base);
    }
}
