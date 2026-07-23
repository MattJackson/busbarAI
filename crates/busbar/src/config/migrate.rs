// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The 1.4.x -> 1.5.0 CONFIG MIGRATOR (`busbar --migrate-config <old.yaml>`) and the LOUD
//! FAIL-CLOSED 1.x detector the boot/`--validate` path runs (P9).
//!
//! Contract redefinition context: the config format is an OPERATOR artifact outside the SemVer
//! freeze, changed only WITH a migration path and a loud fail-closed boot. This module is both
//! halves of that promise:
//!
//! - [`detect_legacy_markers`] recognizes a 1.x config by its structural markers (a `governance:`
//!   block, `auth.group_map:`, a top-level `hooks:` registry, `*_env` secret fields, `target:` in
//!   a pool member, `auth.mode:`) so boot and `--validate` REFUSE to start with a named error
//!   instead of half-parsing a config whose semantics silently flipped (the `allowed_pools: []`
//!   all->none flip, vanished per-key budgets).
//! - [`migrate_config`] mechanically converts every DETERMINISTIC 1.4.x change to the 1.5.0
//!   shape and prints TODO comments wherever a human must decide. ZERO side effects: the caller
//!   prints the new YAML + a change summary; nothing is written.
//!
//! The migrator works on the RAW file (env `${VAR}` references pass through untouched) over the
//! `serde_yaml::Value` tree, so it is total: an unrecognized structure passes through or gains a
//! TODO, never a panic.

use serde_yaml::{Mapping, Value};

/// The named boot error for a detected 1.x config (P9.3). Every marker is listed so the operator
/// sees the full scope before running the migrator.
pub(crate) fn legacy_config_error(markers: &[String]) -> String {
    format!(
        "this looks like a busbar 1.x config; run `busbar --migrate-config <config.yaml>` and \
         review the flagged items. 1.x markers found:\n  - {}\n\
         The 1.5.0 config redesign moved these surfaces (governance dissolved into \
         store/rate_card/groups/advanced; group_map became auth.role_bindings; hooks became \
         inline refs; *_env fields became secret references; pool member target became model). \
         Booting a 1.x config under 1.5.0 rules would silently flip semantics (most critically \
         `allowed_pools: []`, which now means NO pools), so busbar refuses to start instead.",
        markers.join("\n  - ")
    )
}

/// Scan a parsed YAML document for 1.x structural markers. Empty = not a 1.x config (any residual
/// incompatibility then fails through the normal deny-unknown-fields parse errors, which name the
/// exact key). Called by boot AND `--validate` before `DeployCfg` deserializes, so nothing from
/// 1.x ever boots-and-flips.
pub(crate) fn detect_legacy_markers(doc: &Value) -> Vec<String> {
    let mut markers = Vec::new();
    let Some(root) = doc.as_mapping() else {
        return markers;
    };
    let get = |m: &Mapping, k: &str| -> Option<Value> { m.get(Value::from(k)).cloned() };

    if get(root, "governance").is_some() {
        markers.push(
            "`governance:` block (dissolved into store / rate_card / per_request_fee / groups / \
             advanced / auth)"
                .to_string(),
        );
    }
    if let Some(auth) = get(root, "auth").and_then(|v| v.as_mapping().cloned()) {
        if get(&auth, "mode").is_some() {
            markers
                .push("`auth.mode:` (replaced by auth.chain / auth.upstream_credentials)".into());
        }
        if get(&auth, "group_map").is_some() {
            markers.push(
                "`auth.group_map:` (replaced by auth.role_bindings, NESTED BY MODULE; its \
                 rate/budget caps move to a groups: entry)"
                    .into(),
            );
        }
        if get(&auth, "client_tokens").is_some() {
            markers.push("`auth.client_tokens:` (static tokens removed; mint signed keys)".into());
        }
    }
    if get(root, "hooks").is_some() {
        markers.push(
            "top-level `hooks:` registry block (hook instances are now inline refs in \
             pools.<p>.hooks / global_hooks)"
                .into(),
        );
    }
    if let Some(providers) = get(root, "providers").and_then(|v| v.as_mapping().cloned()) {
        for (name, p) in &providers {
            if p.as_mapping()
                .is_some_and(|m| m.contains_key(Value::from("api_key_env")))
            {
                markers.push(format!(
                    "`providers.{}.api_key_env:` (secret fields are now secret references: \
                     api_key: {{ env: VAR }})",
                    name.as_str().unwrap_or("?")
                ));
            }
        }
    }
    if let Some(pools) = get(root, "pools").and_then(|v| v.as_mapping().cloned()) {
        for (name, p) in &pools {
            let members = p
                .as_mapping()
                .and_then(|m| get(m, "members"))
                .and_then(|v| v.as_sequence().cloned())
                .unwrap_or_default();
            if members.iter().any(|mem| {
                mem.as_mapping()
                    .is_some_and(|m| m.contains_key(Value::from("target")))
            }) {
                markers.push(format!(
                    "`pools.{}.members[].target:` (renamed to model)",
                    name.as_str().unwrap_or("?")
                ));
            }
        }
    }
    markers
}

/// The output of one migration run: the new YAML text plus the change / TODO / warning ledgers
/// the CLI prints as the summary.
pub(crate) struct MigrateOutput {
    pub(crate) yaml: String,
    pub(crate) changes: Vec<String>,
    pub(crate) todos: Vec<String>,
    pub(crate) warnings: Vec<String>,
}

/// Mechanically migrate a 1.4.x config document to the 1.5.0 shape (P9.2). Deterministic changes
/// are applied; judgment calls become TODO entries; the `allowed_pools: []` semantic flip gets a
/// LOUD warning per occurrence. Total and side-effect free.
pub(crate) fn migrate_config(raw: &str) -> Result<MigrateOutput, String> {
    let doc: Value =
        serde_yaml::from_str(raw).map_err(|e| format!("input is not valid YAML: {e}"))?;
    let Value::Mapping(mut root) = doc else {
        return Err("input is not a YAML mapping (expected a busbar config document)".to_string());
    };
    let mut changes: Vec<String> = Vec::new();
    let mut todos: Vec<String> = Vec::new();
    let mut warnings: Vec<String> = Vec::new();

    migrate_governance(&mut root, &mut changes, &mut todos);
    migrate_auth(&mut root, &mut changes, &mut todos, &mut warnings);
    migrate_providers(&mut root, &mut changes);
    migrate_hooks_block(&mut root, &mut changes, &mut todos);
    migrate_pools(&mut root, &mut changes, &mut todos);
    migrate_observability(&mut root, &mut changes);

    let body = serde_yaml::to_string(&Value::Mapping(root))
        .map_err(|e| format!("could not serialize the migrated config: {e}"))?;
    // serde_yaml cannot attach comments to nodes, so the TODO/WARNING ledger renders as a header
    // comment block on the printed document (each entry names its config path).
    let mut yaml = String::new();
    yaml.push_str("# busbar 1.5.0 config, migrated by `busbar --migrate-config`.\n");
    yaml.push_str("# Review before deploying; `busbar --validate` must pass.\n");
    for w in &warnings {
        yaml.push_str(&format!("# WARNING(migrate): {w}\n"));
    }
    for t in &todos {
        yaml.push_str(&format!("# TODO(migrate): {t}\n"));
    }
    yaml.push('\n');
    yaml.push_str(&body);
    Ok(MigrateOutput {
        yaml,
        changes,
        todos,
        warnings,
    })
}

fn take(m: &mut Mapping, k: &str) -> Option<Value> {
    m.remove(Value::from(k))
}

fn as_map(v: Value) -> Mapping {
    match v {
        Value::Mapping(m) => m,
        _ => Mapping::new(),
    }
}

/// Map a 1.4.x `budget_period` word to the 1.5.0 C8 window noun.
fn window_noun(period: &str) -> &'static str {
    match period {
        "daily" | "day" => "day",
        "monthly" | "month" => "month",
        "minute" => "minute",
        "hour" => "hour",
        _ => "total",
    }
}

/// `governance:` -> store / rate_card / per_request_fee / groups / advanced / auth.admin_auth.
fn migrate_governance(root: &mut Mapping, changes: &mut Vec<String>, todos: &mut Vec<String>) {
    let Some(gov) = take(root, "governance") else {
        return;
    };
    let mut gov = as_map(gov);

    // store + db_path -> store: { module, settings }.
    let store_module = take(&mut gov, "store").and_then(|v| v.as_str().map(str::to_string));
    let db_path = take(&mut gov, "db_path").and_then(|v| v.as_str().map(str::to_string));
    if let Some(module) = store_module {
        let mut store = Mapping::new();
        store.insert("module".into(), module.clone().into());
        let mut settings = Mapping::new();
        match (module.as_str(), db_path) {
            ("memory", _) => {}
            ("sqlite", Some(p)) => {
                settings.insert("db_path".into(), p.into());
            }
            (_, Some(p)) => {
                settings.insert("url".into(), p.into());
            }
            (_, None) => {}
        }
        if let Some(busy) = take(&mut gov, "sqlite_busy_timeout_ms") {
            settings.insert("busy_timeout_ms".into(), busy);
        }
        if !settings.is_empty() {
            store.insert("settings".into(), Value::Mapping(settings));
        }
        root.insert("store".into(), Value::Mapping(store));
        changes.push("governance.store/db_path -> store: { module, settings }".into());
    }

    if let Some(card) = take(&mut gov, "rate_card") {
        root.insert("rate_card".into(), card);
        changes.push("governance.rate_card -> top-level rate_card".into());
    }
    if let Some(fee) = take(&mut gov, "price_per_request_cents") {
        root.insert("per_request_fee".into(), fee);
        changes.push("governance.price_per_request_cents -> per_request_fee".into());
    }
    if let Some(p1k) = take(&mut gov, "price_per_1k_tokens_cents") {
        // N cents per 1k tokens = 10*N micro-units per token, on every tier of every model.
        let n = p1k.as_f64().unwrap_or(0.0);
        let per_tier = n * 10.0;
        let mut card = as_map(root.remove(Value::from("rate_card")).unwrap_or_default());
        let model_names: Vec<String> = root
            .get(Value::from("models"))
            .and_then(|v| v.as_mapping())
            .map(|m| {
                m.keys()
                    .filter_map(|k| k.as_str().map(str::to_string))
                    .collect()
            })
            .unwrap_or_default();
        for m in &model_names {
            if !card.contains_key(Value::from(m.as_str())) {
                let mut entry = Mapping::new();
                for tier in [
                    "input_utok",
                    "output_utok",
                    "cache_read_utok",
                    "cache_write_utok",
                ] {
                    entry.insert(tier.into(), per_tier.into());
                }
                card.insert(m.as_str().into(), Value::Mapping(entry));
            }
        }
        root.insert("rate_card".into(), Value::Mapping(card));
        changes.push(
            "governance.price_per_1k_tokens_cents -> a rate_card entry per model (N cents/1k = \
             10N micro-units/token on every tier)"
                .into(),
        );
        todos.push(
            "rate_card: entries were synthesized from the flat price_per_1k_tokens_cents; \
             replace the uniform per-tier rates with each model's real prices"
                .into(),
        );
    }
    if let Some(groups) = take(&mut gov, "budget_groups") {
        let mut out = Mapping::new();
        if let Value::Mapping(gm) = groups {
            for (name, g) in gm {
                let mut g = as_map(g);
                let mut entry = Mapping::new();
                if let Some(parent) = take(&mut g, "parent") {
                    entry.insert("parent".into(), parent);
                }
                let amount = take(&mut g, "max_budget_cents").unwrap_or(Value::from(0));
                let period = take(&mut g, "budget_period")
                    .and_then(|v| v.as_str().map(str::to_string))
                    .unwrap_or_else(|| "total".into());
                let mut limit = Mapping::new();
                limit.insert("budget".into(), amount);
                limit.insert("per".into(), window_noun(&period).into());
                entry.insert(
                    "limits".into(),
                    Value::Sequence(vec![Value::Mapping(limit)]),
                );
                out.insert(name, Value::Mapping(entry));
            }
        }
        root.insert("groups".into(), Value::Mapping(out));
        changes.push(
            "governance.budget_groups -> top-level groups (budget caps became generic limits)"
                .into(),
        );
    }
    let mut advanced = Mapping::new();
    if let Some(v) = take(&mut gov, "rate_sweep_interval") {
        advanced.insert("rate_sweep_interval".into(), v);
    }
    if let Some(v) = take(&mut gov, "usage_flush_interval_ms") {
        advanced.insert("usage_flush_interval_ms".into(), v);
    }
    if !advanced.is_empty() {
        root.insert("advanced".into(), Value::Mapping(advanced));
        changes.push("governance.rate_sweep_interval / usage_flush_interval_ms -> advanced".into());
    }
    if let Some(token) = take(&mut gov, "admin_token") {
        // The old field held the (env-interpolated) token VALUE. The 1.5.0 shape is a secret
        // reference on the admin-tokens module; a `${VAR}` reference converts mechanically.
        let auth = root
            .entry("auth".into())
            .or_insert_with(|| Value::Mapping(Mapping::new()));
        if let Value::Mapping(auth) = auth {
            let secret_ref: Value = match token.as_str() {
                Some(s) if s.starts_with("${") && s.ends_with('}') => {
                    let var = &s[2..s.len() - 1];
                    let mut m = Mapping::new();
                    m.insert("env".into(), var.into());
                    Value::Mapping(m)
                }
                _ => {
                    todos.push(
                        "auth.admin_auth[admin-tokens].token: governance.admin_token held a \
                         literal value; move it into an env var or file and reference it \
                         (token: { env: VAR } or { file: /path })"
                            .into(),
                    );
                    let mut m = Mapping::new();
                    m.insert("env".into(), "BUSBAR_ADMIN_TOKEN".into());
                    Value::Mapping(m)
                }
            };
            let mut body = Mapping::new();
            body.insert("token".into(), secret_ref);
            let mut entry = Mapping::new();
            entry.insert("admin-tokens".into(), Value::Mapping(body));
            auth.insert(
                "admin_auth".into(),
                Value::Sequence(vec![Value::Mapping(entry)]),
            );
        }
        changes.push(
            "governance.admin_token -> auth.admin_auth: [ admin-tokens: { token: <secret-ref> } ]"
                .into(),
        );
    }
    // `enabled` was removed in 1.5.0 (governance is presence-driven).
    if take(&mut gov, "enabled").is_some() {
        changes.push("governance.enabled removed (governance is presence-driven)".into());
    }
    for (k, _) in &gov {
        todos.push(format!(
            "governance.{}: no mechanical 1.5.0 equivalent; consult the 1.5.0 CHANGELOG",
            k.as_str().unwrap_or("?")
        ));
    }
}

/// `auth.mode` / `auth.group_map` / `auth.client_tokens` -> chain / role_bindings / (removed).
fn migrate_auth(
    root: &mut Mapping,
    changes: &mut Vec<String>,
    todos: &mut Vec<String>,
    warnings: &mut Vec<String>,
) {
    let Some(Value::Mapping(auth)) = root.get_mut(Value::from("auth")) else {
        return;
    };
    if let Some(mode) = take(auth, "mode").and_then(|v| v.as_str().map(str::to_string)) {
        match mode.as_str() {
            "passthrough" => {
                auth.insert("upstream_credentials".into(), "passthrough".into());
                changes.push(
                    "auth.mode: passthrough -> auth.upstream_credentials: passthrough".into(),
                );
            }
            "none" => {
                changes.push(
                    "auth.mode: none removed (an omitted chain is the open front door)".into(),
                );
            }
            other => {
                auth.insert("chain".into(), Value::Sequence(vec!["keys".into()]));
                changes.push(format!(
                    "auth.mode: {other} -> auth.chain: [keys] (static tokens are removed; mint \
                     signed keys)"
                ));
                todos.push(
                    "auth.chain: the static-token allowlist is GONE in 1.5.0; every caller needs \
                     a minted signed key (POST /api/v1/admin/keys) - 1.x bearer tokens stop \
                     working"
                        .into(),
                );
            }
        }
    }
    if take(auth, "client_tokens").is_some() {
        todos.push(
            "auth.client_tokens removed: static tokens are gone in 1.5.0; mint signed keys for \
             each caller (POST /api/v1/admin/keys)"
                .into(),
        );
        changes.push("auth.client_tokens removed (static tokens are gone)".into());
    }
    let Some(gm) = take(auth, "group_map") else {
        return;
    };
    // Which MODULE do the old flat bindings nest under? Mechanical when the chain names exactly
    // one external module; otherwise a placeholder + TODO.
    let chain_modules: Vec<String> = auth
        .get(Value::from("chain"))
        .and_then(|v| v.as_sequence())
        .map(|seq| {
            seq.iter()
                .filter_map(|e| match e {
                    Value::String(s) => Some(s.clone()),
                    Value::Mapping(m) => {
                        m.keys().next().and_then(|k| k.as_str().map(str::to_string))
                    }
                    _ => None,
                })
                .filter(|m| m != "keys" && m != "tokens" && m != "admin-tokens")
                .collect()
        })
        .unwrap_or_default();
    let module = match chain_modules.as_slice() {
        [one] => one.clone(),
        _ => {
            todos.push(
                "auth.role_bindings: could not determine WHICH auth module the old group_map \
                 roles belong to; replace the '<module>' placeholder with the asserting module's \
                 name (bindings are nested by module in 1.5.0)"
                    .into(),
            );
            "<module>".to_string()
        }
    };
    let mut bindings = Mapping::new();
    let mut generated_groups: Mapping = Mapping::new();
    if let Value::Mapping(gm) = gm {
        for (role, b) in gm {
            let role_name = role.as_str().unwrap_or("?").to_string();
            let mut b = as_map(b);
            let mut binding = Mapping::new();
            if let Some(pools) = take(&mut b, "allowed_pools") {
                if pools.as_sequence().is_some_and(|s| s.is_empty()) {
                    warnings.push(format!(
                        "auth.role_bindings.{module}.{role_name}.allowed_pools: [] - the MEANING \
                         of an empty list FLIPPED in 1.5.0: it used to mean ALL pools, it now \
                         means NO pools. If this role should reach every pool, DELETE the \
                         allowed_pools line (omitted = all); if it should reach none, keep []."
                    ));
                }
                binding.insert("allowed_pools".into(), pools);
            }
            if let Some(g) = take(&mut b, "budget_group").or_else(|| take(&mut b, "group")) {
                binding.insert("group".into(), g);
            }
            if let Some(scope) = take(&mut b, "admin_scope") {
                binding.insert("admin_scope".into(), scope);
            }
            // Inline caps (rpm/tpm/budget) no longer live on a binding: generate a groups entry.
            let rpm = take(&mut b, "rpm_limit");
            let tpm = take(&mut b, "tpm_limit");
            let budget = take(&mut b, "max_budget_cents");
            let period = take(&mut b, "budget_period")
                .and_then(|v| v.as_str().map(str::to_string))
                .unwrap_or_else(|| "total".into());
            if rpm.is_some() || tpm.is_some() || budget.is_some() {
                let gname = format!("migrated-{role_name}");
                let mut limits: Vec<Value> = Vec::new();
                if let Some(r) = rpm {
                    let mut l = Mapping::new();
                    l.insert("requests".into(), r);
                    l.insert("per".into(), "minute".into());
                    limits.push(Value::Mapping(l));
                }
                if let Some(t) = tpm {
                    let mut l = Mapping::new();
                    l.insert("tokens".into(), t);
                    l.insert("per".into(), "minute".into());
                    limits.push(Value::Mapping(l));
                }
                if let Some(bu) = budget {
                    let mut l = Mapping::new();
                    l.insert("budget".into(), bu);
                    l.insert("per".into(), window_noun(&period).into());
                    limits.push(Value::Mapping(l));
                }
                let mut entry = Mapping::new();
                entry.insert("limits".into(), Value::Sequence(limits));
                generated_groups.insert(gname.as_str().into(), Value::Mapping(entry));
                if !binding.contains_key(Value::from("group")) {
                    binding.insert("group".into(), gname.as_str().into());
                }
                todos.push(format!(
                    "groups.{gname}: generated from the old group_map role '{role_name}' inline \
                     caps; review the limits and consider merging it into your real group tree"
                ));
                changes.push(format!(
                    "auth.group_map.{role_name} caps -> generated groups.{gname}"
                ));
            }
            bindings.insert(role, Value::Mapping(binding));
        }
    }
    let mut nested = Mapping::new();
    nested.insert(module.as_str().into(), Value::Mapping(bindings));
    auth.insert("role_bindings".into(), Value::Mapping(nested));
    changes.push(format!(
        "auth.group_map -> auth.role_bindings.{module} (nested by module)"
    ));
    if !generated_groups.is_empty() {
        let groups = root
            .entry("groups".into())
            .or_insert_with(|| Value::Mapping(Mapping::new()));
        if let Value::Mapping(groups) = groups {
            for (k, v) in generated_groups {
                groups.insert(k, v);
            }
        }
    }
}

/// `providers.*.api_key_env: VAR` -> `api_key: { env: VAR }`.
fn migrate_providers(root: &mut Mapping, changes: &mut Vec<String>) {
    let Some(Value::Mapping(providers)) = root.get_mut(Value::from("providers")) else {
        return;
    };
    for (name, p) in providers.iter_mut() {
        let Value::Mapping(p) = p else { continue };
        if let Some(var) = take(p, "api_key_env") {
            let mut secret = Mapping::new();
            secret.insert("env".into(), var);
            p.insert("api_key".into(), Value::Mapping(secret));
            changes.push(format!(
                "providers.{}.api_key_env -> api_key: {{ env: ... }}",
                name.as_str().unwrap_or("?")
            ));
        }
    }
}

/// The top-level `hooks:` registry -> inline refs in pools.<p>.hooks / global_hooks.
fn migrate_hooks_block(root: &mut Mapping, changes: &mut Vec<String>, todos: &mut Vec<String>) {
    let Some(hooks) = take(root, "hooks") else {
        return;
    };
    let Value::Mapping(hooks) = hooks else {
        return;
    };
    changes.push("top-level hooks: registry dissolved into inline refs".into());
    // Build an inline module ref from a registry entry.
    let inline_ref = |name: &str, h: &Mapping, todos: &mut Vec<String>| -> Value {
        let mut r = Mapping::new();
        let mut settings = as_map(h.get(Value::from("settings")).cloned().unwrap_or_default());
        if let Some(url) = h.get(Value::from("webhook")).and_then(|v| v.as_str()) {
            r.insert("module".into(), "webhook".into());
            settings.insert("url".into(), url.into());
        } else if let Some(path) = h.get(Value::from("socket")).and_then(|v| v.as_str()) {
            r.insert("module".into(), "socket".into());
            settings.insert("path".into(), path.into());
        } else {
            todos.push(format!(
                "hook '{name}': no socket/webhook transport found; pick module: webhook \
                 (settings.url) or module: socket (settings.path)"
            ));
            r.insert("module".into(), "webhook".into());
        }
        if !settings.is_empty() {
            r.insert("settings".into(), Value::Mapping(settings));
        }
        for typed in [
            "kind",
            "timeout_ms",
            "on_error",
            "on_empty",
            "at",
            "prompt",
            "user",
            "priority",
        ] {
            if let Some(v) = h.get(Value::from(typed)) {
                r.insert(typed.into(), v.clone());
            }
        }
        Value::Mapping(r)
    };
    let is_true =
        |h: &Mapping, k: &str| h.get(Value::from(k)).and_then(|v| v.as_bool()) == Some(true);

    let mut placed: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
    // 1. global: true entries -> global_hooks.
    let mut global_list: Vec<Value> = root
        .get(Value::from("global_hooks"))
        .and_then(|v| v.as_sequence().cloned())
        .unwrap_or_default();
    for (name, h) in &hooks {
        let (Some(name), Some(h)) = (name.as_str(), h.as_mapping()) else {
            continue;
        };
        if is_true(h, "global") {
            global_list.push(inline_ref(name, h, todos));
            placed.insert(name.to_string());
            changes.push(format!("hooks.{name} (global) -> global_hooks inline ref"));
        }
        if is_true(h, "default") {
            todos.push(format!(
                "hook '{name}' was `default: true` (the pool base ordering); the flag is gone - \
                 add the hook (or a built-in strategy) to each pool's hooks: list explicitly"
            ));
        }
    }
    if !global_list.is_empty() {
        root.insert("global_hooks".into(), Value::Sequence(global_list));
    }
    // 2. pool hook-name references -> inline refs in that pool's hooks list.
    if let Some(Value::Mapping(pools)) = root.get_mut(Value::from("pools")) {
        for (pname, p) in pools.iter_mut() {
            let Value::Mapping(p) = p else { continue };
            let mut list: Vec<Value> = Vec::new();
            let existing = take(p, "hooks")
                .and_then(|v| v.as_sequence().cloned())
                .unwrap_or_default();
            for entry in existing {
                match entry {
                    Value::String(name) => {
                        if let Some(h) = hooks
                            .get(Value::from(name.as_str()))
                            .and_then(|v| v.as_mapping())
                        {
                            list.push(inline_ref(&name, h, todos));
                            placed.insert(name.clone());
                            changes.push(format!(
                                "pools.{}.hooks: '{name}' -> inline module ref",
                                pname.as_str().unwrap_or("?")
                            ));
                        } else {
                            // A built-in strategy name (weighted/cheapest/...) stays bare.
                            list.push(name.into());
                        }
                    }
                    other => list.push(other),
                }
            }
            if !list.is_empty() {
                p.insert("hooks".into(), Value::Sequence(list));
            }
        }
    }
    // 3. Anything registered but never placed needs a human decision.
    for (name, _) in &hooks {
        let Some(name) = name.as_str() else { continue };
        if !placed.contains(name) {
            todos.push(format!(
                "hook '{name}' was registered but referenced by no pool and not global; add it \
                 as an inline ref under the pool(s) it should gate, or drop it"
            ));
        }
    }
}

/// Pool member/breaker/failover mechanical renames + cost-off-members.
fn migrate_pools(root: &mut Mapping, changes: &mut Vec<String>, todos: &mut Vec<String>) {
    let Some(Value::Mapping(pools)) = root.get_mut(Value::from("pools")) else {
        return;
    };
    for (pname, p) in pools.iter_mut() {
        let pname = pname.as_str().unwrap_or("?").to_string();
        let Value::Mapping(p) = p else { continue };
        // The retired singular `policy:` key names a base ordering strategy: PREPEND it to the
        // pool's `hooks:` list (a bare built-in name stays bare). Runs here (always) rather than
        // in `migrate_hooks_block` (which returns early for a config with no `hooks:` registry),
        // so a pool `policy:` migrates whether or not the config had a hooks block.
        if let Some(policy) = take(p, "policy").and_then(|v| v.as_str().map(str::to_string)) {
            let mut list = take(p, "hooks")
                .and_then(|v| v.as_sequence().cloned())
                .unwrap_or_default();
            list.insert(0, policy.as_str().into());
            p.insert("hooks".into(), Value::Sequence(list));
            changes.push(format!("pools.{pname}.policy -> hooks: [{policy}, ...]"));
        }
        if let Some(Value::Sequence(members)) = p.get_mut(Value::from("members")) {
            for mem in members.iter_mut() {
                let Value::Mapping(mem) = mem else { continue };
                if let Some(target) = take(mem, "target") {
                    mem.insert("model".into(), target);
                    changes.push(format!("pools.{pname}.members[].target -> model"));
                }
                if take(mem, "cost_per_mtok").is_some() {
                    todos.push(format!(
                        "pools.{pname}.members[].cost_per_mtok removed: rate_card is the ONLY \
                         cost source in 1.5.0; price the member's model there"
                    ));
                    changes.push(format!(
                        "pools.{pname}.members[].cost_per_mtok removed (rate_card is the cost \
                         source)"
                    ));
                }
            }
        }
        if let Some(Value::Mapping(breaker)) = p.get_mut(Value::from("breaker")) {
            if let Some(Value::Mapping(trip)) = breaker.get_mut(Value::from("trip")) {
                if let Some(v) = take(trip, "window_s") {
                    trip.insert("window_secs".into(), v);
                    changes.push(format!(
                        "pools.{pname}.breaker.trip.window_s -> window_secs"
                    ));
                }
                if let Some(v) = take(trip, "n") {
                    trip.insert("consecutive_n".into(), v);
                    changes.push(format!("pools.{pname}.breaker.trip.n -> consecutive_n"));
                }
            }
        }
        if let Some(Value::Mapping(failover)) = p.get_mut(Value::from("failover")) {
            if let Some(v) = take(failover, "deadline_secs") {
                failover.insert("timeout_secs".into(), v);
                changes.push(format!(
                    "pools.{pname}.failover.deadline_secs -> timeout_secs"
                ));
            }
            if let Some(v) = take(failover, "cap") {
                failover.insert("max_hops".into(), v);
                changes.push(format!("pools.{pname}.failover.cap -> max_hops"));
            }
        }
    }
}

/// `observability.otlp_endpoint` -> `otlp_url` (C7).
fn migrate_observability(root: &mut Mapping, changes: &mut Vec<String>) {
    let Some(Value::Mapping(obs)) = root.get_mut(Value::from("observability")) else {
        return;
    };
    if let Some(v) = take(obs, "otlp_endpoint") {
        obs.insert("otlp_url".into(), v);
        changes.push("observability.otlp_endpoint -> otlp_url".into());
    }
}

#[cfg(test)]
#[path = "tests/migrate_tests.rs"]
mod tests;
