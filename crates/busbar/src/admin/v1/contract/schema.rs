// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! SCHEMA-ONLY response views for the admin endpoints whose handlers build an ad-hoc
//! `serde_json::json!({…})` body rather than serializing a named contract struct (the keys resource,
//! the config-mutation results, `hooks/{name}/schema`+`/status`, the version detail/diff, and the
//! `{items,next_cursor}` list envelopes the keys/audit/versions handlers hand-roll).
//!
//! These types are **never serialized at runtime** — they exist purely so `openapi_doc()` can emit a
//! typed `$ref` for every operation instead of a bodyless `{"description":"OK"}`. Each mirrors, field
//! for field, the exact JSON its handler produces; the golden/drift test (`#[cfg(feature =
//! "openapi-schema")]`) keeps the whole doc — and therefore these shapes — locked to the code. The
//! module is compiled ONLY under `openapi-schema` (a CI-only feature), so it adds nothing to the
//! shipped binary. `#[allow(dead_code)]` because the fields are read by schemars' derive, not by
//! Rust code.
#![allow(dead_code)]

use schemars::JsonSchema;
use serde::Serialize;

use super::{AdminError, HookView};

/// Virtual-key metadata — the `key_meta()` shape returned by `GET /keys/{id}`, `PATCH /keys/{id}`,
/// and as each item of `GET /keys`. Never the secret or its hash.
#[derive(Serialize, JsonSchema)]
pub(crate) struct KeyView {
    pub(crate) id: String,
    pub(crate) name: String,
    pub(crate) allowed_pools: Vec<String>,
    pub(crate) max_budget_cents: Option<i64>,
    pub(crate) budget_period: String,
    pub(crate) rpm_limit: Option<u32>,
    pub(crate) tpm_limit: Option<u32>,
    pub(crate) enabled: bool,
    pub(crate) created_at: u64,
}

/// `POST /keys` (mint) — the key metadata plus the ONCE-shown secret, and (when an AWS SigV4
/// credential was requested) the AccessKeyId + secret access key. The AWS fields are absent on a
/// bearer-only mint.
#[derive(Serialize, JsonSchema)]
pub(crate) struct CreatedKeyView {
    pub(crate) id: String,
    pub(crate) name: String,
    pub(crate) allowed_pools: Vec<String>,
    pub(crate) max_budget_cents: Option<i64>,
    pub(crate) budget_period: String,
    pub(crate) rpm_limit: Option<u32>,
    pub(crate) tpm_limit: Option<u32>,
    pub(crate) enabled: bool,
    pub(crate) created_at: u64,
    /// The bearer secret — shown EXACTLY once, never returned by any read.
    pub(crate) secret: String,
    /// AWS AccessKeyId (present only when `issue_aws_credential` was set). Not secret.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) aws_access_key_id: Option<String>,
    /// AWS SigV4 secret access key — shown once (present only with an AWS credential).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) aws_secret_access_key: Option<String>,
}

/// `POST /keys/{id}/rotate` — the key metadata plus the ONCE-shown fresh bearer secret.
#[derive(Serialize, JsonSchema)]
pub(crate) struct RotatedKeyView {
    pub(crate) id: String,
    pub(crate) name: String,
    pub(crate) allowed_pools: Vec<String>,
    pub(crate) max_budget_cents: Option<i64>,
    pub(crate) budget_period: String,
    pub(crate) rpm_limit: Option<u32>,
    pub(crate) tpm_limit: Option<u32>,
    pub(crate) enabled: bool,
    pub(crate) created_at: u64,
    /// The fresh bearer secret — shown EXACTLY once.
    pub(crate) secret: String,
}

/// `GET /keys/{id}/usage` — the current budget-window counters for one key, plus the fraction of the
/// tightest RPM/TPM cap remaining (`null` = uncapped). `budget_period`/`window_start` are `null`
/// when the key record could not be read.
#[derive(Serialize, JsonSchema)]
pub(crate) struct KeyMeteringView {
    pub(crate) id: String,
    pub(crate) budget_period: Option<String>,
    pub(crate) window_start: Option<u64>,
    pub(crate) as_of: u64,
    pub(crate) spend_cents: i64,
    pub(crate) tokens: u64,
    pub(crate) requests: u64,
    pub(crate) rate_headroom: Option<f64>,
}

/// `GET /keys` — the cursor-paginated key list envelope (`{items, next_cursor}`, hand-rolled in the
/// keys handler rather than via `Page<T>`).
#[derive(Serialize, JsonSchema)]
pub(crate) struct KeyPageView {
    pub(crate) items: Vec<KeyView>,
    pub(crate) next_cursor: Option<String>,
}

/// `POST /config/apply` — apply-a-full-config result. The change is live but not written to disk.
#[derive(Serialize, JsonSchema)]
pub(crate) struct ConfigApplyView {
    pub(crate) applied: bool,
    pub(crate) config_version: u64,
    pub(crate) note: String,
}

/// `POST /config/reload` — reload-from-disk result.
#[derive(Serialize, JsonSchema)]
pub(crate) struct ConfigReloadView {
    pub(crate) reloaded: bool,
    pub(crate) config_version: u64,
}

/// `POST /config/rollback` — restore-a-retained-version result (the restored version + the NEW
/// config version the rollback produced).
#[derive(Serialize, JsonSchema)]
pub(crate) struct ConfigRollbackView {
    pub(crate) restored_version: u64,
    pub(crate) config_version: u64,
}

/// `POST /auth/cache/flush` — number of cached credential-decision entries dropped.
#[derive(Serialize, JsonSchema)]
pub(crate) struct CacheFlushView {
    pub(crate) flushed: usize,
}

/// `PUT /admin-auth` — the resource post-state (`{configured, modules}`, the same shape
/// `GET /admin-auth` returns) plus apply metadata, so a client uses the PUT response as post-state.
#[derive(Serialize, JsonSchema)]
pub(crate) struct AdminAuthPutView {
    pub(crate) configured: bool,
    pub(crate) modules: Vec<String>,
    pub(crate) applied: bool,
    pub(crate) config_version: u64,
    pub(crate) note: String,
}

/// `GET /hooks/{name}/schema` — the hook's self-described settings JSON Schema (proxied over the
/// `describe` wire message), or `null` when the hook/transport does not answer.
#[derive(Serialize, JsonSchema)]
pub(crate) struct HookSchemaView {
    pub(crate) name: String,
    /// The hook's settings JSON Schema verbatim (an arbitrary JSON object), or `null`.
    pub(crate) schema: Option<serde_json::Value>,
}

/// The DESIRED settings side of `hooks/{name}/status`: busbar's registry copy of the hook's settings
/// and their version.
#[derive(Serialize, JsonSchema)]
pub(crate) struct HookDesiredStatus {
    pub(crate) settings: serde_json::Map<String, serde_json::Value>,
    pub(crate) settings_version: u64,
}

/// The REPORTED settings side of `hooks/{name}/status`: what the hook says it is actually running
/// (present only when the hook answered `status`).
#[derive(Serialize, JsonSchema)]
pub(crate) struct HookReportedStatus {
    pub(crate) settings: Option<serde_json::Map<String, serde_json::Value>>,
    pub(crate) settings_version: Option<u64>,
}

/// `GET /hooks/{name}/status` — the hook's OBSERVED state: desired vs reported settings with a
/// `drift` verdict, plus the hook's self-reported metrics. `reported`/`drift` are `null` and `note`
/// is present when the hook did not answer (fail-open); `metrics` is invariantly an array.
#[derive(Serialize, JsonSchema)]
pub(crate) struct HookStatusView {
    pub(crate) name: String,
    pub(crate) desired: HookDesiredStatus,
    pub(crate) reported: Option<HookReportedStatus>,
    pub(crate) drift: Option<bool>,
    /// Validated + bounded self-reported metrics; each entry carries `{name, type, value}` and, when
    /// the hook sent them, optional `labels`/`quantiles`/`estimated`/`ci_low`/`ci_high`/`help`/
    /// `label`/`unit`/`viz`/`max` members.
    pub(crate) metrics: Vec<serde_json::Value>,
    pub(crate) as_of: u64,
    /// Always `"live"` (the read is a live transport query).
    pub(crate) source: String,
    /// A short human note present only on the fail-open (no-answer) branch.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) note: Option<String>,
}

/// `GET /config/versions/{v}` — one retained config version WITH its full hook-surface snapshot
/// (projected through the wire `HookView`, keyed by hook name) and the global wiring at that version.
#[derive(Serialize, JsonSchema)]
pub(crate) struct ConfigVersionDetailView {
    pub(crate) version: u64,
    pub(crate) ts: u64,
    pub(crate) principal: String,
    pub(crate) summary: String,
    pub(crate) hooks: std::collections::BTreeMap<String, HookView>,
    pub(crate) global_hooks: Vec<String>,
}

/// The `hooks` object of a `GET /config/diff` — hook names added / removed / changed between the two
/// versions.
#[derive(Serialize, JsonSchema)]
pub(crate) struct ConfigDiffHooks {
    pub(crate) added: Vec<String>,
    pub(crate) removed: Vec<String>,
    pub(crate) changed: Vec<String>,
}

/// The `global_hooks` delta of a `GET /config/diff` — present only when the global wiring changed.
#[derive(Serialize, JsonSchema)]
pub(crate) struct ConfigDiffGlobalHooks {
    pub(crate) from: Vec<String>,
    pub(crate) to: Vec<String>,
}

/// `GET /config/diff` — structured hook-surface diff between two retained versions. `global_hooks` is
/// present only when the global wiring differed between the two sides.
#[derive(Serialize, JsonSchema)]
pub(crate) struct ConfigDiffView {
    pub(crate) from: u64,
    pub(crate) to: u64,
    pub(crate) hooks: ConfigDiffHooks,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) global_hooks: Option<ConfigDiffGlobalHooks>,
}

/// `GET /audit` — the cursor-paginated audit-log envelope (`{items, next_cursor}`, hand-rolled in the
/// audit handler).
#[derive(Serialize, JsonSchema)]
pub(crate) struct AuditPageView {
    pub(crate) items: Vec<crate::admin::audit::AuditEntry>,
    pub(crate) next_cursor: Option<String>,
}

/// `GET /config/versions` — the cursor-paginated version-history envelope (`{items, next_cursor}`).
#[derive(Serialize, JsonSchema)]
pub(crate) struct ConfigVersionPageView {
    pub(crate) items: Vec<crate::admin::versions::ConfigVersion>,
    pub(crate) next_cursor: Option<String>,
}

/// The stable v1 error envelope (`{"error":{"code","message"}}`). Kept as a schema-only type so the
/// generated `Error` component matches the hand-written one exactly and both stay code-derived.
#[derive(Serialize, JsonSchema)]
pub(crate) struct ErrorBody {
    pub(crate) error: ErrorDetail,
}

/// The `error` member of [`ErrorBody`]: a stable machine `code` + human `message`.
#[derive(Serialize, JsonSchema)]
pub(crate) struct ErrorDetail {
    /// One of the frozen [`AdminError`] codes (see the `code` enum on the generated schema).
    pub(crate) code: String,
    pub(crate) message: String,
}

/// A compile-time cross-check that this schema module stays in step with the frozen error taxonomy:
/// referencing every [`AdminError`] variant here means adding a new variant forces a look at this
/// module. (Never called — the match is the assertion.)
#[allow(unused)]
fn _error_taxonomy_is_referenced(e: &AdminError) {
    match e {
        AdminError::NotFound(_)
        | AdminError::Unauthorized
        | AdminError::MethodNotAllowed
        | AdminError::Forbidden { .. }
        | AdminError::Validation(_)
        | AdminError::VersionConflict(_)
        | AdminError::Conflict(_)
        | AdminError::RateLimited
        | AdminError::Internal => {}
    }
}
