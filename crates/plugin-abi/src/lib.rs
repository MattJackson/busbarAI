// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The busbar **plugin C ABI** — the frozen, KIND-NEUTRAL wire between the engine and a backend
//! (`store` | `secret` | `auth`) that lives in a dynamic library (`.so`/`.dll`/`.dylib`) it loads at
//! runtime, OR is compiled straight in.
//!
//! ## The frozen transport contract (ONE set, all kinds)
//!
//! A plugin exports SIX kind-neutral `extern "C"` symbols (see [`symbol`]). The names carry NO kind —
//! ONE library shape serves every kind, and the KIND is bound at LOAD, never in a per-call envelope.
//! The engine resolves the symbols via `libloading` and calls across the boundary passing
//! **JSON-serialized bytes** (a `ptr + len`), never C structs. JSON — not a `repr(C)` struct —
//! because:
//!
//! - it is **version-tolerant**: fields can be added to the contract records without breaking the
//!   ABI (a new field an old plugin doesn't know is simply ignored / defaulted);
//! - it is **language-agnostic**: a plugin can be written in C/Go/Zig as long as it speaks the
//!   symbols and the JSON;
//! - the cost is **irrelevant**: these backends are off the request hot path (the store is
//!   write-behind, auth is cached), so a serialize per call never touches request latency.
//!
//! The six symbols are `busbar_abi`, `busbar_plugin_kind`, `busbar_open`, `busbar_call`,
//! `busbar_free`, `busbar_close`. Every operation for a kind rides the single `call`, self-described
//! by that kind's request enum, so the C symbol set never grows as a trait does.
//!
//! ## Two version axes (the crux)
//!
//! 1. **Transport version** = [`busbar_abi`], frozen at [`TRANSPORT_VERSION`] (=1), ONE number for all
//!    kinds. It is the low-level linker contract (the six signatures, ptr+len byte buffers, the
//!    plugin-allocates/plugin-frees rule, the status codes). Bumping it is a real, no-turning-back
//!    linker event; it changes ~never.
//! 2. **Per-kind payload schema version** = the SIGNED manifest's `abi_version` field. It bumps
//!    routinely, per kind, ADDITIVELY. The engine negotiates it against `supported_abi` (a contiguous
//!    RANGE per kind, in the loader/registry): in range → load; below the floor / above the max →
//!    refuse LOUD. This is the axis the store schema churned 1→2→3→4 on — all PAYLOAD, zero transport.
//!
//! ## Kind bound AT LOAD — the security spine
//!
//! Kind is NEVER in the per-call envelope. At load the engine reads the signed manifest `kind`,
//! cross-checks it EQUALS the exported [`busbar_plugin_kind`] (mismatch = hard fail-closed load
//! error), then dispatches to the TYPED seam (`Box<dyn Store>` / `Box<dyn SecretModule>` /
//! `Box<dyn AuthModule>`). From there kind is a Rust TYPE, not a wire tag.

use busbar_api::{
    AuditRecord, AwsCredential, MeteringDelta, MeteringRow, UsageDelta, UsageLedger, VirtualKey,
};
use serde::{Deserialize, Serialize};
use std::os::raw::c_void;

pub mod auth;

/// The kind-neutral **TRANSPORT** ABI version, returned by a plugin's `busbar_abi()`. Frozen at 1:
/// this is the low-level linker contract (the six C signatures, ptr+len byte buffers, the
/// plugin-allocates/plugin-frees rule, the status codes). DISTINCT from the per-kind PAYLOAD schema
/// version (the signed manifest's `abi_version`), which bumps additively per kind. Bumping THIS is a
/// real, no-turning-back linker event — side-by-side migration, never a routine change.
pub const TRANSPORT_VERSION: u32 = 1;

/// The kind strings a plugin may declare via `busbar_plugin_kind()` and its signed manifest `kind`.
pub mod kind {
    /// A durable governance store (`Box<dyn busbar_api::Store>`).
    pub const STORE: &str = "store";
    /// A secret-resolution module (`Box<dyn busbar_api::SecretModule>`).
    pub const SECRET: &str = "secret";
    /// An external identity provider / auth module (`Box<dyn busbar_api::AuthModule>`).
    pub const AUTH: &str = "auth";
}

/// The store-plugin ABI version this crate defines. Bumped only on a breaking change to the wire
/// (the request/response shape or the C signatures); additive changes keep the version.
///
/// v2 (1.5.0, pre-release): the scalar `Usage { spend_cents, tokens, requests }` counter became the
/// per-(model, tier) TOKEN LEDGER (`UsageLedger`/`UsageDelta`) and `Get/Put/AddUsage` re-keyed from
/// `key_id` to `bucket_id` (key buckets and budget-group buckets share the shape). A breaking wire
/// change, so the version bumps: a v1 plugin is refused at load, never mis-called. 1.5.0 is
/// unreleased, so no v1 plugin exists in the wild.
///
/// v3 (1.5.0, pre-release): KEYS ARE PURE AUTH. `VirtualKey` (which crosses this ABI as JSON in
/// the key CRUD messages) dropped its inline limits (`max_budget_cents` / `budget_period` /
/// `rpm_limit` / `tpm_limit`), renamed `budget_group` to `group`, and re-encoded `allowed_pools`
/// as an Option (`null` = all pools, `[]` = NO pools - C6). A breaking wire change to a message
/// payload, so the version bumps; still no earlier plugin exists in the wild.
///
/// v4 (1.5.0, pre-release): the usage ledger SPLIT its request count. `UsageLedger`/`UsageDelta`
/// (which cross this ABI as JSON in the `Get/Put/AddUsage` messages) gained `billable_requests`
/// alongside `requests`: `requests` stays the admission count (never refunded, the requests-limit
/// truth), `billable_requests` is admitted minus non-2xx refunds (the fee base for the 2xx-only
/// charge). The field is serde-default, so an older plugin's payload still deserializes; still a
/// wire-shape change to a message payload, so the version bumps in the same unreleased cycle.
pub const ABI_VERSION: u32 = 4;

/// The exported-symbol names the engine resolves after `dlopen`/`LoadLibrary`. A plugin of ANY kind
/// MUST export all SIX with these exact (kind-NEUTRAL) names and the signatures in the `*Fn` type
/// aliases below. NUL-terminated so they pass straight to `libloading`'s C-string symbol lookup. The
/// KIND a library speaks is read from [`PLUGIN_KIND`], not encoded in the symbol names.
pub mod symbol {
    /// `busbar_abi() -> u32` — the frozen TRANSPORT version handshake ([`super::TRANSPORT_VERSION`]).
    pub const ABI: &[u8] = b"busbar_abi\0";
    /// `busbar_plugin_kind() -> *const u8` — a NUL-terminated string, the ONE kind this lib speaks.
    pub const PLUGIN_KIND: &[u8] = b"busbar_plugin_kind\0";
    /// `busbar_open(cfg, cfg_len, out_handle, out_err, out_err_len) -> i32`.
    pub const OPEN: &[u8] = b"busbar_open\0";
    /// `busbar_call(handle, req, req_len, out, out_len) -> i32`.
    pub const CALL: &[u8] = b"busbar_call\0";
    /// `busbar_free(ptr, len)` — free a buffer the plugin allocated for the engine.
    pub const FREE: &[u8] = b"busbar_free\0";
    /// `busbar_close(handle)` — drop the instance.
    pub const CLOSE: &[u8] = b"busbar_close\0";
}

/// The hard cap on a single response/error buffer a plugin returns, checked BEFORE allocation on both
/// sides. Defense against a buggy/hostile plugin handing back a huge length to OOM the engine. 256 MiB
/// is orders of magnitude past any real governance/auth payload, so a legitimate reply never trips it.
pub const MAX_PLUGIN_RESPONSE_LEN: usize = 256 * 1024 * 1024;

/// Status returned by `open`/`call`. `OK`: the out buffer holds the success payload. `ERR`: the out
/// buffer holds a UTF-8 error message (a [`busbar_api::StoreError`] rendered). `PROTOCOL`: an
/// ABI-level violation (null/oversized args, a serialize failure inside the plugin) with no buffer.
pub const STATUS_OK: i32 = 0;
/// A store-level failure — the out buffer carries a UTF-8 error message.
pub const STATUS_ERR: i32 = 1;
/// An ABI/protocol violation (bad arguments, internal serialize failure) — no buffer produced.
pub const STATUS_PROTOCOL: i32 = -1;

/// A `Store` operation and its arguments, serialized as the `call` request payload. One
/// self-describing enum keeps the C ABI to a single `call` symbol regardless of how many methods
/// the `Store` trait grows — the variant IS the op-code. Mirrors [`busbar_api::Store`] one-to-one.
#[derive(Debug, Serialize, Deserialize)]
pub enum StoreRequest {
    PutKey(VirtualKey),
    GetKey(String),
    ListKeys,
    DeleteKey(String),
    /// `get_usage` - the (bucket, window) token ledger. `bucket_id` is a key id or a budget-group
    /// bucket id; no dollar field crosses this wire (spend derives from ledger x rate card).
    GetUsage {
        bucket_id: String,
        window_start: u64,
    },
    /// `put_usage` - ABSOLUTE set of a (bucket, window) ledger (single-writer write-behind).
    PutUsage {
        bucket_id: String,
        window_start: u64,
        ledger: UsageLedger,
    },
    /// `add_usage` - ADDITIVE accumulate of a (bucket, window) ledger: a signed requests delta plus
    /// per-(model, tier) signed token deltas (the fleet-honest flush; counters floor at 0).
    AddUsage {
        bucket_id: String,
        window_start: u64,
        delta: UsageDelta,
    },
    AddMetering(MeteringDelta),
    ListMetering(u64),
    PutAwsCredential(AwsCredential),
    PutKeyWithAwsCredential {
        key: VirtualKey,
        cred: AwsCredential,
    },
    ListAwsCredentials,
    /// `append_audit` — persist one admin audit record durably. ADDITIVE (ABI stays v1): a plugin
    /// built against the older SDK never sees this variant; the engine's loader maps its
    /// "unexpected/unsupported response" into the trait's default no-op, so old plugins are safe.
    AppendAudit(AuditRecord),
    /// `list_audit` — every persisted audit record (oldest-first), the boot restore source. ADDITIVE.
    ListAudit,
    /// `list_audit_tail` - the most-recent `limit` audit records, oldest-first (the BOUNDED boot
    /// restore source). ADDITIVE (ABI stays v1): a plugin built against the older SDK never sees this
    /// variant, so the engine's loader FALLS BACK to `ListAudit` + tail-truncation. Bounds the restore
    /// read so a large durable history cannot exceed the ABI response cap or OOM the ring.
    ListAuditTail(u64),
    /// `add_denylist` - revoke a signed-token key by subject id (1.5.0). ADDITIVE.
    AddDenylist {
        sub: String,
        reason: String,
    },
    /// `list_denylist` - every denied subject id (boot hydrate). ADDITIVE.
    ListDenylist,
}

/// The success payload for a `call`, matched to the request variant. Store-level errors do NOT ride
/// here — they return `STATUS_ERR` with the message in the out buffer — so a caller that sees `OK`
/// deserializes exactly the response shape its request implies.
#[derive(Debug, Serialize, Deserialize)]
pub enum StoreResponse {
    /// A write that returns nothing (`put_key`, `delete_key`, `put_usage`, `add_metering`, …).
    Unit,
    /// `get_key` — the key, or `None` if absent.
    Key(Option<VirtualKey>),
    /// `list_keys` — every key.
    Keys(Vec<VirtualKey>),
    /// `get_usage` - the (bucket, window) token ledger.
    Usage(UsageLedger),
    /// `list_metering` — the bucket's rows.
    Metering(Vec<MeteringRow>),
    /// `list_aws_credentials` — every credential.
    AwsCreds(Vec<AwsCredential>),
    /// `list_audit` — every persisted audit record, oldest-first. ADDITIVE (ABI stays v1).
    Audit(Vec<AuditRecord>),
    /// `list_denylist` - every denied subject id (1.5.0 signed-token revocation). ADDITIVE.
    Denylist(Vec<String>),
}

// ── SECRET-plugin wire (`kind: secret`) ─────────────────────────────────────────────────────────
// A secret plugin rides the SAME five-symbol C shape as a store plugin (version/open/call/free/
// close; JSON payloads over ptr+len), under its own symbol names and its own tiny request enum. A
// plugin is a plugin: the tarball/manifest/signature/trust pipeline is IDENTICAL - only the
// manifest `kind` (and therefore which engine seam consumes it) differs.

/// The secret-plugin PAYLOAD schema version (the signed manifest's `abi_version` for `kind: secret`).
/// v1 (1.5.0): the initial `Resolve` wire. This is the per-kind payload axis, NOT the transport axis
/// — a secret plugin exports the SAME six neutral symbols ([`symbol`]) as every other kind.
pub const SECRET_ABI_VERSION: u32 = 1;

/// A [`busbar_api::SecretModule`] operation, serialized as the secret `call` request payload.
#[derive(Debug, Serialize, Deserialize)]
pub enum SecretRequest {
    /// `resolve` - one secret reference's opaque settings map in, the secret bytes out.
    Resolve {
        settings: serde_json::Map<String, serde_json::Value>,
    },
}

/// The success payload for a secret `call`. Module-level failures return `STATUS_ERR` with a UTF-8
/// message in the out buffer (which must never carry secret material).
#[derive(Debug, Serialize, Deserialize)]
pub enum SecretResponse {
    /// `resolve` - the secret bytes.
    Bytes(Vec<u8>),
}

// ── C fn-pointer signatures the engine resolves ──────────────────────────────────────────────────
// Provided as type aliases so the engine's loader and the plugin's SDK agree on the exact ABI. All
// are `unsafe extern "C"`. Buffers the plugin allocates (the `out*` params) are owned by the engine
// until it calls `busbar_free` on them.

/// `busbar_abi` — returns the [`TRANSPORT_VERSION`] the plugin was built against.
pub type AbiFn = unsafe extern "C" fn() -> u32;

/// `busbar_plugin_kind` — returns a pointer to a NUL-terminated static string naming the ONE kind
/// this library speaks (`"store"` | `"secret"` | `"auth"`).
pub type PluginKindFn = unsafe extern "C" fn() -> *const u8;

/// `busbar_open` — construct an instance from a JSON config blob. On `STATUS_OK`, `*out_handle` is
/// the opaque instance pointer (passed back to `call`/`close`). On `STATUS_ERR`, `*out_err` /
/// `*out_err_len` hold a UTF-8 message the engine must `free`.
pub type OpenFn = unsafe extern "C" fn(
    cfg: *const u8,
    cfg_len: usize,
    out_handle: *mut *mut c_void,
    out_err: *mut *mut u8,
    out_err_len: *mut usize,
) -> i32;

/// `busbar_call` — run one request (JSON in `req`). On `STATUS_OK`, `*out`/`*out_len` hold the JSON
/// response; on `STATUS_ERR`, a UTF-8 error message. Either way the engine owns and must `free` the
/// out buffer.
pub type CallFn = unsafe extern "C" fn(
    handle: *mut c_void,
    req: *const u8,
    req_len: usize,
    out: *mut *mut u8,
    out_len: *mut usize,
) -> i32;

/// `busbar_free` — release a buffer the plugin allocated (`open`'s error, `call`'s payload). The
/// plugin frees with the SAME allocator it allocated with — the engine never frees plugin memory.
pub type FreeFn = unsafe extern "C" fn(ptr: *mut u8, len: usize);

/// `busbar_close` — drop the instance behind `handle`. Called once, at shutdown/unload.
pub type CloseFn = unsafe extern "C" fn(handle: *mut c_void);

#[cfg(test)]
mod tests {
    use super::*;
    use busbar_api::{AuditRecord, VirtualKey};

    fn sample_audit() -> AuditRecord {
        AuditRecord {
            seq: 7,
            ts: 123,
            action: "plugin.install".into(),
            resource: "plugin:x".into(),
            outcome: "applied".into(),
            principal: "admin".into(),
            prev_hash: "abc".into(),
            hash: "def".into(),
        }
    }

    fn sample_key() -> VirtualKey {
        VirtualKey {
            id: "vk_1".into(),
            key_hash: "deadbeef".into(),
            name: "test".into(),
            allowed_pools: Some(vec!["p1".into()]),
            enabled: true,
            created_at: 42,
            group: Some("growth".into()),
            labels: std::collections::BTreeMap::new(),
        }
    }

    /// The request/response enums round-trip through JSON unchanged — the wire is stable and the
    /// variant is self-describing (no separate op-code needed).
    #[test]
    fn request_response_json_roundtrip() {
        let reqs = vec![
            StoreRequest::PutKey(sample_key()),
            StoreRequest::GetKey("vk_1".into()),
            StoreRequest::ListKeys,
            StoreRequest::DeleteKey("vk_1".into()),
            StoreRequest::GetUsage {
                bucket_id: "vk_1".into(),
                window_start: 100,
            },
            StoreRequest::PutUsage {
                bucket_id: "vk_1".into(),
                window_start: 100,
                ledger: busbar_api::UsageLedger {
                    requests: 1,
                    billable_requests: 1,
                    models: vec![busbar_api::ModelTokens {
                        model: "gpt-5".into(),
                        tokens: busbar_api::TierTokens {
                            input: 7,
                            output: 3,
                            cache_read: 1,
                            cache_write: 0,
                        },
                    }],
                },
            },
            StoreRequest::AddUsage {
                bucket_id: "group:growth".into(),
                window_start: 100,
                delta: busbar_api::UsageDelta {
                    requests: 1,
                    billable_requests: 1,
                    models: vec![busbar_api::ModelTokensDelta {
                        model: "gpt-5".into(),
                        tokens: busbar_api::TierTokensDelta {
                            input: 7,
                            output: -3,
                            cache_read: 0,
                            cache_write: 0,
                        },
                    }],
                },
            },
            StoreRequest::ListMetering(9),
            StoreRequest::ListAwsCredentials,
            StoreRequest::AppendAudit(sample_audit()),
            StoreRequest::ListAudit,
            StoreRequest::ListAuditTail(500),
        ];
        for r in reqs {
            let j = serde_json::to_vec(&r).unwrap();
            let back: StoreRequest = serde_json::from_slice(&j).unwrap();
            // Re-serialize and compare bytes (the enums aren't PartialEq, but their JSON is stable).
            assert_eq!(serde_json::to_vec(&back).unwrap(), j);
        }

        // The audit response variant round-trips too.
        let ar = StoreResponse::Audit(vec![sample_audit()]);
        let j = serde_json::to_vec(&ar).unwrap();
        match serde_json::from_slice::<StoreResponse>(&j).unwrap() {
            StoreResponse::Audit(v) => assert_eq!(v, vec![sample_audit()]),
            _ => panic!("wrong variant"),
        }

        let key = sample_key();
        let resp = StoreResponse::Key(Some(key.clone()));
        let j = serde_json::to_vec(&resp).unwrap();
        let back: StoreResponse = serde_json::from_slice(&j).unwrap();
        match back {
            StoreResponse::Key(Some(k)) => assert!(k == key),
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn abi_version_is_two() {
        // v4 = the billable-requests ledger split (1.5.0). A mismatched plugin is refused at the
        // handshake.
        assert_eq!(ABI_VERSION, 4);
    }
}
