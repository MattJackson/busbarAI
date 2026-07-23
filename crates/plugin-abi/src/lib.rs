// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The busbar **store-plugin C ABI** — the frozen, versioned wire between the engine and a
//! `Store` backend that lives in a dynamic library (`.so`/`.dll`/`.dylib`) it loads at runtime,
//! OR is compiled straight in.
//!
//! ## Shape
//!
//! A store plugin exports a tiny fixed set of `extern "C"` symbols (see [`symbol`]). The engine
//! resolves them via `libloading` and calls across the boundary passing **JSON-serialized bytes**
//! (a `ptr + len`), never C structs. JSON — not a `repr(C)` struct — because:
//!
//! - it is **version-tolerant**: fields can be added to the contract records without breaking the
//!   ABI (a new field an old plugin doesn't know is simply ignored / defaulted);
//! - it is **language-agnostic**: a plugin can be written in C/Go/Zig as long as it speaks the
//!   symbols and the JSON;
//! - the cost is **irrelevant**: the store is off the request hot path (the engine holds the
//!   authoritative counters in memory and treats the store as write-behind durability), so a
//!   serialize per call — every ~100 ms flush + admin op — never touches request latency.
//!
//! The whole surface is FIVE functions: `version`, `open`, `call`, `free`, `close`. Every store
//! operation ([`StoreRequest`]) rides the single `call`, self-described by the request enum, so the
//! C symbol set never grows as the `Store` trait does.
//!
//! ## Versioning
//!
//! [`ABI_VERSION`] is the contract version. A plugin exports `busbar_store_abi_version()` returning
//! the version it was built against; the engine refuses to load a mismatch (a plugin built for a
//! different ABI is not loaded, never mis-called). The ABI is append-only, like the frozen Admin API.

use busbar_api::{
    AuditRecord, AwsCredential, MeteringDelta, MeteringRow, UsageDelta, UsageLedger, VirtualKey,
};
use serde::{Deserialize, Serialize};
use std::os::raw::c_void;

/// The store-plugin ABI version this crate defines. Bumped only on a breaking change to the wire
/// (the request/response shape or the C signatures); additive changes keep the version.
///
/// v2 (1.5.0, pre-release): the scalar `Usage { spend_cents, tokens, requests }` counter became the
/// per-(model, tier) TOKEN LEDGER (`UsageLedger`/`UsageDelta`) and `Get/Put/AddUsage` re-keyed from
/// `key_id` to `bucket_id` (key buckets and budget-group buckets share the shape). A breaking wire
/// change, so the version bumps: a v1 plugin is refused at load, never mis-called. 1.5.0 is
/// unreleased, so no v1 plugin exists in the wild.
pub const ABI_VERSION: u32 = 2;

/// The exported-symbol names the engine resolves after `dlopen`/`LoadLibrary`. A store plugin MUST
/// export all five with these exact names and the signatures in the `*Fn` type aliases below. The
/// constants are NUL-terminated so they pass straight to `libloading`'s C-string symbol lookup.
pub mod symbol {
    /// `busbar_store_abi_version() -> u32` — the ABI handshake.
    pub const ABI_VERSION: &[u8] = b"busbar_store_abi_version\0";
    /// `busbar_store_open(cfg, cfg_len, out_handle, out_err, out_err_len) -> i32`.
    pub const OPEN: &[u8] = b"busbar_store_open\0";
    /// `busbar_store_call(handle, req, req_len, out, out_len) -> i32`.
    pub const CALL: &[u8] = b"busbar_store_call\0";
    /// `busbar_store_free(ptr, len)` — free a buffer the plugin allocated for the engine.
    pub const FREE: &[u8] = b"busbar_store_free\0";
    /// `busbar_store_close(handle)` — drop the store instance.
    pub const CLOSE: &[u8] = b"busbar_store_close\0";
}

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
}

// ── SECRET-plugin wire (`kind: secret`) ─────────────────────────────────────────────────────────
// A secret plugin rides the SAME five-symbol C shape as a store plugin (version/open/call/free/
// close; JSON payloads over ptr+len), under its own symbol names and its own tiny request enum. A
// plugin is a plugin: the tarball/manifest/signature/trust pipeline is IDENTICAL - only the
// manifest `kind` (and therefore which engine seam consumes it) differs.

/// The secret-plugin ABI version. v1 (1.5.0): the initial `Resolve` wire.
pub const SECRET_ABI_VERSION: u32 = 1;

/// The exported-symbol names of a SECRET plugin (`kind: secret`). Same five-symbol shape as
/// [`symbol`], distinct names so one dylib could even export both kinds without collision.
pub mod secret_symbol {
    /// `busbar_secret_abi_version() -> u32` - the ABI handshake.
    pub const ABI_VERSION: &[u8] = b"busbar_secret_abi_version\0";
    /// `busbar_secret_open(cfg, cfg_len, out_handle, out_err, out_err_len) -> i32`.
    pub const OPEN: &[u8] = b"busbar_secret_open\0";
    /// `busbar_secret_call(handle, req, req_len, out, out_len) -> i32`.
    pub const CALL: &[u8] = b"busbar_secret_call\0";
    /// `busbar_secret_free(ptr, len)` - free a buffer the plugin allocated for the engine.
    pub const FREE: &[u8] = b"busbar_secret_free\0";
    /// `busbar_secret_close(handle)` - drop the module instance.
    pub const CLOSE: &[u8] = b"busbar_secret_close\0";
}

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
// until it calls `busbar_store_free` on them.

/// `busbar_store_abi_version` — returns the [`ABI_VERSION`] the plugin was built against.
pub type AbiVersionFn = unsafe extern "C" fn() -> u32;

/// `busbar_store_open` — construct a store from a JSON config blob. On `STATUS_OK`, `*out_handle` is
/// the opaque instance pointer (passed back to `call`/`close`). On `STATUS_ERR`, `*out_err` /
/// `*out_err_len` hold a UTF-8 message the engine must `free`.
pub type OpenFn = unsafe extern "C" fn(
    cfg: *const u8,
    cfg_len: usize,
    out_handle: *mut *mut c_void,
    out_err: *mut *mut u8,
    out_err_len: *mut usize,
) -> i32;

/// `busbar_store_call` — run one [`StoreRequest`] (JSON in `req`). On `STATUS_OK`, `*out`/`*out_len`
/// hold the JSON [`StoreResponse`]; on `STATUS_ERR`, a UTF-8 error message. Either way the engine
/// owns and must `free` the out buffer.
pub type CallFn = unsafe extern "C" fn(
    handle: *mut c_void,
    req: *const u8,
    req_len: usize,
    out: *mut *mut u8,
    out_len: *mut usize,
) -> i32;

/// `busbar_store_free` — release a buffer the plugin allocated (`open`'s error, `call`'s payload).
/// The plugin frees with the SAME allocator it allocated with — the engine never frees plugin memory
/// itself.
pub type FreeFn = unsafe extern "C" fn(ptr: *mut u8, len: usize);

/// `busbar_store_close` — drop the store instance behind `handle`. Called once, at shutdown/unload.
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
            allowed_pools: vec!["p1".into()],
            max_budget_cents: Some(1000),
            budget_period: "total".into(),
            rpm_limit: Some(60),
            tpm_limit: None,
            enabled: true,
            created_at: 42,
            budget_group: Some("growth".into()),
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
        // v2 = the token-ledger wire (1.5.0). A v1 plugin is refused at the handshake.
        assert_eq!(ABI_VERSION, 2);
    }
}
