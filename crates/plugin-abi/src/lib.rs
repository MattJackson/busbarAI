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

use busbar_api::{AuditRecord, AwsCredential, MeteringDelta, MeteringRow, Usage, VirtualKey};
use serde::{Deserialize, Serialize};
use std::os::raw::c_void;

/// The store-plugin ABI version this crate defines. Bumped only on a breaking change to the wire
/// (the request/response shape or the C signatures); additive changes keep the version.
pub const ABI_VERSION: u32 = 1;

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
    GetUsage {
        key_id: String,
        window_start: u64,
    },
    PutUsage {
        key_id: String,
        window_start: u64,
        spend_cents: i64,
        tokens: u64,
        requests: u64,
    },
    /// `add_usage` — ADDITIVE accumulate of a key's window counter (signed deltas; the
    /// fleet-honest flush). ADDITIVE (ABI stays v1): a plugin built against an older SDK never
    /// learned this variant and rejects it; the loader falls back to a read-modify-write
    /// (get + put) with documented single-writer semantics.
    AddUsage {
        key_id: String,
        window_start: u64,
        delta_spend_cents: i64,
        delta_tokens: i64,
        delta_requests: i64,
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
    /// `get_usage` — the window counter.
    Usage(Usage),
    /// `list_metering` — the bucket's rows.
    Metering(Vec<MeteringRow>),
    /// `list_aws_credentials` — every credential.
    AwsCreds(Vec<AwsCredential>),
    /// `list_audit` — every persisted audit record, oldest-first. ADDITIVE (ABI stays v1).
    Audit(Vec<AuditRecord>),
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
                key_id: "vk_1".into(),
                window_start: 100,
            },
            StoreRequest::PutUsage {
                key_id: "vk_1".into(),
                window_start: 100,
                spend_cents: 5,
                tokens: 7,
                requests: 1,
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
    fn abi_version_is_one() {
        assert_eq!(ABI_VERSION, 1);
    }
}
