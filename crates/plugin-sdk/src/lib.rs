// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! SDK for writing a busbar **store plugin** in Rust.
//!
//! Writing a plugin is: implement [`busbar_api::Store`] for your backend, write a constructor
//! `fn(&str) -> Result<Box<dyn Store>, String>` (the `&str` is the JSON config the operator set),
//! call [`export_store_plugin!`] with it, and build the crate as a `cdylib`. The macro emits the
//! five `extern "C"` symbols the engine's loader resolves ([`busbar_plugin_abi`]); everything unsafe
//! lives here in [`open_impl`]/[`call_impl`]/[`free_impl`]/[`close_impl`], which are ordinary,
//! unit-tested functions — the macro is a thin, per-plugin wrapper.
//!
//! ```ignore
//! use busbar_plugin_sdk::export_store_plugin;
//! fn open(cfg: &str) -> Result<Box<dyn busbar_api::Store>, String> {
//!     Ok(Box::new(MyStore::new(cfg)?))
//! }
//! export_store_plugin!(open);
//! ```
//!
//! The same crate is usable **statically**: depend on it as a normal `lib` and construct
//! `MyStore` directly — the C ABI is only the *dynamic* delivery path. That is how a build can bake
//! a plugin in (e.g. Postgres compiled straight into a custom binary) without any `cfg` sprawl.

use busbar_api::{Store, StoreError};
use busbar_plugin_abi::{
    StoreRequest, StoreResponse, ABI_VERSION, STATUS_ERR, STATUS_OK, STATUS_PROTOCOL,
};
use std::os::raw::c_void;
use std::panic::{catch_unwind, AssertUnwindSafe};

// Re-export so a plugin's `export_store_plugin!` expansion can name the trait via `$crate`.
pub use busbar_api::Store as StoreTrait;

/// The store handle behind the opaque `*mut c_void` that crosses the ABI: a boxed trait object.
type BoxedStore = Box<dyn Store>;

/// Return the ABI version this SDK builds against (a plugin exports it as `busbar_store_abi_version`).
pub fn abi_version() -> u32 {
    ABI_VERSION
}

/// Run one [`StoreRequest`] against a `Store`. The single match that maps the wire enum to the trait
/// — shared by the C `call` glue and directly unit-testable without any FFI.
pub fn dispatch(store: &dyn Store, req: StoreRequest) -> Result<StoreResponse, StoreError> {
    use StoreRequest as Q;
    use StoreResponse as R;
    Ok(match req {
        Q::PutKey(k) => {
            store.put_key(&k)?;
            R::Unit
        }
        Q::GetKey(id) => R::Key(store.get_key(&id)?),
        Q::ListKeys => R::Keys(store.list_keys()?),
        Q::DeleteKey(id) => {
            store.delete_key(&id)?;
            R::Unit
        }
        Q::GetUsage {
            bucket_id,
            window_start,
        } => R::Usage(store.get_usage(&bucket_id, window_start)?),
        Q::PutUsage {
            bucket_id,
            window_start,
            ledger,
        } => {
            store.put_usage(&bucket_id, window_start, &ledger)?;
            R::Unit
        }
        Q::AddUsage {
            bucket_id,
            window_start,
            delta,
        } => {
            store.add_usage(&bucket_id, window_start, &delta)?;
            R::Unit
        }
        Q::AddMetering(d) => {
            store.add_metering(&d)?;
            R::Unit
        }
        Q::ListMetering(b) => R::Metering(store.list_metering(b)?),
        Q::PutAwsCredential(c) => {
            store.put_aws_credential(&c)?;
            R::Unit
        }
        Q::PutKeyWithAwsCredential { key, cred } => {
            store.put_key_with_aws_credential(&key, &cred)?;
            R::Unit
        }
        Q::ListAwsCredentials => R::AwsCreds(store.list_aws_credentials()?),
        Q::AppendAudit(e) => {
            store.append_audit(&e)?;
            R::Unit
        }
        Q::ListAudit => R::Audit(store.list_audit()?),
        Q::ListAuditTail(limit) => R::Audit(store.list_audit_tail(limit)?),
        Q::AddDenylist { sub, reason } => {
            store.add_denylist(&sub, &reason)?;
            R::Unit
        }
        Q::ListDenylist => R::Denylist(store.list_denylist()?),
    })
}

/// Hand a byte buffer to the engine: allocate as a boxed slice (so cap == len), leak it, and write
/// (ptr, len). The engine owns it until it calls [`free_impl`]. `out`/`out_len` must be non-null.
unsafe fn write_buf(bytes: Vec<u8>, out: *mut *mut u8, out_len: *mut usize) {
    let boxed = bytes.into_boxed_slice();
    let len = boxed.len();
    let ptr = Box::into_raw(boxed) as *mut u8;
    if !out.is_null() {
        *out = ptr;
    }
    if !out_len.is_null() {
        *out_len = len;
    }
}

/// `busbar_store_free` body — reclaim a buffer produced by [`open_impl`]/[`call_impl`]. Freed with the
/// same allocator that produced it (the plugin's), never the engine's.
///
/// # Safety
/// `(ptr, len)` must be exactly a pair this plugin returned and not yet freed.
pub unsafe fn free_impl(ptr: *mut u8, len: usize) {
    if ptr.is_null() {
        return;
    }
    let slice = std::slice::from_raw_parts_mut(ptr, len);
    drop(Box::from_raw(slice as *mut [u8]));
}

/// `busbar_store_open` body — build a store from the JSON config via `ctor`. On success sets
/// `*out_handle`; on failure writes a UTF-8 message to `out_err`/`out_err_len`. A panic in the
/// constructor is caught and reported as a protocol error (a panic must never cross the C boundary).
///
/// # Safety
/// Pointers must be valid per the ABI: `cfg`/`cfg_len` a readable buffer (or len 0), and the three
/// out pointers writable.
pub unsafe fn open_impl(
    cfg: *const u8,
    cfg_len: usize,
    out_handle: *mut *mut c_void,
    out_err: *mut *mut u8,
    out_err_len: *mut usize,
    ctor: fn(&str) -> Result<BoxedStore, String>,
) -> i32 {
    let res = catch_unwind(AssertUnwindSafe(|| {
        let bytes: &[u8] = if cfg_len == 0 {
            &[]
        } else if cfg.is_null() {
            return Err((String::from("null config pointer"), true));
        } else {
            std::slice::from_raw_parts(cfg, cfg_len)
        };
        let s = match std::str::from_utf8(bytes) {
            Ok(s) => s,
            Err(_) => return Err((String::from("config is not valid UTF-8"), true)),
        };
        ctor(s).map_err(|msg| (msg, false))
    }));
    match res {
        Ok(Ok(store)) => {
            let handle = Box::into_raw(Box::new(store)) as *mut c_void;
            if !out_handle.is_null() {
                *out_handle = handle;
            }
            STATUS_OK
        }
        Ok(Err((msg, protocol))) => {
            write_buf(msg.into_bytes(), out_err, out_err_len);
            if protocol {
                STATUS_PROTOCOL
            } else {
                STATUS_ERR
            }
        }
        Err(_) => STATUS_PROTOCOL,
    }
}

/// `busbar_store_call` body — deserialize a [`StoreRequest`], run it, serialize the [`StoreResponse`].
/// On `STATUS_OK` the out buffer holds the response JSON; on a nonzero status it holds a UTF-8 error
/// message. A panic in the backend is caught and reported as a protocol error.
///
/// # Safety
/// `handle` must be a live handle from [`open_impl`]; `req`/`req_len` a readable buffer (or len 0);
/// the out pointers writable.
pub unsafe fn call_impl(
    handle: *mut c_void,
    req: *const u8,
    req_len: usize,
    out: *mut *mut u8,
    out_len: *mut usize,
) -> i32 {
    if handle.is_null() {
        return STATUS_PROTOCOL;
    }
    let store: &BoxedStore = &*(handle as *const BoxedStore);
    let res = catch_unwind(AssertUnwindSafe(|| {
        let bytes: &[u8] = if req_len == 0 {
            &[]
        } else if req.is_null() {
            return Err((String::from("null request pointer"), true));
        } else {
            std::slice::from_raw_parts(req, req_len)
        };
        let request: StoreRequest = match serde_json::from_slice(bytes) {
            Ok(r) => r,
            Err(e) => return Err((format!("malformed request JSON: {e}"), true)),
        };
        match dispatch(store.as_ref(), request) {
            Ok(resp) => serde_json::to_vec(&resp)
                .map_err(|e| (format!("response encode failed: {e}"), true)),
            Err(e) => Err((e.0, false)),
        }
    }));
    match res {
        Ok(Ok(payload)) => {
            write_buf(payload, out, out_len);
            STATUS_OK
        }
        Ok(Err((msg, protocol))) => {
            write_buf(msg.into_bytes(), out, out_len);
            if protocol {
                STATUS_PROTOCOL
            } else {
                STATUS_ERR
            }
        }
        Err(_) => STATUS_PROTOCOL,
    }
}

/// `busbar_store_close` body — drop the store instance behind `handle`. Idempotent on null.
///
/// # Safety
/// `handle` must be a live handle from [`open_impl`] that has not already been closed.
pub unsafe fn close_impl(handle: *mut c_void) {
    if handle.is_null() {
        return;
    }
    drop(Box::from_raw(handle as *mut BoxedStore));
}

// ── SECRET-plugin glue (`kind: secret`) ─────────────────────────────────────────────────────────
// Mirrors the store glue one-to-one: same five-symbol shape, same panic-catching impl style, its
// own handle type (`Box<dyn SecretModule>`) and its own tiny request enum.

/// The secret handle behind the opaque `*mut c_void`: a boxed [`busbar_api::SecretModule`].
type BoxedSecret = Box<dyn busbar_api::SecretModule>;

/// Return the SECRET ABI version this SDK builds against (`busbar_secret_abi_version`).
pub fn secret_abi_version() -> u32 {
    busbar_plugin_abi::SECRET_ABI_VERSION
}

/// Run one [`busbar_plugin_abi::SecretRequest`] against a secret module - the single match that
/// maps the wire enum to the trait, unit-testable without FFI.
pub fn dispatch_secret(
    module: &dyn busbar_api::SecretModule,
    req: busbar_plugin_abi::SecretRequest,
) -> Result<busbar_plugin_abi::SecretResponse, busbar_api::SecretError> {
    match req {
        busbar_plugin_abi::SecretRequest::Resolve { settings } => Ok(
            busbar_plugin_abi::SecretResponse::Bytes(module.resolve(&settings)?),
        ),
    }
}

/// `busbar_secret_open` body - build a secret module from the JSON config via `ctor`.
///
/// # Safety
/// Pointers must be valid per the ABI (see [`open_impl`]).
pub unsafe fn secret_open_impl(
    cfg: *const u8,
    cfg_len: usize,
    out_handle: *mut *mut c_void,
    out_err: *mut *mut u8,
    out_err_len: *mut usize,
    ctor: fn(&str) -> Result<BoxedSecret, String>,
) -> i32 {
    let res = catch_unwind(AssertUnwindSafe(|| {
        let bytes: &[u8] = if cfg_len == 0 {
            &[]
        } else if cfg.is_null() {
            return Err((String::from("null config pointer"), true));
        } else {
            std::slice::from_raw_parts(cfg, cfg_len)
        };
        let s = match std::str::from_utf8(bytes) {
            Ok(s) => s,
            Err(_) => return Err((String::from("config is not valid UTF-8"), true)),
        };
        ctor(s).map_err(|msg| (msg, false))
    }));
    match res {
        Ok(Ok(module)) => {
            let handle = Box::into_raw(Box::new(module)) as *mut c_void;
            if !out_handle.is_null() {
                *out_handle = handle;
            }
            STATUS_OK
        }
        Ok(Err((msg, protocol))) => {
            write_buf(msg.into_bytes(), out_err, out_err_len);
            if protocol {
                STATUS_PROTOCOL
            } else {
                STATUS_ERR
            }
        }
        Err(_) => STATUS_PROTOCOL,
    }
}

/// `busbar_secret_call` body - deserialize a [`busbar_plugin_abi::SecretRequest`], run it,
/// serialize the response. Panics are caught (a panic never crosses the C boundary).
///
/// # Safety
/// `handle` must be a live handle from [`secret_open_impl`]; buffers per the ABI.
pub unsafe fn secret_call_impl(
    handle: *mut c_void,
    req: *const u8,
    req_len: usize,
    out: *mut *mut u8,
    out_len: *mut usize,
) -> i32 {
    if handle.is_null() {
        return STATUS_PROTOCOL;
    }
    let module: &BoxedSecret = &*(handle as *const BoxedSecret);
    let res = catch_unwind(AssertUnwindSafe(|| {
        let bytes: &[u8] = if req_len == 0 {
            &[]
        } else if req.is_null() {
            return Err((String::from("null request pointer"), true));
        } else {
            std::slice::from_raw_parts(req, req_len)
        };
        let request: busbar_plugin_abi::SecretRequest = match serde_json::from_slice(bytes) {
            Ok(r) => r,
            Err(e) => return Err((format!("malformed request JSON: {e}"), true)),
        };
        match dispatch_secret(module.as_ref(), request) {
            Ok(resp) => serde_json::to_vec(&resp)
                .map_err(|e| (format!("response encode failed: {e}"), true)),
            Err(e) => Err((e.0, false)),
        }
    }));
    match res {
        Ok(Ok(payload)) => {
            write_buf(payload, out, out_len);
            STATUS_OK
        }
        Ok(Err((msg, protocol))) => {
            write_buf(msg.into_bytes(), out, out_len);
            if protocol {
                STATUS_PROTOCOL
            } else {
                STATUS_ERR
            }
        }
        Err(_) => STATUS_PROTOCOL,
    }
}

/// `busbar_secret_close` body - drop the secret-module instance. Idempotent on null.
///
/// # Safety
/// `handle` must be a live handle from [`secret_open_impl`] not already closed.
pub unsafe fn secret_close_impl(handle: *mut c_void) {
    if handle.is_null() {
        return;
    }
    drop(Box::from_raw(handle as *mut BoxedSecret));
}

/// Emit the five `extern "C"` SECRET-plugin symbols, wiring them to `$ctor` (a
/// `fn(&str) -> Result<Box<dyn busbar_api::SecretModule>, String>`). Put this at the crate root of
/// a `cdylib` plugin whose manifest declares `kind: secret`.
#[macro_export]
macro_rules! export_secret_plugin {
    ($ctor:path) => {
        #[no_mangle]
        pub extern "C" fn busbar_secret_abi_version() -> u32 {
            $crate::secret_abi_version()
        }

        /// # Safety
        /// Called only by the busbar loader with ABI-valid pointers.
        #[no_mangle]
        pub unsafe extern "C" fn busbar_secret_open(
            cfg: *const u8,
            cfg_len: usize,
            out_handle: *mut *mut ::core::ffi::c_void,
            out_err: *mut *mut u8,
            out_err_len: *mut usize,
        ) -> i32 {
            $crate::secret_open_impl(cfg, cfg_len, out_handle, out_err, out_err_len, $ctor)
        }

        /// # Safety
        /// Called only by the busbar loader with a live handle and ABI-valid pointers.
        #[no_mangle]
        pub unsafe extern "C" fn busbar_secret_call(
            handle: *mut ::core::ffi::c_void,
            req: *const u8,
            req_len: usize,
            out: *mut *mut u8,
            out_len: *mut usize,
        ) -> i32 {
            $crate::secret_call_impl(handle, req, req_len, out, out_len)
        }

        /// # Safety
        /// Called only by the busbar loader with a buffer this plugin returned.
        #[no_mangle]
        pub unsafe extern "C" fn busbar_secret_free(ptr: *mut u8, len: usize) {
            $crate::free_impl(ptr, len)
        }

        /// # Safety
        /// Called only by the busbar loader with a live handle, once.
        #[no_mangle]
        pub unsafe extern "C" fn busbar_secret_close(handle: *mut ::core::ffi::c_void) {
            $crate::secret_close_impl(handle)
        }
    };
}

/// Emit the five `extern "C"` store-plugin symbols, wiring them to `$ctor` (a
/// `fn(&str) -> Result<Box<dyn Store>, String>`). Put this at the crate root of a `cdylib` plugin.
#[macro_export]
macro_rules! export_store_plugin {
    ($ctor:path) => {
        #[no_mangle]
        pub extern "C" fn busbar_store_abi_version() -> u32 {
            $crate::abi_version()
        }

        /// # Safety
        /// Called only by the busbar loader with ABI-valid pointers.
        #[no_mangle]
        pub unsafe extern "C" fn busbar_store_open(
            cfg: *const u8,
            cfg_len: usize,
            out_handle: *mut *mut ::core::ffi::c_void,
            out_err: *mut *mut u8,
            out_err_len: *mut usize,
        ) -> i32 {
            $crate::open_impl(cfg, cfg_len, out_handle, out_err, out_err_len, $ctor)
        }

        /// # Safety
        /// Called only by the busbar loader with a live handle and ABI-valid pointers.
        #[no_mangle]
        pub unsafe extern "C" fn busbar_store_call(
            handle: *mut ::core::ffi::c_void,
            req: *const u8,
            req_len: usize,
            out: *mut *mut u8,
            out_len: *mut usize,
        ) -> i32 {
            $crate::call_impl(handle, req, req_len, out, out_len)
        }

        /// # Safety
        /// Called only by the busbar loader with a buffer this plugin returned.
        #[no_mangle]
        pub unsafe extern "C" fn busbar_store_free(ptr: *mut u8, len: usize) {
            $crate::free_impl(ptr, len)
        }

        /// # Safety
        /// Called only by the busbar loader with a live handle, once.
        #[no_mangle]
        pub unsafe extern "C" fn busbar_store_close(handle: *mut ::core::ffi::c_void) {
            $crate::close_impl(handle)
        }
    };
}

#[cfg(test)]
mod tests {
    use super::*;
    use busbar_api::VirtualKey;
    use busbar_store_memory::MemoryStore;
    use std::ptr;

    /// A test secret module: settings.name in, "resolved:<name>" bytes out; missing name errors.
    struct EchoSecret;
    impl busbar_api::SecretModule for EchoSecret {
        fn resolve(
            &self,
            settings: &serde_json::Map<String, serde_json::Value>,
        ) -> busbar_api::SecretResult<Vec<u8>> {
            match settings.get("name").and_then(|v| v.as_str()) {
                Some(n) => Ok(format!("resolved:{n}").into_bytes()),
                None => Err(busbar_api::SecretError("settings.name required".into())),
            }
        }
    }

    fn secret_ctor(_cfg: &str) -> Result<BoxedSecret, String> {
        Ok(Box::new(EchoSecret))
    }

    /// SECRET glue (P2): dispatch maps the wire enum to the trait, success and failure.
    #[test]
    fn secret_dispatch_resolves_and_fails_closed() {
        let mut settings = serde_json::Map::new();
        settings.insert("name".to_string(), serde_json::Value::String("db".into()));
        match dispatch_secret(
            &EchoSecret,
            busbar_plugin_abi::SecretRequest::Resolve { settings },
        )
        .expect("resolves")
        {
            busbar_plugin_abi::SecretResponse::Bytes(b) => assert_eq!(b, b"resolved:db"),
        }
        let err = dispatch_secret(
            &EchoSecret,
            busbar_plugin_abi::SecretRequest::Resolve {
                settings: serde_json::Map::new(),
            },
        )
        .unwrap_err();
        assert!(err.0.contains("settings.name required"));
    }

    /// SECRET glue (P2): the FFI path (open -> call -> close) round-trips a resolve and surfaces a
    /// module failure as STATUS_ERR with the message in the out buffer.
    #[test]
    fn secret_ffi_roundtrip_open_call_close() {
        unsafe {
            let mut handle: *mut c_void = ptr::null_mut();
            let mut err: *mut u8 = ptr::null_mut();
            let mut err_len: usize = 0;
            let status = secret_open_impl(
                b"{}".as_ptr(),
                2,
                &mut handle,
                &mut err,
                &mut err_len,
                secret_ctor,
            );
            assert_eq!(status, STATUS_OK);
            assert!(!handle.is_null());

            // resolve success
            let mut settings = serde_json::Map::new();
            settings.insert("name".to_string(), serde_json::Value::String("x".into()));
            let req = serde_json::to_vec(&busbar_plugin_abi::SecretRequest::Resolve { settings })
                .unwrap();
            let mut out: *mut u8 = ptr::null_mut();
            let mut out_len: usize = 0;
            let status = secret_call_impl(handle, req.as_ptr(), req.len(), &mut out, &mut out_len);
            assert_eq!(status, STATUS_OK);
            let resp: busbar_plugin_abi::SecretResponse =
                serde_json::from_slice(std::slice::from_raw_parts(out, out_len)).unwrap();
            free_impl(out, out_len);
            match resp {
                busbar_plugin_abi::SecretResponse::Bytes(b) => assert_eq!(b, b"resolved:x"),
            }

            // resolve failure -> STATUS_ERR with the message (never a panic across the boundary)
            let req = serde_json::to_vec(&busbar_plugin_abi::SecretRequest::Resolve {
                settings: serde_json::Map::new(),
            })
            .unwrap();
            let mut out: *mut u8 = ptr::null_mut();
            let mut out_len: usize = 0;
            let status = secret_call_impl(handle, req.as_ptr(), req.len(), &mut out, &mut out_len);
            assert_eq!(status, STATUS_ERR);
            let msg =
                String::from_utf8_lossy(std::slice::from_raw_parts(out, out_len)).into_owned();
            free_impl(out, out_len);
            assert!(msg.contains("settings.name required"), "got {msg}");

            secret_close_impl(handle);
        }
    }

    fn mem_ctor(_cfg: &str) -> Result<BoxedStore, String> {
        Ok(Box::new(MemoryStore::new()))
    }

    fn ctor_that_errors(_cfg: &str) -> Result<BoxedStore, String> {
        Err("nope".to_string())
    }

    fn key(id: &str) -> VirtualKey {
        VirtualKey {
            id: id.into(),
            key_hash: "hash".into(),
            name: "n".into(),
            allowed_pools: None,
            enabled: true,
            created_at: 1,
            group: None,
            labels: std::collections::BTreeMap::new(),
        }
    }

    /// Drive the FFI helpers exactly as the loader would: open → call (put then get) → close, and
    /// free every buffer. Proves the whole serialize → dispatch → deserialize path over the boxed
    /// handle, against a real Store.
    #[test]
    fn ffi_roundtrip_open_call_close() {
        unsafe {
            // open
            let mut handle: *mut c_void = ptr::null_mut();
            let mut err: *mut u8 = ptr::null_mut();
            let mut err_len: usize = 0;
            let cfg = b"{}";
            let st = open_impl(
                cfg.as_ptr(),
                cfg.len(),
                &mut handle,
                &mut err,
                &mut err_len,
                mem_ctor,
            );
            assert_eq!(st, STATUS_OK);
            assert!(!handle.is_null());

            // call: PutKey
            let put = serde_json::to_vec(&StoreRequest::PutKey(key("vk_1"))).unwrap();
            let mut out: *mut u8 = ptr::null_mut();
            let mut out_len: usize = 0;
            let st = call_impl(handle, put.as_ptr(), put.len(), &mut out, &mut out_len);
            assert_eq!(st, STATUS_OK);
            free_impl(out, out_len);

            // call: GetKey -> Some(key)
            let get = serde_json::to_vec(&StoreRequest::GetKey("vk_1".into())).unwrap();
            let mut out: *mut u8 = ptr::null_mut();
            let mut out_len: usize = 0;
            let st = call_impl(handle, get.as_ptr(), get.len(), &mut out, &mut out_len);
            assert_eq!(st, STATUS_OK);
            let resp: StoreResponse =
                serde_json::from_slice(std::slice::from_raw_parts(out, out_len)).unwrap();
            match resp {
                StoreResponse::Key(Some(k)) => assert_eq!(k.id, "vk_1"),
                other => panic!("expected key, got {other:?}"),
            }
            free_impl(out, out_len);

            close_impl(handle);
        }
    }

    /// A malformed request payload is a protocol error with a message, not a crash.
    #[test]
    fn ffi_bad_request_is_protocol_error() {
        unsafe {
            let mut handle: *mut c_void = ptr::null_mut();
            let mut err: *mut u8 = ptr::null_mut();
            let mut err_len: usize = 0;
            assert_eq!(
                open_impl(
                    ptr::null(),
                    0,
                    &mut handle,
                    &mut err,
                    &mut err_len,
                    mem_ctor
                ),
                STATUS_OK
            );
            let junk = b"not json at all";
            let mut out: *mut u8 = ptr::null_mut();
            let mut out_len: usize = 0;
            let st = call_impl(handle, junk.as_ptr(), junk.len(), &mut out, &mut out_len);
            assert_eq!(st, STATUS_PROTOCOL);
            assert!(!out.is_null());
            free_impl(out, out_len);
            close_impl(handle);
        }
    }

    /// The new audit ABI variants dispatch through the trait: `AppendAudit` maps to `append_audit`
    /// (Unit response) and `ListAudit` to `list_audit` (Audit response). Against the memory store the
    /// trait defaults no-op, so append returns Unit and list returns an empty Audit vec — proving the
    /// ADDITIVE variants are wired end-to-end without breaking the existing dispatch.
    #[test]
    fn dispatch_handles_audit_variants() {
        use busbar_api::AuditRecord;
        let store = MemoryStore::new();
        let rec = AuditRecord {
            seq: 1,
            ts: 2,
            action: "hook.register".into(),
            resource: "hook:a".into(),
            outcome: "applied".into(),
            principal: "admin".into(),
            prev_hash: String::new(),
            hash: "h".into(),
        };
        match dispatch(&store, StoreRequest::AppendAudit(rec)).unwrap() {
            StoreResponse::Unit => {}
            other => panic!("expected Unit, got {other:?}"),
        }
        match dispatch(&store, StoreRequest::ListAudit).unwrap() {
            StoreResponse::Audit(v) => assert!(v.is_empty(), "memory store persists no audit"),
            other => panic!("expected Audit, got {other:?}"),
        }
    }

    /// A constructor error surfaces as STATUS_ERR with the message in the error buffer.
    #[test]
    fn ffi_ctor_error_surfaces() {
        unsafe {
            let mut handle: *mut c_void = ptr::null_mut();
            let mut err: *mut u8 = ptr::null_mut();
            let mut err_len: usize = 0;
            let st = open_impl(
                ptr::null(),
                0,
                &mut handle,
                &mut err,
                &mut err_len,
                ctor_that_errors,
            );
            assert_eq!(st, STATUS_ERR);
            assert!(handle.is_null());
            let msg = std::str::from_utf8(std::slice::from_raw_parts(err, err_len)).unwrap();
            assert_eq!(msg, "nope");
            free_impl(err, err_len);
        }
    }
}
