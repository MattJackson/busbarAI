// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Runtime loading of a durable-store backend from a **dynamic library** (`.so`/`.dll`/`.dylib`) over
//! the busbar store C ABI ([`busbar_plugin_abi`]).
//!
//! This is the engine side of "drop a plugin in the folder and it works": [`load_store`] opens a
//! library with `libloading` (portable `dlopen`/`LoadLibrary`), checks the ABI-version handshake,
//! calls the plugin's `open` with the JSON config, and returns a [`DynStore`] — a `Box<dyn Store>` any
//! governance code can use exactly like the compiled-in [`busbar_store_memory::MemoryStore`]. Every
//! `Store` call is serialized to JSON and shipped across the C boundary; because the store is
//! write-behind (off the request hot path), that serialize never touches request latency.
//!
//! The loaded library is kept alive inside the `DynStore` for as long as the store lives — unloading
//! it while the handle is in use would dangle — and the handle is `close`d before the library drops.
//!
//! For the TRUSTED load path, [`load_store_from_bytes`] takes the already-verified library BYTES (not
//! a path) so the bytes that were hash/signature-checked are byte-for-byte the bytes loaded — closing
//! the time-of-check/time-of-use gap a `verify(path)` + `dlopen(path)` pair would leave open.

use busbar_api::{
    AuditRecord, AwsCredential, MeteringDelta, MeteringRow, Store, StoreError, StoreResult,
    UsageDelta, UsageLedger, VirtualKey,
};
use busbar_plugin_abi::{
    symbol, CallFn, CloseFn, FreeFn, StoreRequest, StoreResponse, ABI_VERSION, STATUS_OK,
};
use libloading::Library;
use std::os::raw::c_void;
use std::path::Path;

pub mod registry;
mod stage;
pub mod tarball;

pub use registry::{
    inventory as inventory_tarballs, scan_and_validate, supported_abi, InventoryEntry,
    LoadablePlugin, PluginRegistry, SkippedPlugin,
};
pub use stage::sweep_dead_staging;

/// Hard cap on the byte length the engine will materialize from a single plugin `call` response —
/// defense-in-depth against a plugin (buggy or adversarial) declaring a huge `out_len` and forcing an
/// unbounded engine allocation (OOM). 256 MiB is orders of magnitude past any real governance
/// response (key lists / audit logs are KBs–MBs), so a legitimate reply never trips it.
const MAX_PLUGIN_RESPONSE_LEN: usize = 256 * 1024 * 1024;

/// A `Store` backend loaded from a dynamic library. Holds the resolved C fn pointers, the opaque
/// per-instance handle, and — crucially — the [`Library`] itself so the code the fn pointers point
/// into stays mapped for the store's whole life.
pub struct DynStore {
    handle: *mut c_void,
    call: CallFn,
    free: FreeFn,
    close: CloseFn,
    /// The plugin path, for diagnostics.
    path: String,
    /// The loaded library. Declared BEFORE `_backing` so it drops FIRST (Rust drops fields in
    /// declaration order, AFTER the manual `Drop::drop` below has `close`d the handle). Unloading the
    /// library before the staged backing is released is what makes the Windows cleanup work: the DLL
    /// is unmapped/unlocked first, so the staged file can then be removed instead of failing against
    /// a still-mapped file and leaking the temp. (UNLOAD then REMOVE, per the loader contract.)
    _lib: Library,
    /// The staging backing this load (Linux memfd, or a file in the per-process private temp dir)
    /// when the library was loaded from in-memory verified bytes ([`load_store_from_bytes`]) rather
    /// than a path. Dropping it releases the resource; it MUST drop after `_lib` (see above).
    /// `None` for a plain path load.
    _backing: Option<stage::Staged>,
}

// SAFETY: the backend behind the handle is a `Box<dyn Store>`, which the `Store` contract requires to
// be `Send + Sync`; the handle is just an opaque pointer to that object, and every call is dispatched
// through the plugin's own (thread-safe) implementation. The raw fn pointers are plain code addresses.
unsafe impl Send for DynStore {}
unsafe impl Sync for DynStore {}

impl DynStore {
    /// Serialize a request, ship it across the C ABI, copy + free the response buffer, and decode.
    fn call_raw(&self, req: StoreRequest) -> StoreResult<StoreResponse> {
        let payload = serde_json::to_vec(&req)
            .map_err(|e| StoreError(format!("plugin request encode failed: {e}")))?;
        let mut out: *mut u8 = std::ptr::null_mut();
        let mut out_len: usize = 0;
        let status = unsafe {
            (self.call)(
                self.handle,
                payload.as_ptr(),
                payload.len(),
                &mut out,
                &mut out_len,
            )
        };
        // DEFENSE-IN-DEPTH cap on the plugin-declared response length. The plugin is trusted
        // operator-placed code, but a bug (or an adversarial build) that returns a huge `out_len`
        // would have the engine `to_vec()` an unbounded allocation and OOM. Refuse an over-cap length
        // BEFORE allocating — but still hand the buffer back to the plugin to `free` so we never leak
        // its allocation. The cap is far past any real governance response (a full key/audit list is
        // KBs–MBs), so it never rejects a legitimate reply.
        if let Err(msg) = response_len_ok(out_len, &self.path) {
            if !out.is_null() {
                unsafe { (self.free)(out, out_len) };
            }
            return Err(StoreError(msg));
        }
        // Copy the out buffer into engine-owned memory, then hand it back to the plugin to free (the
        // plugin allocated it; only the plugin may free it).
        let bytes = if out.is_null() || out_len == 0 {
            Vec::new()
        } else {
            unsafe { std::slice::from_raw_parts(out, out_len) }.to_vec()
        };
        if !out.is_null() {
            unsafe { (self.free)(out, out_len) };
        }
        if status == STATUS_OK {
            serde_json::from_slice(&bytes)
                .map_err(|e| StoreError(format!("plugin response decode failed: {e}")))
        } else {
            let msg = String::from_utf8_lossy(&bytes).into_owned();
            Err(StoreError(if msg.is_empty() {
                format!("plugin '{}' call failed (status {status})", self.path)
            } else {
                msg
            }))
        }
    }
}

/// Enforce [`MAX_PLUGIN_RESPONSE_LEN`] on a plugin-declared response length before the engine
/// allocates a buffer for it. Pure so the bound is unit-testable without a live plugin.
fn response_len_ok(out_len: usize, path: &str) -> Result<(), String> {
    if out_len > MAX_PLUGIN_RESPONSE_LEN {
        Err(format!(
            "plugin '{path}' returned an oversized response ({out_len} bytes, max \
             {MAX_PLUGIN_RESPONSE_LEN})"
        ))
    } else {
        Ok(())
    }
}

/// The plugin returned a response variant that doesn't match the request — a contract violation.
fn unexpected(resp: StoreResponse) -> StoreError {
    StoreError(format!("plugin returned an unexpected response: {resp:?}"))
}

impl Store for DynStore {
    fn put_key(&self, key: &VirtualKey) -> StoreResult<()> {
        match self.call_raw(StoreRequest::PutKey(key.clone()))? {
            StoreResponse::Unit => Ok(()),
            other => Err(unexpected(other)),
        }
    }

    fn get_key(&self, id: &str) -> StoreResult<Option<VirtualKey>> {
        match self.call_raw(StoreRequest::GetKey(id.to_string()))? {
            StoreResponse::Key(k) => Ok(k),
            other => Err(unexpected(other)),
        }
    }

    fn list_keys(&self) -> StoreResult<Vec<VirtualKey>> {
        match self.call_raw(StoreRequest::ListKeys)? {
            StoreResponse::Keys(k) => Ok(k),
            other => Err(unexpected(other)),
        }
    }

    fn delete_key(&self, id: &str) -> StoreResult<()> {
        match self.call_raw(StoreRequest::DeleteKey(id.to_string()))? {
            StoreResponse::Unit => Ok(()),
            other => Err(unexpected(other)),
        }
    }

    fn get_usage(&self, bucket_id: &str, window_start: u64) -> StoreResult<UsageLedger> {
        match self.call_raw(StoreRequest::GetUsage {
            bucket_id: bucket_id.to_string(),
            window_start,
        })? {
            StoreResponse::Usage(u) => Ok(u),
            other => Err(unexpected(other)),
        }
    }

    fn put_usage(
        &self,
        bucket_id: &str,
        window_start: u64,
        ledger: &UsageLedger,
    ) -> StoreResult<()> {
        match self.call_raw(StoreRequest::PutUsage {
            bucket_id: bucket_id.to_string(),
            window_start,
            ledger: ledger.clone(),
        })? {
            StoreResponse::Unit => Ok(()),
            other => Err(unexpected(other)),
        }
    }

    fn add_usage(&self, bucket_id: &str, window_start: u64, delta: &UsageDelta) -> StoreResult<()> {
        // ABI v2 makes `AddUsage` part of the base wire (every v2 plugin knows it - the v1-era
        // "older SDK never learned this variant" fallback is gone with the version bump), so an
        // error here is a REAL store error and propagates: silently degrading the fleet-additive
        // accumulate to a read-modify-write against a live shared backend would be a correctness
        // downgrade (lost updates), not a compatibility bridge.
        match self.call_raw(StoreRequest::AddUsage {
            bucket_id: bucket_id.to_string(),
            window_start,
            delta: delta.clone(),
        })? {
            StoreResponse::Unit => Ok(()),
            other => Err(unexpected(other)),
        }
    }

    fn add_metering(&self, delta: &MeteringDelta) -> StoreResult<()> {
        match self.call_raw(StoreRequest::AddMetering(delta.clone()))? {
            StoreResponse::Unit => Ok(()),
            other => Err(unexpected(other)),
        }
    }

    fn list_metering(&self, bucket: u64) -> StoreResult<Vec<MeteringRow>> {
        match self.call_raw(StoreRequest::ListMetering(bucket))? {
            StoreResponse::Metering(m) => Ok(m),
            other => Err(unexpected(other)),
        }
    }

    fn put_aws_credential(&self, cred: &AwsCredential) -> StoreResult<()> {
        match self.call_raw(StoreRequest::PutAwsCredential(cred.clone()))? {
            StoreResponse::Unit => Ok(()),
            other => Err(unexpected(other)),
        }
    }

    fn put_key_with_aws_credential(
        &self,
        key: &VirtualKey,
        cred: &AwsCredential,
    ) -> StoreResult<()> {
        match self.call_raw(StoreRequest::PutKeyWithAwsCredential {
            key: key.clone(),
            cred: cred.clone(),
        })? {
            StoreResponse::Unit => Ok(()),
            other => Err(unexpected(other)),
        }
    }

    fn list_aws_credentials(&self) -> StoreResult<Vec<AwsCredential>> {
        match self.call_raw(StoreRequest::ListAwsCredentials)? {
            StoreResponse::AwsCreds(c) => Ok(c),
            other => Err(unexpected(other)),
        }
    }

    fn append_audit(&self, entry: &AuditRecord) -> StoreResult<()> {
        // A plugin built against an OLDER SDK never learned this request variant and will reject it
        // (a protocol error). The engine's audit write-through is best-effort, so that error simply
        // means "this store has no durable audit" — the RAM ring still holds the entry; we never fail
        // an admin mutation on it. New plugins (durable stores) handle it and return `Unit`.
        match self.call_raw(StoreRequest::AppendAudit(entry.clone()))? {
            StoreResponse::Unit => Ok(()),
            other => Err(unexpected(other)),
        }
    }

    fn list_audit(&self) -> StoreResult<Vec<AuditRecord>> {
        match self.call_raw(StoreRequest::ListAudit)? {
            StoreResponse::Audit(a) => Ok(a),
            other => Err(unexpected(other)),
        }
    }

    fn list_audit_tail(&self, limit: u64) -> StoreResult<Vec<AuditRecord>> {
        // A plugin built against an OLDER SDK never learned this request variant and will reject it
        // (a protocol/decode error). Fall back to the trait default (`list_audit` + tail-truncation)
        // so restore still works against old durable plugins - it just materializes the full list
        // once before truncating rather than bounding at the source. A new plugin returns the bounded
        // tail directly (no full materialization), which is the point of the variant.
        match self.call_raw(StoreRequest::ListAuditTail(limit)) {
            Ok(StoreResponse::Audit(a)) => Ok(a),
            Ok(other) => Err(unexpected(other)),
            Err(_) => {
                let mut all = self.list_audit()?;
                let limit = limit as usize;
                if all.len() > limit {
                    all.drain(0..all.len() - limit);
                }
                Ok(all)
            }
        }
    }
}

impl Drop for DynStore {
    fn drop(&mut self) {
        // Close the instance while the library is still mapped (fields drop after this runs). Field
        // drop order is declaration order: `_lib` is declared BEFORE `_backing`, so the library
        // unloads FIRST and the backing temp file is removed AFTER (essential on Windows, where the
        // file cannot be deleted while the DLL is still mapped).
        unsafe { (self.close)(self.handle) };
    }
}

impl std::fmt::Debug for DynStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DynStore")
            .field("path", &self.path)
            .finish()
    }
}

// ── SECRET plugins (`kind: secret`) ─────────────────────────────────────────────────────────────

/// A [`busbar_api::SecretModule`] loaded from a dynamic library. Mirrors [`DynStore`]: resolved C
/// fn pointers + opaque handle + the mapped [`Library`] (declared before `_backing`; see DynStore's
/// field-order contract).
pub struct DynSecret {
    handle: *mut c_void,
    call: CallFn,
    free: FreeFn,
    close: CloseFn,
    /// The plugin name/path, for diagnostics.
    path: String,
    _lib: Library,
    _backing: Option<stage::Staged>,
}

// SAFETY: the backend behind the handle is a `Box<dyn SecretModule>` (`Send + Sync` by contract);
// the handle is an opaque pointer to it and the raw fn pointers are plain code addresses.
unsafe impl Send for DynSecret {}
unsafe impl Sync for DynSecret {}

impl DynSecret {
    /// Serialize a request, ship it across the C ABI, copy + free the response buffer, and decode.
    fn call_raw(
        &self,
        req: busbar_plugin_abi::SecretRequest,
    ) -> Result<busbar_plugin_abi::SecretResponse, busbar_api::SecretError> {
        let payload = serde_json::to_vec(&req)
            .map_err(|e| busbar_api::SecretError(format!("plugin request encode failed: {e}")))?;
        let mut out: *mut u8 = std::ptr::null_mut();
        let mut out_len: usize = 0;
        let status = unsafe {
            (self.call)(
                self.handle,
                payload.as_ptr(),
                payload.len(),
                &mut out,
                &mut out_len,
            )
        };
        // Same defense-in-depth response-length cap as the store wire (see DynStore::call_raw).
        if let Err(msg) = response_len_ok(out_len, &self.path) {
            if !out.is_null() {
                unsafe { (self.free)(out, out_len) };
            }
            return Err(busbar_api::SecretError(msg));
        }
        let bytes = if out.is_null() || out_len == 0 {
            Vec::new()
        } else {
            unsafe { std::slice::from_raw_parts(out, out_len) }.to_vec()
        };
        if !out.is_null() {
            unsafe { (self.free)(out, out_len) };
        }
        if status == STATUS_OK {
            serde_json::from_slice(&bytes)
                .map_err(|e| busbar_api::SecretError(format!("plugin response decode failed: {e}")))
        } else {
            let msg = String::from_utf8_lossy(&bytes).into_owned();
            Err(busbar_api::SecretError(if msg.is_empty() {
                format!("plugin '{}' call failed (status {status})", self.path)
            } else {
                msg
            }))
        }
    }
}

impl busbar_api::SecretModule for DynSecret {
    fn resolve(
        &self,
        settings: &serde_json::Map<String, serde_json::Value>,
    ) -> busbar_api::SecretResult<Vec<u8>> {
        match self.call_raw(busbar_plugin_abi::SecretRequest::Resolve {
            settings: settings.clone(),
        })? {
            busbar_plugin_abi::SecretResponse::Bytes(b) => Ok(b),
        }
    }
}

impl Drop for DynSecret {
    fn drop(&mut self) {
        // Close while the library is still mapped (fields drop after this; `_lib` before `_backing`).
        unsafe { (self.close)(self.handle) };
    }
}

impl std::fmt::Debug for DynSecret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DynSecret")
            .field("path", &self.path)
            .finish()
    }
}

/// Load a SECRET module from EXACTLY the verified library `bytes` (the TOCTOU-safe entrypoint;
/// see [`load_store_from_bytes`] for the staging contract). `cfg_json` is the module-level config
/// passed to its `open` (usually `{}`; per-reference settings ride each `resolve`).
pub fn load_secret_from_bytes(
    bytes: &[u8],
    cfg_json: &str,
    display: &str,
) -> Result<Box<dyn busbar_api::SecretModule>, String> {
    let (lib, staged) = stage::load_library_from_bytes(bytes, display)?;
    wire_up_secret(lib, cfg_json, display.to_string(), Some(staged))
}

/// Shared core for a secret plugin: ABI handshake, symbol resolution, `open`, assemble [`DynSecret`].
fn wire_up_secret(
    lib: Library,
    cfg_json: &str,
    display: String,
    backing: Option<stage::Staged>,
) -> Result<Box<dyn busbar_api::SecretModule>, String> {
    use busbar_plugin_abi::{secret_symbol, SECRET_ABI_VERSION};
    let abi_version = unsafe {
        let f = lib
            .get::<busbar_plugin_abi::AbiVersionFn>(secret_symbol::ABI_VERSION)
            .map_err(|_| format!("'{display}' is not a busbar secret plugin (no ABI symbol)"))?;
        (*f)()
    };
    if abi_version != SECRET_ABI_VERSION {
        return Err(format!(
            "plugin '{display}' targets secret ABI v{abi_version}, engine speaks \
             v{SECRET_ABI_VERSION}"
        ));
    }
    let (open, call, free, close) = unsafe {
        let open = *lib
            .get::<busbar_plugin_abi::OpenFn>(secret_symbol::OPEN)
            .map_err(|e| format!("plugin '{display}' missing open: {e}"))?;
        let call = *lib
            .get::<CallFn>(secret_symbol::CALL)
            .map_err(|e| format!("plugin '{display}' missing call: {e}"))?;
        let free = *lib
            .get::<FreeFn>(secret_symbol::FREE)
            .map_err(|e| format!("plugin '{display}' missing free: {e}"))?;
        let close = *lib
            .get::<CloseFn>(secret_symbol::CLOSE)
            .map_err(|e| format!("plugin '{display}' missing close: {e}"))?;
        (open, call, free, close)
    };
    let mut handle: *mut c_void = std::ptr::null_mut();
    let mut err: *mut u8 = std::ptr::null_mut();
    let mut err_len: usize = 0;
    let status = unsafe {
        open(
            cfg_json.as_ptr(),
            cfg_json.len(),
            &mut handle,
            &mut err,
            &mut err_len,
        )
    };
    if status != STATUS_OK || handle.is_null() {
        let msg = if err.is_null() || err_len == 0 {
            format!("status {status}")
        } else {
            let m = String::from_utf8_lossy(unsafe { std::slice::from_raw_parts(err, err_len) })
                .into_owned();
            unsafe { free(err, err_len) };
            m
        };
        return Err(format!("plugin '{display}' open failed: {msg}"));
    }
    Ok(Box::new(DynSecret {
        handle,
        call,
        free,
        close,
        path: display,
        _lib: lib,
        _backing: backing,
    }))
}

/// Load a store backend from the dynamic library at `lib_path`, passing `cfg_json` to its `open`.
///
/// Validates the ABI-version handshake before calling anything else (a library that isn't a busbar
/// store plugin, or targets a different ABI, is refused, never mis-called). Returns a ready
/// `Box<dyn Store>` or a human-readable error naming the failure.
pub fn load_store(lib_path: &Path, cfg_json: &str) -> Result<Box<dyn Store>, String> {
    let display = lib_path.display().to_string();
    // SAFETY: loading an operator-placed library is inherently trusted (its init code runs), exactly
    // like the SQLite this replaces was trusted when compiled in. The path comes from config/the
    // plugins dir, not the request path.
    let lib = unsafe { Library::new(lib_path) }
        .map_err(|e| format!("failed to load plugin '{display}': {e}"))?;
    wire_up_store(lib, cfg_json, display, None)
}

/// Load a store backend from EXACTLY the library `bytes` supplied — the TOCTOU-safe entrypoint.
///
/// The plugin pipeline verifies a plugin's hash/signature over the in-memory bytes it unpacked from
/// the signed tarball, then must load THOSE SAME bytes. Handing `load_store` a path would re-open a
/// file, leaving a window in which an attacker with write access could swap it between the
/// verify-read and the `dlopen` (a classic time-of-check/time-of-use gap). This function closes that
/// gap: the caller verifies the bytes ONCE and passes them here; the loader maps EXACTLY those bytes.
///
/// - **Linux**: `memfd_create` + `dlopen("/proc/self/fd/N")` — ZERO disk files, no path an attacker
///   could ever race.
/// - **macOS / Windows**: the verified bytes are written to a fresh `create_new` file inside a
///   per-process PRIVATE `0700` staging directory (`busbar-plugins-<pid>-<random>`) and loaded from
///   there. The staged file is throwaway output regenerated from the verified bytes on every load —
///   a pre-existing on-disk file is NEVER loaded. On clean shutdown the library is unloaded FIRST,
///   then the staged file removed; a crash's leftovers are removed by [`sweep_dead_staging`] at the
///   next boot. Residual (do not overstate): on these platforms the load is by PATH inside the
///   owner-created private dir, so only an attacker who already owns that dir (i.e. the same user)
///   could interfere; a hostile `TMPDIR` base remains the operator's responsibility.
///
/// `display` is a human label for diagnostics (typically the plugin's canonical name).
pub fn load_store_from_bytes(
    bytes: &[u8],
    cfg_json: &str,
    display: &str,
) -> Result<Box<dyn Store>, String> {
    let (lib, staged) = stage::load_library_from_bytes(bytes, display)?;
    wire_up_store(lib, cfg_json, display.to_string(), Some(staged))
}

/// Shared core: given an already-opened [`Library`], run the ABI handshake, resolve the operational
/// symbols, call `open` with the config, and assemble the [`DynStore`]. `backing` is the staging
/// guard for a from-bytes load (kept alive for the store's life), or `None` for a path load.
fn wire_up_store(
    lib: Library,
    cfg_json: &str,
    display: String,
    backing: Option<stage::Staged>,
) -> Result<Box<dyn Store>, String> {
    // ── ABI handshake: refuse anything that isn't a matching-version busbar store plugin ──
    let abi_version = unsafe {
        let f = lib
            .get::<busbar_plugin_abi::AbiVersionFn>(symbol::ABI_VERSION)
            .map_err(|_| format!("'{display}' is not a busbar store plugin (no ABI symbol)"))?;
        (*f)()
    };
    if abi_version != ABI_VERSION {
        return Err(format!(
            "plugin '{display}' targets store ABI v{abi_version}, engine speaks v{ABI_VERSION}"
        ));
    }

    // Resolve the operational symbols (copied out as plain fn pointers; valid while `lib` is mapped).
    let (open, call, free, close) = unsafe {
        let open = *lib
            .get::<busbar_plugin_abi::OpenFn>(symbol::OPEN)
            .map_err(|e| format!("plugin '{display}' missing open: {e}"))?;
        let call = *lib
            .get::<CallFn>(symbol::CALL)
            .map_err(|e| format!("plugin '{display}' missing call: {e}"))?;
        let free = *lib
            .get::<FreeFn>(symbol::FREE)
            .map_err(|e| format!("plugin '{display}' missing free: {e}"))?;
        let close = *lib
            .get::<CloseFn>(symbol::CLOSE)
            .map_err(|e| format!("plugin '{display}' missing close: {e}"))?;
        (open, call, free, close)
    };

    // ── open: construct the store instance from the JSON config ──
    let mut handle: *mut c_void = std::ptr::null_mut();
    let mut err: *mut u8 = std::ptr::null_mut();
    let mut err_len: usize = 0;
    let status = unsafe {
        open(
            cfg_json.as_ptr(),
            cfg_json.len(),
            &mut handle,
            &mut err,
            &mut err_len,
        )
    };
    if status != STATUS_OK || handle.is_null() {
        let msg = if err.is_null() || err_len == 0 {
            format!("status {status}")
        } else {
            let m = String::from_utf8_lossy(unsafe { std::slice::from_raw_parts(err, err_len) })
                .into_owned();
            unsafe { free(err, err_len) };
            m
        };
        return Err(format!("plugin '{display}' open failed: {msg}"));
    }

    Ok(Box::new(DynStore {
        handle,
        call,
        free,
        close,
        path: display,
        _lib: lib,
        _backing: backing,
    }))
}

/// The platform-native filename for a store plugin built from `crate_name` (e.g. `store_sqlite_plugin`
/// → `libbusbar_store_sqlite_plugin.so` / `.dylib` / `busbar_...dll`). Used to resolve `store: <name>`
/// against the plugins directory.
pub fn plugin_library_filename(crate_snake: &str) -> String {
    #[cfg(target_os = "windows")]
    {
        format!("{crate_snake}.dll")
    }
    #[cfg(target_os = "macos")]
    {
        format!("lib{crate_snake}.dylib")
    }
    #[cfg(all(unix, not(target_os = "macos")))]
    {
        format!("lib{crate_snake}.so")
    }
}

/// Validate that a library is a busbar store plugin the engine can speak to — it exports the ABI
/// handshake and targets a matching ABI version — WITHOUT constructing a store (no `open`). Returns
/// the plugin's ABI version. Used to vet an uploaded artifact before writing it into the plugins
/// directory, and to inventory the directory.
pub fn validate_plugin(lib_path: &Path) -> Result<u32, String> {
    let display = lib_path.display().to_string();
    // SAFETY: loading runs the library's init code — the same trust as loading it to serve, which is
    // itself the trust of compiling it in. The path is operator/admin-supplied, never request data.
    let lib = unsafe { Library::new(lib_path) }
        .map_err(|e| format!("failed to load plugin '{display}': {e}"))?;
    let abi_version = unsafe {
        let f = lib
            .get::<busbar_plugin_abi::AbiVersionFn>(symbol::ABI_VERSION)
            .map_err(|_| format!("'{display}' is not a busbar store plugin (no ABI symbol)"))?;
        (*f)()
    };
    if abi_version != ABI_VERSION {
        return Err(format!(
            "plugin '{display}' targets store ABI v{abi_version}, engine speaks v{ABI_VERSION}"
        ));
    }
    // Confirm the operational symbols resolve too, so a half-built library is caught here rather than
    // at first use.
    unsafe {
        lib.get::<busbar_plugin_abi::OpenFn>(symbol::OPEN)
            .map_err(|e| format!("plugin '{display}' missing open: {e}"))?;
        lib.get::<CallFn>(symbol::CALL)
            .map_err(|e| format!("plugin '{display}' missing call: {e}"))?;
        lib.get::<FreeFn>(symbol::FREE)
            .map_err(|e| format!("plugin '{display}' missing free: {e}"))?;
        lib.get::<CloseFn>(symbol::CLOSE)
            .map_err(|e| format!("plugin '{display}' missing close: {e}"))?;
    }
    Ok(abi_version)
}

/// One entry in a plugins-directory inventory: the library filename and whether it validated as a
/// busbar store plugin (with its ABI version, or the reason it didn't). Serialized by the admin
/// `GET /admin/plugins` endpoint.
#[derive(Debug, Clone, serde::Serialize)]
pub struct PluginInfo {
    /// The library filename (not the full path).
    pub file: String,
    /// True when the library exports the store ABI at a version the engine speaks.
    pub valid: bool,
    /// The plugin's ABI version when `valid`.
    pub abi_version: Option<u32>,
    /// Why it didn't validate, when `!valid`.
    pub error: Option<String>,
}

/// Is `file` a dynamic-library name for this platform (by extension)?
fn is_library_file(file: &str) -> bool {
    let ext = if cfg!(target_os = "windows") {
        ".dll"
    } else if cfg!(target_os = "macos") {
        ".dylib"
    } else {
        ".so"
    };
    file.ends_with(ext)
}

/// List the dynamic-library FILENAMES in `dir` (sorted), WITHOUT opening any of them - the pure,
/// side-effect-free directory scan. Unlike [`inventory`], this NEVER `dlopen`s a library, so an
/// untrusted plugin's init/constructor code cannot run just from enumerating the directory. The trust
/// gate (and only then the ABI [`validate_plugin`], which does `dlopen`) is applied by the caller,
/// per file, so no library's code runs until it passes trust. A missing directory is an empty list.
pub fn list_plugin_files(dir: &Path) -> Vec<String> {
    let mut out = Vec::new();
    let Ok(entries) = std::fs::read_dir(dir) else {
        return out;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        let Some(file) = path.file_name().and_then(|f| f.to_str()) else {
            continue;
        };
        if path.is_file() && is_library_file(file) {
            out.push(file.to_string());
        }
    }
    out.sort();
    out
}

/// Inventory the plugins directory: every dynamic library present, each validated (ABI handshake) so
/// the admin surface can show what's installed and whether it's loadable. A missing directory is an
/// empty inventory, not an error.
///
/// WARNING: this `dlopen`s (via [`validate_plugin`]) EVERY library to run the ABI handshake, which
/// executes each library's init/constructor code. It must therefore only be called on libraries that
/// have ALREADY passed the trust gate - never as an untrusted-directory inspection. The admin catalog
/// uses [`list_plugin_files`] + a per-file trust check instead, and `dlopen`s only what trust permits.
pub fn inventory(dir: &Path) -> Vec<PluginInfo> {
    let mut out = Vec::new();
    let Ok(entries) = std::fs::read_dir(dir) else {
        return out;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        let Some(file) = path.file_name().and_then(|f| f.to_str()) else {
            continue;
        };
        if !path.is_file() || !is_library_file(file) {
            continue;
        }
        match validate_plugin(&path) {
            Ok(v) => out.push(PluginInfo {
                file: file.to_string(),
                valid: true,
                abi_version: Some(v),
                error: None,
            }),
            Err(e) => out.push(PluginInfo {
                file: file.to_string(),
                valid: false,
                abi_version: None,
                error: Some(e),
            }),
        }
    }
    out.sort_by(|a, b| a.file.cmp(&b.file));
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Locate the SQLite plugin cdylib in the build's target dir, derived from the test binary's own
    /// path (robust to a custom CARGO_TARGET_DIR). Returns None if it hasn't been built — a
    /// `-p busbar`-only run may not have built it, so the caller skips rather than fails; under
    /// `cargo test --workspace` (preflight/CI) the cdylib is always present and the caller runs.
    ///
    /// CI HARDENING (mirrors the store-postgres live-DB test): CI runs `cargo test --workspace`, so
    /// the cdylib MUST be present. If it is absent while `CI` is set, that is a broken build - a HARD
    /// FAILURE here, not a silent skip, so the only over-the-ABI coverage of the durable store path
    /// cannot quietly vanish. Locally (no `CI`) a missing cdylib still skips cleanly.
    fn sqlite_plugin_path() -> Option<std::path::PathBuf> {
        let candidate = (|| {
            let exe = std::env::current_exe().ok()?; // .../target/<profile>/deps/busbar-<hash>
            let profile_dir = exe.parent()?.parent()?; // .../target/<profile>
            let name = plugin_library_filename("busbar_store_sqlite_plugin");
            let candidate = profile_dir.join(&name);
            candidate.exists().then_some(candidate)
        })();
        if candidate.is_none() && std::env::var_os("CI").is_some() {
            panic!(
                "the sqlite plugin cdylib is not built under CI: `cargo test --workspace` must build \
                 busbar_store_sqlite_plugin. Refusing to silently skip the only over-the-ABI \
                 coverage of the durable store path."
            );
        }
        candidate
    }

    /// End-to-end: load the REAL SQLite plugin cdylib over the C ABI and exercise the Store surface
    /// through the DynStore — put a key, read it back, list, delete, and round-trip usage.
    #[test]
    fn load_and_exercise_sqlite_plugin() {
        let Some(path) = sqlite_plugin_path() else {
            eprintln!("skip: sqlite plugin cdylib not built (run under --workspace)");
            return;
        };
        // In-memory sqlite so the test leaves no file behind.
        let cfg = r#"{"db_path": ":memory:"}"#;
        let store = load_store(&path, cfg).expect("load sqlite plugin");

        let key = VirtualKey {
            id: "vk_dyn".into(),
            key_hash: "abc".into(),
            name: "dynamic".into(),
            allowed_pools: vec!["p".into()],
            max_budget_cents: Some(500),
            budget_period: "total".into(),
            rpm_limit: Some(10),
            tpm_limit: None,
            enabled: true,
            created_at: 7,
            budget_group: Some("growth".into()),
            labels: std::collections::BTreeMap::from([("team".into(), "growth".into())]),
        };
        store.put_key(&key).expect("put_key");

        let got = store.get_key("vk_dyn").expect("get_key").expect("present");
        assert_eq!(got.id, "vk_dyn");
        assert_eq!(got.max_budget_cents, Some(500));
        assert_eq!(
            got.budget_group.as_deref(),
            Some("growth"),
            "budget_group survives the ABI round-trip"
        );
        assert_eq!(got.labels.get("team").map(String::as_str), Some("growth"));

        assert_eq!(store.list_keys().expect("list").len(), 1);

        // The token LEDGER round-trips over the ABI: absolute put, additive add, then read back.
        let ledger = busbar_api::UsageLedger {
            requests: 3,
            models: vec![busbar_api::ModelTokens {
                model: "gpt-5".into(),
                tokens: busbar_api::TierTokens {
                    input: 9,
                    output: 4,
                    cache_read: 2,
                    cache_write: 1,
                },
            }],
        };
        store.put_usage("vk_dyn", 100, &ledger).expect("put_usage");
        store
            .add_usage(
                "vk_dyn",
                100,
                &busbar_api::UsageDelta {
                    requests: 1,
                    models: vec![busbar_api::ModelTokensDelta {
                        model: "gpt-5".into(),
                        tokens: busbar_api::TierTokensDelta {
                            input: 1,
                            output: 1,
                            cache_read: 0,
                            cache_write: 0,
                        },
                    }],
                },
            )
            .expect("add_usage");
        let usage = store.get_usage("vk_dyn", 100).expect("get_usage");
        assert_eq!(usage.requests, 4);
        let t = usage.tokens_for("gpt-5").expect("model row");
        assert_eq!(
            (t.input, t.output, t.cache_read, t.cache_write),
            (10, 5, 2, 1)
        );

        store.delete_key("vk_dyn").expect("delete");
        assert!(store.get_key("vk_dyn").expect("get after delete").is_none());
    }

    /// The DURABLE AUDIT surface (#17) works over the C ABI through the real sqlite plugin: append two
    /// records and read them back oldest-first — proving the new `AppendAudit`/`ListAudit` variants
    /// serialize across the boundary and the plugin persists them. This is the dynamic-library path a
    /// `governance.store: sqlite` deployment actually uses for durable audit.
    #[test]
    fn dyn_store_durable_audit_over_abi() {
        use busbar_api::AuditRecord;
        let Some(path) = sqlite_plugin_path() else {
            eprintln!("skip: sqlite plugin cdylib not built (run under --workspace)");
            return;
        };
        let store = load_store(&path, r#"{"db_path": ":memory:"}"#).expect("load sqlite plugin");
        let rec = |seq: u64, prev: &str, hash: &str| AuditRecord {
            seq,
            ts: 1000 + seq,
            action: "plugin.install".into(),
            resource: format!("plugin:{seq}"),
            outcome: "applied".into(),
            principal: "admin".into(),
            prev_hash: prev.into(),
            hash: hash.into(),
        };
        store.append_audit(&rec(1, "", "h1")).expect("append 1");
        store.append_audit(&rec(2, "h1", "h2")).expect("append 2");
        let got = store.list_audit().expect("list_audit over the ABI");
        assert_eq!(got.len(), 2);
        assert_eq!(
            (got[0].seq, got[1].seq),
            (1, 2),
            "oldest-first across the ABI"
        );
        assert_eq!(
            got[1].prev_hash, "h1",
            "chain fields survive the JSON-over-C round-trip"
        );
        assert_eq!(got[0].resource, "plugin:1");
    }

    /// A non-plugin library (or a missing file) is refused with a clear error, never a crash.
    #[test]
    fn refuses_non_plugin() {
        let err = match load_store(Path::new("/definitely/not/a/plugin.so"), "{}") {
            Err(e) => e,
            Ok(_) => panic!("a missing library must not load"),
        };
        assert!(err.contains("failed to load plugin"), "got: {err}");
    }

    /// `validate_plugin` accepts the real sqlite cdylib (ABI v1) without constructing a store, and
    /// `inventory` finds it (and any sibling plugins) in the target directory as valid.
    #[test]
    fn validate_and_inventory() {
        let Some(path) = sqlite_plugin_path() else {
            eprintln!("skip: sqlite plugin cdylib not built (run under --workspace)");
            return;
        };
        assert_eq!(validate_plugin(&path).expect("validate"), ABI_VERSION);

        let dir = path.parent().unwrap();
        let inv = inventory(dir);
        let sqlite = inv
            .iter()
            .find(|p| p.file.contains("busbar_store_sqlite_plugin"))
            .expect("sqlite plugin in inventory");
        assert!(sqlite.valid);
        assert_eq!(sqlite.abi_version, Some(ABI_VERSION));
        assert!(sqlite.error.is_none());
    }

    /// `inventory` of a missing directory is empty, not an error.
    #[test]
    fn inventory_missing_dir_is_empty() {
        assert!(inventory(Path::new("/no/such/plugins/dir")).is_empty());
    }

    /// The response-length cap accepts a normal reply and REFUSES an over-cap length before any
    /// allocation — defense-in-depth against a plugin declaring a huge `out_len` and OOMing the engine.
    #[test]
    fn response_len_cap_refuses_oversized() {
        assert!(response_len_ok(0, "p").is_ok());
        assert!(response_len_ok(1024, "p").is_ok());
        assert!(
            response_len_ok(MAX_PLUGIN_RESPONSE_LEN, "p").is_ok(),
            "the exact cap is allowed"
        );
        let err = response_len_ok(MAX_PLUGIN_RESPONSE_LEN + 1, "sqlite").unwrap_err();
        assert!(err.contains("oversized response"), "got {err}");
        assert!(err.contains("sqlite"), "names the offending plugin: {err}");
    }

    /// TOCTOU-safe load: `load_store_from_bytes` loads EXACTLY the bytes handed to it — the same bytes
    /// the caller hash/signature-verified — and exercises the store over the ABI to prove the load is
    /// live. This is the path the engine boot uses so the verified bytes and the loaded bytes are one
    /// and the same, with no path re-read in between.
    #[test]
    fn load_store_from_bytes_loads_the_given_bytes() {
        let Some(path) = sqlite_plugin_path() else {
            eprintln!("skip: sqlite plugin cdylib not built (run under --workspace)");
            return;
        };
        let bytes = std::fs::read(&path).expect("read sqlite cdylib");
        let store =
            load_store_from_bytes(&bytes, r#"{"db_path": ":memory:"}"#, "sqlite-from-bytes")
                .expect("load from verified bytes");
        let key = VirtualKey {
            id: "vk_b".into(),
            key_hash: "h".into(),
            name: "b".into(),
            allowed_pools: vec!["p".into()],
            max_budget_cents: Some(1),
            budget_period: "total".into(),
            rpm_limit: None,
            tpm_limit: None,
            enabled: true,
            created_at: 1,
            budget_group: None,
            labels: std::collections::BTreeMap::new(),
        };
        store.put_key(&key).expect("put_key over from-bytes load");
        assert_eq!(
            store.get_key("vk_b").expect("get").expect("present").id,
            "vk_b"
        );
    }

    /// The TOCTOU guarantee, demonstrated end-to-end: verify a set of bytes, then SWAP the on-disk file
    /// at the original path for hostile content — and the from-bytes load is UNAFFECTED, because it
    /// never re-reads that path. Under the old `verify(path)` + `load_store(path)` shape this swap would
    /// have loaded the attacker's file; here the loaded library is the verified `bytes`, full stop.
    #[test]
    fn on_disk_swap_after_verify_does_not_change_what_loads() {
        let Some(path) = sqlite_plugin_path() else {
            eprintln!("skip: sqlite plugin cdylib not built (run under --workspace)");
            return;
        };
        // "Verify" step: read the good bytes (in the engine these are hash/signature-checked here).
        let verified = std::fs::read(&path).expect("read good cdylib");

        // Attacker swaps the file at `path` for junk AFTER we verified — a classic TOCTOU swap.
        let dir = std::env::temp_dir().join(format!("busbar-toctou-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let victim = dir.join(plugin_library_filename("busbar_store_sqlite_plugin"));
        std::fs::write(&victim, &verified).unwrap();
        // Confirm loading the victim PATH would pick up whatever is on disk...
        std::fs::write(&victim, b"\x7fELF hostile junk, not a plugin").unwrap();
        assert!(
            load_store(&victim, r#"{"db_path": ":memory:"}"#).is_err(),
            "the swapped-in junk is not a loadable plugin (path load sees the swap)"
        );
        // ...but the from-bytes load, fed the bytes we verified BEFORE the swap, loads fine.
        let store = load_store_from_bytes(&verified, r#"{"db_path": ":memory:"}"#, "toctou")
            .expect("verified bytes still load despite the on-disk swap");
        assert!(store.list_keys().expect("list over the ABI").is_empty());
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// No leaked artifact + unload-then-remove ordering: after a from-bytes load's store DROPS,
    /// nothing of the load remains on disk. On Linux the load is a memfd (zero disk files by
    /// construction); on macOS/Windows the staged file inside the per-process private directory is
    /// removed when the store drops — and because `DynStore` declares `_lib` before `_backing`, the
    /// library unloads BEFORE the staged file is removed (the order Windows requires: a mapped
    /// DLL's file cannot be deleted).
    #[test]
    fn from_bytes_load_leaves_no_artifact_after_drop() {
        let Some(path) = sqlite_plugin_path() else {
            eprintln!("skip: sqlite plugin cdylib not built (run under --workspace)");
            return;
        };
        let bytes = std::fs::read(&path).expect("read sqlite cdylib");
        // Count staged library FILES across every busbar-plugins-<ourpid>-* dir before and after.
        let base = std::env::temp_dir();
        let prefix = format!("busbar-plugins-{}-", std::process::id());
        let count_staged = || {
            std::fs::read_dir(&base)
                .into_iter()
                .flatten()
                .flatten()
                .filter(|e| {
                    e.file_name()
                        .to_str()
                        .is_some_and(|n| n.starts_with(&prefix))
                })
                .flat_map(|e| std::fs::read_dir(e.path()).into_iter().flatten().flatten())
                .count()
        };
        let before = count_staged();
        {
            let store =
                load_store_from_bytes(&bytes, r#"{"db_path": ":memory:"}"#, "no-leak-check")
                    .expect("load from bytes");
            assert!(store.list_keys().expect("list").is_empty());
        } // store drops here -> library unloads, then the staged backing is released.
        let after = count_staged();
        assert!(
            after <= before,
            "a from-bytes load must leave no staged file behind after the store drops \
             (before={before}, after={after})"
        );
    }

    /// On Linux the from-bytes load is a MEMFD load: it must not create ANY file in the temp base
    /// (the zero-disk property the spec requires on Linux).
    #[cfg(target_os = "linux")]
    #[test]
    fn linux_from_bytes_load_touches_no_disk() {
        let Some(path) = sqlite_plugin_path() else {
            eprintln!("skip: sqlite plugin cdylib not built (run under --workspace)");
            return;
        };
        let bytes = std::fs::read(&path).expect("read sqlite cdylib");
        let base = std::env::temp_dir();
        let prefix = format!("busbar-plugins-{}-", std::process::id());
        let staged_dirs = || {
            std::fs::read_dir(&base)
                .into_iter()
                .flatten()
                .flatten()
                .filter(|e| {
                    e.file_name()
                        .to_str()
                        .is_some_and(|n| n.starts_with(&prefix))
                })
                .count()
        };
        let before = staged_dirs();
        let store = load_store_from_bytes(&bytes, r#"{"db_path": ":memory:"}"#, "memfd-check")
            .expect("memfd load");
        assert!(store.list_keys().expect("list").is_empty());
        assert_eq!(
            staged_dirs(),
            before,
            "a Linux memfd load must not create any staging directory/file"
        );
    }
}
