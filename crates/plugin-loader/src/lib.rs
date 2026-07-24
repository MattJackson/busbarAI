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
    kind as abi_kind, symbol, CallFn, CloseFn, FreeFn, PluginKindFn, StoreRequest, StoreResponse,
    MAX_PLUGIN_RESPONSE_LEN, STATUS_OK, TRANSPORT_VERSION,
};
use libloading::Library;
use std::os::raw::c_void;
use std::path::Path;

pub mod auth;
pub mod registry;
mod stage;
pub mod tarball;

pub use auth::DynAuth;
pub use registry::{
    inventory as inventory_tarballs, scan_and_validate, supported_abi, InventoryEntry,
    LoadablePlugin, PluginRegistry, SkippedPlugin,
};
pub use stage::sweep_dead_staging;

/// The resolved core C fn pointers + the opaque handle + the mapped library + staging backing, shared
/// by every kind's typed wrapper. The KIND is bound at construction (cross-checked against the signed
/// manifest) and then carried by the typed `DynStore`/`DynSecret`/`DynAuth`.
struct RawPlugin {
    handle: *mut c_void,
    call: CallFn,
    free: FreeFn,
    close: CloseFn,
    /// The plugin name/path, for diagnostics.
    path: String,
    /// The mapped library. Declared BEFORE `_backing` so it drops FIRST (fields drop in declaration
    /// order, AFTER `Drop::drop` closes the handle) — the UNLOAD-then-REMOVE order Windows requires.
    _lib: Library,
    /// The staging backing (Linux memfd / private-temp file) for a from-bytes load; `None` for a path
    /// load. MUST drop after `_lib`.
    _backing: Option<stage::Staged>,
}

// SAFETY: every kind's backend is a `Box<dyn Trait>` the trait contract requires to be `Send + Sync`;
// the handle is an opaque pointer to it and the raw fn pointers are plain code addresses.
unsafe impl Send for RawPlugin {}
unsafe impl Sync for RawPlugin {}

impl RawPlugin {
    /// The ONE generic transport primitive: serialize `req`, ship it across the kind-neutral `call`,
    /// cap-check + copy + free the response buffer, and decode it as `Resp`. Replaces the duplicated
    /// per-kind wire calls — store, secret, and auth all go through this; only the TYPES differ.
    fn transport_call<Req: serde::Serialize, Resp: serde::de::DeserializeOwned>(
        &self,
        req: &Req,
    ) -> Result<Resp, String> {
        let payload =
            serde_json::to_vec(req).map_err(|e| format!("plugin request encode failed: {e}"))?;
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
        // Cap-reject BEFORE reading; still hand the buffer back to the plugin to free (it owns it).
        if let Err(msg) = response_len_ok(out_len, &self.path) {
            if !out.is_null() {
                unsafe { (self.free)(out, out_len) };
            }
            return Err(msg);
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
                .map_err(|e| format!("plugin response decode failed: {e}"))
        } else {
            let msg = String::from_utf8_lossy(&bytes).into_owned();
            Err(if msg.is_empty() {
                format!("plugin '{}' call failed (status {status})", self.path)
            } else {
                msg
            })
        }
    }
}

impl Drop for RawPlugin {
    fn drop(&mut self) {
        unsafe { (self.close)(self.handle) };
    }
}

/// Resolve + validate a mapped library against the frozen contract (transport version, kind symbol ==
/// `expected_kind` == the signed-manifest kind), then `open` it and assemble a [`RawPlugin`]. Shared
/// by every kind's `wire_up_*`. `manifest_kind` is the trust-verified signed-manifest `kind` that the
/// exported `busbar_plugin_kind()` is cross-checked against (mismatch = hard fail-closed load error).
fn wire_up_raw(
    lib: Library,
    cfg_json: &str,
    display: String,
    expected_kind: &str,
    manifest_kind: &str,
    backing: Option<stage::Staged>,
) -> Result<RawPlugin, String> {
    // ── 1. Transport handshake FIRST — refuse a non-matching transport before resolving open/call. ──
    let transport = unsafe {
        let f = lib
            .get::<busbar_plugin_abi::AbiFn>(symbol::ABI)
            .map_err(|_| format!("'{display}' is not a busbar plugin (no busbar_abi symbol)"))?;
        (*f)()
    };
    if transport != TRANSPORT_VERSION {
        return Err(format!(
            "plugin '{display}' targets transport ABI v{transport}, engine speaks v{TRANSPORT_VERSION}"
        ));
    }

    // ── 2. Kind bound at load — read the exported kind, cross-check it against the seam AND the
    //       signed manifest. Any disagreement is a hard fail-closed load error naming both. ──
    let exported_kind = read_plugin_kind(&lib, &display)?;
    if exported_kind != expected_kind {
        return Err(format!(
            "plugin '{display}' exports kind '{exported_kind}' but is being loaded as '{expected_kind}'"
        ));
    }
    if exported_kind != manifest_kind {
        return Err(format!(
            "plugin '{display}' kind mismatch: exported symbol says '{exported_kind}', signed \
             manifest says '{manifest_kind}' — refusing to load"
        ));
    }

    // ── 3. Resolve the operational symbols (copied out as plain fn pointers; valid while mapped). ──
    let (open, call, free, close) = unsafe {
        let open = *lib
            .get::<busbar_plugin_abi::OpenFn>(symbol::OPEN)
            .map_err(|e| format!("plugin '{display}' missing busbar_open: {e}"))?;
        let call = *lib
            .get::<CallFn>(symbol::CALL)
            .map_err(|e| format!("plugin '{display}' missing busbar_call: {e}"))?;
        let free = *lib
            .get::<FreeFn>(symbol::FREE)
            .map_err(|e| format!("plugin '{display}' missing busbar_free: {e}"))?;
        let close = *lib
            .get::<CloseFn>(symbol::CLOSE)
            .map_err(|e| format!("plugin '{display}' missing busbar_close: {e}"))?;
        (open, call, free, close)
    };

    // ── 4. open: construct the instance from the JSON config. ──
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

    Ok(RawPlugin {
        handle,
        call,
        free,
        close,
        path: display,
        _lib: lib,
        _backing: backing,
    })
}

/// Read `busbar_plugin_kind()` from a mapped library into an owned `String`.
fn read_plugin_kind(lib: &Library, display: &str) -> Result<String, String> {
    let ptr = unsafe {
        let f = lib.get::<PluginKindFn>(symbol::PLUGIN_KIND).map_err(|_| {
            format!("'{display}' is not a busbar plugin (no busbar_plugin_kind symbol)")
        })?;
        (*f)()
    };
    if ptr.is_null() {
        return Err(format!("plugin '{display}' returned a null kind string"));
    }
    // SAFETY: the plugin contract requires a NUL-terminated 'static string.
    let cstr = unsafe { std::ffi::CStr::from_ptr(ptr as *const std::os::raw::c_char) };
    cstr.to_str()
        .map(str::to_string)
        .map_err(|_| format!("plugin '{display}' kind string is not valid UTF-8"))
}

/// A `Store` backend loaded from a dynamic library over the kind-neutral ABI. Wraps a [`RawPlugin`]
/// whose kind was bound to `store` at load, so every `Store` method is a typed `transport_call`.
pub struct DynStore {
    raw: RawPlugin,
}

impl DynStore {
    /// Serialize a request, ship it across the kind-neutral C ABI, decode the response.
    fn call_raw(&self, req: StoreRequest) -> StoreResult<StoreResponse> {
        self.raw
            .transport_call::<StoreRequest, StoreResponse>(&req)
            .map_err(StoreError)
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

    fn add_denylist(&self, sub: &str, reason: &str) -> StoreResult<()> {
        match self.call_raw(StoreRequest::AddDenylist {
            sub: sub.to_string(),
            reason: reason.to_string(),
        })? {
            StoreResponse::Unit => Ok(()),
            other => Err(unexpected(other)),
        }
    }

    fn list_denylist(&self) -> StoreResult<Vec<String>> {
        // A plugin built against an older SDK rejects the unknown variant; fall back to the trait
        // default (empty) so an old durable plugin hydrates nothing rather than failing boot.
        match self.call_raw(StoreRequest::ListDenylist) {
            Ok(StoreResponse::Denylist(d)) => Ok(d),
            Ok(other) => Err(unexpected(other)),
            Err(_) => Ok(Vec::new()),
        }
    }
}

impl std::fmt::Debug for DynStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DynStore")
            .field("path", &self.raw.path)
            .finish()
    }
}

// ── SECRET plugins (`kind: secret`) ─────────────────────────────────────────────────────────────

/// A [`busbar_api::SecretModule`] loaded from a dynamic library over the kind-neutral ABI. Wraps a
/// [`RawPlugin`] whose kind was bound to `secret` at load.
pub struct DynSecret {
    raw: RawPlugin,
}

impl busbar_api::SecretModule for DynSecret {
    fn resolve(
        &self,
        settings: &serde_json::Map<String, serde_json::Value>,
    ) -> busbar_api::SecretResult<Vec<u8>> {
        let req = busbar_plugin_abi::SecretRequest::Resolve {
            settings: settings.clone(),
        };
        match self
            .raw
            .transport_call::<_, busbar_plugin_abi::SecretResponse>(&req)
            .map_err(busbar_api::SecretError)?
        {
            busbar_plugin_abi::SecretResponse::Bytes(b) => Ok(b),
        }
    }
}

impl std::fmt::Debug for DynSecret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DynSecret")
            .field("path", &self.raw.path)
            .finish()
    }
}

/// Load a SECRET module from EXACTLY the verified library `bytes` (the TOCTOU-safe entrypoint;
/// see [`load_store_from_bytes`] for the staging contract). `manifest_kind` is the trust-verified
/// signed-manifest `kind`, cross-checked against the library's exported `busbar_plugin_kind()`.
pub fn load_secret_from_bytes(
    bytes: &[u8],
    cfg_json: &str,
    display: &str,
    manifest_kind: &str,
) -> Result<Box<dyn busbar_api::SecretModule>, String> {
    let (lib, staged) = stage::load_library_from_bytes(bytes, display)?;
    let raw = wire_up_raw(
        lib,
        cfg_json,
        display.to_string(),
        abi_kind::SECRET,
        manifest_kind,
        Some(staged),
    )?;
    Ok(Box::new(DynSecret { raw }))
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
    // A bare path load has no signed manifest to cross-check; the seam's expected kind (`store`) is
    // the authority, so pass it as the manifest kind too (the exported-kind == expected-kind gate
    // still enforces the library is a store). The trust-verified from-bytes path is the real gate.
    let raw = wire_up_raw(
        lib,
        cfg_json,
        display,
        abi_kind::STORE,
        abi_kind::STORE,
        None,
    )?;
    Ok(Box::new(DynStore { raw }))
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
/// `display` is a human label for diagnostics (typically the plugin's canonical name); `manifest_kind`
/// is the trust-verified signed-manifest `kind`, cross-checked against `busbar_plugin_kind()`.
pub fn load_store_from_bytes(
    bytes: &[u8],
    cfg_json: &str,
    display: &str,
    manifest_kind: &str,
) -> Result<Box<dyn Store>, String> {
    let (lib, staged) = stage::load_library_from_bytes(bytes, display)?;
    let raw = wire_up_raw(
        lib,
        cfg_json,
        display.to_string(),
        abi_kind::STORE,
        manifest_kind,
        Some(staged),
    )?;
    Ok(Box::new(DynStore { raw }))
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

/// Validate that a library is a busbar plugin the engine can speak to — it exports the TRANSPORT
/// handshake at a matching version, a supported kind, and all operational symbols — WITHOUT
/// constructing an instance (no `open`). Returns the transport ABI version. Used to vet an uploaded
/// artifact before writing it into the plugins directory, and to inventory the directory.
pub fn validate_plugin(lib_path: &Path) -> Result<u32, String> {
    let display = lib_path.display().to_string();
    // SAFETY: loading runs the library's init code — the same trust as loading it to serve, which is
    // itself the trust of compiling it in. The path is operator/admin-supplied, never request data.
    let lib = unsafe { Library::new(lib_path) }
        .map_err(|e| format!("failed to load plugin '{display}': {e}"))?;
    let transport = unsafe {
        let f = lib
            .get::<busbar_plugin_abi::AbiFn>(symbol::ABI)
            .map_err(|_| format!("'{display}' is not a busbar plugin (no busbar_abi symbol)"))?;
        (*f)()
    };
    if transport != TRANSPORT_VERSION {
        return Err(format!(
            "plugin '{display}' targets transport ABI v{transport}, engine speaks v{TRANSPORT_VERSION}"
        ));
    }
    // The exported kind must be one the engine supports (a range exists for it).
    let plugin_kind = read_plugin_kind(&lib, &display)?;
    if supported_abi(&plugin_kind).is_empty() {
        return Err(format!(
            "plugin '{display}' declares unsupported kind '{plugin_kind}'"
        ));
    }
    // Confirm the operational symbols resolve too, so a half-built library is caught here rather than
    // at first use.
    unsafe {
        lib.get::<busbar_plugin_abi::OpenFn>(symbol::OPEN)
            .map_err(|e| format!("plugin '{display}' missing busbar_open: {e}"))?;
        lib.get::<CallFn>(symbol::CALL)
            .map_err(|e| format!("plugin '{display}' missing busbar_call: {e}"))?;
        lib.get::<FreeFn>(symbol::FREE)
            .map_err(|e| format!("plugin '{display}' missing busbar_free: {e}"))?;
        lib.get::<CloseFn>(symbol::CLOSE)
            .map_err(|e| format!("plugin '{display}' missing busbar_close: {e}"))?;
    }
    Ok(transport)
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
            allowed_pools: Some(vec!["p".into()]),
            enabled: true,
            created_at: 7,
            group: Some("growth".into()),
            labels: std::collections::BTreeMap::from([("team".into(), "growth".into())]),
        };
        store.put_key(&key).expect("put_key");

        let got = store.get_key("vk_dyn").expect("get_key").expect("present");
        assert_eq!(got.id, "vk_dyn");
        assert_eq!(
            got.group.as_deref(),
            Some("growth"),
            "the group binding survives the ABI round-trip"
        );
        assert_eq!(
            got.allowed_pools,
            Some(vec!["p".to_string()]),
            "the pool grant survives the ABI round-trip"
        );
        assert_eq!(got.labels.get("team").map(String::as_str), Some("growth"));

        assert_eq!(store.list_keys().expect("list").len(), 1);

        // The token LEDGER round-trips over the ABI: absolute put, additive add, then read back.
        let ledger = busbar_api::UsageLedger {
            requests: 3,
            billable_requests: 3,
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
                    billable_requests: 1,
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
        assert_eq!(validate_plugin(&path).expect("validate"), TRANSPORT_VERSION);

        let dir = path.parent().unwrap();
        let inv = inventory(dir);
        let sqlite = inv
            .iter()
            .find(|p| p.file.contains("busbar_store_sqlite_plugin"))
            .expect("sqlite plugin in inventory");
        assert!(sqlite.valid);
        assert_eq!(sqlite.abi_version, Some(TRANSPORT_VERSION));
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
        let store = load_store_from_bytes(
            &bytes,
            r#"{"db_path": ":memory:"}"#,
            "sqlite-from-bytes",
            "store",
        )
        .expect("load from verified bytes");
        let key = VirtualKey {
            id: "vk_b".into(),
            key_hash: "h".into(),
            name: "b".into(),
            allowed_pools: Some(vec!["p".into()]),
            enabled: true,
            created_at: 1,
            group: None,
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
        let store =
            load_store_from_bytes(&verified, r#"{"db_path": ":memory:"}"#, "toctou", "store")
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
            let store = load_store_from_bytes(
                &bytes,
                r#"{"db_path": ":memory:"}"#,
                "no-leak-check",
                "store",
            )
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
        let store =
            load_store_from_bytes(&bytes, r#"{"db_path": ":memory:"}"#, "memfd-check", "store")
                .expect("memfd load");
        assert!(store.list_keys().expect("list").is_empty());
        assert_eq!(
            staged_dirs(),
            before,
            "a Linux memfd load must not create any staging directory/file"
        );
    }
}
