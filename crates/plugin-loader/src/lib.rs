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

use busbar_api::{
    AwsCredential, MeteringDelta, MeteringRow, Store, StoreError, StoreResult, Usage, VirtualKey,
};
use busbar_plugin_abi::{
    symbol, CallFn, CloseFn, FreeFn, StoreRequest, StoreResponse, ABI_VERSION, STATUS_OK,
};
use libloading::Library;
use std::os::raw::c_void;
use std::path::Path;

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
    /// Kept last so it drops LAST (fields drop in declaration order): the fn pointers and handle
    /// remain valid until after `Drop` has `close`d the handle.
    _lib: Library,
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

    fn get_usage(&self, key_id: &str, window_start: u64) -> StoreResult<Usage> {
        match self.call_raw(StoreRequest::GetUsage {
            key_id: key_id.to_string(),
            window_start,
        })? {
            StoreResponse::Usage(u) => Ok(u),
            other => Err(unexpected(other)),
        }
    }

    fn put_usage(
        &self,
        key_id: &str,
        window_start: u64,
        spend_cents: i64,
        tokens: u64,
        requests: u64,
    ) -> StoreResult<()> {
        match self.call_raw(StoreRequest::PutUsage {
            key_id: key_id.to_string(),
            window_start,
            spend_cents,
            tokens,
            requests,
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
}

impl Drop for DynStore {
    fn drop(&mut self) {
        // Close the instance while the library is still mapped (fields drop after this runs; `_lib`
        // is declared last so it unloads last).
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

/// Inventory the plugins directory: every dynamic library present, each validated (ABI handshake) so
/// the admin surface can show what's installed and whether it's loadable. A missing directory is an
/// empty inventory, not an error.
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
    /// `-p busbar`-only run may not have built it, so the test skips rather than fails; under
    /// `cargo test --workspace` (preflight/CI) the cdylib is always present and the test runs.
    fn sqlite_plugin_path() -> Option<std::path::PathBuf> {
        let exe = std::env::current_exe().ok()?; // .../target/<profile>/deps/busbar-<hash>
        let profile_dir = exe.parent()?.parent()?; // .../target/<profile>
        let name = plugin_library_filename("busbar_store_sqlite_plugin");
        let candidate = profile_dir.join(&name);
        candidate.exists().then_some(candidate)
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
        };
        store.put_key(&key).expect("put_key");

        let got = store.get_key("vk_dyn").expect("get_key").expect("present");
        assert_eq!(got.id, "vk_dyn");
        assert_eq!(got.max_budget_cents, Some(500));

        assert_eq!(store.list_keys().expect("list").len(), 1);

        store.put_usage("vk_dyn", 100, 42, 9, 3).expect("put_usage");
        let usage = store.get_usage("vk_dyn", 100).expect("get_usage");
        assert_eq!(usage.spend_cents, 42);
        assert_eq!(usage.tokens, 9);
        assert_eq!(usage.requests, 3);

        store.delete_key("vk_dyn").expect("delete");
        assert!(store.get_key("vk_dyn").expect("get after delete").is_none());
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
}
