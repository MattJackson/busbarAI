// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The **SQLite store as a droppable busbar plugin** — a `cdylib` that exports the store C ABI
//! ([`busbar_plugin_abi`]). Build it, drop the resulting `.so`/`.dll`/`.dylib` into the engine's
//! plugins folder, and set `governance.store: sqlite`; the engine loads it in-process at boot.
//!
//! This crate is deliberately tiny: all the SQLite logic lives in the `busbar-store-sqlite` `lib`
//! crate (which a custom build can also link statically). Here we only adapt the engine's JSON
//! config into a `SqliteStore` and hand the trait object to the SDK, which emits the five extern-C
//! symbols the loader resolves.

use busbar_api::Store;
use busbar_store_sqlite::SqliteStore;

/// Construct a SQLite store from the JSON config the engine passes through `open`. Shape (both keys
/// optional, sensible defaults so an empty `{}` works):
///
/// ```json
/// { "db_path": "busbar-governance.db", "busy_timeout_ms": 5000 }
/// ```
fn open(cfg: &str) -> Result<Box<dyn Store>, String> {
    let v: serde_json::Value = if cfg.trim().is_empty() {
        serde_json::Value::Object(Default::default())
    } else {
        serde_json::from_str(cfg).map_err(|e| format!("invalid sqlite plugin config: {e}"))?
    };
    let path = v
        .get("db_path")
        .and_then(|x| x.as_str())
        .unwrap_or("busbar-governance.db");
    let busy_timeout_ms = v
        .get("busy_timeout_ms")
        .and_then(|x| x.as_i64())
        .unwrap_or(5000);
    let store = SqliteStore::open(path, busy_timeout_ms).map_err(|e| e.0)?;
    Ok(Box::new(store))
}

busbar_plugin_sdk::export_store_plugin!(open);
