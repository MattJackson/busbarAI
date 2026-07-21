// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The **Redis store as a droppable busbar plugin** — a `cdylib` exporting the store C ABI. Build it,
//! drop the resulting `.so`/`.dll`/`.dylib` into the engine's plugins folder, and set
//! `governance.store: redis`; the engine loads it in-process at boot. One Redis behind a fleet of
//! busbar nodes means shared virtual keys, budgets, usage, and audit across the cluster.
//!
//! All the KV modeling lives in the `busbar-store-redis` `lib` crate (which a custom build can also
//! link statically). Here we only adapt the engine's JSON config into a `RedisStore`.

use busbar_api::Store;
use busbar_store_redis::RedisStore;

/// Construct a Redis store from the JSON config the engine passes through `open`:
///
/// ```json
/// { "url": "redis://:password@host:6379/0" }
/// ```
///
/// The engine passes `governance.db_path` as this `url` (see the boot store-load), mirroring how the
/// Postgres plugin receives its libpq URL.
fn open(cfg: &str) -> Result<Box<dyn Store>, String> {
    let v: serde_json::Value = if cfg.trim().is_empty() {
        serde_json::Value::Object(Default::default())
    } else {
        serde_json::from_str(cfg).map_err(|e| format!("invalid redis plugin config: {e}"))?
    };
    let url = v.get("url").and_then(|x| x.as_str()).ok_or_else(|| {
        "redis plugin config requires a \"url\" (a redis:// connection string)".to_string()
    })?;
    let store = RedisStore::connect(url).map_err(|e| e.0)?;
    Ok(Box::new(store))
}

busbar_plugin_sdk::export_store_plugin!(open);
