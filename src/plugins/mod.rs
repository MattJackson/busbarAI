// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Matthew Jackson

//! Default-included, compile-removable PLUGINS.
//!
//! The engine ships a curated set of plugins but contains no plugin-specific logic itself — each
//! plugin implements an engine contract (today: `crate::auth::AuthModule`) and lives in its own
//! subdirectory here, architecturally identical to a third-party/private plugin. A plugin is
//! removed from the binary by dropping its cargo feature (`--no-default-features`) — compliance
//! by compilation. Any plugin we choose to include by default lives here; anything unwanted is
//! simply not compiled in.

pub(crate) mod token;
