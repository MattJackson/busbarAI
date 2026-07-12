// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Default-included, compile-removable PLUGINS, organized by TYPE.
//!
//! The engine ships a curated set of plugins but contains no plugin-specific logic itself. Plugins
//! come in distinct TYPES, each implementing a distinct engine contract at a distinct pipeline
//! stage — today there are two:
//!
//! - **`auth`** — implements `crate::auth::AuthModule`; runs at the `auth` stage (before the HTTP
//!   router) to establish the caller. `tokens` is the built-in; SAML/AD/OIDC are private-repo peers.
//! - **`hooks`** — implements the hook contract; fires on the IR (tap/gate) after the request is
//!   understood. Reserved for BUILT-IN hooks compiled into the binary (most hooks are external
//!   socket/webhook processes and live outside the engine entirely).
//!
//! Each plugin lives in `plugins/<type>/<name>/` and is architecturally identical to a third-party
//! plugin of the same type. A plugin is removed from the binary by dropping its cargo feature
//! (`--no-default-features`) — compliance by compilation.

pub(crate) mod auth;
pub(crate) mod hooks;
