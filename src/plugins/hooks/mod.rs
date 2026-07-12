// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Hook plugins — BUILT-IN hooks compiled into the binary, implementing the hook contract on the IR
//! (tap/gate). Distinct from auth plugins: a different contract at a different pipeline stage.
//!
//! No built-in hooks ship today — hooks are normally external socket/webhook processes registered
//! at runtime (`hooks:` config), so they live outside the engine. This module is the reserved home
//! for any hook we choose to compile in by default (e.g. a future in-tree redaction hook); each
//! would live in `plugins/hooks/<name>/` behind its own cargo feature.

/// The built-in RANKING hooks (cheapest/fastest/least_busy/usage) — order-gates over the
/// `RoutingPolicy` contract, relocated out of the engine core. Removable (`hooks-ranking` feature).
#[cfg(feature = "hooks-ranking")]
pub(crate) mod ranking;
