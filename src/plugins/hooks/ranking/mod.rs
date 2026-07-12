// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Matthew Jackson

//! The built-in RANKING hooks — `cheapest` / `fastest` / `least_busy` / `usage` (see `ranking.rs`).
//!
//! These are removable built-in order-hooks: each implements the engine's `RoutingPolicy` contract
//! and ranks candidates on a signal the hook wire already projects, so an external hook could do the
//! same. `weighted` is NOT here — it is the engine's non-removable inline SWRR floor (the
//! `default hook`), never a plugin. (The `weighted` NAME/entry lives alongside for registry
//! completeness, but the floor's zero-cost behavior is the engine's inline path, not this policy.)

#[allow(clippy::module_inception)]
mod ranking;
pub(crate) use ranking::{
    native_policy, POLICY_NAME_CHEAPEST, POLICY_NAME_FASTEST, POLICY_NAME_LEAST_BUSY,
    POLICY_NAME_USAGE,
};
