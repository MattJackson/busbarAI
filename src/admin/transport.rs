// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The Admin API TRANSPORT port — the "driving adapter" seam over the shared service.
//!
//! `AdminTransport` is transport-AGNOSTIC: the trait every wire format plugs into. Given the shared
//! `AdminService`, an adapter builds whatever it needs to expose the frozen operations. The JSON-REST
//! family (`super::json`, versioned by submodule — `json::v1::JsonV1`) is the first transport; a
//! GraphQL, gRPC, or MCP adapter later is a NEW `AdminTransport` impl calling the SAME `AdminService`
//! methods and reusing the SAME `contract` views/errors — no operation logic is ever duplicated per
//! transport (or per version).
//!
//! An adapter's ONLY jobs are (1) translate its wire request into a service call and (2) project the
//! typed `Result<View, AdminError>` back onto its wire. All logic, scope, atomicity, and audit live in
//! the service; the contract types live in `contract`.

use std::sync::Arc;

use axum::Router;

use crate::state::AppHandle;

/// The port a wire format implements to expose the admin surface. `name()` labels the transport for
/// logs/negotiation (e.g. `"json/v1"`); `router()` returns the mount this transport contributes. The
/// router's state is `Arc<AppHandle>` (the hot-swap seam): each handler loads the CURRENT snapshot from
/// it into a per-request `AdminService`, so reads reflect a config apply and the mutation path swaps
/// through the handle.
pub(crate) trait AdminTransport {
    /// The stable wire name of this transport+version (`"json/v1"`, `"graphql/v1"`, `"mcp/v1"`, …).
    fn name(&self) -> &'static str;

    /// Build the router exposing this transport's endpoints over the `Arc<AppHandle>` state.
    fn router(&self) -> Router<Arc<AppHandle>>;
}

/// Mount an admin transport onto `router`. Called from `main`; the router's `Arc<AppHandle>` state is
/// applied later by `with_state`. Keeping this a free function (not inline in `main`) means
/// swapping/adding a transport — or a new API version — is a one-line change at the call site.
pub(crate) fn mount<T: AdminTransport>(
    router: Router<Arc<AppHandle>>,
    transport: &T,
) -> Router<Arc<AppHandle>> {
    tracing::info!(transport = transport.name(), "admin API transport mounted");
    router.merge(transport.router())
}
