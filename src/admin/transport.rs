// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Matthew Jackson

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

use super::v1::service::AdminService;
use crate::state::App;

/// The port a wire format implements to expose the admin surface. All state is the shared service; an
/// adapter is otherwise a zero-sized strategy. `name()` labels the transport for logs/negotiation
/// (e.g. `"json/v1"`); `router()` returns the mount this transport contributes, backed by that service.
pub(crate) trait AdminTransport {
    /// The stable wire name of this transport+version (`"json/v1"`, `"graphql/v1"`, `"mcp/v1"`, …).
    fn name(&self) -> &'static str;

    /// Build the router exposing this transport's endpoints, all backed by the shared service.
    fn router(&self, service: Arc<AdminService>) -> Router<Arc<App>>;
}

/// Mount an admin transport onto `router` over the shared `App`. Called from `main` once the `App` is
/// built. Keeping this a free function (not inline in `main`) means swapping/adding a transport — or a
/// new API version — is a one-line change at the call site.
pub(crate) fn mount<T: AdminTransport>(
    router: Router<Arc<App>>,
    transport: &T,
    app: Arc<App>,
) -> Router<Arc<App>> {
    let service = Arc::new(AdminService::new(app));
    tracing::info!(transport = transport.name(), "admin API transport mounted");
    router.merge(transport.router(service))
}
