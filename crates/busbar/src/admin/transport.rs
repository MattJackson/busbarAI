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
//!
//! MOUNT GRAMMAR: every busbar-NATIVE API surface mounts ALGORITHMICALLY at
//! `/api/<version>/<area>/…` — a transport declares its `version()` + `area()` and its router uses
//! RELATIVE paths; `mount` computes the prefix. Adding a surface (a future `events`, `metrics`, or a
//! `v2` of an area) is one new impl + one `mount` call — no route hand-wiring, and the prefix can
//! never drift between the router, the scope matrix, and the OpenAPI doc (all three read the same
//! constants in `contract`).

use std::sync::Arc;

use axum::Router;

use crate::state::AppHandle;

/// The port a wire format implements to expose a native API surface. `name()` labels the transport
/// for logs/negotiation (e.g. `"json/v1"`); `version()`/`area()` place it in the mount grammar; and
/// `router()` returns RELATIVE routes mounted under `/api/<version>/<area>`. The router's state is
/// `Arc<AppHandle>` (the hot-swap seam): each handler loads the CURRENT snapshot from it into a
/// per-request `AdminService`, so reads reflect a config apply and the mutation path swaps through
/// the handle.
pub(crate) trait AdminTransport {
    /// The stable wire name of this transport+version (`"json/v1"`, `"graphql/v1"`, `"mcp/v1"`, …).
    fn name(&self) -> &'static str;

    /// The API version segment of the mount (`"v1"`, later `"v2"`).
    fn version(&self) -> &'static str;

    /// The API area segment of the mount (`"admin"`; later `"events"`, `"metrics"`, …).
    fn area(&self) -> &'static str;

    /// Build the router exposing this transport's endpoints (RELATIVE paths — `/info`, `/hooks`, …)
    /// over the `Arc<AppHandle>` state. `mount` nests it under `/api/<version>/<area>`.
    fn router(&self) -> Router<Arc<AppHandle>>;
}

/// Mount a native-API transport onto `router` at its computed `/api/<version>/<area>` prefix. Called
/// from `main`; the router's `Arc<AppHandle>` state is applied later by `with_state`. Adding a
/// transport, area, or version is one `mount` call — the prefix is derived, never hand-written.
pub(crate) fn mount<T: AdminTransport>(
    router: Router<Arc<AppHandle>>,
    transport: &T,
) -> Router<Arc<AppHandle>> {
    let prefix = format!(
        "{}/{}/{}",
        crate::admin::v1::contract::API_ROOT,
        transport.version(),
        transport.area()
    );
    tracing::info!(
        transport = transport.name(),
        prefix = %prefix,
        "native API surface mounted"
    );
    router.nest(&prefix, transport.router())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// CONTRACT LOCK: the algorithmic mount prefix computed from JsonV1's version()/area() must be
    /// byte-identical to `contract::ADMIN_PREFIX` — the constant the scope matrix, the rate-class
    /// gate, and the OpenAPI doc all key on. A drift here would mount the surface at a path the
    /// authorization matrix doesn't recognize.
    #[test]
    fn json_v1_mount_prefix_matches_contract_const() {
        let t = crate::admin::JsonV1;
        let computed = format!(
            "{}/{}/{}",
            crate::admin::v1::contract::API_ROOT,
            t.version(),
            t.area()
        );
        assert_eq!(computed, crate::admin::v1::contract::ADMIN_PREFIX);
    }
}
