// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Admin API **v1** — the frozen, additive-only surface, as a self-contained version unit.
//!
//! Version-first layout (Matthew 7/11): everything that can differ between API versions lives under
//! the version directory, so releasing v2 is a LAYER operation — copy `v1/` to `v2/`, change only what
//! differs, and mount `/admin/v2/*` alongside. v1 never breaks.
//!
//! - [`contract`] — v1 typed views + the stable error taxonomy (the frozen surface in Rust).
//! - [`service`] — the v1 application service: typed operations returning `contract` views/errors,
//!   over the shared engine (`App`). Version-agnostic engine logic will factor to a shared core when
//!   v2 lands (extract-on-second-use); today the ops are simple reads.
//! - [`json`] — the JSON-REST wire adapter (`JsonV1`) mounting `/admin/v1/*`. A `graphql` sibling
//!   would speak the same service over a different wire.
//!
//! The transport PORT (`super::transport::AdminTransport`) is shared across versions and transports.

pub(crate) mod contract;
pub(crate) mod json;
pub(crate) mod service;
