// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The `admin-tokens` admin-auth plugin (see `admin_tokens.rs`).

// The `<name>/<name>.rs` layout is the deliberate plugin convention (each plugin is a self-contained
// subdir); the same-name nesting is intentional, not accidental.
#[allow(clippy::module_inception)]
mod admin_tokens;
pub(crate) use admin_tokens::{authenticate_admin_tokens, ADMIN_TOKENS_PRINCIPAL_ID};
