// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Matthew Jackson

//! The `tokens` auth plugin (see `token.rs`).

// The `<plugin>/<plugin>.rs` layout is the deliberate plugin convention (each plugin is a
// self-contained subdir); the same-name nesting is intentional, not accidental.
#[allow(clippy::module_inception)]
mod token;
pub(crate) use token::TokensModule;
