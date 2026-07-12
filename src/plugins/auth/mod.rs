// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Matthew Jackson

//! Auth plugins — implementations of the `crate::auth::AuthModule` contract (the `auth` stage).
//! `tokens` is the built-in default; SAML / AD / OIDC are developed as peers in the private repo.

pub(crate) mod tokens;
