// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Matthew Jackson

use std::collections::HashMap;
use std::sync::atomic::AtomicUsize;
use std::sync::Arc;

pub(crate) use crate::store::now;
pub(crate) use crate::{proto::Protocol, store::StateStore};

use reqwest::Client;

// ---------- lane (one per model) ----------
#[derive(Clone)]
pub(crate) struct Lane {
    pub(crate) model: String,
    pub(crate) provider: String,
    pub(crate) base_url: String,
    pub(crate) api_key: String,
    pub(crate) protocol: ProtocolKind,
    pub(crate) max: usize,
}

#[derive(Clone)]
pub(crate) enum ProtocolKind {
    Anthropic(crate::proto::AnthropicProtocol),
}

impl ProtocolKind {
    pub(crate) fn upstream_path(&self) -> &str {
        match self {
            ProtocolKind::Anthropic(p) => p.upstream_path(),
        }
    }

    pub(crate) fn auth_headers(
        &self,
        key: &str,
    ) -> Vec<(axum::http::HeaderName, axum::http::HeaderValue)> {
        match self {
            ProtocolKind::Anthropic(p) => p.auth_headers(key),
        }
    }

    pub(crate) fn rewrite_model(&self, body: &mut serde_json::Value, model: &str) {
        match self {
            ProtocolKind::Anthropic(p) => p.rewrite_model(body, model),
        }
    }

    pub(crate) fn classify(
        &self,
        status: axum::http::StatusCode,
        body: &[u8],
    ) -> crate::proto::CanonicalSignal {
        match self {
            ProtocolKind::Anthropic(p) => p.classify(status, body),
        }
    }
}

pub(crate) struct App {
    pub(crate) lanes: Vec<Lane>,
    pub(crate) store: Arc<dyn StateStore>,
    pub(crate) by_model: HashMap<String, usize>,
    pub(crate) pools: HashMap<String, Vec<usize>>,
    pub(crate) rr: AtomicUsize,
    pub(crate) client: Client,
    pub(crate) auth: Arc<crate::auth::AuthMiddleware>,
    pub(crate) auth_mode: crate::auth::AuthMode,
}
