// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Matthew Jackson

use std::collections::HashMap;
use std::sync::atomic::AtomicUsize;
use std::sync::Arc;

pub(crate) use crate::proto::Protocol;
pub(crate) use crate::store::now;
pub(crate) use crate::store::StateStore;

use reqwest::Client;

// ---------- lane (one per model) ----------
#[derive(Clone)]
pub(crate) struct Lane {
    pub(crate) model: String,
    pub(crate) provider: String,
    pub(crate) base_url: String,
    pub(crate) api_key: String,
    pub(crate) protocol: Arc<Protocol>,
    pub(crate) max: usize,
    // error_map cloned into each lane at startup for Stage 1b normalization
    pub(crate) error_map: Arc<std::collections::HashMap<String, String>>,
    /// Optional maximum context window size for this lane's model (B-504b).
    pub(crate) context_max: Option<usize>,
}

/// A pool lane with its associated weight (B-401).
#[derive(Clone)]
pub(crate) struct WeightedLane {
    pub(crate) idx: usize,  // index into lanes array
    pub(crate) weight: u32, // member weight from config
}

pub(crate) struct App {
    pub(crate) lanes: Vec<Lane>,
    pub(crate) store: Arc<dyn StateStore>,
    pub(crate) by_model: HashMap<String, usize>,
    /// Pools now carry weights alongside lane indices (B-401).
    pub(crate) pools: HashMap<String, Vec<WeightedLane>>,
    /// Round-robin counter - no longer used after B-401 but kept for potential fallback.
    #[allow(dead_code)] // No longer used; SWRR handles selection
    pub(crate) rr: AtomicUsize,
    pub(crate) client: Client,
    pub(crate) auth: Arc<crate::auth::AuthMiddleware>,
    pub(crate) auth_mode: crate::auth::AuthMode,
    /// B-402: Default failover config (deadline_s and max_failover cap).
    #[allow(dead_code)] // Used by forward.rs for default policy
    pub(crate) failover_cfg: Option<crate::config::FailoverCfg>,
    /// B-403: Fallback pools mapping (pool name -> WeightedLane vec) for fallback mode.
    pub(crate) fallback_pools: HashMap<String, Vec<WeightedLane>>,
    /// B-403: OnExhausted config per pool name.
    #[allow(dead_code)] // Used by forward.rs for exhaustion handling
    pub(crate) on_exhausted_cfgs: std::collections::HashMap<String, crate::config::OnExhausted>,
}
