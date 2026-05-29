// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Matthew Jackson

use std::collections::HashMap;
use std::sync::{
    atomic::{AtomicBool, AtomicI64, AtomicU32, AtomicU64, AtomicUsize, Ordering},
    Arc,
};
use std::time::{SystemTime, UNIX_EPOCH};

use tokio::sync::Semaphore;

use crate::proto::Protocol;

const COOLDOWN_BASE_SECS: u64 = 15;
const COOLDOWN_MAX_SECS: u64 = 120;
const COOLDOWN_TRANSIENT_SECS: u64 = 10;

pub(crate) fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

// ---------- lane (one per model) ----------
pub(crate) struct Lane {
    pub(crate) model: String,
    pub(crate) provider: String,
    pub(crate) base_url: String,
    pub(crate) api_key: String,
    pub(crate) protocol: Arc<dyn Protocol>,
    pub(crate) sem: Arc<Semaphore>,
    pub(crate) max: usize,
    pub(crate) limited: bool,
    pub(crate) budget: AtomicI64,
    pub(crate) cooldown_until: AtomicU64,
    pub(crate) streak: AtomicU32,
    pub(crate) dead: AtomicBool,
    pub(crate) dead_reason: std::sync::Mutex<String>,
    pub(crate) inflight: AtomicI64,
    pub(crate) ok: AtomicU64,
    pub(crate) err: AtomicU64,
}
impl Lane {
    pub(crate) fn usable(&self, t: u64) -> bool {
        if self.dead.load(Ordering::Relaxed) {
            return false;
        }
        if self.limited && self.budget.load(Ordering::Relaxed) <= 0 {
            return false;
        }
        t >= self.cooldown_until.load(Ordering::Relaxed)
    }
    pub(crate) fn kill(&self, reason: &str) {
        self.dead.store(true, Ordering::Relaxed);
        *self.dead_reason.lock().unwrap() = reason.to_string();
        eprintln!("[{}] STOPPED permanently: {}", self.model, reason);
    }
    pub(crate) fn cooldown_rate_limit(&self) {
        let s = self.streak.fetch_add(1, Ordering::Relaxed) + 1;
        let secs = (COOLDOWN_BASE_SECS * s as u64).min(COOLDOWN_MAX_SECS);
        self.cooldown_until.store(now() + secs, Ordering::Relaxed);
        self.err.fetch_add(1, Ordering::Relaxed);
        eprintln!(
            "[{}] rate-limited (streak {}), cooldown {}s",
            self.model, s, secs
        );
    }
    pub(crate) fn cooldown_transient(&self, what: &str) {
        self.cooldown_until
            .store(now() + COOLDOWN_TRANSIENT_SECS, Ordering::Relaxed);
        self.err.fetch_add(1, Ordering::Relaxed);
        eprintln!(
            "[{}] transient ({}), cooldown {}s",
            self.model, what, COOLDOWN_TRANSIENT_SECS
        );
    }
    #[allow(dead_code)] // Used by forward() when streaming - permit held until stream end
    pub(crate) fn success(&self) {
        self.streak.store(0, Ordering::Relaxed);
        self.ok.fetch_add(1, Ordering::Relaxed);
        if self.limited && self.budget.fetch_sub(1, Ordering::Relaxed) - 1 <= 0 {
            self.kill("request budget exhausted");
        }
    }
}

pub(crate) struct App {
    pub(crate) lanes: Vec<Lane>,
    pub(crate) by_model: HashMap<String, usize>,
    pub(crate) pools: HashMap<String, Vec<usize>>,
    pub(crate) rr: AtomicUsize,
    pub(crate) client: reqwest::Client,
    pub(crate) auth: Arc<crate::auth::AuthMiddleware>,
}
