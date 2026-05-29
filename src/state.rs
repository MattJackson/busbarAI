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
pub struct Lane {
    pub model: String,
    pub provider: String,
    pub base_url: String,
    pub api_key: String,
    pub protocol: Arc<dyn Protocol>,
    pub sem: Arc<Semaphore>,
    pub max: usize,
    pub limited: bool,
    pub budget: AtomicI64,
    pub cooldown_until: AtomicU64,
    pub streak: AtomicU32,
    pub dead: AtomicBool,
    pub dead_reason: std::sync::Mutex<String>,
    pub inflight: AtomicI64,
    pub ok: AtomicU64,
    pub err: AtomicU64,
}
impl Lane {
    pub fn usable(&self, t: u64) -> bool {
        if self.dead.load(Ordering::Relaxed) {
            return false;
        }
        if self.limited && self.budget.load(Ordering::Relaxed) <= 0 {
            return false;
        }
        t >= self.cooldown_until.load(Ordering::Relaxed)
    }
    pub fn kill(&self, reason: &str) {
        self.dead.store(true, Ordering::Relaxed);
        *self.dead_reason.lock().unwrap() = reason.to_string();
        eprintln!("[{}] STOPPED permanently: {}", self.model, reason);
    }
    pub fn cooldown_rate_limit(&self) {
        let s = self.streak.fetch_add(1, Ordering::Relaxed) + 1;
        let secs = (COOLDOWN_BASE_SECS * s as u64).min(COOLDOWN_MAX_SECS);
        self.cooldown_until.store(now() + secs, Ordering::Relaxed);
        self.err.fetch_add(1, Ordering::Relaxed);
        eprintln!(
            "[{}] rate-limited (streak {}), cooldown {}s",
            self.model, s, secs
        );
    }
    pub fn cooldown_transient(&self, what: &str) {
        self.cooldown_until
            .store(now() + COOLDOWN_TRANSIENT_SECS, Ordering::Relaxed);
        self.err.fetch_add(1, Ordering::Relaxed);
        eprintln!(
            "[{}] transient ({}), cooldown {}s",
            self.model, what, COOLDOWN_TRANSIENT_SECS
        );
    }
    pub fn success(&self) {
        self.streak.store(0, Ordering::Relaxed);
        self.ok.fetch_add(1, Ordering::Relaxed);
        if self.limited && self.budget.fetch_sub(1, Ordering::Relaxed) - 1 <= 0 {
            self.kill("request budget exhausted");
        }
    }
}

pub struct App {
    pub lanes: Vec<Lane>,
    pub by_model: HashMap<String, usize>,
    pub pools: HashMap<String, Vec<usize>>,
    pub rr: AtomicUsize,
    pub client: reqwest::Client,
    pub auth: Arc<crate::auth::AuthMiddleware>,
}
