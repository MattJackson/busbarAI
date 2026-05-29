// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Matthew Jackson

use std::collections::HashMap;
use std::sync::Arc;

use axum::{
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use serde_json::{json, Value};

use crate::state::{now, App};
use std::sync::atomic::Ordering;

pub async fn stats(State(app): State<Arc<App>>) -> Response {
    let t = now();
    let lanes: Vec<Value> = app.lanes.iter().map(|l| json!({
        "model": l.model, "provider": l.provider, "max_concurrent": l.max,
        "inflight": l.inflight.load(Ordering::Relaxed), "free_slots": l.sem.available_permits(),
        "ok": l.ok.load(Ordering::Relaxed), "err": l.err.load(Ordering::Relaxed),
        "usable": l.usable(t), "dead": l.dead.load(Ordering::Relaxed),
        "dead_reason": *l.dead_reason.lock().unwrap(),
        "cooldown_remaining_s": l.cooldown_until.load(Ordering::Relaxed).saturating_sub(t),
        "streak": l.streak.load(Ordering::Relaxed),
        "budget": if l.limited { l.budget.load(Ordering::Relaxed) } else { -1 },
    })).collect();
    let pools: HashMap<&String, Vec<&str>> = app
        .pools
        .iter()
        .map(|(n, idx)| {
            (
                n,
                idx.iter().map(|&i| app.lanes[i].model.as_str()).collect(),
            )
        })
        .collect();
    Json(json!({ "pools": pools, "lanes": lanes })).into_response()
}

pub async fn healthz(State(app): State<Arc<App>>) -> Response {
    let t = now();
    if app.lanes.iter().any(|l| l.usable(t)) {
        (StatusCode::OK, "ok").into_response()
    } else {
        (StatusCode::SERVICE_UNAVAILABLE, "no usable lanes").into_response()
    }
}
