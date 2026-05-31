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

pub(crate) async fn stats(State(app): State<Arc<App>>) -> Response {
    let t = now();
    let lanes: Vec<Value> = (0..app.lanes.len())
        .map(|i| {
            let snap = app.store.snapshot(i, t);
            json!({
                "model": snap.model,
                "provider": snap.provider,
                "max_concurrent": snap.max_concurrent,
                "inflight": snap.inflight,
                "free_slots": snap.free_slots,
                "ok": snap.ok,
                "err": snap.err,
                "client_fault": snap.client_fault,
                "usable": snap.usable,
                "dead": snap.dead,
                "dead_reason": snap.dead_reason,
                "cooldown_remaining_s": snap.cooldown_remaining_s,
                "streak": snap.streak,
                "budget": snap.budget,
            })
        })
        .collect();
    let pools: HashMap<&String, Vec<&str>> = app
        .pools
        .iter()
        .map(|(n, weighted_lanes)| {
            (
                n,
                weighted_lanes
                    .iter()
                    .map(|wl| app.lanes[wl.idx].model.as_str())
                    .collect(),
            )
        })
        .collect();
    Json(json!({ "pools": pools, "lanes": lanes })).into_response()
}

pub(crate) async fn healthz(State(app): State<Arc<App>>) -> Response {
    let t = now();
    if (0..app.lanes.len()).any(|i| app.store.usable(i, t)) {
        (StatusCode::OK, "ok").into_response()
    } else {
        (StatusCode::SERVICE_UNAVAILABLE, "no usable lanes").into_response()
    }
}
