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
    // Side-effect-FREE readiness check: `/healthz` is unauthenticated and high-frequency (k8s
    // liveness, load balancers), so it must NOT transition expired-Open lanes to HalfOpen or steal
    // the single-flight recovery probe from organic traffic — use the non-mutating `is_ready_any_cell`,
    // not the mutating `usable`. `is_ready_any_cell` (not the default-cell-only `is_ready`) checks the
    // default cell AND every per-pool cell: production routes through NAMED pools whose per-pool cells
    // trip independently, so reading only the default `""` cell would report 200 while every pool lane
    // is circuit-broken (the default cell never moves for pool-routed traffic).
    if (0..app.lanes.len()).any(|i| app.store.is_ready_any_cell(i, t)) {
        (StatusCode::OK, "ok").into_response()
    } else {
        (StatusCode::SERVICE_UNAVAILABLE, "no usable lanes").into_response()
    }
}
