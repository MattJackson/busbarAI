// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Matthew Jackson

use std::collections::HashMap;
use std::sync::Arc;

use axum::{
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Response},
    Extension, Json,
};
use serde_json::{json, Value};

use crate::governance::{pool_allowed, GovCtx};
use crate::state::{now, App};

/// `/stats` reports the pool/lane topology. It is governance-scoped: a virtual key with a
/// non-empty `allowed_pools` must NOT learn the full topology of pools and lanes it can never
/// reach (info disclosure — a restricted tenant could otherwise enumerate every model, provider,
/// and pool the gateway fronts). We FILTER the reported pools to those the caller may target, and
/// the reported lanes to the union of lanes reachable via those visible pools.
///
/// An empty `allowed_pools` (or `key: None` — governance disabled, or the operator/admin default
/// `GovCtx`) means "all pools", so those callers see the full topology exactly as before: this
/// preserves today's operator/admin behavior.
pub(crate) async fn stats(
    State(app): State<Arc<App>>,
    Extension(gov): Extension<GovCtx>,
) -> Response {
    let t = now();

    // Decide which pools are visible to this caller. `None` => no key restriction (the visible set
    // is every pool). `Some(key)` with empty `allowed_pools` is handled by `pool_allowed`, which
    // admits every pool — so an unrestricted key also sees everything.
    let restricted = gov
        .key
        .as_ref()
        .is_some_and(|k| !k.allowed_pools.is_empty());

    let visible_pool = |name: &str| -> bool {
        match gov.key.as_ref() {
            Some(key) => pool_allowed(key, name),
            None => true,
        }
    };

    let pools: HashMap<&String, Vec<&str>> = app
        .pools
        .iter()
        .filter(|(n, _)| visible_pool(n))
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

    // Lanes are filtered to those reachable via a visible pool ONLY when the caller is restricted.
    // An unrestricted caller (no key, or empty `allowed_pools`) sees every lane — including any
    // lane not bound to a pool — exactly as before. A restricted caller sees only the lanes its
    // visible pools route to; lanes outside those pools (and pool-less lanes) stay hidden, so the
    // lane list can't be used to enumerate the topology the pool filter just removed.
    let lane_visible = |i: usize| -> bool {
        if !restricted {
            return true;
        }
        app.pools
            .iter()
            .filter(|(n, _)| visible_pool(n))
            .any(|(_, weighted_lanes)| weighted_lanes.iter().any(|wl| wl.idx == i))
    };

    let lanes: Vec<Value> = (0..app.lanes.len())
        .filter(|&i| lane_visible(i))
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::governance::VirtualKey;
    use crate::test_support::{LaneSpec, TestApp};

    /// A virtual key restricted to `allowed_pools` (empty = all pools).
    fn vkey(allowed_pools: &[&str]) -> VirtualKey {
        VirtualKey {
            id: "k-test".to_string(),
            key_hash: "deadbeef".to_string(),
            name: "test".to_string(),
            allowed_pools: allowed_pools.iter().map(|s| s.to_string()).collect(),
            max_budget_cents: None,
            budget_period: "total".to_string(),
            rpm_limit: None,
            tpm_limit: None,
            enabled: true,
            created_at: 1_700_000_000,
        }
    }

    /// Two pools, three lanes: `pool-a` -> lanes {0,1}, `pool-b` -> lane {2}. Lane 2's model is
    /// private to `pool-b` so a `pool-a`-only key must never see it.
    fn topology_app() -> Arc<App> {
        TestApp::new()
            .lane(LaneSpec::new(
                "model-a0",
                crate::proto::Protocol::openai(),
                "http://a0",
            ))
            .lane(LaneSpec::new(
                "model-a1",
                crate::proto::Protocol::openai(),
                "http://a1",
            ))
            .lane(LaneSpec::new(
                "model-b",
                crate::proto::Protocol::openai(),
                "http://b",
            ))
            .pool("pool-a", &[(0, 1), (1, 1)])
            .pool("pool-b", &[(2, 1)])
            .build()
    }

    async fn stats_json(app: Arc<App>, gov: GovCtx) -> Value {
        let resp = stats(State(app), Extension(gov)).await;
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .expect("collect /stats body");
        serde_json::from_slice(&bytes).expect("/stats body is JSON")
    }

    /// Regression for LOW #36 (info-disclosure): a vkey restricted to `pool-a` must see ONLY
    /// `pool-a` in the reported topology and ONLY the lanes that pool routes to — never `pool-b`
    /// or its private lane `model-b`.
    #[tokio::test]
    async fn test_stats_restricted_key_sees_only_its_pools_and_lanes() {
        let app = topology_app();
        let gov = GovCtx {
            key: Some(vkey(&["pool-a"])),
        };
        let body = stats_json(app, gov).await;

        let pools = body["pools"].as_object().expect("pools object");
        assert!(pools.contains_key("pool-a"), "allowed pool must be visible");
        assert!(
            !pools.contains_key("pool-b"),
            "a pool the key cannot target must be hidden; got {pools:?}"
        );

        let lane_models: Vec<&str> = body["lanes"]
            .as_array()
            .expect("lanes array")
            .iter()
            .map(|l| l["model"].as_str().expect("lane model"))
            .collect();
        assert!(
            lane_models.contains(&"model-a0") && lane_models.contains(&"model-a1"),
            "lanes reachable via the visible pool must be reported; got {lane_models:?}"
        );
        assert!(
            !lane_models.contains(&"model-b"),
            "a lane private to a hidden pool must NOT leak in the lane list; got {lane_models:?}"
        );
    }

    /// An empty `allowed_pools` (operator/admin default) preserves today's behavior: the FULL
    /// topology — every pool and every lane — is reported.
    #[tokio::test]
    async fn test_stats_empty_allowed_pools_sees_full_topology() {
        let app = topology_app();
        let gov = GovCtx {
            key: Some(vkey(&[])),
        };
        let body = stats_json(app, gov).await;

        let pools = body["pools"].as_object().expect("pools object");
        assert!(pools.contains_key("pool-a") && pools.contains_key("pool-b"));

        let lanes = body["lanes"].as_array().expect("lanes array");
        assert_eq!(lanes.len(), 3, "an unrestricted key sees every lane");
    }

    /// No key at all (governance disabled) is equivalent to unrestricted: full topology.
    #[tokio::test]
    async fn test_stats_no_key_sees_full_topology() {
        let app = topology_app();
        let body = stats_json(app, GovCtx::default()).await;

        let pools = body["pools"].as_object().expect("pools object");
        assert!(pools.contains_key("pool-a") && pools.contains_key("pool-b"));
        assert_eq!(body["lanes"].as_array().expect("lanes array").len(), 3);
    }
}
