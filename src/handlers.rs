// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Matthew Jackson

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

    // BTreeMap (not HashMap) so the serialized `pools` object has a stable, sorted key order —
    // `app.pools` is a HashMap whose iteration order is randomized per process, which otherwise
    // makes `/stats` output non-reproducible across restarts. Lane order is already deterministic
    // (index order, and lane indices are now built sorted-by-model — see main.rs).
    let pools: std::collections::BTreeMap<&String, Vec<&str>> = app
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

/// `GET /v1/models` — the OpenAI list-models surface. This is the first call an OpenAI SDK
/// (`client.models.list()`) or a self-hosted UI (Open WebUI, LibreChat) makes to populate a
/// model picker, so busbar answers it with every name a client can put in a request body:
/// configured model entries AND pool names (a pool is a routable model from the client's
/// point of view).
///
/// Governance-scoped with the same rules as `/stats`: a virtual key with a non-empty
/// `allowed_pools` sees only its visible pools and the models reachable through them —
/// the model list must not leak topology the pool ACL hides.
pub(crate) async fn list_models(
    State(app): State<Arc<App>>,
    Extension(gov): Extension<GovCtx>,
    headers: axum::http::HeaderMap,
) -> Response {
    list_models_dialect(app, gov, &headers, false)
}

/// `GET /v1beta/models` — the same list in Gemini's dialect (their SDK's discovery path).
pub(crate) async fn list_models_v1beta(
    State(app): State<Arc<App>>,
    Extension(gov): Extension<GovCtx>,
    headers: axum::http::HeaderMap,
) -> Response {
    list_models_dialect(app, gov, &headers, true)
}

/// Three protocols put their list-models endpoint on the same noun, each with its own
/// envelope: OpenAI and Anthropic share `GET /v1/models` outright, and Gemini lists at
/// `GET /v1(beta)/models`. Primary (POST) surfaces are disjoint by path, so this is the
/// one place busbar disambiguates callers by PROTOCOL FINGERPRINT instead:
///
/// - `anthropic-version` header — the Anthropic API requires it, so their SDK always
///   sends it -> Anthropic envelope
/// - `x-goog-api-key` header or the /v1beta path -> Gemini envelope
/// - otherwise -> OpenAI envelope (the compatible ecosystem's default; Cohere's SDK
///   carries no reliable fingerprint and receives this shape, documented)
///
/// The list itself is the same data in every dialect: the names a client may put in a
/// request body. No privileged protocol - the data is one, the rendering is the caller's.
fn list_models_dialect(
    app: Arc<App>,
    gov: GovCtx,
    headers: &axum::http::HeaderMap,
    gemini_path: bool,
) -> Response {
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

    // Stable order: pools first, then direct models, each sorted — SDK consumers and UIs
    // render this list directly, and a deterministic order diffs cleanly in tests and docs.
    let mut names: Vec<&str> = app
        .pools
        .keys()
        .filter(|n| visible_pool(n))
        .map(String::as_str)
        .collect();
    names.sort_unstable();

    let mut models: Vec<&str> = app
        .by_model
        .keys()
        .filter(|m| {
            if !restricted {
                return true;
            }
            // A restricted key sees a direct model only if a visible pool routes to its lane
            // (mirrors the /stats lane rule; pool-less lanes stay hidden from restricted keys).
            let Some(&idx) = app.by_model.get(*m) else {
                return false;
            };
            app.pools
                .iter()
                .filter(|(n, _)| visible_pool(n))
                .any(|(_, wls)| wls.iter().any(|wl| wl.idx == idx))
        })
        .map(String::as_str)
        .collect();
    models.sort_unstable();
    names.extend(models);
    names.dedup();

    if headers.contains_key("anthropic-version") {
        let data: Vec<Value> = names
            .iter()
            .map(|id| {
                json!({
                    "type": "model",
                    "id": id,
                    "display_name": id,
                    "created_at": "1970-01-01T00:00:00Z"
                })
            })
            .collect();
        return Json(json!({
            "data": data,
            "has_more": false,
            "first_id": names.first(),
            "last_id": names.last(),
        }))
        .into_response();
    }
    if gemini_path || headers.contains_key("x-goog-api-key") {
        let models: Vec<Value> = names
            .iter()
            .map(|id| {
                json!({
                    "name": format!("models/{id}"),
                    "displayName": id,
                    "supportedGenerationMethods": ["generateContent", "streamGenerateContent"]
                })
            })
            .collect();
        return Json(json!({ "models": models })).into_response();
    }
    let data: Vec<Value> = names
        .iter()
        .map(|id| json!({ "id": id, "object": "model", "created": 0, "owned_by": "busbar" }))
        .collect();
    Json(json!({ "object": "list", "data": data })).into_response()
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

    /// Regression (info-disclosure): a vkey restricted to `pool-a` must see ONLY
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

    async fn models_ids(app: Arc<App>, gov: GovCtx) -> Vec<String> {
        let resp = list_models(State(app), Extension(gov), axum::http::HeaderMap::new()).await;
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .expect("collect /v1/models body");
        let body: Value = serde_json::from_slice(&bytes).expect("/v1/models body is JSON");
        assert_eq!(body["object"], "list", "OpenAI list envelope");
        body["data"]
            .as_array()
            .expect("data array")
            .iter()
            .map(|m| {
                assert_eq!(m["object"], "model", "OpenAI model object");
                m["id"].as_str().expect("model id").to_string()
            })
            .collect()
    }

    /// `models.list()` is the first call an OpenAI SDK or a self-hosted UI makes. An
    /// unrestricted caller sees every routable name: pools first, then direct models,
    /// each sorted (a deterministic order UIs can render directly).
    #[tokio::test]
    async fn test_v1_models_lists_pools_and_models() {
        let app = topology_app();
        let ids = models_ids(app, GovCtx::default()).await;
        assert_eq!(
            ids,
            ["pool-a", "pool-b", "model-a0", "model-a1", "model-b"],
            "pools then models, each sorted"
        );
    }

    /// Info-disclosure regression: a key restricted to `pool-a` must not enumerate
    /// `pool-b` or its private model through the model list — same rule as /stats.
    #[tokio::test]
    async fn test_v1_models_restricted_key_sees_only_reachable_names() {
        let app = topology_app();
        let gov = GovCtx {
            key: Some(vkey(&["pool-a"])),
        };
        let ids = models_ids(app, gov).await;
        assert_eq!(
            ids,
            ["pool-a", "model-a0", "model-a1"],
            "hidden pool and its private lane must not leak; got {ids:?}"
        );
    }

    /// An empty `allowed_pools` key (operator default) sees the full list, like /stats.
    #[tokio::test]
    async fn test_v1_models_empty_allowed_pools_sees_all() {
        let app = topology_app();
        let gov = GovCtx {
            key: Some(vkey(&[])),
        };
        let ids = models_ids(app, gov).await;
        assert_eq!(ids.len(), 5);
    }

    async fn models_body(app: Arc<App>, headers: axum::http::HeaderMap, beta: bool) -> Value {
        let resp = if beta {
            list_models_v1beta(State(app), Extension(GovCtx::default()), headers).await
        } else {
            list_models(State(app), Extension(GovCtx::default()), headers).await
        };
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .expect("collect body");
        serde_json::from_slice(&bytes).expect("JSON body")
    }

    /// The Anthropic SDK always sends `anthropic-version` (their API requires it) — the
    /// same path answers in the Anthropic list envelope for those callers.
    #[tokio::test]
    async fn test_v1_models_anthropic_fingerprint_gets_anthropic_envelope() {
        let mut headers = axum::http::HeaderMap::new();
        headers.insert("anthropic-version", "2023-06-01".parse().unwrap());
        let body = models_body(topology_app(), headers, false).await;
        assert_eq!(body["has_more"], false, "Anthropic list envelope");
        let first = &body["data"][0];
        assert_eq!(first["type"], "model");
        assert_eq!(first["id"], "pool-a");
        assert!(body.get("object").is_none(), "no OpenAI envelope fields");
    }

    /// Gemini callers (x-goog-api-key header, or the /v1beta path their SDK uses) get the
    /// Gemini models envelope with `models/<id>` resource names.
    #[tokio::test]
    async fn test_v1_models_gemini_fingerprint_gets_gemini_envelope() {
        let mut headers = axum::http::HeaderMap::new();
        headers.insert("x-goog-api-key", "k".parse().unwrap());
        let body = models_body(topology_app(), headers, false).await;
        assert_eq!(body["models"][0]["name"], "models/pool-a");

        let beta = models_body(topology_app(), axum::http::HeaderMap::new(), true).await;
        assert_eq!(
            beta["models"][0]["name"], "models/pool-a",
            "/v1beta path implies Gemini"
        );
    }
}
