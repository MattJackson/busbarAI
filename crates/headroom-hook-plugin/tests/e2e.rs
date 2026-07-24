// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! End-to-end coverage of the `headroom` compression gate loaded over the REAL loader `open_hook` seam
//! (`load_hook_from_bytes`). This is the exact seam the engine sees: an `Arc<dyn RoutingPolicy>`
//! indistinguishable from a compiled-in policy, whose `transform` compresses the granted prompt and
//! whose reply is parsed through the engine's own fail-closed `hooks::wire` normalizers.
//!
//! Mirrors `webrequest-hook-plugin/tests/e2e.rs`:
//! - `transform` with the prompt projected (grant given) → a `Rewrite` outcome carrying the shrunk body;
//! - `transform` with an already-tight prompt → `Abstain` (nothing to compress, original body proceeds);
//! - `transform` with NO prompt projected (grant absent) → `Abstain`;
//! - `decide` abstains (Headroom ranks nothing);
//! - `describe`/`status` return the gate's own schema + cumulative honest savings.

use busbar_api::{
    Candidate, RoutingContext, RoutingDecision, RoutingPolicy, RoutingRequest, TransformOutcome,
};
use busbar_plugin_loader::hook::{load_hook_from_bytes, HookProjectors};
use std::sync::Arc;
use std::time::Duration;

/// Locate the built `headroom` cdylib in the target dir (mirrors the loader's hook_plugin_path).
fn plugin_path() -> Option<std::path::PathBuf> {
    let exe = std::env::current_exe().ok()?;
    let profile_dir = exe.parent()?.parent()?;
    let name = busbar_plugin_loader::plugin_library_filename("busbar_headroom_hook_plugin");
    let candidate = profile_dir.join(&name);
    candidate.exists().then_some(candidate)
}

/// The engine-side projectors: the same tiny fail-closed shims the loader's own hook test uses,
/// standing in for the engine's real `hooks::wire`. The `transform` projector carries the granted
/// prompt as `request.system` + `request.messages` (`{role, text}`), and `transform_outcome` maps a
/// `{"rewrite":{"messages":[...]}}` reply to a Rewrite (reject > rewrite > abstain).
fn projectors() -> Arc<HookProjectors> {
    Arc::new(HookProjectors {
        decide: Box::new(|req, cands, _ctx| {
            serde_json::json!({
                "request": { "pool": req.pool },
                "candidates": cands.iter().map(|c| serde_json::json!({"idx": c.idx})).collect::<Vec<_>>(),
            })
        }),
        transform: Box::new(|req| {
            // Project the prompt EXACTLY as the core does when prompt: rw is granted: system + the
            // message bodies. When `req.prompt` is None (grant absent) the projection carries no
            // prompt keys, so Headroom sees nothing to compress and abstains.
            serde_json::json!({
                "request": {
                    "system": req.prompt.as_ref().and_then(|p| p.system.as_ref().map(|s| s.as_ref().to_string())),
                    "messages": req.prompt.as_ref().map(|p| {
                        p.messages.iter().map(|(r, t)| {
                            serde_json::json!({"role": r.as_ref(), "text": t.as_ref()})
                        }).collect::<Vec<_>>()
                    }),
                }
            })
        }),
        normalize: Box::new(|v, cands| {
            let Some(order) = v.get("order").and_then(|o| o.as_array()) else {
                return RoutingDecision::Abstain;
            };
            let valid: std::collections::HashSet<usize> = cands.iter().map(|c| c.idx).collect();
            RoutingDecision::from_ranked(
                order.iter().filter_map(|x| x.as_u64().map(|x| x as usize)),
                &valid,
            )
        }),
        transform_outcome: Box::new(|v| {
            match v
                .get("rewrite")
                .and_then(|r| r.get("messages"))
                .and_then(|m| m.as_array())
            {
                Some(msgs) if !msgs.is_empty() => {
                    TransformOutcome::Rewrite(busbar_api::RewriteReply {
                        messages: msgs.clone(),
                        tools: Vec::new(),
                    })
                }
                _ => TransformOutcome::Abstain,
            }
        }),
        status: Box::new(|v| {
            v.get("status").map(|s| busbar_api::HookStatus {
                settings_version: None,
                settings: s.get("settings").and_then(|x| x.as_object()).cloned(),
                metrics: s.get("metrics").and_then(|m| m.as_array()).cloned(),
            })
        }),
        describe_schema: Box::new(|v| v.get("schema").cloned()),
    })
}

/// Load the gate over the real loader seam with the given `settings` JSON.
fn load(settings: &str) -> Arc<dyn RoutingPolicy> {
    let path = plugin_path().expect("headroom cdylib built under --workspace");
    let bytes = std::fs::read(&path).expect("read headroom cdylib");
    load_hook_from_bytes(
        &bytes,
        settings,
        "headroom",
        "hook",
        "headroom",
        projectors(),
    )
    .expect("load the headroom plugin over the ABI")
}

/// A request with a prompt (grant given): the projector will carry system + the message body.
fn req_with_prompt(system: Option<&str>, text: &str) -> RoutingRequest<'static> {
    RoutingRequest {
        pool: "p",
        ingress_protocol: "anthropic",
        requested_model: None,
        message_count: 1,
        tool_count: 0,
        has_tools: false,
        total_chars: text.len(),
        system_chars: system.map(|s| s.len()).unwrap_or(0),
        max_tokens: None,
        stream: false,
        prompt: Some(busbar_api::PromptProjection {
            system: system.map(|s| s.to_string().into()),
            messages: vec![("user".into(), text.to_string().into())],
        }),
        identity: None,
    }
}

/// A request with NO prompt (grant absent): the projector carries no prompt keys → Headroom abstains.
fn req_without_prompt() -> RoutingRequest<'static> {
    RoutingRequest {
        pool: "p",
        ingress_protocol: "anthropic",
        requested_model: None,
        message_count: 1,
        tool_count: 0,
        has_tools: false,
        total_chars: 0,
        system_chars: 0,
        max_tokens: None,
        stream: false,
        prompt: None,
        identity: None,
    }
}

fn cand(idx: usize) -> Candidate<'static> {
    Candidate {
        idx,
        model: "m",
        provider: "prov",
        weight: 1,
        context_max: None,
        tier: None,
        cost_per_mtok: None,
        tags: &[],
        latency_ms: None,
        available_concurrency: 1,
        budget_remaining: None,
        rate_headroom: None,
    }
}

fn ctx() -> RoutingContext<'static> {
    RoutingContext {
        pool: "p",
        budget_remaining: None,
        budget: &[],
    }
}

const BUDGET: Duration = Duration::from_secs(5);

/// END-TO-END: load the gate, `transform` a compressible prompt (grant given) → a Rewrite carrying the
/// shrunk message body.
#[tokio::test]
async fn transform_compresses_granted_prompt() {
    if plugin_path().is_none() {
        eprintln!("skip: headroom cdylib not built (run under --workspace)");
        return;
    }
    let policy = load("{}");
    let req = req_with_prompt(None, "hello     world\nhello     world\n\n\n\nbye");
    match policy.transform(&req, BUDGET).await {
        TransformOutcome::Rewrite(rw) => {
            assert_eq!(rw.messages.len(), 1);
            assert_eq!(rw.messages[0]["text"], "hello world\n\nbye");
        }
        other => panic!("expected Rewrite, got {other:?}"),
    }
}

/// `transform` of an already-tight prompt → Abstain (nothing to compress; the original body proceeds).
#[tokio::test]
async fn transform_abstains_when_nothing_to_compress() {
    if plugin_path().is_none() {
        return;
    }
    let policy = load("{}");
    let req = req_with_prompt(None, "already tight prose");
    assert!(matches!(
        policy.transform(&req, BUDGET).await,
        TransformOutcome::Abstain
    ));
}

/// `transform` with NO prompt projected (operator grant absent) → Abstain. Headroom can never coerce
/// content: without the projection it simply has nothing to rewrite.
#[tokio::test]
async fn transform_abstains_without_grant() {
    if plugin_path().is_none() {
        return;
    }
    let policy = load("{}");
    assert!(matches!(
        policy.transform(&req_without_prompt(), BUDGET).await,
        TransformOutcome::Abstain
    ));
}

/// `decide` abstains over the seam (Headroom ranks nothing).
#[tokio::test]
async fn decide_abstains() {
    if plugin_path().is_none() {
        return;
    }
    let policy = load("{}");
    let d = policy
        .decide(&req_with_prompt(None, "x"), &[cand(0)], &ctx(), BUDGET)
        .await
        .expect("decide ok");
    assert_eq!(d, RoutingDecision::Abstain);
}

/// `describe` returns the config schema; `status` reports the resolved level + cumulative honest
/// savings after a real transform (chars_saved > 0), with no prompt content surfaced.
#[tokio::test]
async fn describe_and_status_over_the_seam() {
    if plugin_path().is_none() {
        return;
    }
    let policy = load(r#"{"level":"balanced"}"#);
    let schema = policy.describe(BUDGET).await.expect("describe schema");
    assert_eq!(schema["type"], "object");

    // Run a compressible transform so status has something honest to report.
    let req = req_with_prompt(Some("Be   concise.\n\n\n\nBe concise."), "a\n\n\n\nb");
    let _ = policy.transform(&req, BUDGET).await;

    let status = policy.status(BUDGET).await.expect("status");
    let settings = status.settings.expect("status settings");
    assert_eq!(settings.get("level").unwrap(), "balanced");
    let metrics = status.metrics.expect("metrics");
    let saved = metrics
        .iter()
        .find(|m| m["name"] == "headroom_chars_saved_total")
        .expect("chars_saved metric");
    assert!(
        saved["value"].as_u64().unwrap() > 0,
        "compression saved characters"
    );
}

/// `configure` over the seam acks a well-formed level push and NACKs a malformed one (parity with the
/// webrequest forwarder's re-validation ack/nack).
#[tokio::test]
async fn configure_acks_and_nacks_over_the_seam() {
    if plugin_path().is_none() {
        return;
    }
    let policy = load("{}");
    let mut good = serde_json::Map::new();
    good.insert("level".into(), serde_json::json!("conservative"));
    policy
        .configure("headroom", &good, 2, BUDGET)
        .await
        .expect("a well-formed level push acks");

    let mut bad = serde_json::Map::new();
    bad.insert("level".into(), serde_json::json!(123));
    assert!(
        policy.configure("headroom", &bad, 3, BUDGET).await.is_err(),
        "a non-string level must NACK (malformed push does not commit)"
    );
}
