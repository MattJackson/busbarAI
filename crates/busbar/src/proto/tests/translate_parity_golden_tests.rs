// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Cross-protocol TRANSLATE-PATH byte-parity goldens (anthropic ingress ⇄ openai egress).
//!
//! These tests pin the EXACT BYTES the non-streaming translate path emits for a corpus of
//! representative bodies, against golden fixtures committed under `tests/golden/`. The goldens were
//! generated from the pre-optimization translate pipeline (the `serde_json::Value`-building
//! reader/writer path), so any CPU/allocation optimization of the translate path — including a
//! direct-serialize fast path that skips the intermediate `Value` — must reproduce the wire output
//! BYTE-FOR-BYTE or these tests fail. This is the fidelity wall for the translation-wave perf work.
//!
//! The harness replays the same step list the production seams run:
//!   * REQUEST  (`translate_request_cross_protocol`, JSON branch): parse → anthropic
//!     `read_request` → `IrReq::prepare_for_egress` → openai `write_request` →
//!     `strip_router_shim_keys` → `rewrite_model_if_needed` → `crate::json::to_vec`.
//!   * RESPONSE (proxy engine buffered cross-protocol branch): parse → openai `read_response` →
//!     `IrResp::prepare_for_ingress` → anthropic `write_response` → `inject_response_metrics` →
//!     `crate::json::to_vec`.
//!
//! The one nondeterministic output field — the anthropic writer's synthesized `id`
//! (`msg_01<24 base62>`) on the response side — is shape-asserted and then NORMALIZED to a fixed
//! token before comparison, so everything else (key order, number formatting, string escaping,
//! field presence) is compared byte-exact.
//!
//! Regenerating goldens (ONLY for an intentional wire-shape change):
//!   `BUSBAR_BLESS_GOLDEN=1 cargo test -p busbar translate_parity_golden` then commit the diff.

use crate::ir::variant::{EgressPrep, IrReq, IrResp};

/// The lane wire model stamped on the egress request (mirrors `rewrite_model_if_needed`).
const LANE_MODEL: &str = "gpt-4o-mini";
/// Fixed epoch for `prepare_for_ingress` so the synthesized `created` boundary signal (unused by
/// the anthropic writer, but part of the IR contract) is deterministic.
const FIXED_NOW: u64 = 1_752_000_000;
/// Fixed 24-char base62 token substituted for the synthesized anthropic message id.
const FIXED_ID: &str = "msg_01GOLDENGOLDENGOLDENGOLD";

fn golden_dir() -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src/proto/tests/golden")
}

fn bless() -> bool {
    std::env::var_os("BUSBAR_BLESS_GOLDEN").is_some()
}

/// Compare `actual` to the committed golden `name`, or rewrite the golden in bless mode.
fn check_golden(name: &str, actual: &[u8]) {
    let path = golden_dir().join(name);
    if bless() {
        std::fs::create_dir_all(golden_dir()).expect("create golden dir");
        std::fs::write(&path, actual).expect("write golden");
        return;
    }
    let expected = std::fs::read(&path)
        .unwrap_or_else(|e| panic!("missing golden {name} ({e}); run with BUSBAR_BLESS_GOLDEN=1"));
    assert_eq!(
        expected,
        actual,
        "translate output drifted from golden {name}\n--- golden ---\n{}\n--- actual ---\n{}",
        String::from_utf8_lossy(&expected),
        String::from_utf8_lossy(actual),
    );
}

/// The production REQUEST translate steps for the anthropic→openai lane, byte-for-byte.
fn translate_request_a2o(body: &str) -> Vec<u8> {
    let anthropic = crate::proto::protocol_for("anthropic").expect("anthropic protocol");
    let openai = crate::proto::protocol_for("openai").expect("openai protocol");
    let v: serde_json::Value = crate::json::parse(body.as_bytes()).expect("valid corpus JSON");
    let ir = anthropic.reader().read_request(&v).expect("reads");
    let mut req = IrReq::Chat(ir);
    req.prepare_for_egress(&EgressPrep {
        ingress_protocol: "anthropic",
        egress_requires_max_tokens: openai.writer().requires_max_tokens(),
        lane_default_max_tokens: None,
        global_default_max_tokens: 4096,
        reasoning_allowed: true,
        reasoning_budgets: crate::ir::REASONING_BUDGET_DEFAULTS,
        prompt_caching_allowed: true,
    });
    let IrReq::Chat(ir) = req else { unreachable!() };
    let mut out = openai.writer().write_request(&ir);
    crate::proxy::strip_router_shim_keys(&mut out, "openai");
    openai
        .writer()
        .rewrite_model_if_needed(&mut out, LANE_MODEL);
    crate::json::to_vec(&out).expect("serializes")
}

/// The production RESPONSE translate steps for the openai→anthropic lane, byte-for-byte, with the
/// synthesized `id` normalized to `FIXED_ID` after a shape assertion.
fn translate_response_o2a(body: &str) -> Vec<u8> {
    let anthropic = crate::proto::protocol_for("anthropic").expect("anthropic protocol");
    let openai = crate::proto::protocol_for("openai").expect("openai protocol");
    let v: serde_json::Value = crate::json::parse(body.as_bytes()).expect("valid corpus JSON");
    let ir = openai.reader().read_response(&v).expect("reads");
    let mut resp = IrResp::Chat(ir);
    resp.prepare_for_ingress("anthropic", FIXED_NOW);
    let IrResp::Chat(ir) = resp else {
        unreachable!()
    };
    let mut out = anthropic.writer().write_response(&ir);
    anthropic
        .writer()
        .inject_response_metrics(&mut out, Some(123));
    // Normalize the synthesized message id (the ONLY nondeterministic byte range) after asserting
    // it has the native shape: `msg_01` + 24 base62 chars = 30 chars total.
    let obj = out.as_object_mut().expect("response object");
    let id = obj
        .get("id")
        .and_then(|i| i.as_str())
        .expect("id present")
        .to_string();
    assert!(
        id.starts_with("msg_01")
            && id.len() == 30
            && id.as_bytes()[6..].iter().all(|b| b.is_ascii_alphanumeric()),
        "synthesized anthropic id must keep the native msg_01<24 base62> shape, got {id:?}"
    );
    obj.insert("id".to_string(), serde_json::json!(FIXED_ID));
    crate::json::to_vec(&out).expect("serializes")
}

/// Corpus of representative anthropic REQUEST bodies (the ingress dialect): plain chat, multi-turn
/// with sampling controls, system array + cache breakpoints + images, tool use round-trip, thinking
/// ask + metadata carry, unmodeled extras (cleared cross-protocol), and degenerate content shapes.
const REQUEST_CORPUS: &[(&str, &str)] = &[
    (
        "req_a2o_plain.json",
        r#"{"model":"claude-sonnet-4-20250514","max_tokens":256,"messages":[{"role":"user","content":"Hello, world"}]}"#,
    ),
    (
        "req_a2o_multi_turn.json",
        r#"{"model":"claude-sonnet-4-20250514","max_tokens":1024,"temperature":0.7,"top_p":0.9,"stop_sequences":["END","STOP"],"stream":true,"system":"You are terse.","messages":[{"role":"user","content":"What is 2+2?"},{"role":"assistant","content":"4"},{"role":"user","content":[{"type":"text","text":"And squared?"}]}]}"#,
    ),
    (
        "req_a2o_system_array_images.json",
        r#"{"model":"claude-sonnet-4-20250514","max_tokens":512,"system":[{"type":"text","text":"Be helpful.","cache_control":{"type":"ephemeral"}},{"type":"text","text":"Cite sources."}],"messages":[{"role":"user","content":[{"type":"text","text":"Describe these."},{"type":"image","source":{"type":"base64","media_type":"image/png","data":"aGVsbG8="}},{"type":"image","source":{"type":"url","url":"https://example.com/cat.png"}}]}]}"#,
    ),
    (
        "req_a2o_tools.json",
        r#"{"model":"claude-sonnet-4-20250514","max_tokens":2048,"tools":[{"name":"get_weather","description":"Get weather","input_schema":{"type":"object","properties":{"city":{"type":"string"}},"required":["city"]},"cache_control":{"type":"ephemeral"}}],"tool_choice":{"type":"tool","name":"get_weather","disable_parallel_tool_use":true},"messages":[{"role":"user","content":"Weather in Paris?"},{"role":"assistant","content":[{"type":"text","text":"Checking."},{"type":"tool_use","id":"toolu_01AAA","name":"get_weather","input":{"city":"Paris"}}]},{"role":"user","content":[{"type":"tool_result","tool_use_id":"toolu_01AAA","content":[{"type":"text","text":"18C "},{"type":"text","text":"sunny"}]}]},{"role":"user","content":[{"type":"tool_result","tool_use_id":"toolu_01AAA","content":"plain string result","is_error":true}]}]}"#,
    ),
    (
        "req_a2o_thinking_metadata.json",
        r#"{"model":"claude-sonnet-4-20250514","max_tokens":8192,"top_k":40,"stream":true,"thinking":{"type":"enabled","budget_tokens":2048},"metadata":{"user_id":"user-1234"},"messages":[{"role":"user","content":"Think hard about prime numbers."}]}"#,
    ),
    (
        "req_a2o_extras_cleared.json",
        r#"{"model":"claude-sonnet-4-20250514","max_tokens":128,"service_tier":"auto","top_secret_extension":{"a":[1,2,3]},"messages":[{"role":"user","content":"hi"}]}"#,
    ),
    (
        "req_a2o_degenerate.json",
        r#"{"model":"claude-sonnet-4-20250514","max_tokens":64,"messages":[{"role":"assistant","content":""},{"role":"user","content":[{"type":"document","title":"x"},{"type":"text","text":"escape\" \\ ✓\nnewline"}]},{"role":"system","content":"late system turn"}]}"#,
    ),
];

/// Corpus of representative openai RESPONSE bodies (the egress dialect): plain completion,
/// tool_calls, cached usage details, reasoning content, multi-part array content, and a
/// usage-less/minimal body.
const RESPONSE_CORPUS: &[(&str, &str)] = &[
    (
        "resp_o2a_plain.json",
        r#"{"id":"chatcmpl-abc123","object":"chat.completion","created":1752000000,"model":"gpt-4o-mini","choices":[{"index":0,"message":{"role":"assistant","content":"Hello there!"},"finish_reason":"stop"}],"usage":{"prompt_tokens":12,"completion_tokens":4,"total_tokens":16}}"#,
    ),
    (
        "resp_o2a_tool_calls.json",
        r#"{"id":"chatcmpl-def456","object":"chat.completion","created":1752000001,"model":"gpt-4o-mini","choices":[{"index":0,"message":{"role":"assistant","content":null,"tool_calls":[{"id":"call_XYZ","type":"function","function":{"name":"get_weather","arguments":"{\"city\":\"Paris\"}"}},{"id":"call_ZZZ","type":"function","function":{"name":"get_time","arguments":"not json"}}]},"finish_reason":"tool_calls"}],"usage":{"prompt_tokens":50,"completion_tokens":20,"total_tokens":70}}"#,
    ),
    (
        "resp_o2a_cached_usage.json",
        r#"{"id":"chatcmpl-ghi789","object":"chat.completion","created":1752000002,"model":"gpt-4o-mini","system_fingerprint":"fp_44709d6fcb","choices":[{"index":0,"message":{"role":"assistant","content":"Cached reply"},"finish_reason":"stop"}],"usage":{"prompt_tokens":100,"completion_tokens":10,"total_tokens":110,"prompt_tokens_details":{"cached_tokens":80}}}"#,
    ),
    (
        "resp_o2a_reasoning.json",
        r#"{"id":"chatcmpl-jkl012","object":"chat.completion","created":1752000003,"model":"deepseek-r1","choices":[{"index":0,"message":{"role":"assistant","reasoning_content":"Let me think...","content":"42"},"finish_reason":"stop"}],"usage":{"prompt_tokens":9,"completion_tokens":33,"total_tokens":42}}"#,
    ),
    (
        "resp_o2a_multipart.json",
        r#"{"id":"chatcmpl-mno345","object":"chat.completion","created":1752000004,"model":"gpt-4o-mini","choices":[{"index":0,"message":{"role":"assistant","content":[{"type":"text","text":"part one "},{"type":"text","text":"part two"},{"type":"refusal","refusal":"no thanks"}]},"finish_reason":"length"}],"usage":{"prompt_tokens":7,"completion_tokens":7,"total_tokens":14}}"#,
    ),
    (
        "resp_o2a_minimal.json",
        r#"{"id":"chatcmpl-pqr678","object":"chat.completion","created":1752000005,"model":"gpt-4o-mini","choices":[{"index":0,"message":{"role":"assistant","content":"ok \"quoted\" ✓"},"finish_reason":"stop"}]}"#,
    ),
];

#[test]
fn translate_parity_golden_request_anthropic_to_openai() {
    for (name, body) in REQUEST_CORPUS {
        let actual = translate_request_a2o(body);
        check_golden(name, &actual);
    }
}

#[test]
fn translate_parity_golden_response_openai_to_anthropic() {
    for (name, body) in RESPONSE_CORPUS {
        let actual = translate_response_o2a(body);
        check_golden(name, &actual);
    }
}
