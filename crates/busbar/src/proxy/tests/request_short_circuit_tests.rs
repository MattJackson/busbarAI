use super::translate_request_cross_protocol;
use crate::proto::gemini::GEMINI_JSON_ARRAY_SHIM_KEY;
use crate::proto::Protocol;
use crate::test_support::{LaneSpec, TestApp};
use serde_json::json;

// Build a single-lane App whose one lane speaks `proto` with the given `lane_model`. The lane
// base_url is unused (the short-circuit never dispatches). `i == 0` is the lane index.
fn app_with_lane(proto: Protocol, lane_model: &str) -> std::sync::Arc<crate::state::App> {
    TestApp::new()
        .lane(LaneSpec::new(lane_model, proto, "http://unused.local"))
        .build()
}

// Drive the request seam for a SAME-protocol hop (ingress == egress) and return the egress bytes.
fn shape_same_proto(
    proto: Protocol,
    proto_name: &'static str,
    lane_model: &str,
    body: serde_json::Value,
) -> Vec<u8> {
    let app = app_with_lane(proto, lane_model);
    // hop_bytes = the exact serialized source bytes the caller retained for this hop.
    let hop_bytes = crate::json::to_vec(&body).unwrap();
    translate_request_cross_protocol(
        &app,
        0,
        proto_name,
        crate::handlers::chat(proto_name),
        Some(body),
        crate::proxy::APPLICATION_JSON,
        true,
        &hop_bytes,
    )
    .expect("same-proto shaping is infallible for a valid body")
}

// ---- FIDELITY PROOF: pristine same-proto request → bytes == retained original, all 6 protocols.

// BODY-MODEL protocols (anthropic/openai/cohere/responses): a pristine request carries `model`
// == lane.model and no shim keys, so NOTHING mutates → short-circuit emits the original bytes.
#[test]
fn pristine_same_proto_is_byte_identical_body_model() {
    let cases: &[(Protocol, &'static str, serde_json::Value)] = &[
        (
            Protocol::anthropic(),
            "anthropic",
            json!({"model":"claude-3","max_tokens":7,"messages":[{"role":"user","content":"hi"}]}),
        ),
        (
            Protocol::openai(),
            "openai",
            json!({"model":"gpt-4o","messages":[{"role":"user","content":"hi"}],"temperature":0.5}),
        ),
        (
            Protocol::cohere(),
            "cohere",
            json!({"model":"command-r","messages":[{"role":"user","content":"hi"}]}),
        ),
        (
            Protocol::responses(),
            "responses",
            json!({"model":"gpt-4o","input":"hi"}),
        ),
    ];
    for (proto, name, body) in cases {
        // lane.model == body.model → rewrite_model_if_needed is a no-op (#3 not triggered).
        let lane_model = body.get("model").and_then(|m| m.as_str()).unwrap();
        let hop_bytes = crate::json::to_vec(body).unwrap();
        let out = shape_same_proto(proto.clone(), name, lane_model, body.clone());
        assert_eq!(
            out, hop_bytes,
            "{name}: pristine same-proto request must short-circuit to the retained original bytes"
        );
    }
}

// `upstream_model` override must win on the wire. Covers the override branch of
// `Lane::upstream_model()` that no existing test exercises (all default `upstream_model` to
// `None`). Body-model protocol: rewrite_model_if_needed installs `upstream_model`. URL-model
// protocol: upstream_path_for_stream embeds `upstream_model` in the path.
#[test]
fn upstream_model_override_rewrites_body_and_url_model() {
    // Body-model protocol: rewrite_model_if_needed installs `upstream_model`.
    let app = TestApp::new()
        .lane(
            LaneSpec::new("config-key", Protocol::openai(), "http://unused.local")
                .upstream_model("upstream-real"),
        )
        .build();
    let body = json!({"model":"client-alias","messages":[]});
    let hop_bytes = crate::json::to_vec(&body).unwrap();
    let out = translate_request_cross_protocol(
        &app,
        0,
        "openai",
        crate::handlers::chat("openai"),
        Some(body),
        crate::proxy::APPLICATION_JSON,
        true,
        &hop_bytes,
    )
    .expect("same-proto shaping is infallible for a valid body");
    let parsed: serde_json::Value = serde_json::from_slice(&out).unwrap();
    assert_eq!(
        parsed.get("model").and_then(|m| m.as_str()),
        Some("upstream-real"),
        "body-model egress must carry the upstream_model override"
    );

    // URL-model protocol: upstream_path_for_stream embeds upstream_model in the path.
    let app = TestApp::new()
        .lane(
            LaneSpec::new("config-key", Protocol::bedrock(), "http://unused.local")
                .upstream_model("upstream.real/model"),
        )
        .build();
    let writer = app.lanes[0].protocol.writer();
    assert_eq!(
            writer.upstream_path_for_stream(app.lanes[0].wire_model(), false),
            "/model/upstream.real/model/converse",
            "URL-model path must embed the upstream_model override (raw; percent-encoding happens at sign/send time)"
        );
}

// Claude-on-Vertex: an anthropic lane with a Vertex `path_base` carries the model in the URL
// (`:rawPredict`), so request finalization must DROP the body `model` and INJECT `anthropic_version`
// (Vertex's required discriminator). This is the BODY half of the wrinkle — the harness proves the
// URL/mint end-to-end, but a signature-blind mock can't assert the body transform, so it's pinned
// here. A regression that stopped dropping `model` or stopped injecting the version would 400 on
// real Vertex; this test catches it offline.
#[test]
fn claude_on_vertex_drops_model_and_injects_anthropic_version() {
    let vbase = "/v1/projects/p/locations/us-central1/publishers/anthropic/models";
    let app = TestApp::new()
        .lane(
            LaneSpec::new(
                "claude-3-5-sonnet",
                Protocol::anthropic(),
                "https://us-central1-aiplatform.googleapis.com",
            )
            .path_base(vbase),
        )
        .build();
    let body = json!({"model":"claude-3-5-sonnet","max_tokens":7,"messages":[{"role":"user","content":"hi"}]});
    let hop_bytes = crate::json::to_vec(&body).unwrap();
    let out = translate_request_cross_protocol(
        &app,
        0,
        "anthropic",
        crate::handlers::chat("anthropic"),
        Some(body),
        crate::proxy::APPLICATION_JSON,
        true,
        &hop_bytes,
    )
    .expect("anthropic-vertex shaping is infallible for a valid body");
    let v: serde_json::Value = serde_json::from_slice(&out).unwrap();
    assert!(
        v.get("model").is_none(),
        "model must be dropped — it rides the :rawPredict URL, not the body: {v}"
    );
    assert_eq!(
        v.get("anthropic_version").and_then(|x| x.as_str()),
        Some("vertex-2023-10-16"),
        "the anthropic_version discriminator must be injected: {v}"
    );
    assert!(
        v.get("messages").is_some(),
        "the rest of the request body must be preserved through the transform: {v}"
    );
}

// MODEL-IN-URL protocols (gemini/bedrock): a pristine native request carries NO body `model`
#[test]
fn pristine_same_proto_is_byte_identical_url_model() {
    let cases: &[(Protocol, &'static str, serde_json::Value)] = &[
        (
            Protocol::gemini(),
            "gemini",
            json!({"contents":[{"role":"user","parts":[{"text":"hi"}]}]}),
        ),
        (
            Protocol::bedrock(),
            "bedrock",
            json!({"messages":[{"role":"user","content":[{"text":"hi"}]}]}),
        ),
    ];
    for (proto, name, body) in cases {
        let hop_bytes = crate::json::to_vec(body).unwrap();
        // The egress payload is byte-identical to the retained original. Bedrock reaches this via
        // the true short-circuit (its `rewrite_model_if_needed` is a no-op → pristine). Gemini's
        // default rewrite inserts the lane model which the same-proto strip then removes — a net
        // no-op on the Value, so canonical re-serialization still yields the identical bytes. Both
        // satisfy the byte-fidelity contract (the test that matters); only the path differs.
        let out = shape_same_proto(proto.clone(), name, "url-model-x", body.clone());
        assert_eq!(
            out, hop_bytes,
            "{name}: pristine same-proto url-model request egress must be byte-identical to input"
        );
    }
}

// ---- INVALIDATORS #1-#4: each must force NON-pristine and produce the correct rewritten bytes.

// #1: gemini JSON-array shim key present → stripped → NON-pristine → bytes differ, key gone.
#[test]
fn invalidator_1_gemini_array_shim_key_forces_non_pristine() {
    // Use a body-model ingress so only #1 fires (the key is stripped on EVERY egress).
    let body = json!({"model":"gpt-4o","messages":[],GEMINI_JSON_ARRAY_SHIM_KEY:true});
    let hop_bytes = crate::json::to_vec(&body).unwrap();
    let out = shape_same_proto(Protocol::openai(), "openai", "gpt-4o", body);
    assert_ne!(
        out, hop_bytes,
        "#1: array-shim key present must invalidate the short-circuit"
    );
    let parsed: serde_json::Value = serde_json::from_slice(&out).unwrap();
    assert!(
        parsed.get(GEMINI_JSON_ARRAY_SHIM_KEY).is_none(),
        "#1: the never-native array shim key must be stripped from the egress body"
    );
}

// #2: `stream` present on a PATH-MODEL egress (gemini) → stripped → NON-pristine → stream gone.
#[test]
fn invalidator_2_stream_on_path_model_egress_forces_non_pristine() {
    let body = json!({"contents":[{"role":"user","parts":[{"text":"hi"}]}],"stream":true});
    let hop_bytes = crate::json::to_vec(&body).unwrap();
    let out = shape_same_proto(Protocol::gemini(), "gemini", "url-model-x", body);
    assert_ne!(
        out, hop_bytes,
        "#2: `stream` on a path-model egress must invalidate"
    );
    let parsed: serde_json::Value = serde_json::from_slice(&out).unwrap();
    assert!(
        parsed.get("stream").is_none(),
        "#2: `stream` must be stripped for a path-model (gemini) egress"
    );
}

// #2 negative control: `stream` on a BODY-MODEL egress (openai) is the writer-authored field the
// backend needs → NOT stripped → with model matching lane, request stays pristine + byte-identical.
#[test]
fn invalidator_2_stream_on_body_model_egress_stays_pristine() {
    let body = json!({"model":"gpt-4o","messages":[],"stream":true});
    let hop_bytes = crate::json::to_vec(&body).unwrap();
    let out = shape_same_proto(Protocol::openai(), "openai", "gpt-4o", body);
    assert_eq!(
        out, hop_bytes,
        "#2 neg: `stream` on a body-model egress must be PRESERVED → request stays pristine"
    );
}

// #3: lane.model differs from body.model → rewrite_model_if_needed installs the lane model →
// NON-pristine → bytes differ, model rewritten to the authoritative lane model.
#[test]
fn invalidator_3_model_rewrite_forces_non_pristine() {
    let body = json!({"model":"client-alias","messages":[]});
    let hop_bytes = crate::json::to_vec(&body).unwrap();
    let out = shape_same_proto(Protocol::openai(), "openai", "gpt-4o-real", body);
    assert_ne!(
        out, hop_bytes,
        "#3: a model alias differing from lane.model must invalidate"
    );
    let parsed: serde_json::Value = serde_json::from_slice(&out).unwrap();
    assert_eq!(
        parsed.get("model").and_then(|m| m.as_str()),
        Some("gpt-4o-real"),
        "#3: the egress body must carry the authoritative lane model"
    );
}

// #3 negative control: body.model already EQUALS lane.model → no change → pristine short-circuit.
#[test]
fn invalidator_3_matching_model_stays_pristine() {
    let body = json!({"model":"gpt-4o-real","messages":[]});
    let hop_bytes = crate::json::to_vec(&body).unwrap();
    let out = shape_same_proto(Protocol::openai(), "openai", "gpt-4o-real", body);
    assert_eq!(
        out, hop_bytes,
        "#3 neg: a body model already matching lane.model must NOT invalidate (byte-identical)"
    );
}

// #4: same-proto gemini passthrough with a body `model` (a router shim) → stripped after rewrite →
// NON-pristine → bytes differ, model gone (gemini carries model in the URL).
#[test]
fn invalidator_4_same_proto_model_shim_strip_forces_non_pristine() {
    let body = json!({"model":"router-shim","contents":[{"role":"user","parts":[{"text":"hi"}]}]});
    let hop_bytes = crate::json::to_vec(&body).unwrap();
    let out = shape_same_proto(Protocol::gemini(), "gemini", "url-model-x", body);
    assert_ne!(
        out, hop_bytes,
        "#4: a same-proto path-model body `model` must invalidate"
    );
    let parsed: serde_json::Value = serde_json::from_slice(&out).unwrap();
    assert!(
        parsed.get("model").is_none(),
        "#4: a same-proto gemini/bedrock body `model` shim must be stripped"
    );
}
