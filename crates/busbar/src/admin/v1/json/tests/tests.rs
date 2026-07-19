use super::*;

/// Collect an axum Response into (status, content-type, parsed JSON body) for the wire-helper
/// micro-tests below.
async fn parts(resp: Response) -> (StatusCode, String, serde_json::Value) {
    let status = resp.status();
    let ct = resp
        .headers()
        .get(CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default()
        .to_string();
    use http_body_util::BodyExt;
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    let body = serde_json::from_slice(&bytes).expect("body is JSON");
    (status, ct, body)
}

/// The error envelope projection is `{"error":{"code","message"}}` with the error's status — the
/// shape v1 tooling parses — served as application/json.
#[tokio::test]
async fn err_json_uses_stable_envelope() {
    let (status, ct, body) = parts(err_json(&AdminError::NotFound("hook".into()))).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_eq!(ct, crate::proxy::APPLICATION_JSON);
    assert_eq!(body["error"]["code"], "not_found");
    assert!(
        body["error"]["message"]
            .as_str()
            .is_some_and(|m| !m.is_empty()),
        "message is human text, never empty"
    );
    assert_eq!(
        body["error"].as_object().unwrap().len(),
        2,
        "the envelope is exactly code+message (additive changes go OUTSIDE error)"
    );
}

/// `ok_json` serializes the view verbatim with the GIVEN status and application/json.
#[tokio::test]
async fn ok_json_serializes_view_with_given_status() {
    #[derive(Serialize)]
    struct View {
        name: &'static str,
        n: u32,
    }
    let (status, ct, body) = parts(ok_json(StatusCode::CREATED, &View { name: "x", n: 7 })).await;
    assert_eq!(status, StatusCode::CREATED);
    assert_eq!(ct, crate::proxy::APPLICATION_JSON);
    assert_eq!(body, json!({"name": "x", "n": 7}));
}

/// `respond` — the single seam every v1 handler funnels through — maps Ok to the given status
/// and Err to the error's own status + envelope (the Ok-status never leaks onto an error).
#[tokio::test]
async fn respond_maps_ok_and_err() {
    let ok: Result<serde_json::Value, AdminError> = Ok(json!({"ok": true}));
    let (status, _, body) = parts(respond(StatusCode::OK, ok)).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["ok"], true);

    let err: Result<serde_json::Value, AdminError> = Err(AdminError::RateLimited);
    let (status, _, body) = parts(respond(StatusCode::OK, err)).await;
    assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(body["error"]["code"], "rate_limited");
}

/// Structural lock on the discovery doc: OpenAPI 3.1, an info.version that matches the crate,
/// and every path under the ONE contract prefix (whose literal value is pinned by the golden
/// test in contract.rs) — the doc never mixes prefixes.
#[cfg(feature = "openapi-schema")]
#[test]
fn openapi_doc_is_31_and_v1_prefixed() {
    let doc = openapi_doc();
    assert!(
        doc["openapi"].as_str().unwrap().starts_with("3.1"),
        "discovery doc is OpenAPI 3.1"
    );
    assert_eq!(doc["info"]["version"], env!("CARGO_PKG_VERSION"));
    let prefix = format!("{}/", crate::admin::v1::contract::ADMIN_PREFIX);
    for path in doc["paths"].as_object().unwrap().keys() {
        assert!(
            path.starts_with(&prefix),
            "{path} escaped the frozen {prefix} prefix"
        );
    }
}

/// Release tooling, not a behavioral assertion. Publishing the OpenAPI schema is a release chore
/// WE do — an operator gets the doc from the live `GET /openapi.json` endpoint or the release
/// asset, so it earns no user-facing CLI surface. This test is the build-time handle CI uses to
/// capture the artifact straight from the same `openapi_doc()` the gateway serves, guaranteeing the
/// published file matches the shipped binary. A normal `cargo test` (no env var) just re-asserts
/// the doc is well-formed; the release workflow sets `BUSBAR_EMIT_OPENAPI=<path>` to also write the
/// pretty-printed document there, then uploads it to the GitHub Release.
#[cfg(feature = "openapi-schema")]
#[test]
fn emit_openapi_artifact() {
    let doc = openapi_doc();
    assert!(
        doc["openapi"]
            .as_str()
            .unwrap_or_default()
            .starts_with("3.1"),
        "OpenAPI document must be 3.1"
    );
    if let Ok(path) = std::env::var("BUSBAR_EMIT_OPENAPI") {
        let json = serde_json::to_string_pretty(&doc).expect("serialize OpenAPI document");
        std::fs::write(&path, json).unwrap_or_else(|e| panic!("write {path}: {e}"));
    }
}

/// CONTRACT LOCK: every openapi path+method is annotated with `x-busbar-required-scope`, and
/// the annotation matches the enforced `required_scope` matrix exactly (one source of truth —
/// this test guards against a future hand-written path entry forgetting or contradicting it).
#[cfg(feature = "openapi-schema")]
#[test]
fn openapi_paths_annotate_required_scope() {
    let doc = openapi_doc();
    let paths = doc["paths"].as_object().expect("paths object");
    assert!(!paths.is_empty());
    for (path, methods) in paths {
        for (method, op) in methods.as_object().expect("methods") {
            let m = match method.as_str() {
                "get" => axum::http::Method::GET,
                "post" => axum::http::Method::POST,
                "put" => axum::http::Method::PUT,
                "patch" => axum::http::Method::PATCH,
                "delete" => axum::http::Method::DELETE,
                // Path-item `x-*` specification extensions (e.g. `x-busbar-error-envelope`) are
                // valid OpenAPI and are not operations — they carry no scope annotation.
                ext if ext.starts_with("x-") => continue,
                other => panic!("unexpected method {other} on {path}"),
            };
            let annotated = op["x-busbar-required-scope"]
                .as_str()
                .unwrap_or_else(|| panic!("{method} {path} missing scope annotation"));
            let enforced = crate::admin::v1::contract::required_scope(&m, path).as_str();
            assert_eq!(annotated, enforced, "{method} {path} annotation drifted");
        }
    }
}

/// CONTRACT LOCK: the openapi Error-schema `code` enum must EXACTLY match the frozen `AdminError`
/// codes — no drift between the discovery doc and the taxonomy tooling actually receives. Every
/// variant's `code()` must appear in the enum, and the enum must list nothing else.
#[cfg(feature = "openapi-schema")]
#[test]
fn openapi_error_enum_matches_admin_error_codes() {
    use std::collections::BTreeSet;
    let doc = openapi_doc();
    let enum_codes: BTreeSet<String> = doc["components"]["schemas"]["Error"]["properties"]["error"]
        ["properties"]["code"]["enum"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap().to_string())
        .collect();
    // The exhaustive set of AdminError codes — kept in lock-step with `AdminError::code`.
    let actual_codes: BTreeSet<String> = [
        AdminError::NotFound(String::new()),
        AdminError::Unauthorized,
        AdminError::Forbidden {
            needed: crate::admin::v1::contract::Scope::Full,
        },
        AdminError::MethodNotAllowed,
        AdminError::Validation(String::new()),
        AdminError::VersionConflict(String::new()),
        AdminError::Conflict(String::new()),
        AdminError::RateLimited,
        AdminError::Internal,
    ]
    .iter()
    .map(|e| e.code().to_string())
    .collect();
    assert_eq!(
        enum_codes, actual_codes,
        "openapi error-code enum drifted from AdminError::code"
    );
}

/// REGRESSION (audit c1r12): the §6.3 escalation 403 fires on PUT `/hooks/{name}` and PATCH
/// `/hooks/{name}/settings` (a `hooks-register` principal touching a content-seeing / global
/// hook), exactly as it does on POST `/hooks` — so all three must DOCUMENT the 403.
#[cfg(feature = "openapi-schema")]
#[test]
fn openapi_hook_escalation_endpoints_document_403() {
    let doc = openapi_doc();
    let cases = [
        ("/api/v1/admin/hooks", "post"),
        ("/api/v1/admin/hooks/{name}", "put"),
        ("/api/v1/admin/hooks/{name}", "delete"),
        ("/api/v1/admin/hooks/{name}/settings", "patch"),
    ];
    for (path, method) in cases {
        assert!(
            doc["paths"][path][method]["responses"]["403"].is_object(),
            "{method} {path} can 403 on §6.3 escalation but its openapi omits it"
        );
    }
}

/// The committed static OpenAPI document the LIVE handler serves (via `include_str!`). The release
/// binary can't regenerate it (schemars is CI-only), so this path is what every build ships.
#[cfg(feature = "openapi-schema")]
const COMMITTED_OPENAPI_PATH: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/src/admin/v1/json/openapi.json"
);

/// Serialize the doc the way it is committed: pretty-printed + a trailing newline (POSIX text file).
#[cfg(feature = "openapi-schema")]
fn render_committed_openapi() -> String {
    format!(
        "{}\n",
        serde_json::to_string_pretty(&openapi_doc()).expect("serialize openapi doc")
    )
}

/// GOLDEN + DRIFT GUARD: the committed `openapi.json` (served live via `include_str!`) MUST equal the
/// document `openapi_doc()` generates right now. Run with `UPDATE_OPENAPI=1` to REGENERATE the file
/// (after an intentional contract change); otherwise this asserts byte-equality, so the static file
/// the release binary serves can never silently drift from the typed route contract in code.
#[cfg(feature = "openapi-schema")]
#[test]
fn openapi_json_matches_committed_file() {
    let fresh = render_committed_openapi();
    if std::env::var("UPDATE_OPENAPI").is_ok_and(|v| v == "1") {
        std::fs::write(COMMITTED_OPENAPI_PATH, &fresh)
            .unwrap_or_else(|e| panic!("write {COMMITTED_OPENAPI_PATH}: {e}"));
        return;
    }
    let committed = std::fs::read_to_string(COMMITTED_OPENAPI_PATH)
        .unwrap_or_else(|e| panic!("read {COMMITTED_OPENAPI_PATH}: {e}"));
    assert_eq!(
        committed, fresh,
        "committed openapi.json is stale — regenerate with `UPDATE_OPENAPI=1 cargo test -p busbar \
         --features openapi-schema openapi_json_matches_committed_file`"
    );
}

/// The static string the live handler serves must be BYTE-IDENTICAL to the committed file — i.e.
/// `include_str!` compiled in the same bytes the drift test checks. (Guards against, e.g., a stale
/// build cache serving an old embed.)
#[cfg(feature = "openapi-schema")]
#[test]
fn served_openapi_equals_committed_file() {
    let committed =
        std::fs::read_to_string(COMMITTED_OPENAPI_PATH).expect("read committed openapi");
    assert_eq!(super::OPENAPI_JSON, committed);
}

/// COVERAGE LOCK: 100% of operations carry a typed success-response BODY schema. Every operation
/// (each method under each path, excluding `x-*` path-item extensions) must have — for its success
/// status (204 No Content excepted — it has no body) — a `content.application/json.schema` that is a
/// `$ref` into `components.schemas`, and every referenced component must be defined. This is the
/// machine proof that no operation regressed to a bodyless `{"description":"OK"}`.
#[cfg(feature = "openapi-schema")]
#[test]
fn openapi_every_operation_has_a_typed_response_schema() {
    let doc = openapi_doc();
    let schemas = doc["components"]["schemas"].as_object().expect("schemas");
    let paths = doc["paths"].as_object().expect("paths");
    let mut op_count = 0usize;
    let mut with_body = 0usize;
    for (path, methods) in paths {
        for (method, op) in methods.as_object().expect("methods") {
            if method.starts_with("x-") {
                continue;
            }
            op_count += 1;
            let responses = op["responses"].as_object().expect("responses");
            // The success response: the single 2xx entry (200/201). 204 (No Content) has no body.
            let success = responses
                .keys()
                .find(|s| s.starts_with('2') && s.as_str() != "204");
            let Some(status) = success else {
                // A 204-only op (DELETE) legitimately has no success body.
                assert!(
                    responses.contains_key("204"),
                    "{method} {path} has no 2xx success response"
                );
                continue;
            };
            with_body += 1;
            let schema = &responses[status]["content"]["application/json"]["schema"];
            // The discovery endpoint (`GET /openapi.json`) returns an OpenAPI document — described by
            // an inline object schema, not a component `$ref` (no named struct, and modeling the
            // OpenAPI meta-schema would be circular). Every OTHER operation must be a `$ref`.
            if path.ends_with("/openapi.json") {
                assert_eq!(
                    schema["type"], "object",
                    "{method} {path} must at least declare an object body"
                );
                continue;
            }
            let reference = schema["$ref"]
                .as_str()
                .unwrap_or_else(|| panic!("{method} {path} {status} has no $ref response schema"));
            let name = reference
                .strip_prefix("#/components/schemas/")
                .unwrap_or_else(|| {
                    panic!("{method} {path} $ref is not a component ref: {reference}")
                });
            assert!(
                schemas.contains_key(name),
                "{method} {path} references undefined schema {name}"
            );
        }
    }
    // Sanity: the surface is ~34 operations; every non-204 op carries a body.
    assert!(op_count >= 30, "unexpectedly few operations: {op_count}");
    assert!(
        with_body >= 28,
        "too few operations with a response body: {with_body}/{op_count}"
    );
}
