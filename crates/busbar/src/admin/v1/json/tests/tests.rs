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

/// CONTRACT LOCK: every openapi path+method is annotated with `x-busbar-required-scope`, and
/// the annotation matches the enforced `required_scope` matrix exactly (one source of truth —
/// this test guards against a future hand-written path entry forgetting or contradicting it).
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
