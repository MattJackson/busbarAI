use super::*;
use axum::http::Method;

/// GOLDEN WIRE LITERALS: the mount constants pinned byte-for-byte. Everything else in the app
/// DERIVES paths from these constants (no hand-written absolute path anywhere) — so this pin is
/// the ONE place a path change must be made deliberately, and the tripwire that catches an
/// accidental edit sailing through the derived code.
#[test]
fn mount_constants_are_the_frozen_wire_literals() {
    assert_eq!(API_ROOT, "/api");
    assert_eq!(ADMIN_PREFIX, "/api/v1/admin");
    assert!(
        ADMIN_PREFIX.starts_with(API_ROOT),
        "the admin prefix hangs off the native-API root"
    );
}

/// The §1 authorization matrix, test-locked: reads are read-only, hook-definition mutations
/// are hooks-register, everything else (keys, config, auth, cache) is full. Unknown methods
/// fail closed to full.
#[test]
fn required_scope_matrix() {
    for path in [
        "/api/v1/admin/info",
        "/api/v1/admin/hooks",
        "/api/v1/admin/keys",
        "/api/v1/admin/config",
        "/api/v1/admin/audit",
    ] {
        assert_eq!(
            required_scope(&Method::GET, path),
            Scope::ReadOnly,
            "{path}"
        );
    }
    assert_eq!(
        required_scope(&Method::POST, "/api/v1/admin/hooks"),
        Scope::HooksRegister
    );
    assert_eq!(
        required_scope(&Method::DELETE, "/api/v1/admin/hooks/my-hook"),
        Scope::HooksRegister
    );
    assert_eq!(
        required_scope(&Method::PATCH, "/api/v1/admin/hooks/my-hook/settings"),
        Scope::HooksRegister
    );
    // A sibling path must not inherit the hooks scope (boundary-safe prefix).
    assert_eq!(
        required_scope(&Method::POST, "/api/v1/admin/hooksx"),
        Scope::Full
    );
    assert_eq!(
        required_scope(&Method::POST, "/api/v1/admin/keys"),
        Scope::Full
    );
    assert_eq!(
        required_scope(&Method::POST, "/api/v1/admin/config/apply"),
        Scope::Full
    );
    assert_eq!(
        required_scope(&Method::OPTIONS, "/api/v1/admin/hooks"),
        Scope::Full,
        "unknown methods fail closed"
    );
}

/// The scope ladder: read-only ⊂ hooks-register ⊂ full — and parse round-trips the tokens.
#[test]
fn scope_ladder_allows() {
    assert!(Scope::Full.allows(Scope::ReadOnly));
    assert!(Scope::Full.allows(Scope::HooksRegister));
    assert!(Scope::HooksRegister.allows(Scope::ReadOnly));
    assert!(!Scope::HooksRegister.allows(Scope::Full));
    assert!(!Scope::ReadOnly.allows(Scope::HooksRegister));
    assert!(Scope::parse("bogus").is_none());
    assert_eq!(Scope::parse("hooks-register"), Some(Scope::HooksRegister));
}

/// The stable error taxonomy is locked: each variant's `code` + HTTP status is the frozen wire
/// contract tooling branches on. A change here is a breaking change to v1 and must fail this test.
#[test]
fn admin_error_codes_and_statuses_are_frozen() {
    let cases = [
        (AdminError::NotFound("key".into()), "not_found", 404u16),
        (AdminError::Unauthorized, "unauthorized", 401),
        (AdminError::MethodNotAllowed, "method_not_allowed", 405),
        (
            AdminError::Forbidden {
                needed: Scope::Full,
            },
            "forbidden",
            403,
        ),
        (AdminError::Validation("bad".into()), "invalid_request", 400),
        (
            AdminError::VersionConflict("stale".into()),
            "version_conflict",
            409,
        ),
        (AdminError::Conflict("state".into()), "conflict", 409),
        (AdminError::RateLimited, "rate_limited", 429),
        (AdminError::Internal, "internal", 500),
    ];
    for (e, code, status) in cases {
        assert_eq!(e.code(), code, "frozen error code changed");
        assert_eq!(e.http_status(), status, "frozen error status changed");
    }
}
