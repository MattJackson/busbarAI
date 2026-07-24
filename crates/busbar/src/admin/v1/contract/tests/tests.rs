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
    // MINTING a key (POST /keys, the collection) is the delegated `mint` scope — NOT `full` and NOT
    // `hooks-register` (self-service D2). The auto-provision-on-mint leaf creation rides this same
    // request, so the whole mint path is `mint`.
    assert_eq!(
        required_scope(&Method::POST, "/api/v1/admin/keys"),
        Scope::Mint
    );
    // A sibling of /keys must NOT inherit the mint scope (boundary-safe exact match).
    assert_eq!(
        required_scope(&Method::POST, "/api/v1/admin/keysx"),
        Scope::Full
    );
    // Per-key lifecycle verbs are NOT mint — a self-service portal mints, it does not
    // revoke/rotate/rebind. These stay `full`.
    assert_eq!(
        required_scope(&Method::DELETE, "/api/v1/admin/keys/vk_123"),
        Scope::Full
    );
    assert_eq!(
        required_scope(&Method::PATCH, "/api/v1/admin/keys/vk_123"),
        Scope::Full
    );
    assert_eq!(
        required_scope(&Method::POST, "/api/v1/admin/keys/vk_123/rotate"),
        Scope::Full
    );
    assert_eq!(
        required_scope(&Method::POST, "/api/v1/admin/config/apply"),
        Scope::Full
    );
    // Group CRUD stays `full` (a mint token auto-provisions a leaf via POST /keys, but cannot
    // freely mutate arbitrary groups).
    assert_eq!(
        required_scope(&Method::POST, "/api/v1/admin/groups"),
        Scope::Full
    );
    assert_eq!(
        required_scope(&Method::OPTIONS, "/api/v1/admin/hooks"),
        Scope::Full,
        "unknown methods fail closed"
    );
}

/// The scope LATTICE (a diamond, not a chain): `ReadOnly` ⊂ {`HooksRegister`, `Mint`} ⊂ `Full`,
/// with `HooksRegister` and `Mint` as INCOMPARABLE SIBLINGS. `allows` must NOT be `>=`: the whole
/// point (self-service D2) is that a mint credential cannot register a hook and a hooks-register
/// credential cannot mint. Also: parse round-trips every token.
#[test]
fn scope_lattice_allows() {
    // Full is god-mode: satisfies every requirement.
    assert!(Scope::Full.allows(Scope::ReadOnly));
    assert!(Scope::Full.allows(Scope::HooksRegister));
    assert!(Scope::Full.allows(Scope::Mint));
    assert!(Scope::Full.allows(Scope::Full));

    // Every grant can read.
    assert!(Scope::ReadOnly.allows(Scope::ReadOnly));
    assert!(Scope::HooksRegister.allows(Scope::ReadOnly));
    assert!(Scope::Mint.allows(Scope::ReadOnly));

    // Each middle rung satisfies ONLY itself (plus read) — the sibling property.
    assert!(Scope::HooksRegister.allows(Scope::HooksRegister));
    assert!(Scope::Mint.allows(Scope::Mint));

    // THE CROSS-SIBLING PROHIBITION (the crux of D2): mint ⇏ hooks-register and vice versa. Under a
    // naive `self >= needed` ordinal these would leak (Mint outranks HooksRegister), so this is the
    // regression guard for the enumerated `allows`.
    assert!(
        !Scope::Mint.allows(Scope::HooksRegister),
        "a mint credential must NOT be able to register hooks"
    );
    assert!(
        !Scope::HooksRegister.allows(Scope::Mint),
        "a hooks-register credential must NOT be able to mint keys"
    );

    // Neither middle rung reaches full.
    assert!(!Scope::HooksRegister.allows(Scope::Full));
    assert!(!Scope::Mint.allows(Scope::Full));
    assert!(!Scope::ReadOnly.allows(Scope::HooksRegister));
    assert!(!Scope::ReadOnly.allows(Scope::Mint));
    assert!(!Scope::ReadOnly.allows(Scope::Full));

    // Token round-trips (incl. the new `mint` token and its wire spelling).
    assert!(Scope::parse("bogus").is_none());
    assert_eq!(Scope::parse("read-only"), Some(Scope::ReadOnly));
    assert_eq!(Scope::parse("hooks-register"), Some(Scope::HooksRegister));
    assert_eq!(Scope::parse("mint"), Some(Scope::Mint));
    assert_eq!(Scope::parse("full"), Some(Scope::Full));
    assert_eq!(Scope::Mint.as_str(), "mint");
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

/// F1 CONTRACT: the admin usage response ALWAYS serializes `currency: "USD"`, sourced from the
/// single `USAGE_CURRENCY` const (so a future removal is one line). Emitted ONLY on `UsageView`
/// (the `GET /api/v1/admin/usage` surface); the per-key/per-model ledger views stay
/// currency-agnostic. Regression: the audit/cost pass dropped this field, breaking the
/// contract + the committed openapi.json.
#[test]
fn usage_view_serializes_currency_from_const() {
    let view = UsageView {
        window: UsageWindow { start: 0, end: 1 },
        as_of: 0,
        currency: (),
        total: UsageBreakdown::default(),
        by_model: Vec::new(),
        by_key: Vec::new(),
        by_key_truncated: false,
        others: None,
    };
    let v: serde_json::Value = serde_json::to_value(&view).expect("serialize UsageView");
    assert_eq!(
        v.get("currency").and_then(|c| c.as_str()),
        Some(USAGE_CURRENCY),
        "usage response must carry the currency field from the USAGE_CURRENCY const"
    );
    assert_eq!(USAGE_CURRENCY, "USD");
    // The per-model / per-key ledger rows stay currency-agnostic (no currency key).
    let row = UsageBreakdown::default();
    let rv: serde_json::Value = serde_json::to_value(row).expect("serialize breakdown");
    assert!(
        rv.get("currency").is_none(),
        "the raw-split ledger breakdown must NOT carry a currency"
    );
}
