/// The re-key union semantics: pools union (`[]` = every pool), caps are most-permissive
/// (a granting group without a cap lifts it; otherwise max wins), and a principal whose
/// groups never set `allowed_pools` gets NO synthetic key (admin-only groups confer no
/// data-plane access).
#[test]
fn synthesize_principal_key_union_semantics() {
    use crate::config::GroupMapEntry;
    let mut gm = std::collections::HashMap::new();
    gm.insert(
        "a".to_string(),
        GroupMapEntry {
            allowed_pools: Some(vec!["p1".to_string()]),
            rpm_limit: Some(10),
            tpm_limit: Some(1000),
            max_budget_cents: Some(500),
            ..Default::default()
        },
    );
    gm.insert(
        "b".to_string(),
        GroupMapEntry {
            allowed_pools: Some(vec!["p2".to_string()]),
            rpm_limit: Some(60),
            // no tpm cap: lifts the axis entirely (most permissive)
            ..Default::default()
        },
    );
    gm.insert(
        "admin-only".to_string(),
        GroupMapEntry {
            admin_scope: Some("full".to_string()),
            ..Default::default()
        },
    );
    gm.insert(
        "all-pools".to_string(),
        GroupMapEntry {
            allowed_pools: Some(vec![]),
            ..Default::default()
        },
    );

    let mut p = crate::auth::Principal::from_id("test:u");
    p.groups = vec!["a".to_string(), "b".to_string()];
    let k = synthesize_principal_key(&p, &gm).expect("granting groups synthesize");
    assert_eq!(k.id, "test:u", "keyed by the principal id");
    let mut pools = k.allowed_pools.clone();
    pools.sort();
    assert_eq!(
        pools,
        vec!["p1".to_string(), "p2".to_string()],
        "pools union"
    );
    assert_eq!(k.rpm_limit, Some(60), "max rpm wins");
    assert_eq!(k.tpm_limit, None, "a capless granting group lifts the cap");
    assert_eq!(k.max_budget_cents, None, "same for budget");
    assert!(k.enabled);

    // An explicit [] on any granting group = every pool.
    p.groups = vec!["a".to_string(), "all-pools".to_string()];
    let k = synthesize_principal_key(&p, &gm).expect("granting");
    assert!(k.allowed_pools.is_empty(), "explicit [] grants every pool");

    // Admin-only groups (and unmapped ones) confer no data-plane key.
    p.groups = vec!["admin-only".to_string(), "unmapped".to_string()];
    assert!(
        synthesize_principal_key(&p, &gm).is_none(),
        "no allowed_pools grant = no synthetic key (fail closed)"
    );
    p.groups = vec![];
    assert!(synthesize_principal_key(&p, &gm).is_none());
}
use super::*;

fn sample_key(id: &str, hash: &str) -> VirtualKey {
    VirtualKey {
        id: id.to_string(),
        key_hash: hash.to_string(),
        name: "test-key".to_string(),
        allowed_pools: vec!["prod".to_string(), "cheap".to_string()],
        max_budget_cents: Some(5000),
        budget_period: BUDGET_PERIOD_MONTHLY.to_string(),
        rpm_limit: Some(60),
        tpm_limit: None,
        enabled: true,
        created_at: 1_700_000_000,
    }
}

/// H1: CONCURRENCY through the REAL admission wrapper. Unlike
/// `test_concurrent_charges_cannot_overshoot_cap` (which hits `Store::charge_within_budget`
/// directly and bypasses the `spawn_blocking` offload), this fires N concurrent tasks through
/// `GovState::try_charge_request_within_budget` on a SHARED `Arc<GovState>` — the exact async
/// admission entrypoint the route path calls. With a 1c flat fee and a 5c cap, exactly 5 of 20
/// concurrent admissions may land and final spend must be EXACTLY 5 (cap-respecting, no overshoot).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_concurrent_govstate_admission_respects_cap() {
    let store = Arc::new(MemoryStore::new());
    let gov = Arc::new(GovState::new(store.clone(), 1, 0, None).unwrap()); // 1c flat fee
    let (key, _s) = gov
        .create_key(
            NewKeySpec {
                name: "k".to_string(),
                allowed_pools: vec![],
                max_budget_cents: Some(5), // 5c cap → at most 5 one-cent admissions
                budget_period: BUDGET_PERIOD_TOTAL.to_string(),
                rpm_limit: None,
                tpm_limit: None,
            },
            1_700_000_000,
        )
        .unwrap();
    let at = 1_700_000_000u64;
    let mut handles = Vec::new();
    for _ in 0..20 {
        let gov = gov.clone();
        let key = key.clone();
        handles.push(tokio::spawn(async move {
            gov.try_charge_request_within_budget(&key, at)
        }));
    }
    let mut admitted = 0u32;
    for h in handles {
        if h.await.unwrap() {
            admitted += 1;
        }
    }
    assert_eq!(
        admitted, 5,
        "exactly 5 of 20 concurrent GovState admissions fit under a 5c/1c cap"
    );
    // The hard cap is enforced by the AUTHORITATIVE in-memory cell; flush it to the durable store
    // before asserting the persisted spend.
    gov.flush_budgets();
    assert_eq!(
        store.get_usage(&key.id, 0).unwrap().spend_cents,
        5,
        "final spend must be EXACTLY 5 — the in-memory admission path holds the hard cap, no overshoot"
    );
}

/// H2: the charge → refund → re-admit money cycle through `GovState`. Charge a key to its cap so the
/// next request is rejected; `refund_request` (fire-and-forget `offload_store_write`) reverses one
/// charge; after draining the blocking write a new request is admitted again. Proves a refunded fee
/// genuinely frees budget on the live admission path.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_charge_refund_readmit_cycle() {
    let store = Arc::new(MemoryStore::new());
    let gov = Arc::new(GovState::new(store.clone(), 1, 0, None).unwrap()); // 1c flat fee
    let (key, _s) = gov
        .create_key(
            NewKeySpec {
                name: "k".to_string(),
                allowed_pools: vec![],
                max_budget_cents: Some(1), // 1c cap → exactly one request fits
                budget_period: BUDGET_PERIOD_TOTAL.to_string(),
                rpm_limit: None,
                tpm_limit: None,
            },
            1_700_000_000,
        )
        .unwrap();
    let at = 1_700_000_000u64;
    // Charge to the cap.
    assert!(
        gov.try_charge_request_within_budget(&key, at),
        "1st (1c) admitted, spends the whole 1c cap"
    );
    // At cap → next request rejected.
    assert!(
        !gov.try_charge_request_within_budget(&key, at),
        "2nd rejected: budget is exhausted at the cap"
    );
    // Refund the charge (fire-and-forget offloaded write), then drain the blocking pool.
    gov.refund_request(&key, at);
    let mut spend = i64::MAX;
    for _ in 0..200 {
        tokio::task::yield_now().await;
        spend = store.get_usage(&key.id, 0).unwrap().spend_cents;
        if spend == 0 {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(1)).await;
    }
    assert_eq!(spend, 0, "refund must reverse the charge back to 0 spend");
    // Budget is free again → a new request is re-admitted.
    assert!(
        gov.try_charge_request_within_budget(&key, at),
        "post-refund request re-admitted: the refunded fee freed the budget"
    );
}

/// fix 2a wrapper: `try_charge_request_within_budget` charges the flat fee and rejects atomically
/// at the cap. 1c/request flat fee, 2c cap → 2 admitted, 3rd rejected.
#[tokio::test]
async fn test_try_charge_request_within_budget_rejects_at_cap() {
    let store = Arc::new(MemoryStore::new());
    let gov = GovState::new(store, 1, 0, None).unwrap(); // 1c flat fee
    let (key, _s) = gov
        .create_key(
            NewKeySpec {
                name: "k".to_string(),
                allowed_pools: vec![],
                max_budget_cents: Some(2),
                budget_period: BUDGET_PERIOD_TOTAL.to_string(),
                rpm_limit: None,
                tpm_limit: None,
            },
            1_700_000_000,
        )
        .unwrap();
    let at = 1_700_000_000u64;
    assert!(
        gov.try_charge_request_within_budget(&key, at),
        "1st (1c) admitted"
    );
    assert!(
        gov.try_charge_request_within_budget(&key, at),
        "2nd (2c) admitted"
    );
    assert!(
        !gov.try_charge_request_within_budget(&key, at),
        "3rd (would be 3c > 2c cap) rejected atomically"
    );
}

/// The metering series: `add_metering` UPSERTs per (key, bucket, model, provider) with the raw
/// token SPLIT preserved and +1 request per call; `list_metering` reads exactly one bucket; a
/// second bucket never bleeds in.
#[test]
fn test_metering_accumulates_split_per_key_model_and_bucket() {
    let s = MemoryStore::new();
    let day = metering_bucket(1_700_000_123); // mid-day epoch floors to its bucket start
    assert_eq!(day % METERING_BUCKET_SECS, 0);
    let d = |model: &str, input: u64, output: u64| MeteringDelta {
        key_id: "vk_a".into(),
        bucket: day,
        model: model.into(),
        provider: "openai".into(),
        tokens_input: input,
        tokens_output: output,
        tokens_cache_read: 7,
        tokens_cache_creation: 3,
    };
    // Two responses on the same (key, model) accumulate; a different model is its own row.
    s.add_metering(&d("gpt-x", 100, 20)).unwrap();
    s.add_metering(&d("gpt-x", 50, 10)).unwrap();
    s.add_metering(&d("gpt-y", 1, 2)).unwrap();
    // A different bucket must NOT appear in this bucket's read.
    s.add_metering(&MeteringDelta {
        bucket: day + METERING_BUCKET_SECS,
        ..d("gpt-x", 999, 999)
    })
    .unwrap();

    let mut rows = s.list_metering(day).unwrap();
    rows.sort_by(|a, b| a.model.cmp(&b.model));
    assert_eq!(rows.len(), 2, "two models in this bucket: {rows:?}");
    let x = &rows[0];
    assert_eq!((x.model.as_str(), x.provider.as_str()), ("gpt-x", "openai"));
    assert_eq!(
        (x.tokens_input, x.tokens_output, x.requests),
        (150, 30, 2),
        "raw split accumulates + one request per response"
    );
    assert_eq!(
        (x.tokens_cache_read, x.tokens_cache_creation),
        (14, 6),
        "cache reads/writes carry separately (they price differently)"
    );
    assert_eq!(rows[1].model, "gpt-y");
    assert_eq!(rows[1].requests, 1);
}

/// `GovState::record_metering` end-to-end (no tokio runtime → the offload runs inline): the
/// IrUsage split lands in the store under the request's day bucket; a `None` usage (flat-fee op)
/// still counts the request.
#[test]
fn test_record_metering_from_ir_usage_and_flat() {
    let store = Arc::new(MemoryStore::new());
    let gov = GovState::new(store, 0, 0, None).unwrap();
    let now = 1_700_000_500;
    let usage = crate::ir::IrUsage {
        input_tokens: 11,
        output_tokens: 22,
        cache_read_input_tokens: Some(5),
        cache_creation_input_tokens: None,
    };
    gov.record_metering("vk_m", "claude-z", "anthropic", Some(&usage), now);
    gov.record_metering("vk_m", "claude-z", "anthropic", None, now); // flat-fee op
    let rows = gov.metering_for(metering_bucket(now)).unwrap();
    assert_eq!(rows.len(), 1);
    let r = &rows[0];
    assert_eq!(
        (r.key_id.as_str(), r.model.as_str(), r.provider.as_str()),
        ("vk_m", "claude-z", "anthropic")
    );
    assert_eq!(
        (
            r.tokens_input,
            r.tokens_output,
            r.tokens_cache_read,
            r.tokens_cache_creation,
            r.requests
        ),
        (11, 22, 5, 0, 2),
        "split preserved; the flat-fee response still counted its request"
    );
}

#[test]
fn test_virtualkey_debug_redacts_key_hash() {
    // LOW #17 (SECURITY): VirtualKey's Debug must NOT print `key_hash` (the stored authenticator
    // for the key's secret). A derived Debug leaked it in plaintext; the manual impl prints
    // presence only. The hash value is deliberately distinctive so a substring check catches it.
    let mut k = sample_key("vk_dbg", "SECRET-key-hash-value-zzz");
    let dbg = format!("{k:?}");
    assert!(
        !dbg.contains("SECRET-key-hash-value-zzz"),
        "VirtualKey Debug leaked key_hash: {dbg}"
    );
    assert!(
        dbg.contains("<redacted; present>"),
        "VirtualKey Debug should mark key_hash present-but-redacted: {dbg}"
    );
    // Non-secret fields are still shown so the struct stays diagnosable.
    assert!(dbg.contains("vk_dbg"), "id must still appear: {dbg}");
    assert!(dbg.contains("test-key"), "name must still appear: {dbg}");

    // Redaction holds TRANSITIVELY through GovCtx (its derived Debug delegates to VirtualKey's).
    let ctx = GovCtx {
        key: Some(std::sync::Arc::new(k.clone())),
    };
    let ctx_dbg = format!("{ctx:?}");
    assert!(
        !ctx_dbg.contains("SECRET-key-hash-value-zzz"),
        "GovCtx Debug leaked the embedded key_hash: {ctx_dbg}"
    );

    // An empty hash is marked absent (defensive; the request path never builds such a key).
    k.key_hash = String::new();
    let dbg_empty = format!("{k:?}");
    assert!(
        dbg_empty.contains("<absent>"),
        "empty key_hash should read as absent: {dbg_empty}"
    );
}

#[test]
fn test_create_key_with_aws_issues_and_resolves_credential() {
    let store = Arc::new(MemoryStore::new());
    let gov = GovState::new(store, 0, 0, None).unwrap();
    let (key, _bearer, akid, secret) = gov
        .create_key_with_aws(
            NewKeySpec {
                name: "bedrock-key".to_string(),
                allowed_pools: vec!["prod".to_string()],
                max_budget_cents: Some(1000),
                budget_period: BUDGET_PERIOD_TOTAL.to_string(),
                rpm_limit: None,
                tpm_limit: None,
            },
            1_700_000_000,
        )
        .unwrap();
    // AccessKeyId is AKIA-prefixed, 20 chars; secret is 40 chars.
    assert!(akid.starts_with("AKIA"), "akid shape: {akid}"); // golden wire-contract literal (kept bare on purpose)
    assert_eq!(akid.len(), 20); // golden wire-contract literal (kept bare on purpose)
    assert_eq!(secret.len(), 40); // golden wire-contract literal (kept bare on purpose)
                                  // The AccessKeyId resolves to the SAME key + its secret.
    let entry = gov.lookup_by_access_key_id(&akid).expect("akid resolves");
    assert_eq!(entry.key.id, key.id);
    assert_eq!(entry.secret_access_key, secret);
    assert!(entry.key.enabled);
    // An unknown AccessKeyId resolves to None.
    assert!(gov
        .lookup_by_access_key_id("AKIAdoesnotexist0000")
        .is_none());
    // The bearer secret still resolves the key via the hash index too.
    assert_eq!(gov.lookup(&_bearer).unwrap().id, key.id);
}

/// Contract guard for the OS-CSPRNG-backed credential generators (`getrandom`). Pins the exact
/// wire shapes that downstream AWS SDKs and busbar's bearer scheme validate, so a future
/// `getrandom` major (or any change to these minting fns) that alters length, prefix, or charset
/// fails HERE with a clear cause — instead of surfacing later as a confusing auth rejection.
#[test]
fn test_credential_generators_contract() {
    // Bearer secret: `sk-bb-` prefix + 64 lowercase-hex chars (32 random bytes = 256-bit secret).
    let s = generate_secret().expect("OS entropy available");
    assert!(s.starts_with(SK_SECRET_PREFIX), "bearer prefix: {s}");
    let hex_part = &s[SK_SECRET_PREFIX.len()..];
    assert_eq!(hex_part.len(), 64, "32 random bytes -> 64 hex chars");
    assert!(
        hex_part
            .bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase()),
        "bearer body is lowercase hex: {hex_part}"
    );

    // AWS AccessKeyId: `AKIA` prefix + uppercase-alphanumeric body, fixed total length 20.
    let akid = generate_aws_access_key_id().expect("OS entropy available");
    assert_eq!(akid.len(), AWS_ACCESS_KEY_ID_LEN);
    assert!(
        akid.starts_with(AWS_ACCESS_KEY_PREFIX),
        "akid prefix: {akid}"
    );
    assert!(
        akid.bytes()
            .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit()),
        "akid is uppercase-alphanumeric: {akid}"
    );

    // AWS secret access key: fixed 40 chars (240 bits over a base64-ish alphabet).
    let sak = generate_aws_secret_access_key().expect("OS entropy available");
    assert_eq!(sak.len(), AWS_SECRET_ACCESS_KEY_LEN);

    // Each draw differs — proves the CSPRNG is actually read, not returning a constant.
    assert_ne!(generate_secret().unwrap(), s, "secrets must not repeat");
    assert_ne!(
        generate_aws_access_key_id().unwrap(),
        akid,
        "akids must not repeat"
    );
}

#[test]
fn test_aws_credential_persists_across_reload() {
    // A credential minted in one GovState must be visible to a fresh GovState over the same store
    // (durable + rebuilt into the AccessKeyId index at construction).
    let store: Arc<dyn Store> = Arc::new(MemoryStore::new());
    let akid = {
        let gov = GovState::new(store.clone(), 0, 0, None).unwrap();
        let (_k, _b, akid, _s) = gov
            .create_key_with_aws(
                NewKeySpec {
                    name: "k".to_string(),
                    allowed_pools: vec![],
                    max_budget_cents: None,
                    budget_period: BUDGET_PERIOD_TOTAL.to_string(),
                    rpm_limit: None,
                    tpm_limit: None,
                },
                0,
            )
            .unwrap();
        akid
    };
    let gov2 = GovState::new(store, 0, 0, None).unwrap();
    assert!(
        gov2.lookup_by_access_key_id(&akid).is_some(),
        "credential must survive a reload"
    );
}

#[test]
fn test_delete_key_removes_aws_credential() {
    // Revoking a key must remove its AWS credential so it can no longer authenticate via SigV4.
    let store = Arc::new(MemoryStore::new());
    let gov = GovState::new(store, 0, 0, None).unwrap();
    let (key, _b, akid, _s) = gov
        .create_key_with_aws(
            NewKeySpec {
                name: "k".to_string(),
                allowed_pools: vec![],
                max_budget_cents: None,
                budget_period: BUDGET_PERIOD_TOTAL.to_string(),
                rpm_limit: None,
                tpm_limit: None,
            },
            0,
        )
        .unwrap();
    assert!(gov.lookup_by_access_key_id(&akid).is_some());
    gov.delete_key(&key.id).unwrap();
    assert!(
        gov.lookup_by_access_key_id(&akid).is_none(),
        "a revoked key's AWS credential must be gone"
    );
    // And the durable credential row is gone too.
    assert!(gov.store().list_aws_credentials().unwrap().is_empty());
}

#[test]
fn test_refresh_updates_both_indices_atomically() {
    // LOW-1 invariant: a key minted WITH an AWS credential is resolvable through BOTH auth
    // indices (the hashed-bearer `by_hash` index AND the AccessKeyId `by_access_key_id` index),
    // and a `delete_key` (which calls `refresh`) clears it from BOTH in the same swap. This pins
    // the single-lock atomic refresh against a future split-lock regression where one index could
    // be updated without the other.
    let store = Arc::new(MemoryStore::new());
    let gov = GovState::new(store, 0, 0, None).unwrap();
    let (key, bearer, akid, _secret) = gov
        .create_key_with_aws(
            NewKeySpec {
                name: "dual-index-key".to_string(),
                allowed_pools: vec![],
                max_budget_cents: None,
                budget_period: BUDGET_PERIOD_TOTAL.to_string(),
                rpm_limit: None,
                tpm_limit: None,
            },
            1_700_000_000,
        )
        .unwrap();

    // Present in BOTH indices before deletion.
    assert_eq!(
        gov.lookup(&bearer).map(|k| k.id.clone()),
        Some(key.id.clone()),
        "bearer must resolve via by_hash before delete"
    );
    assert_eq!(
        gov.lookup_by_access_key_id(&akid).map(|e| e.key.id),
        Some(key.id.clone()),
        "akid must resolve via by_access_key_id before delete"
    );

    // delete_key -> refresh swaps both indices under the single caches lock.
    gov.delete_key(&key.id).unwrap();

    // Absent from BOTH indices after deletion — neither lags the other.
    assert!(
        gov.lookup(&bearer).is_none(),
        "bearer must be gone from by_hash after delete"
    );
    assert!(
        gov.lookup_by_access_key_id(&akid).is_none(),
        "akid must be gone from by_access_key_id after delete"
    );
}

#[test]
fn test_aws_credential_debug_redacts_secret() {
    // The symmetric SigV4 secret must NEVER appear in Debug output (AwsCredential or AwsKeyEntry).
    let cred = AwsCredential {
        access_key_id: "AKIAPUBLIC1234567890".to_string(),
        key_id: "vk_x".to_string(),
        secret_access_key: "SUPER-SECRET-SIGNING-KEY-zzz".to_string(),
    };
    let dbg = format!("{cred:?}");
    assert!(
        !dbg.contains("SUPER-SECRET-SIGNING-KEY-zzz"),
        "AwsCredential Debug leaked the secret: {dbg}"
    );
    assert!(dbg.contains("<redacted; present>"));
    assert!(dbg.contains("AKIAPUBLIC1234567890"), "akid is not secret");

    let entry = AwsKeyEntry {
        key: sample_key("vk_x", "hash"),
        secret_access_key: "SUPER-SECRET-SIGNING-KEY-zzz".to_string(),
    };
    let edbg = format!("{entry:?}");
    assert!(
        !edbg.contains("SUPER-SECRET-SIGNING-KEY-zzz"),
        "AwsKeyEntry Debug leaked the secret: {edbg}"
    );
}

#[test]
fn test_generated_aws_credentials_are_distinct() {
    // Two mints must produce distinct AccessKeyIds and secrets (CSPRNG-sourced, not constant).
    let store = Arc::new(MemoryStore::new());
    let gov = GovState::new(store, 0, 0, None).unwrap();
    let mk = |gov: &GovState, n: &str| {
        gov.create_key_with_aws(
            NewKeySpec {
                name: n.to_string(),
                allowed_pools: vec![],
                max_budget_cents: None,
                budget_period: BUDGET_PERIOD_TOTAL.to_string(),
                rpm_limit: None,
                tpm_limit: None,
            },
            0,
        )
        .unwrap()
    };
    let (_k1, _b1, akid1, s1) = mk(&gov, "a");
    let (_k2, _b2, akid2, s2) = mk(&gov, "b");
    assert_ne!(akid1, akid2);
    assert_ne!(s1, s2);
}

#[test]
fn test_govstate_lookup_pool_allowed_refresh() {
    let store = Arc::new(MemoryStore::new());
    let secret = "sk-vk-abc";
    let mut k = sample_key("k1", &crate::sigv4::sha256_hex(secret.as_bytes()));
    k.allowed_pools = vec!["prod".to_string()];
    store.put_key(&k).unwrap();

    let gov = GovState::new(store, 1, 0, None).unwrap();
    // hashed-secret lookup hits the cache.
    assert_eq!(gov.lookup(secret).unwrap().id, "k1");
    assert!(gov.lookup("wrong-secret").is_none());

    let resolved = gov.lookup(secret).unwrap();
    assert!(pool_allowed(&resolved, "prod"));
    assert!(!pool_allowed(&resolved, "other"));

    // A key added after construction isn't visible until refresh().
    let secret2 = "sk-vk-def";
    let mut k2 = sample_key("k2", &crate::sigv4::sha256_hex(secret2.as_bytes()));
    k2.allowed_pools = vec![]; // empty = all pools
    gov.store().put_key(&k2).unwrap();
    assert!(gov.lookup(secret2).is_none(), "not cached pre-refresh");
    gov.refresh().unwrap();
    let r2 = gov.lookup(secret2).unwrap();
    assert!(pool_allowed(&r2, "anything"), "empty allowed_pools = all");
}

#[test]
fn test_budget_window_periods() {
    assert_eq!(budget_window(BUDGET_PERIOD_TOTAL, 1_700_000_000), 0);
    assert_eq!(budget_window("unknown", 1_700_000_000), 0);
    assert_eq!(
        budget_window(BUDGET_PERIOD_DAILY, 1_700_000_000),
        1_699_920_000
    );
    // 1700000000 = 2023-11-14 → 2023-11-01 00:00Z = 1698796800.
    assert_eq!(
        budget_window(BUDGET_PERIOD_MONTHLY, 1_700_000_000),
        1_698_796_800
    );
}

/// LEGACY / NON-PRODUCTION PATH. This exercises the deprecated, non-atomic read-then-write pair
/// `is_over_budget` then `record_request`. That pair is NO LONGER on the admission path; the live
/// request path charges atomically via `GovState::try_charge_request_within_budget` and
/// `Store::charge_within_budget` — see `test_concurrent_charges_cannot_overshoot_cap` and
/// `test_concurrent_govstate_admission_respects_cap`. This test covers only the still-present
/// tests-plus-token-reconciliation API surface of the old pair; it does NOT imply the live hard-cap
/// path is covered. Renamed with a `legacy_` prefix to make that explicit.
#[test]
fn legacy_test_is_over_budget_and_record() {
    let store = Arc::new(MemoryStore::new());
    let mut k = sample_key("k1", "h1");
    k.max_budget_cents = Some(100);
    k.budget_period = BUDGET_PERIOD_TOTAL.to_string();
    store.put_key(&k).unwrap();
    let gov = GovState::new(store, 30, 0, None).unwrap(); // 30 cents/request

    // `record_request` now charges the AUTHORITATIVE in-memory cell (write-behind); `is_over_budget`
    // reads the DURABLE store, so flush the cell before each read to reflect the accrued spend.
    assert!(!gov.is_over_budget(&k, 1_700_000_000));
    for _ in 0..3 {
        gov.record_request(&k, 1_700_000_000, 0); // 90c < 100c
    }
    gov.flush_budgets();
    assert!(!gov.is_over_budget(&k, 1_700_000_000));
    gov.record_request(&k, 1_700_000_000, 0); // 120c ≥ 100c
    gov.flush_budgets();
    assert!(gov.is_over_budget(&k, 1_700_000_000));

    let mut unlimited = k.clone();
    unlimited.max_budget_cents = None;
    assert!(!gov.is_over_budget(&unlimited, 1_700_000_000));
}

#[test]
fn test_record_tokens_cost() {
    let store = Arc::new(MemoryStore::new());
    // 50 cents per 1000 tokens, no per-request fee.
    let gov = GovState::new(store.clone(), 0, 50, None).unwrap();
    gov.record_tokens("k1", BUDGET_PERIOD_TOTAL, 1_700_000_000, 2000); // 2000 * 50 / 1000 = 100 cents
                                                                       // record_tokens now accrues to the AUTHORITATIVE in-memory cell (write-behind); flush it to the
                                                                       // durable store before asserting the persisted counter.
    gov.flush_budgets();
    let u = store.get_usage("k1", 0).unwrap();
    assert_eq!(u.spend_cents, 100);
    assert_eq!(u.tokens, 2000);
}

/// Regression (sub-cent truncation): a request whose token cost is < 1 cent must NOT be
/// zero-billed and lost. With 1¢/1k pricing a 500-token request costs 0.5¢ — pure integer-cent
/// math truncated that to 0 forever. The millicent carry accrues it, so two such requests
/// accumulate to a whole cent. (No runtime → `offload_store_write` runs the write inline.)
#[test]
fn test_record_tokens_sub_cent_carry_accumulates() {
    let store = Arc::new(MemoryStore::new());
    let gov = GovState::new(store.clone(), 0, 1, None).unwrap(); // 1¢ per 1000 tokens

    gov.record_tokens("k1", BUDGET_PERIOD_TOTAL, 1_700_000_000, 500); // 0.5¢ → carried, flush 0
    gov.flush_budgets(); // drain the write-behind cell to the durable store before asserting
    let u1 = store.get_usage("k1", 0).unwrap();
    assert_eq!(
        u1.spend_cents, 0,
        "first sub-cent request flushes 0 cents (remainder carried)"
    );
    assert_eq!(u1.tokens, 500, "but the token COUNT is still recorded");

    gov.record_tokens("k1", BUDGET_PERIOD_TOTAL, 1_700_000_000, 500); // +0.5¢ → 1.0¢ crosses, flush 1
    gov.flush_budgets();
    let u2 = store.get_usage("k1", 0).unwrap();
    assert_eq!(
        u2.spend_cents, 1,
        "two 0.5¢ requests accrue a whole cent — no truncation loss"
    );
    assert_eq!(u2.tokens, 1000);
}

/// Regression (sub-cent carry must NOT leak across budget windows): the remainder is keyed to the
/// window it was generated in and reset on rollover, so a 0.5¢ remainder from one daily window is
/// NOT flushed into the next day's spend. Without the window-reset both 0.5¢ requests would key the
/// same per-key carry and the day-2 request would flush 1¢ that belonged to day 1.
#[test]
fn test_sub_cent_carry_does_not_leak_across_budget_windows() {
    let store = Arc::new(MemoryStore::new());
    let gov = GovState::new(store.clone(), 0, 1, None).unwrap(); // 1¢ per 1000 tokens
    let day1 = 1_700_000_000;
    let day2 = day1 + 86_400; // one day later → a different "daily" window
    let w1 = budget_window(BUDGET_PERIOD_DAILY, day1);
    let w2 = budget_window(BUDGET_PERIOD_DAILY, day2);
    assert_ne!(
        w1, w2,
        "the two timestamps must fall in different daily windows"
    );

    gov.record_tokens("k1", BUDGET_PERIOD_DAILY, day1, 500); // 0.5¢ in window 1 → carried, flush 0
    gov.flush_budgets(); // persist the day-1 cell before it rolls over to day 2
    assert_eq!(store.get_usage("k1", w1).unwrap().spend_cents, 0);

    gov.record_tokens("k1", BUDGET_PERIOD_DAILY, day2, 500); // 0.5¢ in window 2: the day-1 remainder is reset
    gov.flush_budgets(); // persist the (rolled-over) day-2 cell
    assert_eq!(
        store.get_usage("k1", w2).unwrap().spend_cents,
        0,
        "day-2 window must NOT inherit day-1's sub-cent remainder (no cross-window leak)"
    );
    assert_eq!(store.get_usage("k1", w2).unwrap().tokens, 500);
}

/// Token-charge write-behind UNDER a real Tokio runtime: `record_tokens` now accrues to the
/// AUTHORITATIVE in-memory cell (no store round-trip), and the durable counter is updated by the
/// write-behind flusher. This runs `record_tokens` inside a multi-thread runtime, then invokes
/// `flush_budgets` (the flusher's per-tick body) and asserts the persisted counter reflects the
/// token cost. Pins the `record_tokens → in-memory cell → flush_budgets → put_usage` path.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_record_tokens_offload_under_runtime() {
    let store = Arc::new(MemoryStore::new());
    // 50 cents per 1000 tokens, no per-request fee.
    let gov = GovState::new(store.clone(), 0, 50, None).unwrap();
    // 2000 tokens * 50c / 1000 = 100c. Accrued in memory; not yet persisted.
    gov.record_tokens("k1", BUDGET_PERIOD_TOTAL, 1_700_000_000, 2000);
    assert_eq!(
        store.get_usage("k1", 0).unwrap().spend_cents,
        0,
        "write-behind: the durable counter is untouched until a flush"
    );
    // Flush the dirty cell to the durable store (the flusher's per-tick body).
    assert_eq!(gov.flush_budgets(), 1, "one dirty cell flushed");
    let u = store.get_usage("k1", 0).unwrap();
    assert_eq!(
        u.spend_cents, 100,
        "2000 tokens at 50c/1k must spend exactly 100c after the flush"
    );
    assert_eq!(
        u.tokens, 2000,
        "raw token count must be recorded for TPM accounting"
    );
}

#[test]
fn test_check_rate_rpm_window() {
    let store = Arc::new(MemoryStore::new());
    let gov = GovState::new(store, 1, 0, None).unwrap();
    let mut k = sample_key("k1", "h1");
    k.rpm_limit = Some(2);
    k.tpm_limit = None;
    let now = 1_700_000_040; // mid-window

    assert!(gov.check_rate(&k, now).is_ok(), "1st request");
    assert!(gov.check_rate(&k, now).is_ok(), "2nd request");
    let retry = gov.check_rate(&k, now).unwrap_err();
    assert!((1..=60).contains(&retry), "3rd → 429 with retry {retry}");
    // Next 60s window resets the counter.
    assert!(
        gov.check_rate(&k, now + 60).is_ok(),
        "new window admits again"
    );

    // A key with no RPM/TPM cap is never rate-limited.
    let mut unl = sample_key("k2", "h2");
    unl.rpm_limit = None;
    unl.tpm_limit = None;
    for _ in 0..100 {
        assert!(gov.check_rate(&unl, now).is_ok());
    }
}

/// `rate_headroom` (routing `usage` signal): pure observation of the per-key RPM/TPM budget
/// remaining this window, as a `[0,1]` fraction. `None` when neither limit is set; never mutates
/// the window; clamps an over-budget window to `0.0`; takes the MIN of RPM/TPM when both are set.
#[test]
fn test_rate_headroom_reports_fraction_remaining() {
    let store = Arc::new(MemoryStore::new());
    let gov = GovState::new(store, 0, 0, None).unwrap();
    let now = 1_700_000_040; // mid-window

    // No limits → no headroom signal.
    let mut unl = sample_key("ku", "hu");
    unl.rpm_limit = None;
    unl.tpm_limit = None;
    assert_eq!(gov.rate_headroom(&unl, now), None);

    // RPM=0: a fully-closed limit. The code guards the divide-by-zero (rpm==0 → no headroom);
    // assert 0.0 rather than a panic, so a future removal of that guard is caught here.
    let mut kz = sample_key("kz", "hz");
    kz.rpm_limit = Some(0);
    kz.tpm_limit = None;
    assert_eq!(
        gov.rate_headroom(&kz, now),
        Some(0.0),
        "rpm=0 is fully closed → 0.0 headroom, not a divide-by-zero panic"
    );

    // RPM=4: fresh window is fully available (1.0). Observation must NOT consume budget.
    let mut k = sample_key("k1", "h1");
    k.rpm_limit = Some(4);
    k.tpm_limit = None;
    assert_eq!(gov.rate_headroom(&k, now), Some(1.0));
    assert_eq!(
        gov.rate_headroom(&k, now),
        Some(1.0),
        "rate_headroom is read-only; repeated reads must not drain the window"
    );

    // Consume 1 of 4 via the admission path → 3/4 headroom = 0.75.
    assert!(gov.check_rate(&k, now).is_ok());
    let h = gov.rate_headroom(&k, now).unwrap();
    assert!((h - 0.75).abs() < 1e-9, "expected 0.75 headroom, got {h}");

    // Both RPM and TPM set: headroom is the tighter (min). Drive RPM to the cap → 0.0, clamped.
    let mut kb = sample_key("k2", "h2");
    kb.rpm_limit = Some(2);
    kb.tpm_limit = Some(100_000); // very loose; RPM governs
    let w = 1_700_000_100;
    assert!(gov.check_rate(&kb, w).is_ok());
    assert!(gov.check_rate(&kb, w).is_ok());
    // RPM now at 2/2 used → 0.0 headroom (min with the loose TPM).
    let hb = gov.rate_headroom(&kb, w).unwrap();
    assert!(
        hb.abs() < 1e-9,
        "RPM at cap must yield 0.0 headroom, got {hb}"
    );
}

#[test]
fn test_tpm_enforced_against_accrued_tokens_same_window() {
    // TPM is enforced against tokens from completed requests in the current window.
    let store = Arc::new(MemoryStore::new());
    let gov = GovState::new(store, 0, 0, None).unwrap();
    let mut k = sample_key("k1", "h1");
    k.rpm_limit = None;
    k.tpm_limit = Some(1000);
    let now = 1_700_000_040; // mid-window

    // First request admitted (window token counter starts at 0).
    assert!(
        gov.check_rate(&k, now).is_ok(),
        "first request admits regardless of TPM"
    );
    // Its response completes in the same window and accrues 1000 tokens (>= the cap).
    gov.record_tokens("k1", BUDGET_PERIOD_TOTAL, now, 1000);
    // Next request in the same window is now rejected on TPM.
    let retry = gov.check_rate(&k, now + 1).unwrap_err();
    assert!(
        (1..=60).contains(&retry),
        "TPM exceeded → 429, retry {retry}"
    );
}

#[test]
fn test_add_rate_tokens_straddling_request_credits_live_window_not_dropped() {
    // MED #6 regression. Production feeds `add_rate_tokens` the request's pinned `charged_at` (the
    // window it STARTED in), not a fresh completion clock. A request that straddles a 60s boundary
    // is admitted in its start window W0, but a LATER admission for the same key rolls the live
    // entry forward to W1 before this request's (streamed) response completes. The credit then
    // arrives carrying `charged_at` in W0 while the live entry is in W1.
    //
    // The old code took `window (W0) < st.window_start (W1)` and either DROPPED the credit or
    // reinitialised the entry back to W0 — wiping the live W1 counter. Either way the straddling
    // request escaped TPM. The fix credits the entry's LIVE (W1) window in place, so the tokens
    // count against the key's currently-live TPM budget.
    let store = Arc::new(MemoryStore::new());
    let gov = GovState::new(store, 0, 0, None).unwrap();
    let mut k = sample_key("k1", "h1");
    k.rpm_limit = Some(10);
    k.tpm_limit = Some(500);
    let w0 = 1_700_000_040 / 60 * 60; // a window boundary
    let w1 = w0 + RATE_WINDOW_SECS; // the next window

    // The straddling request is admitted in W0 (creates a W0 entry).
    assert!(gov.check_rate(&k, w0).is_ok());
    // A later request for the same key lands in W1 and rolls the live entry forward to W1.
    assert!(gov.check_rate(&k, w1).is_ok());
    // The straddling request's response completes; its credit carries the pinned `charged_at` in
    // W0 (older than the live W1 entry). It must land on the LIVE W1 window, not be dropped.
    gov.record_tokens("k1", BUDGET_PERIOD_TOTAL, w0, 400);
    gov.record_tokens("k1", BUDGET_PERIOD_TOTAL, w0, 200); // 600 >= 500 against the live W1 budget
    let retry = gov.check_rate(&k, w1 + 1).unwrap_err();
    assert!(
        (1..=60).contains(&retry),
        "straddling request's tokens enforce TPM in the live window, not dropped"
    );
}

#[test]
fn test_add_rate_tokens_reinitialises_a_genuinely_stale_entry() {
    // The complement of the straddle case: when the credit's start-window is strictly NEWER than
    // the entry's window, the entry is genuinely stale (an old window the amortized sweep has not
    // yet evicted). It must be reinitialised to the new window before crediting, so a stale entry
    // never carries its old counts forward.
    let store = Arc::new(MemoryStore::new());
    let gov = GovState::new(store, 0, 0, None).unwrap();
    let mut k = sample_key("k1", "h1");
    k.rpm_limit = Some(10);
    k.tpm_limit = Some(100);
    let w0 = 1_700_000_040 / 60 * 60;
    let w1 = w0 + RATE_WINDOW_SECS;

    // Seed a stale W0 entry directly (simulating an entry the sweep has not yet evicted), then
    // credit with a NEWER start window W1.
    {
        let mut map = gov.rate.write().unwrap_or_else(|p| p.into_inner());
        map.insert(
            "k1".to_string(),
            RateState {
                window_start: w0,
                requests: 5,
                tokens: 999,
            },
        );
    }
    gov.record_tokens("k1", BUDGET_PERIOD_TOTAL, w1, 40);
    let map = gov.rate.read().unwrap_or_else(|p| p.into_inner());
    let st = map.get("k1").expect("entry exists");
    assert_eq!(
        st.window_start, w1,
        "stale entry reinitialised to the new window"
    );
    assert_eq!(st.requests, 0, "stale request count cleared");
    assert_eq!(st.tokens, 40, "only the new window's tokens are credited");
}

#[test]
fn test_check_rate_fast_path_reuses_entry_no_double_reset() {
    // The get_mut fast path must not reset an existing current-window entry (which would drop
    // the request count and break RPM). Two requests in the same window must both count.
    let store = Arc::new(MemoryStore::new());
    let gov = GovState::new(store, 0, 0, None).unwrap();
    let mut k = sample_key("k1", "h1");
    k.rpm_limit = Some(2);
    k.tpm_limit = None;
    let now = 1_700_000_040;
    assert!(gov.check_rate(&k, now).is_ok());
    assert!(gov.check_rate(&k, now).is_ok());
    assert!(
        gov.check_rate(&k, now).is_err(),
        "RPM=2 → third rejected (entry reused, not reset)"
    );
}

#[test]
fn test_check_rate_resets_stale_entry_without_eager_sweep() {
    // Regression for the amortized-sweep change: a key whose entry belongs to an OLDER window
    // must have its counters reset on its next admission EVEN IF the global eviction sweep did
    // not run this call. Previously the per-call `retain` guaranteed a fresh entry; now the
    // per-key reset in `check_rate` must do it. We exhaust RPM in W0, then advance a full window
    // and confirm the key is admitted again (stale W0 counts must not carry forward).
    let store = Arc::new(MemoryStore::new());
    let gov = GovState::new(store, 0, 0, None).unwrap();
    let mut k = sample_key("k1", "h1");
    k.rpm_limit = Some(1);
    k.tpm_limit = None;
    let w0 = 1_700_000_040 / 60 * 60;

    // Burn the single W0 slot; a second W0 request is rejected.
    assert!(gov.check_rate(&k, w0).is_ok(), "W0 first admits");
    assert!(
        gov.check_rate(&k, w0).is_err(),
        "W0 second rejected (RPM=1)"
    );

    // Force the sweep ticker so the eager retain does NOT run on the next call — proving the
    // per-key reset (not the sweep) is what clears the stale W0 entry. The sweep test is now
    // POST-increment: a call fires the sweep when the value AFTER its increment is a multiple of
    // N. Set the ticker to 1 so the next call's post-increment value is 2, which is not a
    // multiple of N.
    gov.rate_sweep_ticker.store(1, Ordering::Relaxed);
    assert!(
        !2u32.is_multiple_of(RATE_SWEEP_INTERVAL),
        "test precondition: next call's post-increment value must skip the eager sweep"
    );

    // A request a full window later must be admitted: the stale W0 entry is reset in place.
    let w1 = w0 + RATE_WINDOW_SECS;
    assert!(
        gov.check_rate(&k, w1).is_ok(),
        "new window admits again despite no eager sweep (per-key stale reset)"
    );
    // And the reset took the count back to zero, so W1's own RPM=1 is re-enforced.
    assert!(
        gov.check_rate(&k, w1).is_err(),
        "W1 second rejected — counter reset to 0, not carried from W0"
    );
}

#[test]
fn test_check_rate_sweep_evicts_silent_keys_to_bound_map() {
    // The amortized sweep must still evict entries for keys that have gone silent in older
    // windows, so the map stays bounded. We seed many distinct keys in W0, then trigger a sweep
    // on a later window and confirm the stale entries are gone.
    let store = Arc::new(MemoryStore::new());
    let gov = GovState::new(store, 0, 0, None).unwrap();
    let w0 = 1_700_000_040 / 60 * 60;

    for i in 0..10 {
        let mut k = sample_key(&format!("k{i}"), &format!("h{i}"));
        k.rpm_limit = Some(5);
        k.tpm_limit = None;
        assert!(gov.check_rate(&k, w0).is_ok());
    }
    assert_eq!(
        gov.rate.read().unwrap_or_else(|p| p.into_inner()).len(),
        10,
        "10 W0 entries present"
    );

    // Force the next call to run the eager sweep. POST-increment: the sweep fires when the value
    // AFTER the increment is a multiple of N, so set the ticker to N-1 (the next call's
    // post-increment value is N, a multiple of the interval).
    gov.rate_sweep_ticker
        .store(RATE_SWEEP_INTERVAL - 1, Ordering::Relaxed);
    let mut survivor = sample_key("survivor", "hs");
    survivor.rpm_limit = Some(5);
    survivor.tpm_limit = None;
    let w_later = w0 + RATE_WINDOW_SECS * 2;
    assert!(gov.check_rate(&survivor, w_later).is_ok());

    let map = gov.rate.read().unwrap_or_else(|p| p.into_inner());
    assert_eq!(
        map.len(),
        1,
        "sweep evicted all 10 stale W0 entries, leaving only the current-window survivor"
    );
    assert!(map.contains_key("survivor"));
}

#[test]
fn test_check_rate_sweep_cadence_post_increment_no_off_by_one() {
    // Regression for the sweep-cadence off-by-one. The sweep must use POST-increment semantics:
    //  - It must NOT fire on the very first call (ticker starts at 0; the pre-increment value 0
    //    is a multiple of N, but the post-increment value 1 is not), so startup against an empty
    //    map does no wasted scan.
    //  - It must fire on calls N, 2N, 3N, ...
    //  - The u32 wrap boundary must NOT skip a cycle: when the pre-increment value is 0xFFFFFFFF
    //    (not a multiple of N), the post-increment value wraps to 0 (a multiple of N) and the
    //    sweep still fires.
    let store = Arc::new(MemoryStore::new());
    let gov = GovState::new(store, 0, 0, None).unwrap();
    let mut k = sample_key("k1", "h1");
    k.rpm_limit = Some(1_000_000);
    k.tpm_limit = None;
    let w0 = 1_700_000_040 / 60 * 60;

    // Seed a STALE entry under an older window so a sweep would evict it. Use a distinct key so
    // we can observe whether the sweep ran by whether the stale entry survives.
    {
        let mut map = gov.rate.write().unwrap_or_else(|p| p.into_inner());
        map.insert(
            "stale".to_string(),
            RateState {
                window_start: w0 - RATE_WINDOW_SECS,
                requests: 0,
                tokens: 0,
            },
        );
    }

    // FIRST call: ticker is 0, post-increment value is 1 (not a multiple of N) -> NO sweep.
    // The stale entry must survive.
    assert_eq!(gov.rate_sweep_ticker.load(Ordering::Relaxed), 0);
    assert!(gov.check_rate(&k, w0).is_ok());
    assert!(
        gov.rate
            .read()
            .unwrap_or_else(|p| p.into_inner())
            .contains_key("stale"),
        "first call must NOT sweep (post-increment value 1 is not a multiple of N)"
    );

    // Drive the ticker to N-1 so the next call's post-increment value is exactly N -> sweep runs.
    gov.rate_sweep_ticker
        .store(RATE_SWEEP_INTERVAL - 1, Ordering::Relaxed);
    assert!(gov.check_rate(&k, w0).is_ok());
    assert!(
        !gov.rate
            .read()
            .unwrap_or_else(|p| p.into_inner())
            .contains_key("stale"),
        "call N must run the sweep and evict the stale entry"
    );

    // WRAP boundary: pre-increment value 0xFFFFFFFF is NOT a multiple of N, but post-increment
    // wraps to 0 (a multiple of N) so the sweep must still fire — no skipped cycle.
    {
        let mut map = gov.rate.write().unwrap_or_else(|p| p.into_inner());
        map.insert(
            "stale2".to_string(),
            RateState {
                window_start: w0 - RATE_WINDOW_SECS,
                requests: 0,
                tokens: 0,
            },
        );
    }
    gov.rate_sweep_ticker.store(u32::MAX, Ordering::Relaxed);
    assert!(gov.check_rate(&k, w0).is_ok());
    assert_eq!(
        gov.rate_sweep_ticker.load(Ordering::Relaxed),
        0,
        "ticker wrapped to 0"
    );
    assert!(
        !gov.rate
            .read()
            .unwrap_or_else(|p| p.into_inner())
            .contains_key("stale2"),
        "wrap boundary must still sweep (post-increment 0 is a multiple of N) — no skipped cycle"
    );
}

#[tokio::test]
async fn test_record_request_offloaded_charges_under_runtime() {
    // Inside a Tokio runtime, record_request now charges the AUTHORITATIVE in-memory cell (no store
    // round-trip); the write-behind flusher persists it. The charge must land in memory immediately
    // and reach the durable store after a flush.
    let store = Arc::new(MemoryStore::new());
    let mut k = sample_key("k1", "h1");
    k.max_budget_cents = Some(1000);
    k.budget_period = BUDGET_PERIOD_TOTAL.to_string();
    let gov = GovState::new(store.clone(), 30, 0, None).unwrap();

    gov.record_request(&k, 1_700_000_000, 0);
    assert_eq!(
        store.get_usage("k1", 0).unwrap().spend_cents,
        0,
        "write-behind: durable counter untouched until a flush"
    );
    assert_eq!(gov.flush_budgets(), 1, "one dirty cell flushed");
    assert_eq!(
        store.get_usage("k1", 0).unwrap().spend_cents,
        30,
        "record_request must charge the per-request fee (visible after flush)"
    );

    // And the async budget gate observes it (30 < 1000 → not over).
    assert!(!gov.is_over_budget_async(&k, 1_700_000_000).await);
}

#[test]
fn test_record_request_clamps_negative_per_request_price() {
    // A negative per-request price must NOT decrement accrued spend (which would drive spend
    // below zero and defeat the budget cap). The fee is clamped at >= 0, symmetric with the
    // per-1k-token price clamp in record_tokens.
    let store = Arc::new(MemoryStore::new());
    let mut k = sample_key("k1", "h1");
    k.max_budget_cents = Some(100);
    k.budget_period = BUDGET_PERIOD_TOTAL.to_string();
    let gov = GovState::new(store.clone(), -50, 0, None).unwrap(); // hostile negative price

    for _ in 0..5 {
        gov.record_request(&k, 1_700_000_000, 0);
    }
    gov.flush_budgets(); // persist the write-behind cell before asserting the durable counter
    let u = store.get_usage("k1", 0).unwrap();
    assert_eq!(
        u.spend_cents, 0,
        "negative per-request price must clamp to 0, never decrement spend"
    );
    assert_eq!(u.requests, 5, "requests are still counted");
    // Spend can never be driven below zero to evade the cap.
    assert!(!gov.is_over_budget(&k, 1_700_000_000));
}

#[test]
fn test_record_tokens_clamps_negative_per_1k_price() {
    // Mirror assertion for the token-price path (already clamped pre-fix; lock it in).
    let store = Arc::new(MemoryStore::new());
    let gov = GovState::new(store.clone(), 0, -100, None).unwrap();
    gov.record_tokens("k1", BUDGET_PERIOD_TOTAL, 1_700_000_000, 5000);
    gov.flush_budgets(); // persist the write-behind cell before asserting the durable counter
    let u = store.get_usage("k1", 0).unwrap();
    assert_eq!(u.spend_cents, 0, "negative token price must clamp to 0");
    assert_eq!(u.tokens, 5000, "tokens are still counted");
}

#[test]
fn test_create_key_minted_id_is_free_so_mint_succeeds() {
    // A normal mint derives a fresh id and the collision guard does not fire (the id is free).
    let store = Arc::new(MemoryStore::new());
    let gov = GovState::new(store.clone(), 1, 0, None).unwrap();
    let spec = NewKeySpec {
        name: "first".to_string(),
        allowed_pools: vec![],
        max_budget_cents: None,
        budget_period: BUDGET_PERIOD_TOTAL.to_string(),
        rpm_limit: None,
        tpm_limit: None,
    };
    let (key, secret) = gov.create_key(spec, 1_700_000_000).unwrap();
    assert!(key.id.starts_with("vk_")); // golden wire-contract literal (kept bare on purpose)
                                        // The minted key resolves by its own secret.
    assert_eq!(gov.lookup(&secret).unwrap().id, key.id);
}

#[test]
fn test_update_key_toggles_enabled_and_limits_in_place() {
    // PATCH /admin/keys/:id (#28): a key can be disabled WITHOUT destroying it, and its caps
    // adjusted, with the secret/hash preserved. A missing field leaves its value unchanged.
    let store = Arc::new(MemoryStore::new());
    let gov = GovState::new(store.clone(), 1, 0, None).unwrap();
    let (key, secret) = gov
        .create_key(
            NewKeySpec {
                name: "k".to_string(),
                allowed_pools: vec![],
                max_budget_cents: None,
                budget_period: BUDGET_PERIOD_TOTAL.to_string(),
                rpm_limit: Some(10),
                tpm_limit: None,
            },
            1_700_000_000,
        )
        .unwrap();
    assert!(key.enabled, "new key starts enabled");
    let hash = key.key_hash.clone();

    // Disable it; leave the limits untouched (outer None = field absent).
    let updated = gov
        .update_key(&key.id, Some(false), None, None, None)
        .unwrap()
        .expect("key exists");
    assert!(!updated.enabled, "key is now disabled");
    assert_eq!(updated.rpm_limit, Some(10), "untouched field preserved");
    assert_eq!(updated.key_hash, hash, "secret hash is not rotated");
    // The disabled state is enforced on the next lookup (the cache was refreshed).
    let looked = gov.lookup(&secret).unwrap();
    assert!(!looked.enabled, "lookup reflects the disabled key");

    // Re-enable and bump the rate cap in one call (Some(Some(50)) = set).
    let re = gov
        .update_key(&key.id, Some(true), Some(Some(50)), None, None)
        .unwrap()
        .expect("key exists");
    assert!(re.enabled);
    assert_eq!(re.rpm_limit, Some(50));

    // Updating a non-existent key returns Ok(None) (the handler maps this to 404).
    assert!(gov
        .update_key("vk_does_not_exist", Some(false), None, None, None)
        .unwrap()
        .is_none());
}

#[test]
fn test_update_key_clears_caps_to_unlimited_with_inner_none() {
    // THREE-STATE caps (LOW #16/#19): `Some(None)` CLEARS a cap back to unlimited; `None` (outer)
    // leaves it unchanged; `Some(Some(v))` sets it. The old single-Option shape could only set or
    // leave-unchanged, never clear. Verify all three transitions on every cap field.
    let store = Arc::new(MemoryStore::new());
    let gov = GovState::new(store.clone(), 1, 0, None).unwrap();
    let (key, _secret) = gov
        .create_key(
            NewKeySpec {
                name: "k".to_string(),
                allowed_pools: vec![],
                max_budget_cents: Some(5000),
                budget_period: BUDGET_PERIOD_TOTAL.to_string(),
                rpm_limit: Some(10),
                tpm_limit: Some(2000),
            },
            1_700_000_000,
        )
        .unwrap();
    assert_eq!(key.rpm_limit, Some(10));
    assert_eq!(key.tpm_limit, Some(2000));
    assert_eq!(key.max_budget_cents, Some(5000));

    // Clear ALL three caps to unlimited with inner None.
    let cleared = gov
        .update_key(&key.id, None, Some(None), Some(None), Some(None))
        .unwrap()
        .expect("key exists");
    assert_eq!(cleared.rpm_limit, None, "rpm cleared to unlimited");
    assert_eq!(cleared.tpm_limit, None, "tpm cleared to unlimited");
    assert_eq!(
        cleared.max_budget_cents, None,
        "budget cleared to unlimited"
    );
    // The clear persisted through the store, not just the returned struct.
    let persisted = store.get_key(&key.id).unwrap().unwrap();
    assert_eq!(persisted.rpm_limit, None);
    assert_eq!(persisted.tpm_limit, None);
    assert_eq!(persisted.max_budget_cents, None);

    // Now SET them again from the cleared state.
    let reset = gov
        .update_key(
            &key.id,
            None,
            Some(Some(7)),
            Some(Some(99)),
            Some(Some(123)),
        )
        .unwrap()
        .expect("key exists");
    assert_eq!(reset.rpm_limit, Some(7));
    assert_eq!(reset.tpm_limit, Some(99));
    assert_eq!(reset.max_budget_cents, Some(123));

    // And absence (outer None) leaves them UNCHANGED.
    let unchanged = gov
        .update_key(&key.id, Some(false), None, None, None)
        .unwrap()
        .expect("key exists");
    assert!(!unchanged.enabled, "enabled toggled");
    assert_eq!(unchanged.rpm_limit, Some(7), "absent leaves rpm unchanged");
    assert_eq!(unchanged.tpm_limit, Some(99), "absent leaves tpm unchanged");
    assert_eq!(
        unchanged.max_budget_cents,
        Some(123),
        "absent leaves budget unchanged"
    );
}

#[test]
fn test_unlimited_key_does_not_grow_rate_map() {
    // LOW #17 (memory): a key with NO RPM/TPM cap must never grow the ephemeral `rate` map. Both
    // the rate-limit gate (`check_rate`) and the post-response accounting (`record_request` /
    // `record_tokens`) must skip the map for an uncapped key — otherwise every request leaks one
    // entry per uncapped key forever. Drive many requests for an uncapped key and assert the map
    // stays empty; then a capped key DOES get an entry (the feed still works where it should).
    let store = Arc::new(MemoryStore::new());
    let gov = GovState::new(store, 5, 7, None).unwrap();

    let mut uncapped = sample_key("uncapped", "h_unl");
    uncapped.rpm_limit = None;
    uncapped.tpm_limit = None;
    let now = 1_700_000_040;
    for _ in 0..50 {
        assert!(gov.check_rate(&uncapped, now).is_ok());
        gov.record_request(&uncapped, now, 1234); // non-zero tokens — would feed the map pre-fix
    }
    // record_tokens carries only the key id (no caps), so it must also not materialise an entry.
    gov.record_tokens("uncapped", BUDGET_PERIOD_TOTAL, now, 9999);
    assert!(
        gov.rate
            .read()
            .unwrap_or_else(|p| p.into_inner())
            .get("uncapped")
            .is_none(),
        "an uncapped key must never gain a rate-map entry"
    );

    // A capped key still gets fed: check_rate creates its entry and record_request credits TPM.
    let mut capped = sample_key("capped", "h_cap");
    capped.rpm_limit = Some(100);
    capped.tpm_limit = Some(100_000);
    assert!(gov.check_rate(&capped, now).is_ok());
    gov.record_request(&capped, now, 500);
    let map = gov.rate.read().unwrap_or_else(|p| p.into_inner());
    let st = map
        .get("capped")
        .expect("a capped key must have a rate-map entry");
    assert_eq!(st.tokens, 500, "capped key's TPM counter was fed");
    assert!(
        map.get("uncapped").is_none(),
        "uncapped key still absent after a capped key was added"
    );
}

#[test]
fn test_add_rate_tokens_is_update_only_never_materialises_entry() {
    // LOW #12 (completeness): `add_rate_tokens` is UPDATE-ONLY. It must NEVER create a missing
    // entry, even for a capped key. The former `create_if_absent = true` recovery branch (fed by
    // `record_request` for a "swept-capped-key") was DEAD: production always passes `tokens = 0`
    // through `record_request`, so the credit returns at the `tokens == 0` guard before reaching
    // any create path, and the token fee flows through `record_tokens` (update-only). Old code
    // with the recovery branch would have materialised an entry here from `record_request` with
    // non-zero tokens; the corrected update-only code must not.
    let store = Arc::new(MemoryStore::new());
    let gov = GovState::new(store, 5, 7, None).unwrap();

    // A CAPPED key with NO prior `check_rate` admission -> it has no rate-map entry yet.
    let mut capped = sample_key("late", "h_late");
    capped.rpm_limit = Some(10);
    capped.tpm_limit = Some(1000);
    let now = 1_700_000_040;

    // Feed non-zero tokens via record_request WITHOUT a preceding check_rate. The dead recovery
    // branch (create_if_absent) would have inserted an entry crediting 500 tokens; update-only
    // must leave the map untouched for this key.
    gov.record_request(&capped, now, 500);
    assert!(
        gov.rate
            .read()
            .unwrap_or_else(|p| p.into_inner())
            .get("late")
            .is_none(),
        "add_rate_tokens must not materialise an entry for a key with no prior check_rate"
    );

    // Likewise via record_tokens (the token-fee path): no entry exists, so nothing is created.
    gov.record_tokens("late", BUDGET_PERIOD_TOTAL, now, 500);
    assert!(
        gov.rate
            .read()
            .unwrap_or_else(|p| p.into_inner())
            .get("late")
            .is_none(),
        "record_tokens (update-only) must not materialise an entry either"
    );

    // Once check_rate creates the entry (the real admission path), a subsequent credit lands.
    assert!(gov.check_rate(&capped, now).is_ok());
    gov.record_request(&capped, now, 300);
    let map = gov.rate.read().unwrap_or_else(|p| p.into_inner());
    assert_eq!(
        map.get("late")
            .expect("entry exists after check_rate")
            .tokens,
        300,
        "an existing entry is credited update-only",
    );
}

#[test]
fn test_ensure_id_free_for_hash_guards_silent_overwrite() {
    // The PRIMARY KEY `id` is a 64-bit prefix of the full key_hash, so a collision can put a new
    // secret's id atop an unrelated key. The guard must REFUSE when the id already holds a
    // DIFFERENT key_hash (rather than let put_key UPSERT-overwrite and invalidate the incumbent),
    // while allowing a free id or an idempotent same-hash re-mint.
    let store = Arc::new(MemoryStore::new());
    let gov = GovState::new(store.clone(), 1, 0, None).unwrap();

    // A free id is allowed.
    gov.ensure_id_free_for_hash("vk_freshid", "HASH_A")
        .expect("a free id must be allowed");

    // Seed an incumbent key occupying that id under HASH_A.
    let incumbent = sample_key("vk_freshid", "HASH_A");
    store.put_key(&incumbent).unwrap();
    gov.refresh().unwrap();

    // Same id, SAME hash: idempotent re-mint is allowed.
    gov.ensure_id_free_for_hash("vk_freshid", "HASH_A")
        .expect("same-hash re-mint must be allowed");

    // Same id, DIFFERENT hash: must be rejected (the collision the fix guards against).
    let err = gov
        .ensure_id_free_for_hash("vk_freshid", "HASH_B_DIFFERENT")
        .expect_err("colliding id with a different hash must be rejected");
    assert!(
        err.to_string().contains("id collision"),
        "error must explain the id collision; got: {err}"
    );

    // The incumbent row is untouched (never overwritten).
    let still = store.get_key("vk_freshid").unwrap().unwrap();
    assert_eq!(still.key_hash, "HASH_A", "incumbent must not be clobbered");
}

#[test]
fn test_poisoned_rate_lock_recovers_not_panics() {
    // Regression: a panic while the `rate` lock is held poisons it. The hot-path accessors must
    // RECOVER (via into_inner) rather than `.unwrap()`-panic on every subsequent call, which
    // would cascade a single transient fault into a full governance outage. We deliberately
    // poison the lock, then assert check_rate/add_rate_tokens still function.
    let store = Arc::new(MemoryStore::new());
    let gov = Arc::new(GovState::new(store, 0, 0, None).unwrap());
    let mut k = sample_key("k1", "h1");
    k.rpm_limit = Some(2);
    k.tpm_limit = None;
    let now = 1_700_000_040;

    // Poison the rate lock: panic inside the write guard.
    let g = gov.clone();
    let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _guard = g.rate.write().unwrap();
        panic!("intentional poison");
    }));
    assert!(gov.rate.is_poisoned(), "lock must be poisoned for the test");

    // Despite the poison, the hot path keeps working (no panic, RPM still enforced).
    assert!(gov.check_rate(&k, now).is_ok(), "1st admits after poison");
    assert!(gov.check_rate(&k, now).is_ok(), "2nd admits after poison");
    assert!(
        gov.check_rate(&k, now).is_err(),
        "RPM=2 still enforced on a recovered (poisoned) lock"
    );
}

#[test]
fn test_poisoned_by_hash_lock_recovers_not_panics() {
    // The auth-path key cache lock has the same hazard: a poisoned `by_hash` must not make every
    // subsequent `lookup` panic. Poison it, then confirm lookup still resolves a cached key.
    let store = Arc::new(MemoryStore::new());
    let secret = "sk-vk-abc";
    let k = sample_key("k1", &crate::sigv4::sha256_hex(secret.as_bytes()));
    store.put_key(&k).unwrap();
    let gov = Arc::new(GovState::new(store, 1, 0, None).unwrap());

    let g = gov.clone();
    let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _guard = g.caches.write().unwrap();
        panic!("intentional poison");
    }));
    assert!(gov.caches.is_poisoned(), "cache lock must be poisoned");

    // lookup still works (no panic) and refresh still succeeds on the recovered guard.
    assert_eq!(gov.lookup(secret).unwrap().id, "k1");
    gov.refresh()
        .expect("refresh recovers the poisoned cache lock");
    assert_eq!(gov.lookup(secret).unwrap().id, "k1");
}
