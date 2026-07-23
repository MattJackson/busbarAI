/// The re-key union semantics under role_bindings (C6): pools union (OMITTED `allowed_pools` on
/// any granting binding = every pool; explicit `[]` contributes nothing), the synthesized key
/// carries NO inline caps (keys are pure auth; limits live on `groups:`), the first bound
/// `group` becomes the key's budget_group, and a principal whose roles all bind `[]` (or bind
/// nothing) gets NO synthetic key (fail closed).
#[test]
fn synthesize_principal_key_union_semantics() {
    use crate::config::RoleBindingCfg;
    let mut table = std::collections::BTreeMap::new();
    table.insert(
        "a".to_string(),
        RoleBindingCfg {
            allowed_pools: Some(vec!["p1".to_string()]),
            group: Some("finance".to_string()),
            ..Default::default()
        },
    );
    table.insert(
        "b".to_string(),
        RoleBindingCfg {
            allowed_pools: Some(vec!["p2".to_string()]),
            ..Default::default()
        },
    );
    // An ADMIN-ONLY role: admin scope, but an explicit [] pool grant = NO data-plane access.
    table.insert(
        "admin-only".to_string(),
        RoleBindingCfg {
            allowed_pools: Some(vec![]),
            admin_scope: Some("full".to_string()),
            ..Default::default()
        },
    );
    // OMITTED allowed_pools = ALL pools (C6).
    table.insert("all-pools".to_string(), RoleBindingCfg::default());

    let mut p = crate::auth::Principal::from_id("test:u");
    p.groups = vec!["a".to_string(), "b".to_string()];
    let k = synthesize_principal_key(&p, Some(&table)).expect("bound roles synthesize");
    assert_eq!(k.id, "test:u", "keyed by the principal id");
    let mut pools = k.allowed_pools.clone();
    pools.sort();
    assert_eq!(
        pools,
        vec!["p1".to_string(), "p2".to_string()],
        "pools union"
    );
    // Keys are PURE AUTH: no rate/budget caps ride the synthesized key (limits live on groups).
    assert_eq!(k.rpm_limit, None, "no per-key rpm cap");
    assert_eq!(k.tpm_limit, None, "no per-key tpm cap");
    assert_eq!(k.max_budget_cents, None, "no per-key budget cap");
    assert_eq!(
        k.budget_group.as_deref(),
        Some("finance"),
        "the bound group becomes the key's budget_group"
    );
    assert!(k.enabled);

    // An OMITTED allowed_pools on any granting binding = every pool (empty Vec encoding).
    p.groups = vec!["a".to_string(), "all-pools".to_string()];
    let k = synthesize_principal_key(&p, Some(&table)).expect("granting");
    assert!(
        k.allowed_pools.is_empty(),
        "omitted allowed_pools grants every pool"
    );

    // All granting bindings say []: the EMPTY SET - no synthetic key (fail closed).
    p.groups = vec!["admin-only".to_string(), "unbound".to_string()];
    assert!(
        synthesize_principal_key(&p, Some(&table)).is_none(),
        "an all-[] pool grant = no synthetic key (fail closed)"
    );
    p.groups = vec![];
    assert!(synthesize_principal_key(&p, Some(&table)).is_none());
    // No bindings table for the identifying module at all: nothing to grant.
    p.groups = vec!["a".to_string()];
    assert!(synthesize_principal_key(&p, None).is_none());
}

/// REGRESSION (audit cost-1.5.0, bucket-namespace hardening): a principal whose id literally
/// starts with `group:` must NEVER get a synthetic key. The synthetic key's `id` is its ledger
/// bucket id, and budget-group buckets share that namespace as `group:<name>` - an IdP-supplied
/// id like `group:acme` would otherwise charge/read/alias the `acme` budget group's cell.
/// Fail closed: no key, no data-plane access, no collision.
#[test]
fn group_prefixed_principal_id_cannot_alias_a_budget_group_bucket() {
    use crate::config::RoleBindingCfg;
    let mut table = std::collections::BTreeMap::new();
    // OMITTED allowed_pools = ALL pools: the broadest possible grant.
    table.insert("eng".to_string(), RoleBindingCfg::default());

    // Control: the same grants under a benign id DO synthesize, and the bucket id is the
    // principal id - which is exactly why the reserved prefix must be rejected.
    let mut ok = crate::auth::Principal::from_id("sso:alice");
    ok.groups = vec!["eng".to_string()];
    let k = synthesize_principal_key(&ok, Some(&table)).expect("benign id synthesizes");
    assert_eq!(k.id, "sso:alice", "the key id IS the ledger bucket id");

    // The attack shape: identical grants, but the id sits in the budget-group bucket namespace.
    // It must produce NO key at all (fail closed), so no ledger cell keyed `group:acme` can ever
    // be created or charged on behalf of this principal.
    let mut evil = crate::auth::Principal::from_id("group:acme");
    evil.groups = vec!["eng".to_string()];
    assert!(
        synthesize_principal_key(&evil, Some(&table)).is_none(),
        "a group:-prefixed principal id must be refused, never keyed into the ledger"
    );

    // The bare prefix is equally reserved.
    let mut bare = crate::auth::Principal::from_id("group:");
    bare.groups = vec!["eng".to_string()];
    assert!(synthesize_principal_key(&bare, Some(&table)).is_none());
}

/// REGRESSION (vk_ alias hardening): a principal whose id starts with `vk_` must NEVER get a
/// synthetic key. A real virtual key's id is `vk_<16 hex>` and IS its ledger/rate bucket id, so an
/// IdP-supplied subject shaped `vk_<...>` would alias a real virtual key's ledger + rate bucket
/// (charging/reading it, or riding its rate window). Fail closed like the `group:` guard.
#[test]
fn vk_prefixed_principal_id_cannot_alias_a_virtual_key_bucket() {
    use crate::config::RoleBindingCfg;
    let mut table = std::collections::BTreeMap::new();
    table.insert("eng".to_string(), RoleBindingCfg::default());

    // A `vk_`-shaped id (the exact shape of a real minted virtual key) must produce NO key.
    let mut evil = crate::auth::Principal::from_id("vk_deadbeefdeadbeef");
    evil.groups = vec!["eng".to_string()];
    assert!(
        synthesize_principal_key(&evil, Some(&table)).is_none(),
        "a vk_-prefixed principal id must be refused, never keyed into a virtual key's bucket"
    );

    // The bare prefix is equally reserved.
    let mut bare = crate::auth::Principal::from_id("vk_");
    bare.groups = vec!["eng".to_string()];
    assert!(synthesize_principal_key(&bare, Some(&table)).is_none());
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
        budget_group: None,
        labels: std::collections::BTreeMap::new(),
    }
}

/// Flat cost model: no rate card (tokens derive to 0), no groups, the given per-request fee.
fn flat_cost(fee: i64) -> crate::cost::CostModel {
    crate::cost::CostModel::flat(fee)
}

/// A one-entry rate card (input tier only, `input_utok` micro-units/token).
fn one_entry_card(
    model: &str,
    input_utok: f64,
) -> std::collections::BTreeMap<String, crate::config::RateEntryCfg> {
    std::collections::BTreeMap::from([(
        model.to_string(),
        crate::config::RateEntryCfg {
            input_utok,
            output_utok: 0.0,
            cache_read_utok: 0.0,
            cache_write_utok: 0.0,
        },
    )])
}

/// A `groups:` entry carrying one BUDGET limit (cap in cents on the given runtime period noun:
/// total | daily | monthly | minute | hour) and an optional parent.
fn budget_group_cfg(cap: i64, period: &str, parent: Option<&str>) -> crate::config::GroupCfg {
    use crate::config::groups::{LimitCfg, LimitMetric, LimitWindow};
    let per = match period {
        "daily" => LimitWindow::Day,
        "monthly" => LimitWindow::Month,
        "minute" => LimitWindow::Minute,
        "hour" => LimitWindow::Hour,
        _ => LimitWindow::Total,
    };
    crate::config::GroupCfg {
        parent: parent.map(String::from),
        enabled: true,
        limits: vec![LimitCfg {
            metric: LimitMetric::Budget,
            amount: u64::try_from(cap).unwrap_or(0),
            per: Some(per),
        }],
    }
}

/// A cost model with ONE rate-card entry (input tier only, `input_utok` micro-units/token) and no
/// flat fee - the minimal token-priced model.
fn card_cost(model: &str, input_utok: f64) -> crate::cost::CostModel {
    crate::cost::CostModel::resolve_parts(
        Some(&one_entry_card(model, input_utok)),
        0,
        &std::collections::BTreeMap::new(),
    )
}

/// A cost model with budget GROUPS (name, cap, period, parent) and a flat fee, no rate card.
fn group_cost(fee: i64, groups: &[(&str, i64, &str, Option<&str>)]) -> crate::cost::CostModel {
    let groups_cfg: std::collections::BTreeMap<String, crate::config::GroupCfg> = groups
        .iter()
        .map(|(name, cap, period, parent)| {
            (name.to_string(), budget_group_cfg(*cap, period, *parent))
        })
        .collect();
    crate::cost::CostModel::resolve_parts(None, fee, &groups_cfg)
}

/// A cost model with BOTH a one-entry rate card and budget groups, no flat fee.
fn card_and_group_cost(
    model: &str,
    input_utok: f64,
    groups: &[(&str, i64, &str, Option<&str>)],
) -> crate::cost::CostModel {
    let groups_cfg: std::collections::BTreeMap<String, crate::config::GroupCfg> = groups
        .iter()
        .map(|(name, cap, period, parent)| {
            (name.to_string(), budget_group_cfg(*cap, period, *parent))
        })
        .collect();
    crate::cost::CostModel::resolve_parts(Some(&one_entry_card(model, input_utok)), 0, &groups_cfg)
}

/// An input-only tier split of `n` tokens (the scalar-total shorthand old tests used).
fn tt(n: u64) -> TierTokens {
    TierTokens {
        input: n,
        output: 0,
        cache_read: 0,
        cache_write: 0,
    }
}

/// The store ledger's total tokens for (bucket, window) - the old scalar `tokens` view.
fn ledger_tokens(store: &MemoryStore, bucket: &str, window: u64) -> u64 {
    store.get_usage(bucket, window).unwrap().total_tokens()
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
    let gov = Arc::new(GovState::new(store.clone(), None).unwrap());
    let cost = Arc::new(flat_cost(1)); // 1c flat fee
    let (key, _s) = gov
        .create_key(
            NewKeySpec {
                name: "k".to_string(),
                allowed_pools: vec![],
                max_budget_cents: Some(5), // 5c cap → at most 5 one-cent admissions
                budget_period: BUDGET_PERIOD_TOTAL.to_string(),
                rpm_limit: None,
                tpm_limit: None,
                budget_group: None,
                labels: std::collections::BTreeMap::new(),
            },
            1_700_000_000,
        )
        .unwrap();
    let at = 1_700_000_000u64;
    let mut handles = Vec::new();
    for _ in 0..20 {
        let gov = gov.clone();
        let cost = cost.clone();
        let key = key.clone();
        handles.push(tokio::spawn(async move {
            gov.try_charge_request_within_budget(&cost, &key, at)
                .is_ok()
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
    // The hard cap is enforced by the AUTHORITATIVE in-memory cell; flush it to the durable
    // ledger. Spend is DERIVED (fee x requests), so the durable proof is the request count.
    gov.flush_budgets();
    assert_eq!(
        store.get_usage(&key.id, 0).unwrap().requests,
        5,
        "exactly 5 requests ledgered - the in-memory admission path holds the hard cap, no overshoot"
    );
    assert_eq!(
        gov.usage_for(&cost, &key.id, at)
            .unwrap()
            .unwrap()
            .spend_cents,
        5,
        "derived spend = 5 requests x 1c fee"
    );
}

/// H2: the charge → refund → re-admit money cycle through `GovState`. Charge a key to its cap so the
/// next request is rejected; `refund_request` (fire-and-forget `offload_store_write`) reverses one
/// charge; after draining the blocking write a new request is admitted again. Proves a refunded fee
/// genuinely frees budget on the live admission path.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_charge_refund_readmit_cycle() {
    let store = Arc::new(MemoryStore::new());
    let gov = Arc::new(GovState::new(store.clone(), None).unwrap());
    let cost = flat_cost(1); // 1c flat fee
    let (key, _s) = gov
        .create_key(
            NewKeySpec {
                name: "k".to_string(),
                allowed_pools: vec![],
                max_budget_cents: Some(1), // 1c cap → exactly one request fits
                budget_period: BUDGET_PERIOD_TOTAL.to_string(),
                rpm_limit: None,
                tpm_limit: None,
                budget_group: None,
                labels: std::collections::BTreeMap::new(),
            },
            1_700_000_000,
        )
        .unwrap();
    let at = 1_700_000_000u64;
    // Charge to the cap.
    assert!(
        gov.try_charge_request_within_budget(&cost, &key, at)
            .is_ok(),
        "1st (1c) admitted, spends the whole 1c cap"
    );
    // At cap - next request rejected, naming the KEY bucket.
    assert_eq!(
        gov.try_charge_request_within_budget(&cost, &key, at),
        Err(BudgetBlocked::Key),
        "2nd rejected: the key's own budget is exhausted at the cap"
    );
    // Refund reverses the in-memory charge synchronously (the fee derives from the request count).
    gov.refund_request(&cost, &key, at);
    assert_eq!(
        gov.usage_for(&cost, &key.id, at)
            .unwrap()
            .unwrap()
            .spend_cents,
        0,
        "refund must reverse the derived charge back to 0 spend"
    );
    // Budget is free again - a new request is re-admitted.
    assert!(
        gov.try_charge_request_within_budget(&cost, &key, at)
            .is_ok(),
        "post-refund request re-admitted: the refunded fee freed the budget"
    );
}

/// fix 2a wrapper: `try_charge_request_within_budget` charges the flat fee and rejects atomically
/// at the cap. 1c/request flat fee, 2c cap → 2 admitted, 3rd rejected.
#[tokio::test]
async fn test_try_charge_request_within_budget_rejects_at_cap() {
    let store = Arc::new(MemoryStore::new());
    let gov = GovState::new(store, None).unwrap();
    let cost = flat_cost(1); // 1c flat fee
    let (key, _s) = gov
        .create_key(
            NewKeySpec {
                name: "k".to_string(),
                allowed_pools: vec![],
                max_budget_cents: Some(2),
                budget_period: BUDGET_PERIOD_TOTAL.to_string(),
                rpm_limit: None,
                tpm_limit: None,
                budget_group: None,
                labels: std::collections::BTreeMap::new(),
            },
            1_700_000_000,
        )
        .unwrap();
    let at = 1_700_000_000u64;
    assert!(
        gov.try_charge_request_within_budget(&cost, &key, at)
            .is_ok(),
        "1st (1c) admitted"
    );
    assert!(
        gov.try_charge_request_within_budget(&cost, &key, at)
            .is_ok(),
        "2nd (2c) admitted"
    );
    assert_eq!(
        gov.try_charge_request_within_budget(&cost, &key, at),
        Err(BudgetBlocked::Key),
        "3rd (would be 3c > 2c cap) rejected atomically, naming the key bucket"
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
    let gov = GovState::new(store, None).unwrap();
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
    let gov = GovState::new(store, None).unwrap();
    let (key, _bearer, akid, secret) = gov
        .create_key_with_aws(
            NewKeySpec {
                name: "bedrock-key".to_string(),
                allowed_pools: vec!["prod".to_string()],
                max_budget_cents: Some(1000),
                budget_period: BUDGET_PERIOD_TOTAL.to_string(),
                rpm_limit: None,
                tpm_limit: None,
                budget_group: None,
                labels: std::collections::BTreeMap::new(),
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
        let gov = GovState::new(store.clone(), None).unwrap();
        let (_k, _b, akid, _s) = gov
            .create_key_with_aws(
                NewKeySpec {
                    name: "k".to_string(),
                    allowed_pools: vec![],
                    max_budget_cents: None,
                    budget_period: BUDGET_PERIOD_TOTAL.to_string(),
                    rpm_limit: None,
                    tpm_limit: None,
                    budget_group: None,
                    labels: std::collections::BTreeMap::new(),
                },
                0,
            )
            .unwrap();
        akid
    };
    let gov2 = GovState::new(store, None).unwrap();
    assert!(
        gov2.lookup_by_access_key_id(&akid).is_some(),
        "credential must survive a reload"
    );
}

#[test]
fn test_delete_key_removes_aws_credential() {
    // Revoking a key must remove its AWS credential so it can no longer authenticate via SigV4.
    let store = Arc::new(MemoryStore::new());
    let gov = GovState::new(store, None).unwrap();
    let (key, _b, akid, _s) = gov
        .create_key_with_aws(
            NewKeySpec {
                name: "k".to_string(),
                allowed_pools: vec![],
                max_budget_cents: None,
                budget_period: BUDGET_PERIOD_TOTAL.to_string(),
                rpm_limit: None,
                tpm_limit: None,
                budget_group: None,
                labels: std::collections::BTreeMap::new(),
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
    let gov = GovState::new(store, None).unwrap();
    let (key, bearer, akid, _secret) = gov
        .create_key_with_aws(
            NewKeySpec {
                name: "dual-index-key".to_string(),
                allowed_pools: vec![],
                max_budget_cents: None,
                budget_period: BUDGET_PERIOD_TOTAL.to_string(),
                rpm_limit: None,
                tpm_limit: None,
                budget_group: None,
                labels: std::collections::BTreeMap::new(),
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
    let gov = GovState::new(store, None).unwrap();
    let mk = |gov: &GovState, n: &str| {
        gov.create_key_with_aws(
            NewKeySpec {
                name: n.to_string(),
                allowed_pools: vec![],
                max_budget_cents: None,
                budget_period: BUDGET_PERIOD_TOTAL.to_string(),
                rpm_limit: None,
                tpm_limit: None,
                budget_group: None,
                labels: std::collections::BTreeMap::new(),
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

    let gov = GovState::new(store, None).unwrap();
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

/// DERIVED-SPEND admission: the cap check recomputes spend = fee x requests from the ledger on
/// every admission (no stored spend). 30c fee, 100c cap: 3 admissions land (90c derived); the 4th
/// (would derive 120c) is rejected. An uncapped key is never blocked.
#[test]
fn test_derived_spend_enforces_cap_from_request_ledger() {
    let store = Arc::new(MemoryStore::new());
    let mut k = sample_key("k1", "h1");
    k.max_budget_cents = Some(100);
    k.budget_period = BUDGET_PERIOD_TOTAL.to_string();
    store.put_key(&k).unwrap();
    let gov = GovState::new(store, None).unwrap();
    let cost = flat_cost(30); // 30 cents/request

    for i in 0..3 {
        assert!(
            gov.try_charge_request_within_budget(&cost, &k, 1_700_000_000)
                .is_ok(),
            "admission {i} fits (derived spend stays under 100c)"
        );
    }
    assert_eq!(
        gov.usage_for(&cost, "k1", 1_700_000_000)
            .unwrap()
            .unwrap()
            .spend_cents,
        90,
        "derived spend = 3 requests x 30c"
    );
    assert_eq!(
        gov.try_charge_request_within_budget(&cost, &k, 1_700_000_000),
        Err(BudgetBlocked::Key),
        "4th would derive 120c >= 100c cap"
    );

    let mut unlimited = k.clone();
    unlimited.max_budget_cents = None;
    assert!(gov
        .try_charge_request_within_budget(&cost, &unlimited, 1_700_000_000)
        .is_ok());
}

/// FLEET-ADDITIVE FLUSH (1.5.0): TWO GovStates ("nodes") sharing ONE durable store each accrue
/// spend and flush — the durable record must hold the SUM of both nodes' accruals, not whichever
/// node flushed last (the lost-update the old absolute `put_usage` overwrite caused). Also: a
/// re-flush with nothing new is a no-op (the acked baseline advances), so nothing double-counts.
#[test]
fn test_two_node_flush_is_additive_no_lost_update() {
    let store = Arc::new(MemoryStore::new());
    let mut k = sample_key("k_fleet", "h_fleet");
    k.budget_period = BUDGET_PERIOD_TOTAL.to_string();
    store.put_key(&k).unwrap();

    // Two independent GovStates over the SAME store = two busbar nodes sharing a cluster store.
    let node_a = GovState::new(store.clone(), None).unwrap();
    let node_b = GovState::new(store.clone(), None).unwrap();
    let cost = flat_cost(10); // 10c flat fee

    // Node A charges 3 requests + per-model tokens; node B charges 2 + tokens on TWO models.
    for _ in 0..3 {
        assert!(node_a
            .try_charge_request_within_budget(&cost, &k, 1_700_000_000)
            .is_ok());
    }
    node_a.record_usage(&cost, &k, "gpt-5", &tt(100), 1_700_000_000);
    for _ in 0..2 {
        assert!(node_b
            .try_charge_request_within_budget(&cost, &k, 1_700_000_000)
            .is_ok());
    }
    node_b.record_usage(&cost, &k, "gpt-5", &tt(40), 1_700_000_000);
    node_b.record_usage(&cost, &k, "haiku", &tt(7), 1_700_000_000);
    node_a.flush_budgets();
    node_b.flush_budgets();

    let u = store.get_usage("k_fleet", 0).unwrap();
    assert_eq!(
        u.requests, 5,
        "the durable record is the FLEET SUM (3 + 2), not last-writer-wins"
    );
    assert_eq!(
        u.tokens_for("gpt-5").unwrap().input,
        140,
        "per-model token deltas SUM across nodes (100 + 40)"
    );
    assert_eq!(
        u.tokens_for("haiku").unwrap().input,
        7,
        "a model only one node used still lands"
    );

    // Re-flushing with nothing new must not double-count (the acked baselines advanced).
    node_a.flush_budgets();
    node_b.flush_budgets();
    let u = store.get_usage("k_fleet", 0).unwrap();
    assert_eq!(u.requests, 5, "an idle re-flush adds nothing");
    assert_eq!(u.tokens_for("gpt-5").unwrap().input, 140);

    // More accrual on one node keeps accumulating correctly.
    assert!(node_a
        .try_charge_request_within_budget(&cost, &k, 1_700_000_000)
        .is_ok());
    node_a.flush_budgets();
    assert_eq!(store.get_usage("k_fleet", 0).unwrap().requests, 6);
}

/// A REFUND between flushes produces a NEGATIVE delta that the additive flush carries through: the
/// durable record ends at the true net spend, never below zero.
#[test]
fn test_additive_flush_carries_refund_deltas() {
    let store = Arc::new(MemoryStore::new());
    let mut k = sample_key("k_refund", "h_refund");
    k.budget_period = BUDGET_PERIOD_TOTAL.to_string();
    store.put_key(&k).unwrap();
    let gov = GovState::new(store.clone(), None).unwrap();
    let cost = flat_cost(10);

    // Charge 2 requests, flush (durable 2), then refund one and flush again: net 1.
    assert!(gov
        .try_charge_request_within_budget(&cost, &k, 1_700_000_000)
        .is_ok());
    assert!(gov
        .try_charge_request_within_budget(&cost, &k, 1_700_000_000)
        .is_ok());
    gov.flush_budgets();
    assert_eq!(store.get_usage("k_refund", 0).unwrap().requests, 2);

    gov.refund_request(&cost, &k, 1_700_000_000);
    gov.flush_budgets();
    let u = store.get_usage("k_refund", 0).unwrap();
    assert_eq!(u.requests, 1, "the refund's negative delta lands durably");
    assert_eq!(
        gov.usage_for(&cost, "k_refund", 1_700_000_000)
            .unwrap()
            .unwrap()
            .spend_cents,
        10,
        "derived spend follows the refunded request count"
    );
}

/// A FAILED flush re-marks the cell dirty WITHOUT advancing the acked baseline, so the unacked
/// delta is retried (not lost) on the next tick once the store recovers.
#[test]
fn test_failed_flush_retries_the_unacked_delta() {
    /// A store whose add_usage fails until `healthy` flips true.
    struct FlakyStore {
        inner: MemoryStore,
        healthy: std::sync::atomic::AtomicBool,
    }
    impl busbar_api::Store for FlakyStore {
        fn put_key(&self, k: &busbar_api::VirtualKey) -> busbar_api::StoreResult<()> {
            self.inner.put_key(k)
        }
        fn get_key(&self, id: &str) -> busbar_api::StoreResult<Option<busbar_api::VirtualKey>> {
            self.inner.get_key(id)
        }
        fn list_keys(&self) -> busbar_api::StoreResult<Vec<busbar_api::VirtualKey>> {
            self.inner.list_keys()
        }
        fn delete_key(&self, id: &str) -> busbar_api::StoreResult<()> {
            self.inner.delete_key(id)
        }
        fn get_usage(&self, id: &str, w: u64) -> busbar_api::StoreResult<busbar_api::UsageLedger> {
            self.inner.get_usage(id, w)
        }
        fn put_usage(
            &self,
            id: &str,
            w: u64,
            l: &busbar_api::UsageLedger,
        ) -> busbar_api::StoreResult<()> {
            self.inner.put_usage(id, w, l)
        }
        fn add_usage(
            &self,
            id: &str,
            w: u64,
            d: &busbar_api::UsageDelta,
        ) -> busbar_api::StoreResult<()> {
            if !self.healthy.load(std::sync::atomic::Ordering::Relaxed) {
                return Err(busbar_api::StoreError("store down".into()));
            }
            self.inner.add_usage(id, w, d)
        }
        fn add_metering(&self, d: &busbar_api::MeteringDelta) -> busbar_api::StoreResult<()> {
            self.inner.add_metering(d)
        }
        fn list_metering(&self, b: u64) -> busbar_api::StoreResult<Vec<busbar_api::MeteringRow>> {
            self.inner.list_metering(b)
        }
        fn append_audit(&self, e: &busbar_api::AuditRecord) -> busbar_api::StoreResult<()> {
            self.inner.append_audit(e)
        }
        fn list_audit(&self) -> busbar_api::StoreResult<Vec<busbar_api::AuditRecord>> {
            self.inner.list_audit()
        }
    }
    let store = Arc::new(FlakyStore {
        inner: MemoryStore::new(),
        healthy: std::sync::atomic::AtomicBool::new(false),
    });
    let mut k = sample_key("k_flaky", "h_flaky");
    k.budget_period = BUDGET_PERIOD_TOTAL.to_string();
    store.inner.put_key(&k).unwrap();
    let gov = GovState::new(store.clone(), None).unwrap();
    let cost = flat_cost(10);

    assert!(gov
        .try_charge_request_within_budget(&cost, &k, 1_700_000_000)
        .is_ok());
    gov.flush_budgets(); // store down: delta stays unacked, cell re-marked dirty
    assert_eq!(store.inner.get_usage("k_flaky", 0).unwrap().requests, 0);

    store
        .healthy
        .store(true, std::sync::atomic::Ordering::Relaxed);
    gov.flush_budgets(); // retried: the full unacked delta lands exactly once
    assert_eq!(store.inner.get_usage("k_flaky", 0).unwrap().requests, 1);
    gov.flush_budgets(); // and does not double-count afterwards
    assert_eq!(store.inner.get_usage("k_flaky", 0).unwrap().requests, 1);
}

/// Token accrual + derived spend: 2000 input tokens at 500 micro-units/token derive to exactly
/// 100 cents; the LEDGER stores only tokens (no spend column exists to assert). Then the
/// REPRICE-ON-READ proof: the SAME ledger derived under a corrected (halved) rate card yields the
/// corrected spend - no data migration, tokens never changed.
#[test]
fn test_record_usage_derives_spend_and_reprices_on_read() {
    let store = Arc::new(MemoryStore::new());
    let gov = GovState::new(store.clone(), None).unwrap();
    let k = {
        let mut k = sample_key("k1", "h1");
        k.budget_period = BUDGET_PERIOD_TOTAL.to_string();
        store.put_key(&k).unwrap();
        k
    };
    let cost = card_cost("gpt-5", 500.0); // 500 micro-units/token
    gov.record_usage(&cost, &k, "gpt-5", &tt(2000), 1_700_000_000);
    gov.flush_budgets();
    let ledger = store.get_usage("k1", 0).unwrap();
    assert_eq!(ledger.tokens_for("gpt-5").unwrap().input, 2000);
    let u = gov.usage_for(&cost, "k1", 1_700_000_000).unwrap().unwrap();
    assert_eq!(u.spend_cents, 100, "2000 x 500 micro = 100 cents derived");
    assert_eq!(u.tokens, 2000);

    // REPRICE-ON-READ: correct the rate (halve it) and the SAME ledger derives half the spend.
    let corrected = card_cost("gpt-5", 250.0);
    let u = gov
        .usage_for(&corrected, "k1", 1_700_000_000)
        .unwrap()
        .unwrap();
    assert_eq!(
        u.spend_cents, 50,
        "historical derived spend halves on the next read under the corrected rate"
    );
    assert_eq!(u.tokens, 2000, "tokens never changed - they are the truth");
}

/// SUB-CENT PRECISION WITHOUT A CARRY (the millicent carry map is GONE): the ledger stores RAW
/// tokens, so no precision is ever truncated or carried. At 10 micro-units/token (the old
/// 1 cent/1k), one 500-token request derives 0 whole cents but the 500 tokens are fully recorded;
/// after a second 500-token request the SAME ledger derives exactly 1 cent - no truncation loss,
/// no carry state.
#[test]
fn test_sub_cent_precision_via_ledger_no_carry() {
    let store = Arc::new(MemoryStore::new());
    let gov = GovState::new(store.clone(), None).unwrap();
    let k = {
        let mut k = sample_key("k1", "h1");
        k.budget_period = BUDGET_PERIOD_TOTAL.to_string();
        store.put_key(&k).unwrap();
        k
    };
    let cost = card_cost("m", 10.0); // 10 micro-units/token = the old 1 cent per 1k tokens

    gov.record_usage(&cost, &k, "m", &tt(500), 1_700_000_000);
    let u1 = gov.usage_for(&cost, "k1", 1_700_000_000).unwrap().unwrap();
    assert_eq!(u1.spend_cents, 0, "0.5 cents derives to 0 whole cents");
    assert_eq!(
        u1.tokens, 500,
        "but every token is recorded - nothing truncated"
    );

    gov.record_usage(&cost, &k, "m", &tt(500), 1_700_000_000);
    let u2 = gov.usage_for(&cost, "k1", 1_700_000_000).unwrap().unwrap();
    assert_eq!(
        u2.spend_cents, 1,
        "two 0.5-cent requests derive a whole cent from the raw ledger - no carry needed"
    );
    assert_eq!(u2.tokens, 1000);
}

/// Window isolation without a carry: tokens accrue to the window they were charged in; a daily
/// rollover starts a fresh ledger cell, so one window's tokens can never leak into the next
/// window's derived spend.
#[test]
fn test_ledger_windows_are_isolated_across_days() {
    let store = Arc::new(MemoryStore::new());
    let gov = GovState::new(store.clone(), None).unwrap();
    let k = {
        let mut k = sample_key("k1", "h1");
        k.budget_period = BUDGET_PERIOD_DAILY.to_string();
        store.put_key(&k).unwrap();
        k
    };
    let cost = card_cost("m", 10.0);
    let day1 = 1_700_000_000;
    let day2 = day1 + 86_400;
    let w1 = budget_window(BUDGET_PERIOD_DAILY, day1);
    let w2 = budget_window(BUDGET_PERIOD_DAILY, day2);
    assert_ne!(w1, w2);

    gov.record_usage(&cost, &k, "m", &tt(500), day1);
    gov.flush_budgets(); // persist the day-1 cell before it rolls over
    gov.record_usage(&cost, &k, "m", &tt(500), day2);
    gov.flush_budgets();
    assert_eq!(
        ledger_tokens(&store, "k1", w1),
        500,
        "day-1 tokens stay in day 1"
    );
    assert_eq!(
        ledger_tokens(&store, "k1", w2),
        500,
        "day-2 window holds only its own tokens (no cross-window leak)"
    );
}

/// Token-ledger write-behind UNDER a real Tokio runtime: `record_usage` accrues to the
/// AUTHORITATIVE in-memory cell (no store round-trip); the durable ledger is updated only by
/// `flush_budgets` (the flusher's per-tick body). Pins the
/// `record_usage -> in-memory cell -> flush_budgets -> add_usage` path.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_record_usage_write_behind_under_runtime() {
    let store = Arc::new(MemoryStore::new());
    let gov = GovState::new(store.clone(), None).unwrap();
    let k = {
        let mut k = sample_key("k1", "h1");
        k.budget_period = BUDGET_PERIOD_TOTAL.to_string();
        store.put_key(&k).unwrap();
        k
    };
    let cost = card_cost("gpt-5", 500.0);
    gov.record_usage(&cost, &k, "gpt-5", &tt(2000), 1_700_000_000);
    assert_eq!(
        store.get_usage("k1", 0).unwrap(),
        UsageLedger::default(),
        "write-behind: the durable ledger is untouched until a flush"
    );
    assert_eq!(gov.flush_budgets(), 1, "one dirty cell flushed");
    let u = store.get_usage("k1", 0).unwrap();
    assert_eq!(
        u.tokens_for("gpt-5").unwrap().input,
        2000,
        "the per-model tier split lands durably"
    );
    assert_eq!(
        gov.usage_for(&cost, "k1", 1_700_000_000)
            .unwrap()
            .unwrap()
            .spend_cents,
        100,
        "2000 tokens at 500 micro/token derive exactly 100c"
    );
}

#[test]
fn test_check_rate_rpm_window() {
    let store = Arc::new(MemoryStore::new());
    let gov = GovState::new(store, None).unwrap();
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
    let gov = GovState::new(store, None).unwrap();
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
    let gov = GovState::new(store, None).unwrap();
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
    gov.record_usage(&flat_cost(0), &k, "m", &tt(1000), now);
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
    let gov = GovState::new(store, None).unwrap();
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
    gov.record_usage(&flat_cost(0), &k, "m", &tt(400), w0);
    gov.record_usage(&flat_cost(0), &k, "m", &tt(200), w0); // 600 >= 500 against the live W1 budget
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
    let gov = GovState::new(store, None).unwrap();
    let mut k = sample_key("k1", "h1");
    k.rpm_limit = Some(10);
    k.tpm_limit = Some(100);
    let w0 = 1_700_000_040 / 60 * 60;
    let w1 = w0 + RATE_WINDOW_SECS;

    // Seed a stale W0 entry directly (simulating an entry the sweep has not yet evicted), then
    // credit with a NEWER start window W1.
    {
        let mut map = gov.rate.write("k1");
        map.insert(
            "k1".to_string(),
            RateState {
                window_start: w0,
                requests: 5,
                tokens: 999,
            },
        );
    }
    gov.record_usage(&flat_cost(0), &k, "m", &tt(40), w1);
    let map = gov.rate.read("k1");
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
    let gov = GovState::new(store, None).unwrap();
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
    let gov = GovState::new(store, None).unwrap();
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
    gov.rate.sweep_ticker_for("k1").store(1, Ordering::Relaxed);
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
    // windows, so the map stays bounded. Under the sharded rate map the sweep is PER-SHARD, so we
    // exercise a single shard: seed a stale entry and a live key that share ONE shard, force that
    // shard's sweep on the live key's admission, and confirm the stale co-tenant is evicted.
    let store = Arc::new(MemoryStore::new());
    let gov = GovState::new(store, None).unwrap();
    let w0 = 1_700_000_040 / 60 * 60;

    let mut live = sample_key("survivor", "hs");
    live.rpm_limit = Some(5);
    live.tpm_limit = None;

    // Seed a STALE (older-window) entry directly INTO the live key's shard so the eager sweep on
    // that shard has something to evict. Using the survivor's shard guarantees co-tenancy.
    {
        let mut map = gov.rate.write("survivor");
        map.insert(
            "stale-cotenant".to_string(),
            RateState {
                window_start: w0 - RATE_WINDOW_SECS,
                requests: 0,
                tokens: 0,
            },
        );
    }

    // Force the next admission on this shard to run the eager sweep. POST-increment: the sweep
    // fires when the value AFTER the increment is a multiple of N, so set THIS SHARD's ticker to
    // N-1 (the next call's post-increment value is N, a multiple of the interval).
    gov.rate
        .sweep_ticker_for("survivor")
        .store(RATE_SWEEP_INTERVAL - 1, Ordering::Relaxed);
    let w_later = w0 + RATE_WINDOW_SECS * 2;
    assert!(gov.check_rate(&live, w_later).is_ok());

    let map = gov.rate.read("survivor");
    assert!(
        !map.contains_key("stale-cotenant"),
        "the shard's sweep evicted the stale co-tenant"
    );
    assert!(
        map.contains_key("survivor"),
        "the current-window key survives its own sweep"
    );
}

/// REGRESSION: the budget shard sweep must be PERIOD-AGNOSTIC.
/// The original sweep retained only cells matching THIS key's `window`, so a daily-period key's
/// Nth admission evicted the valid CURRENT cells of `total`/`monthly` keys sharing the shard —
/// silently resetting their accrued spend (the hard cap) and dropping dirty unflushed spend.
/// The fix mirrors the carry-map rule (audit 1.4.0): age-based retain, `total` (window 0) never
/// ages out. This test seeds current-window co-tenants of BOTH other periods plus one genuinely
/// stale cell into the daily key's shard, fires the sweep, and asserts only the stale cell dies.
#[test]
fn test_budget_sweep_is_period_agnostic_across_cotenants() {
    let store = Arc::new(MemoryStore::new());
    let gov = GovState::new(store, None).unwrap(); // 1c flat fee
    let now = 1_700_000_040u64;

    let mut daily = sample_key("survivor", "hs");
    daily.budget_period = BUDGET_PERIOD_DAILY.to_string();
    daily.max_budget_cents = Some(5000);

    // A seeded ledger cell with `requests` accrued (spend derives from requests x fee).
    let seeded = |window_start: u64, requests: u64, dirty: bool| BudgetCell {
        window_start,
        requests,
        flushed_requests: 0,
        models: Vec::new(),
        dirty,
    };

    // Seed co-tenants directly INTO the survivor's shard (same idiom as the rate sweep test).
    {
        let mut map = gov.budget.write("survivor");
        // A `total`-period key: window_start == 0, nearly-exhausted accrual. The buggy sweep
        // evicted this cell (0 != daily window) - resetting a nearly-exhausted hard cap.
        map.insert("total-cotenant".to_string(), seeded(0, 4999, true));
        // A `monthly`-period key in its CURRENT window: also evicted by the buggy sweep
        // (monthly window != daily window) despite being live and authoritative.
        map.insert(
            "monthly-cotenant".to_string(),
            seeded(budget_window(BUDGET_PERIOD_MONTHLY, now), 1234, true),
        );
        // A genuinely stale bounded-window cell (older than 31 d): the sweep SHOULD evict this.
        map.insert(
            "stale-cotenant".to_string(),
            seeded(now - 32 * SECS_PER_DAY, 1, false),
        );
    }

    // Force the survivor's next admission to run this shard's sweep (post-increment semantics).
    gov.budget
        .sweep_ticker_for("survivor")
        .store(RATE_SWEEP_INTERVAL - 1, Ordering::Relaxed);
    assert!(
        gov.try_charge_request_within_budget(&flat_cost(1), &daily, now)
            .is_ok(),
        "daily key admits"
    );

    let map = gov.budget.read("survivor");
    let total = map
        .get("total-cotenant")
        .expect("total-period cell must survive the sweep (window 0 never ages out)");
    assert_eq!(
        (total.requests, total.dirty),
        (4999, true),
        "total-period accrual + dirty flag intact"
    );
    let monthly = map
        .get("monthly-cotenant")
        .expect("current monthly cell must survive the sweep");
    assert_eq!(monthly.requests, 1234, "monthly accrual intact");
    assert!(
        !map.contains_key("stale-cotenant"),
        "genuinely stale (>31 d) bounded-window cell is still evicted"
    );
    assert!(
        map.contains_key("survivor"),
        "the charging key's own cell exists"
    );
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
    let gov = GovState::new(store, None).unwrap();
    let mut k = sample_key("k1", "h1");
    k.rpm_limit = Some(1_000_000);
    k.tpm_limit = None;
    let w0 = 1_700_000_040 / 60 * 60;

    // Seed a STALE co-tenant under an older window, INTO k1's shard, so k1's own admission runs the
    // (per-shard) sweep that would evict it. Distinct entry key so we observe whether the sweep ran.
    {
        let mut map = gov.rate.write("k1");
        map.insert(
            "stale".to_string(),
            RateState {
                window_start: w0 - RATE_WINDOW_SECS,
                requests: 0,
                tokens: 0,
            },
        );
    }

    // FIRST call: k1's shard ticker is 0, post-increment value is 1 (not a multiple of N) -> NO
    // sweep. The stale co-tenant must survive.
    assert_eq!(gov.rate.sweep_ticker_for("k1").load(Ordering::Relaxed), 0);
    assert!(gov.check_rate(&k, w0).is_ok());
    assert!(
        gov.rate.read("k1").contains_key("stale"),
        "first call must NOT sweep (post-increment value 1 is not a multiple of N)"
    );

    // Drive k1's shard ticker to N-1 so the next call's post-increment value is exactly N -> sweep.
    gov.rate
        .sweep_ticker_for("k1")
        .store(RATE_SWEEP_INTERVAL - 1, Ordering::Relaxed);
    assert!(gov.check_rate(&k, w0).is_ok());
    assert!(
        !gov.rate.read("k1").contains_key("stale"),
        "call N must run the sweep and evict the stale entry"
    );

    // WRAP boundary: pre-increment value 0xFFFFFFFF is NOT a multiple of N, but post-increment
    // wraps to 0 (a multiple of N) so the sweep must still fire — no skipped cycle.
    {
        let mut map = gov.rate.write("k1");
        map.insert(
            "stale2".to_string(),
            RateState {
                window_start: w0 - RATE_WINDOW_SECS,
                requests: 0,
                tokens: 0,
            },
        );
    }
    gov.rate
        .sweep_ticker_for("k1")
        .store(u32::MAX, Ordering::Relaxed);
    assert!(gov.check_rate(&k, w0).is_ok());
    assert_eq!(
        gov.rate.sweep_ticker_for("k1").load(Ordering::Relaxed),
        0,
        "ticker wrapped to 0"
    );
    assert!(
        !gov.rate.read("k1").contains_key("stale2"),
        "wrap boundary must still sweep (post-increment 0 is a multiple of N) — no skipped cycle"
    );
}

#[tokio::test]
async fn test_admission_charge_write_behind_under_runtime() {
    // Inside a Tokio runtime, the admission charge lands in the AUTHORITATIVE in-memory cell (no
    // store round-trip); the write-behind flusher persists the request-count delta. Spend derives.
    let store = Arc::new(MemoryStore::new());
    let mut k = sample_key("k1", "h1");
    k.max_budget_cents = Some(1000);
    k.budget_period = BUDGET_PERIOD_TOTAL.to_string();
    let gov = GovState::new(store.clone(), None).unwrap();
    let cost = flat_cost(30);

    assert!(gov
        .try_charge_request_within_budget(&cost, &k, 1_700_000_000)
        .is_ok());
    assert_eq!(
        store.get_usage("k1", 0).unwrap().requests,
        0,
        "write-behind: durable ledger untouched until a flush"
    );
    assert_eq!(gov.flush_budgets(), 1, "one dirty cell flushed");
    assert_eq!(
        store.get_usage("k1", 0).unwrap().requests,
        1,
        "the request-count delta lands durably after the flush"
    );
    // Derived spend follows: 1 request x 30c fee, still under the 1000c cap.
    assert!(gov
        .try_charge_request_within_budget(&cost, &k, 1_700_000_000)
        .is_ok());
}

#[test]
fn test_negative_fee_and_rate_clamp_to_zero() {
    // A hostile/misconfigured NEGATIVE per-request fee or per-token rate must clamp to 0, never
    // derive negative spend that could evade a cap. (`CostModel::flat` clamps the fee;
    // `RateNanos::from_cfg` clamps a negative rate.)
    let store = Arc::new(MemoryStore::new());
    let mut k = sample_key("k1", "h1");
    k.max_budget_cents = Some(100);
    k.budget_period = BUDGET_PERIOD_TOTAL.to_string();
    store.put_key(&k).unwrap();
    let gov = GovState::new(store.clone(), None).unwrap();
    let cost = flat_cost(-50); // hostile negative fee -> clamped to 0

    for _ in 0..5 {
        assert!(gov
            .try_charge_request_within_budget(&cost, &k, 1_700_000_000)
            .is_ok());
    }
    let u = gov.usage_for(&cost, "k1", 1_700_000_000).unwrap().unwrap();
    assert_eq!(u.spend_cents, 0, "negative fee clamps to 0 derived spend");
    assert_eq!(u.requests, 5, "requests are still counted");

    // A negative per-token rate likewise derives 0 (never subtracts).
    let neg_rate = card_cost("m", -100.0);
    gov.record_usage(&neg_rate, &k, "m", &tt(5000), 1_700_000_000);
    let u = gov
        .usage_for(&neg_rate, "k1", 1_700_000_000)
        .unwrap()
        .unwrap();
    assert_eq!(u.spend_cents, 0, "negative token rate clamps to 0");
    assert_eq!(u.tokens, 5000, "tokens are still counted");
}

#[test]
fn test_create_key_minted_id_is_free_so_mint_succeeds() {
    // A normal mint derives a fresh id and the collision guard does not fire (the id is free).
    let store = Arc::new(MemoryStore::new());
    let gov = GovState::new(store.clone(), None).unwrap();
    let spec = NewKeySpec {
        name: "first".to_string(),
        allowed_pools: vec![],
        max_budget_cents: None,
        budget_period: BUDGET_PERIOD_TOTAL.to_string(),
        rpm_limit: None,
        tpm_limit: None,
        budget_group: None,
        labels: std::collections::BTreeMap::new(),
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
    let gov = GovState::new(store.clone(), None).unwrap();
    let (key, secret) = gov
        .create_key(
            NewKeySpec {
                name: "k".to_string(),
                allowed_pools: vec![],
                max_budget_cents: None,
                budget_period: BUDGET_PERIOD_TOTAL.to_string(),
                rpm_limit: Some(10),
                tpm_limit: None,
                budget_group: None,
                labels: std::collections::BTreeMap::new(),
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
    let gov = GovState::new(store.clone(), None).unwrap();
    let (key, _secret) = gov
        .create_key(
            NewKeySpec {
                name: "k".to_string(),
                allowed_pools: vec![],
                max_budget_cents: Some(5000),
                budget_period: BUDGET_PERIOD_TOTAL.to_string(),
                rpm_limit: Some(10),
                tpm_limit: Some(2000),
                budget_group: None,
                labels: std::collections::BTreeMap::new(),
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
    let gov = GovState::new(store, None).unwrap();
    let cost = flat_cost(5);

    let mut uncapped = sample_key("uncapped", "h_unl");
    uncapped.rpm_limit = None;
    uncapped.tpm_limit = None;
    uncapped.max_budget_cents = None;
    let now = 1_700_000_040;
    for _ in 0..50 {
        assert!(gov.check_rate(&uncapped, now).is_ok());
        gov.record_usage(&cost, &uncapped, "m", &tt(1234), now); // would feed the map pre-fix
    }
    assert!(
        gov.rate.read("uncapped").get("uncapped").is_none(),
        "an uncapped key must never gain a rate-map entry"
    );

    // A capped key still gets fed: check_rate creates its entry and record_usage credits TPM.
    let mut capped = sample_key("capped", "h_cap");
    capped.rpm_limit = Some(100);
    capped.tpm_limit = Some(100_000);
    assert!(gov.check_rate(&capped, now).is_ok());
    gov.record_usage(&cost, &capped, "m", &tt(500), now);
    let map = gov.rate.read("capped");
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
    let gov = GovState::new(store, None).unwrap();
    let cost = flat_cost(5);

    // A CAPPED key with NO prior `check_rate` admission -> it has no rate-map entry yet.
    let mut capped = sample_key("late", "h_late");
    capped.rpm_limit = Some(10);
    capped.tpm_limit = Some(1000);
    let now = 1_700_000_040;

    // Feed non-zero tokens via record_usage WITHOUT a preceding check_rate: update-only must
    // leave the rate map untouched for this key (no entry is ever materialised outside
    // check_rate).
    gov.record_usage(&cost, &capped, "m", &tt(500), now);
    assert!(
        gov.rate.read("late").get("late").is_none(),
        "add_rate_tokens must not materialise an entry for a key with no prior check_rate"
    );

    // Once check_rate creates the entry (the real admission path), a subsequent credit lands.
    assert!(gov.check_rate(&capped, now).is_ok());
    gov.record_usage(&cost, &capped, "m", &tt(300), now);
    let map = gov.rate.read("late");
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
    let gov = GovState::new(store.clone(), None).unwrap();

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
    let gov = Arc::new(GovState::new(store, None).unwrap());
    let mut k = sample_key("k1", "h1");
    k.rpm_limit = Some(2);
    k.tpm_limit = None;
    let now = 1_700_000_040;

    // Poison the rate SHARD that key "k1" resolves to: panic inside its write guard.
    let g = gov.clone();
    let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _guard = g.rate.shard_lock_for("k1").write().unwrap();
        panic!("intentional poison");
    }));
    assert!(
        gov.rate.shard_lock_for("k1").is_poisoned(),
        "k1's shard lock must be poisoned for the test"
    );

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
    let gov = Arc::new(GovState::new(store, None).unwrap());

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

/// A `Store` decorator that (1) RECORDS every `add_usage` requests-delta in call-COMPLETION order
/// and (2) can BLOCK the first `add_usage` until the test releases it. This lets the test hold one
/// flush in flight while it accrues NEWER requests, proving the flusher's serialization gate keeps
/// two flushes from overlapping and the additive deltas land exactly once. All other methods
/// delegate to an inner `MemoryStore`.
struct RecordingBarrierStore {
    inner: MemoryStore,
    block_first: std::sync::atomic::AtomicBool,
    entered: std::sync::mpsc::SyncSender<()>,
    release: std::sync::Mutex<std::sync::mpsc::Receiver<()>>,
    writes: std::sync::Mutex<Vec<i64>>,
}

impl Store for RecordingBarrierStore {
    fn put_key(&self, key: &VirtualKey) -> StoreResult<()> {
        self.inner.put_key(key)
    }
    fn get_key(&self, id: &str) -> StoreResult<Option<VirtualKey>> {
        self.inner.get_key(id)
    }
    fn list_keys(&self) -> StoreResult<Vec<VirtualKey>> {
        self.inner.list_keys()
    }
    fn delete_key(&self, id: &str) -> StoreResult<()> {
        self.inner.delete_key(id)
    }
    fn get_usage(&self, bucket_id: &str, window_start: u64) -> StoreResult<UsageLedger> {
        self.inner.get_usage(bucket_id, window_start)
    }
    fn put_usage(
        &self,
        bucket_id: &str,
        window_start: u64,
        ledger: &UsageLedger,
    ) -> StoreResult<()> {
        self.inner.put_usage(bucket_id, window_start, ledger)
    }
    fn add_usage(&self, bucket_id: &str, window_start: u64, delta: &UsageDelta) -> StoreResult<()> {
        // The FIRST flush's add_usage signals it has entered, then blocks until the test releases
        // it - pinning that flush "in flight" so the test can attempt an overlapping flush.
        if self
            .block_first
            .swap(false, std::sync::atomic::Ordering::SeqCst)
        {
            let _ = self.entered.send(());
            let _ = self.release.lock().unwrap().recv();
        }
        let r = self.inner.add_usage(bucket_id, window_start, delta);
        // Record in COMPLETION order so the test can audit exactly which deltas landed.
        self.writes.lock().unwrap().push(delta.requests);
        r
    }
    fn add_metering(&self, delta: &MeteringDelta) -> StoreResult<()> {
        self.inner.add_metering(delta)
    }
    fn list_metering(&self, bucket: u64) -> StoreResult<Vec<MeteringRow>> {
        self.inner.list_metering(bucket)
    }
}

/// Regression (write-behind overlap): the periodic flusher must never let two `flush_budgets`
/// runs overlap - overlapping snapshots could race baseline advancement and double- or
/// under-count deltas. We hold the first flush's `add_usage` paused, accrue NEWER requests, and
/// let the flusher fire (and SKIP) overlapping ticks; after release + shutdown the durable ledger
/// must hold EXACTLY the total accrued requests - nothing lost, nothing double-counted.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_write_behind_flush_serializes_and_counts_exactly_once() {
    crate::metrics::init();
    let (entered_tx, entered_rx) = std::sync::mpsc::sync_channel::<()>(1);
    let (release_tx, release_rx) = std::sync::mpsc::channel::<()>();
    let store = Arc::new(RecordingBarrierStore {
        inner: MemoryStore::new(),
        block_first: std::sync::atomic::AtomicBool::new(true),
        entered: entered_tx,
        release: std::sync::Mutex::new(release_rx),
        writes: std::sync::Mutex::new(Vec::new()),
    });
    let gov = Arc::new(GovState::new(store.clone(), None).unwrap());
    let cost = flat_cost(1);
    let at = 1_700_000_000u64;
    let mut key = sample_key("k1", "h1");
    key.max_budget_cents = None; // uncapped: every charge lands
    key.budget_period = BUDGET_PERIOD_TOTAL.to_string(); // window 0, unambiguous durable read

    // Accrue an OLDER 3 requests, then start the flusher: its first tick snapshots that cell and
    // its `add_usage` BLOCKS mid-write (holding the flush in flight).
    for _ in 0..3 {
        assert!(gov
            .try_charge_request_within_budget(&cost, &key, at)
            .is_ok());
    }
    let (shutdown_tx, shutdown_rx) = tokio::sync::broadcast::channel::<()>(1);
    crate::governance::spawn_budget_flusher(gov.clone(), shutdown_rx);

    // Wait until the first flush is paused inside add_usage.
    tokio::task::spawn_blocking(move || entered_rx.recv().unwrap())
        .await
        .unwrap();

    // While that older flush is pinned, accrue 2 NEWER requests and re-mark the cell dirty.
    assert!(gov
        .try_charge_request_within_budget(&cost, &key, at)
        .is_ok());
    assert!(gov
        .try_charge_request_within_budget(&cost, &key, at)
        .is_ok());

    // Give the flusher time to fire (and SKIP) several overlapping ticks while the first blocks.
    tokio::time::sleep(std::time::Duration::from_millis(400)).await;

    // Release the first (older) flush; it completes writing its 3-request delta.
    release_tx.send(()).unwrap();

    // Shut down: the final flush WAITS for the in-flight flush to drain, then flushes the
    // remaining 2-request delta.
    shutdown_tx.send(()).unwrap();
    tokio::time::sleep(std::time::Duration::from_millis(300)).await;

    // The durable ledger holds EXACTLY 5 requests: additive deltas, serialized, exactly once.
    let durable = store.inner.get_usage("k1", 0).unwrap().requests;
    assert_eq!(
        durable, 5,
        "additive flushes must sum to exactly the accrued requests - no loss, no double count"
    );
    // The completed deltas sum to 5 as well (e.g. [3, 2]) - never a duplicated snapshot.
    let writes = store.writes.lock().unwrap().clone();
    assert_eq!(
        writes.iter().sum::<i64>(),
        5,
        "the sum of flushed deltas equals the accrued total: {writes:?}"
    );
}

// ─── Budget-group CHAIN enforcement (1.5.0 cost model) ───────────────────────────────────────────

/// CHAIN ENFORCEMENT, AND semantics: a key inside bob -> growth must pass EVERY bucket. With the
/// key uncapped and bob capped at 2 requests' worth of fee, the third admission is rejected
/// NAMING the blocking group ("bob"), and NOTHING is charged on the rejected attempt (all-or-
/// nothing: neither the key bucket nor growth gains a request).
#[test]
fn test_chain_enforcement_rejects_naming_the_blocking_group() {
    let store = Arc::new(MemoryStore::new());
    let gov = GovState::new(store.clone(), None).unwrap();
    let cost = group_cost(
        10, // 10c flat fee
        &[
            ("growth", 1_000_000, "monthly", None),
            ("bob", 25, "monthly", Some("growth")), // 25c cap: two 10c-fee requests fit
        ],
    );
    let mut k = sample_key("vk_bob", "h_bob");
    k.max_budget_cents = None; // key bucket uncapped: the GROUP must be what blocks
    k.budget_period = BUDGET_PERIOD_TOTAL.to_string();
    k.budget_group = Some("bob".to_string());
    store.put_key(&k).unwrap();
    let at = 1_700_000_000u64;

    // Group spend derives from TOKENS only (the fee counts on the key bucket alone), so cap bob
    // via token accrual: 2 units of tokens under a card... simpler: bob's cap is checked against
    // derived token spend, which stays 0 without a rate card - so exercise the reject via a ZERO
    // cap group instead.
    let zero = group_cost(10, &[("broke", 0, "monthly", None)]);
    let mut kb = sample_key("vk_broke", "h_broke");
    kb.max_budget_cents = None;
    kb.budget_group = Some("broke".to_string());
    store.put_key(&kb).unwrap();
    assert_eq!(
        gov.try_charge_request_within_budget(&zero, &kb, at),
        Err(BudgetBlocked::Group("broke".to_string())),
        "a zero-cap group blocks and is NAMED"
    );
    // All-or-nothing: the rejected attempt charged NOTHING anywhere.
    assert_eq!(
        gov.usage_for(&zero, "vk_broke", at)
            .unwrap()
            .unwrap()
            .requests,
        0
    );

    // The bob chain admits while under every cap and charges EVERY bucket in the chain.
    assert!(gov.try_charge_request_within_budget(&cost, &k, at).is_ok());
    gov.flush_budgets();
    assert_eq!(
        store.get_usage("vk_bob", 0).unwrap().requests,
        1,
        "key bucket charged"
    );
    let bob_window = budget_window("monthly", at);
    assert_eq!(
        store.get_usage("group:bob", bob_window).unwrap().requests,
        1,
        "group bucket charged in ITS OWN (monthly) window"
    );
    assert_eq!(
        store
            .get_usage("group:growth", bob_window)
            .unwrap()
            .requests,
        1,
        "the whole ancestor chain is charged atomically"
    );
}

/// TOKEN spend blocks a GROUP: with a rate card, tokens accrued through the chain push the group's
/// derived spend to its cap and the next admission is rejected naming that group - the key's own
/// (uncapped) bucket never blocks. Proves group caps are enforced on DERIVED token spend.
#[test]
#[allow(clippy::field_reassign_with_default)]
fn test_group_token_spend_blocks_chain_admission() {
    let store = Arc::new(MemoryStore::new());
    let gov = GovState::new(store.clone(), None).unwrap();
    // 100 micro-units/token; group cap = 100 cents = 10_000 tokens' worth. No flat fee.
    let cost = card_and_group_cost("gpt-5", 100.0, &[("team", 100, "total", None)]);

    let mut k = sample_key("vk_t", "h_t");
    k.max_budget_cents = None;
    k.budget_period = BUDGET_PERIOD_TOTAL.to_string();
    k.budget_group = Some("team".to_string());
    store.put_key(&k).unwrap();
    let at = 1_700_000_000u64;

    assert!(gov.try_charge_request_within_budget(&cost, &k, at).is_ok());
    // Accrue exactly the cap's worth of tokens: 10_000 x 100 micro = 100 cents.
    gov.record_usage(&cost, &k, "gpt-5", &tt(10_000), at);
    assert_eq!(
        gov.try_charge_request_within_budget(&cost, &k, at),
        Err(BudgetBlocked::Group("team".to_string())),
        "the group's derived token spend reached its cap; the 429 names the group"
    );
}

/// REGRESSION (audit cost-1.5.0 #1): a boundary-STRADDLING admission - pinned `charged_at` in the
/// OLD window, arriving after a concurrent admission already rolled the live cell to the NEW
/// window - must charge the live cell IN PLACE. The pre-fix charge arm rewound the live cell to
/// the straddler's older window (`BudgetCell::fresh(old_window)`), wiping the new window's
/// accrued tokens/requests AND flush baselines; and the pre-fix check arm derived the straddler's
/// spend as 0 (fresh window), admitting past an exhausted cap.
#[test]
fn test_boundary_straddle_charge_never_rewinds_the_live_cell() {
    let store = Arc::new(MemoryStore::new());
    let gov = GovState::new(store, None).unwrap();
    // 100 micro-units/token, no flat fee: 10_000 tokens = 100 cents of derived spend.
    let cost = card_cost("m", 100.0);
    let mut k = sample_key("vk_straddle", "h_s");
    k.max_budget_cents = Some(150);
    k.budget_period = BUDGET_PERIOD_DAILY.to_string();
    let w0_late = 3 * crate::governance::SECS_PER_DAY - 5; // just before the day boundary
    let w1_early = 3 * crate::governance::SECS_PER_DAY + 5; // just after (the LIVE window)

    // A W1 admission rolls the cell to the new day and accrues real spend there.
    gov.try_charge_request_within_budget(&cost, &k, w1_early)
        .expect("fresh window admits");
    gov.record_usage(&cost, &k, "m", &tt(10_000), w1_early);
    let before = gov
        .derived_bucket_usage(&cost, &k.id, &k.budget_period, false, w1_early)
        .unwrap();
    assert_eq!((before.tokens, before.requests), (10_000, 1));

    // The straddler (charged_at still in W0) is admitted - 100c < 150c cap - and must charge the
    // LIVE cell without rewinding it.
    gov.try_charge_request_within_budget(&cost, &k, w0_late)
        .expect("under-cap straddler admits");
    let after = gov
        .derived_bucket_usage(&cost, &k.id, &k.budget_period, false, w1_early)
        .unwrap();
    assert_eq!(
        (after.tokens, after.requests),
        (10_000, 2),
        "the live window's ledger survives a straddling charge (no rewind); the straddler's \
         request lands in the live cell"
    );

    // Exhaust the live window's cap; a further STRADDLING admission must SEE that spend and
    // reject (pre-fix it derived 0 for the 'stale' window and admitted).
    gov.record_usage(&cost, &k, "m", &tt(10_000), w1_early); // now 200c > 150c cap
    assert_eq!(
        gov.try_charge_request_within_budget(&cost, &k, w0_late),
        Err(BudgetBlocked::Key),
        "a straddler is checked against the live cell's derived spend, not a phantom fresh window"
    );
}

/// FAIL-CLOSED: a key bound to a budget_group this node's config does not know is NOT admitted
/// (MissingGroup named), and accrual degrades to the key bucket only (tokens never lost).
#[test]
fn test_missing_budget_group_fails_closed() {
    let store = Arc::new(MemoryStore::new());
    let gov = GovState::new(store.clone(), None).unwrap();
    let cost = flat_cost(1); // no groups configured
    let mut k = sample_key("vk_g", "h_g");
    k.budget_group = Some("ghost".to_string());
    k.budget_period = BUDGET_PERIOD_TOTAL.to_string();
    store.put_key(&k).unwrap();
    let at = 1_700_000_000u64;

    assert_eq!(
        gov.try_charge_request_within_budget(&cost, &k, at),
        Err(BudgetBlocked::MissingGroup("ghost".to_string())),
        "an unresolvable chain is never admitted (fail closed), naming the missing group"
    );
    // Accrual (post-admission on another node, or a race) still ledgers to the key bucket.
    gov.record_usage(&cost, &k, "m", &tt(7), at);
    gov.flush_budgets();
    assert_eq!(ledger_tokens(&store, "vk_g", 0), 7, "tokens are never lost");
}

/// HYDRATION covers GROUP buckets: a group's durable ledger persists a restart (fresh GovState),
/// so chain enforcement resumes from the persisted group accrual, not zero.
#[test]
#[allow(clippy::field_reassign_with_default)]
fn test_hydrate_budgets_restores_group_buckets() {
    let store: Arc<dyn Store> = Arc::new(MemoryStore::new());
    let cost = group_cost(10, &[("team", 25, "total", None)]); // 2 x 10c fit under 25c
    let mut k = sample_key("vk_h", "h_h");
    k.max_budget_cents = None;
    k.budget_period = BUDGET_PERIOD_TOTAL.to_string();
    k.budget_group = Some("team".to_string());
    store.put_key(&k).unwrap();
    let at = 1_700_000_000u64;

    {
        let gov = GovState::new(store.clone(), None).unwrap();
        // The team cap is on derived TOKEN spend (fee counts on the key bucket only) - seed the
        // group's ledger with tokens via a card so the persisted spend is meaningful.
        let card = card_and_group_cost("m", 100.0, &[("team", 25, "total", None)]);
        gov.record_usage(&card, &k, "m", &tt(2_500), at); // 2500 x 100 micro = 25 cents = the cap
        gov.flush_budgets();
        drop(card);
    }

    // Restart: a fresh GovState hydrates key AND group cells from the durable ledger.
    let gov2 = GovState::new(store.clone(), None).unwrap();
    let card = card_and_group_cost("m", 100.0, &[("team", 25, "total", None)]);
    gov2.hydrate_budgets(&card, at).expect("hydrate");
    assert_eq!(
        gov2.try_charge_request_within_budget(&card, &k, at),
        Err(BudgetBlocked::Group("team".to_string())),
        "post-restart enforcement resumes from the PERSISTED group ledger (25c derived >= 25c cap)"
    );
    let _ = cost;
}

/// M9 (boot fail-open): `hydrate_budgets` must PROPAGATE a store error, not warn-and-reset to empty
/// cells. A store that fails `get_usage` (a boot-time blip) previously left budgets at ZERO, letting
/// a maxed-out key spend its whole cap again. Now the error surfaces (boot fails).
#[test]
#[allow(clippy::field_reassign_with_default)]
fn test_hydrate_budgets_propagates_store_error() {
    use busbar_api::{StoreError, StoreResult, UsageLedger, VirtualKey};

    /// A store that delegates to an inner MemoryStore but FAILS `get_usage` (simulating a boot blip).
    struct FailGetUsage {
        inner: MemoryStore,
    }
    impl Store for FailGetUsage {
        fn put_key(&self, k: &VirtualKey) -> StoreResult<()> {
            self.inner.put_key(k)
        }
        fn get_key(&self, id: &str) -> StoreResult<Option<VirtualKey>> {
            self.inner.get_key(id)
        }
        fn list_keys(&self) -> StoreResult<Vec<VirtualKey>> {
            self.inner.list_keys()
        }
        fn delete_key(&self, id: &str) -> StoreResult<()> {
            self.inner.delete_key(id)
        }
        fn get_usage(&self, _bucket_id: &str, _window: u64) -> StoreResult<UsageLedger> {
            Err(StoreError("simulated store blip on get_usage".into()))
        }
        fn put_usage(&self, b: &str, w: u64, l: &UsageLedger) -> StoreResult<()> {
            self.inner.put_usage(b, w, l)
        }
        fn add_metering(&self, d: &busbar_api::MeteringDelta) -> StoreResult<()> {
            self.inner.add_metering(d)
        }
        fn list_metering(&self, bucket: u64) -> StoreResult<Vec<busbar_api::MeteringRow>> {
            self.inner.list_metering(bucket)
        }
    }

    let inner = MemoryStore::new();
    let mut k = sample_key("vk_m9", "m9_h");
    k.max_budget_cents = Some(10);
    k.budget_period = BUDGET_PERIOD_TOTAL.to_string();
    inner.put_key(&k).unwrap();
    let store: Arc<dyn Store> = Arc::new(FailGetUsage { inner });
    // The key must have a non-empty ledger so hydration actually reaches get_usage.
    store
        .put_usage(
            "vk_m9",
            budget_window(BUDGET_PERIOD_TOTAL, 0),
            &UsageLedger {
                requests: 1,
                models: vec![],
            },
        )
        .ok(); // put_usage delegates to inner; ignore if the fault store had returned Err (it doesn't)
    let gov = GovState::new(store, None).unwrap();
    let err = gov
        .hydrate_budgets(&crate::cost::CostModel::flat(1), 0)
        .expect_err(
            "a store get_usage error must PROPAGATE (fail boot), not reset budgets to zero",
        );
    assert!(
        err.to_string().contains("simulated store blip"),
        "the store error must surface verbatim; got: {err}"
    );
}

/// The HOOK SEAM projection: `budget_state` reports the key bucket + every ancestor group with
/// derived spend_micros + remaining_micros + each bucket's OWN window, innermost first.
#[test]
fn test_budget_state_projects_the_whole_chain() {
    let store = Arc::new(MemoryStore::new());
    let gov = GovState::new(store.clone(), None).unwrap();
    let cost = group_cost(
        10,
        &[
            ("acme", 1_000, "monthly", None),
            ("growth", 500, "monthly", Some("acme")),
        ],
    );
    let mut k = sample_key("vk_s", "h_s");
    k.max_budget_cents = Some(100);
    k.budget_period = BUDGET_PERIOD_TOTAL.to_string();
    k.budget_group = Some("growth".to_string());
    store.put_key(&k).unwrap();
    let at = 1_700_000_000u64;

    assert!(gov.try_charge_request_within_budget(&cost, &k, at).is_ok());
    let state = gov.budget_state(&cost, &k, at);
    assert_eq!(state.len(), 3, "key + growth + acme");
    assert_eq!(state[0].bucket_id, "vk_s");
    assert_eq!(state[0].budget_group, None);
    assert_eq!(
        state[0].spend_micros_at_current_rate,
        10 * 10_000,
        "key bucket: 1 request x 10c fee = 100_000 micros"
    );
    assert_eq!(
        state[0].remaining_micros,
        Some(100 * 10_000 - 100_000),
        "remaining under the key's 100c cap"
    );
    assert_eq!(state[0].budget_period, "total");
    assert_eq!(state[1].bucket_id, "group:growth");
    assert_eq!(state[1].budget_group.as_deref(), Some("growth"));
    assert_eq!(
        state[1].spend_micros_at_current_rate, 0,
        "group spend is tokens-only (no fee), still 0"
    );
    assert_eq!(state[1].remaining_micros, Some(500 * 10_000));
    assert_eq!(state[1].budget_period, "monthly");
    assert_eq!(state[2].bucket_id, "group:acme");
}
