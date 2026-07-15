use super::{attempt_cap, effective_attempt_timeout_ms};
use crate::state::WeightedLane;

fn member(idx: usize, attempt_timeout_ms: Option<u64>) -> WeightedLane {
    WeightedLane {
        reasoning: None,
        idx,
        weight: 1,
        attempt_timeout_ms,
    }
}

fn rmember(idx: usize, reasoning: Option<bool>) -> WeightedLane {
    WeightedLane {
        reasoning,
        idx,
        weight: 1,
        attempt_timeout_ms: None,
    }
}

/// effective_reasoning: the pool-member override wins over the model-level flag; absent member
/// override inherits the model flag; no candidate row falls back to the model flag.
#[test]
fn effective_reasoning_member_override_wins() {
    use super::effective_reasoning;
    let cands = vec![
        rmember(0, Some(true)),
        rmember(1, Some(false)),
        rmember(2, None),
    ];
    assert!(
        effective_reasoning(&cands, 0, false),
        "member true beats model false"
    );
    assert!(
        !effective_reasoning(&cands, 1, true),
        "member false beats model true"
    );
    assert!(
        effective_reasoning(&cands, 2, true),
        "no member override inherits model true"
    );
    assert!(
        !effective_reasoning(&cands, 2, false),
        "no member override inherits model false"
    );
    assert!(
        !effective_reasoning(&[], 5, false),
        "no candidate row uses the model flag"
    );
}

/// The layering the feature promises: the pool-member override wins over the model-level
/// default, so the SAME model can carry a 10000ms cap in one pool and 50ms in another.
#[test]
fn test_member_override_wins_over_model_default() {
    let cands = vec![member(0, Some(50)), member(1, None)];
    assert_eq!(
        effective_attempt_timeout_ms(&cands, 0, Some(10_000)),
        Some(50),
        "the pool-member override must beat the model-level default"
    );
}

/// A member WITHOUT an override inherits the model-level default.
#[test]
fn test_model_default_applies_when_member_has_no_override() {
    let cands = vec![member(0, Some(50)), member(1, None)];
    assert_eq!(
        effective_attempt_timeout_ms(&cands, 1, Some(10_000)),
        Some(10_000),
        "a member with no override must fall back to the model-level cap"
    );
}

/// Neither level set → uncapped (None): the attempt runs under the ordinary transport timeout.
#[test]
fn test_no_cap_anywhere_is_none() {
    let cands = vec![member(0, None)];
    assert_eq!(effective_attempt_timeout_ms(&cands, 0, None), None);
}

/// The default `""` cell (single-model route) has no member rows at all — the model-level
/// value is the only source.
#[test]
fn test_empty_cands_uses_model_default() {
    assert_eq!(effective_attempt_timeout_ms(&[], 3, Some(750)), Some(750));
    assert_eq!(effective_attempt_timeout_ms(&[], 3, None), None);
}

/// The cap is floored by the request's remaining budget, and never zero.
#[test]
fn test_attempt_cap_budget_floor() {
    // Plenty of budget: the cap is the configured value.
    assert_eq!(attempt_cap(200, 30).as_millis(), 200);
    // Cap larger than the remaining budget: clamped to the budget.
    assert_eq!(attempt_cap(10_000, 2).as_millis(), 2_000);
    // Exhausted budget: clamped to 1ms, never a zero-duration (instant-fail) timer.
    assert_eq!(attempt_cap(10_000, 0).as_millis(), 1);
}
