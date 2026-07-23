use crate::config;

#[test]
fn test_config_parsing_status_503() {
    let cfg: config::OnExhaustedCfg = serde_yaml::from_str("reject").unwrap();
    assert!(matches!(cfg.to_runtime(), config::OnExhausted::Status503));
}

#[test]
fn test_config_parsing_least_bad() {
    let cfg: config::OnExhaustedCfg = serde_yaml::from_str("least_bad").unwrap();
    assert!(matches!(cfg.to_runtime(), config::OnExhausted::LeastBad));
}

#[test]
fn test_config_parsing_fallback_pool() {
    let cfg: config::OnExhaustedCfg = serde_yaml::from_str("{ fallback_pool: drain }").unwrap();
    if let config::OnExhausted::FallbackPool(name) = cfg.to_runtime() {
        assert_eq!(name, "drain");
    } else {
        panic!("Expected FallbackPool variant");
    }
}

#[test]
fn test_config_parsing_unknown_fails() {
    let result: Result<config::OnExhaustedCfg, _> = serde_yaml::from_str("invalid");
    assert!(result.is_err(), "Unknown action should fail parsing");
}

#[test]
fn test_config_parsing_bare_fallback_pool_fails() {
    // The old colon form `fallback_pool:drain` is no longer a bare keyword; only the
    // structured `{ fallback_pool: name }` map is accepted.
    let result: Result<config::OnExhaustedCfg, _> = serde_yaml::from_str("'fallback_pool:drain'");
    assert!(result.is_err(), "Colon-form keyword should fail parsing");
}
