
use crate::config;

#[test]
fn test_config_parsing_status_503() {
    let result = config::OnExhausted::parse("reject").unwrap();
    assert!(matches!(result, config::OnExhausted::Status503));
}

#[test]
fn test_config_parsing_least_bad() {
    let result = config::OnExhausted::parse("least_bad").unwrap();
    assert!(matches!(result, config::OnExhausted::LeastBad));
}

#[test]
fn test_config_parsing_fallback_pool() {
    let result = config::OnExhausted::parse("fallback_pool:drain").unwrap();
    if let config::OnExhausted::FallbackPool(name) = result {
        assert_eq!(name, "drain");
    } else {
        panic!("Expected FallbackPool variant");
    }
}

#[test]
fn test_config_parsing_unknown_fails() {
    let result = config::OnExhausted::parse("invalid");
    assert!(result.is_err(), "Unknown action should fail parsing");
}
