use super::{admin_api_key_matches, constant_time_eq};

#[test]
fn constant_time_eq_rejects_same_prefix_with_different_lengths() {
    assert!(!constant_time_eq("prefix", "prefix-suffix"));
}

#[test]
fn constant_time_eq_handles_long_inputs() {
    let a = "a".repeat(300);
    let b = "a".repeat(300);

    assert!(constant_time_eq(&a, &b));
}

#[test]
fn admin_api_key_matches_rejects_empty_keys() {
    assert!(!admin_api_key_matches("", ""));
    assert!(!admin_api_key_matches("test-key", ""));
    assert!(admin_api_key_matches("test-key", "test-key"));
}
