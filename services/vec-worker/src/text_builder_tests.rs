
use super::*;

#[test]
fn append_value_skips_none() {
    let mut lines = vec!["kind: event".to_string()];
    append_value(&mut lines, "field_a", None);
    append_value(&mut lines, "field_b", Some(""));
    append_value(&mut lines, "field_c", Some("value"));
    assert_eq!(lines, vec!["kind: event", "field_c: value"]);
}

#[test]
fn normalize_json_object_sorts_keys() {
    let mut map = serde_json::Map::new();
    map.insert("z".into(), serde_json::json!(1));
    map.insert("a".into(), serde_json::json!(2));
    let val = serde_json::Value::Object(map);
    let result = normalize_json(&val);
    // Verify keys appear in sorted order (a before z)
    let a_pos = result.find(r#""a":2"#).expect("key 'a:2' not found");
    let z_pos = result.find(r#""z":1"#).expect("key 'z:1' not found");
    assert!(a_pos < z_pos, "keys should be sorted: 'a' before 'z'");
}

#[test]
fn is_empty_value_filters_noise() {
    assert!(is_empty_value(""));
    assert!(is_empty_value("0"));
    assert!(is_empty_value("false"));
    assert!(is_empty_value("FALSE"));
    assert!(is_empty_value("None"));
    assert!(is_empty_value("null"));
    assert!(is_empty_value("unknown"));
    assert!(!is_empty_value("beacon"));
    assert!(!is_empty_value("management"));
    assert!(!is_empty_value("-79"));
    assert!(!is_empty_value("my-network"));
}

#[test]
fn append_value_skips_empty_values() {
    let mut lines = vec!["kind: event".to_string()];
    append_value(&mut lines, "security_flags", Some("0"));
    append_value(&mut lines, "protected", Some("false"));
    append_value(&mut lines, "channel_number", Some("6"));
    append_value(&mut lines, "signal_dbm", Some("-79"));
    assert_eq!(
        lines,
        vec!["kind: event", "channel_number: 6", "signal_dbm: -79"]
    );
}

#[test]
fn normalize_wps_name_strips_screen_size() {
    assert_eq!(normalize_wps_name(r#"60" Hisense Roku TV"#), "hisense roku");
    assert_eq!(
        normalize_wps_name(r#"55" Samsung Smart TV"#),
        "samsung smart"
    );
    assert_eq!(normalize_wps_name("65 inch LG TV"), "lg");
    assert_eq!(normalize_wps_name("Apple TV"), "apple");
    // "null" is preserved by normalize but filtered by is_empty_value
    assert_eq!(normalize_wps_name("null"), "null");
}

#[test]
fn normalize_wps_name_lowercases_no_op() {
    // A name that's already clean should remain unchanged (minus lowercasing)
    assert_eq!(normalize_wps_name("Google Chromecast"), "google chromecast");
    assert_eq!(normalize_wps_name("Amazon Fire Stick"), "amazon fire stick");
}

#[test]
fn truncate_token_sequence_no_op_when_short() {
    let budget = MAX_TOKENS - OVERHEAD_TOKENS;
    let tokens = "BEACON AUTH ASSOC_REQ EAPOL DATA_QOS";
    assert_eq!(truncate_token_sequence(tokens, budget), tokens);
}

#[test]
fn truncate_token_sequence_truncates_and_annotates() {
    let budget = MAX_TOKENS - OVERHEAD_TOKENS; // 368
    let tokens: String = (0..600).map(|_| "BEACON").collect::<Vec<_>>().join(" ");
    let result = truncate_token_sequence(&tokens, budget);
    assert!(
        result.contains("(+232 truncated)"),
        "expected truncation annotation, got: {}",
        &result[..result.len().min(80)]
    );
    // Should not exceed budget (368 content words + annotation words)
    let content_words = result
        .split_whitespace()
        .take_while(|w| !w.starts_with("(+"))
        .count();
    assert_eq!(content_words, budget);
}

#[test]
fn clamp_text_no_op_when_within_budget() {
    let text = "kind: frame_sequence\ntokens: BEACON AUTH\nframe_count: 2";
    assert_eq!(clamp_text(text), text);
}

#[test]
fn clamp_text_clamps_oversized_text() {
    let long_value: String = (0..500)
        .map(|i| format!("word{}", i))
        .collect::<Vec<_>>()
        .join(" ");
    let text = format!("kind: event\nfield: {}", long_value);
    let clamped = clamp_text(&text);
    let word_count = clamped.split_whitespace().count();
    assert!(
        word_count <= word_budget(MAX_TOKENS),
        "clamped text has {} words, expected <= {}",
        word_count,
        word_budget(MAX_TOKENS)
    );
}

#[test]
fn word_budget_512_is_170() {
    // (512 * 1) / 3 = 170 words at the 3-tokens-per-word ratio
    assert_eq!(word_budget(512), 170);
}

#[test]
fn insert_log_prob_line_does_not_reclamp_frame_sequence_text() {
    let tokens = (0..(MAX_TOKENS - OVERHEAD_TOKENS))
        .map(|_| "BEACON")
        .collect::<Vec<_>>()
        .join(" ");
    let mut text = format!(
        "kind: frame_sequence\ntokens: {}\nsource_mac: aa:bb:cc:dd:ee:ff\nframe_count: {}",
        tokens,
        MAX_TOKENS - OVERHEAD_TOKENS
    );

    insert_log_prob_line(&mut text, -12.345678);

    assert!(text.contains("log_prob: -12.345678"));
    assert!(text.contains("frame_count: 368"));
    let content_words = text
        .split_whitespace()
        .filter(|word| *word == "BEACON")
        .count();
    assert_eq!(content_words, MAX_TOKENS - OVERHEAD_TOKENS);
}

#[test]
fn frame_sequence_token_budget_is_368() {
    // Verify the direct budget for frame sequences (1 token per word, no multiplier)
    assert_eq!(MAX_TOKENS - OVERHEAD_TOKENS, 368);
}
