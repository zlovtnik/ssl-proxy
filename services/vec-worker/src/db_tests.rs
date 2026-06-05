
use super::*;

#[test]
fn backoff_seconds_clamps_low() {
    assert_eq!(backoff_seconds(0), 10);
    assert_eq!(backoff_seconds(1), 10);
}

#[test]
fn backoff_seconds_linear() {
    assert_eq!(backoff_seconds(2), 20);
    assert_eq!(backoff_seconds(5), 50);
}

#[test]
fn backoff_seconds_clamps_high() {
    assert_eq!(backoff_seconds(30), 300);
    assert_eq!(backoff_seconds(100), 300);
}

#[test]
fn format_vector_literal_empty() {
    assert_eq!(format_vector_literal(&[]), "[]");
}

#[test]
fn format_vector_literal_integers() {
    let v = format_vector_literal(&[1.0, 2.0, 3.0]);
    assert_eq!(v, "[1.0,2.0,3.0]");
}

#[test]
fn format_vector_literal_fractional() {
    let v = format_vector_literal(&[0.123456, -1.5, 3.14159]);
    assert!(v.starts_with('['));
    assert!(v.ends_with(']'));
    assert!(v.contains("0.123456"));
    assert!(v.contains("-1.5"));
}

#[test]
fn build_metadata_skips_nones() {
    let input = EmbeddingInput {
        text: "test".into(),
        source_observed_at: None,
        source_stream_name: Some("wireless.audit".into()),
        source_sensor_id: None,
        source_location_id: Some("loc-1".into()),
        source_mac: None,
    };
    let meta = build_metadata(&input);
    let obj = meta.as_object().unwrap();
    assert_eq!(obj.len(), 2);
    assert_eq!(obj["source_stream_name"], "wireless.audit");
    assert_eq!(obj["source_location_id"], "loc-1");
}
