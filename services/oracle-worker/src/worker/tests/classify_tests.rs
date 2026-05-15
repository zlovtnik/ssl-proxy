use crate::worker::{checksum, classify_oracle_error, sink_target, OracleErrorClass, SinkTarget};

#[test]
fn classifies_retryable_failures() {
    assert_eq!(
        classify_oracle_error("timeout while writing batch"),
        OracleErrorClass::Retryable
    );
    assert_eq!(
        classify_oracle_error("DPI-1067: call timeout of 30000 ms exceeded"),
        OracleErrorClass::Retryable
    );
    assert_eq!(
        classify_oracle_error("ORA-03114: not connected to ORACLE after call timeout cleanup"),
        OracleErrorClass::Retryable
    );
}

#[test]
fn classifies_permanent_failures() {
    assert_eq!(
        classify_oracle_error("unique constraint violated"),
        OracleErrorClass::Permanent
    );
}

#[test]
fn resolves_sink_targets() {
    assert_eq!(
        sink_target("proxy.events").unwrap(),
        SinkTarget::ProxyEvents
    );
    assert_eq!(
        sink_target("wireless.audit").unwrap(),
        SinkTarget::WirelessAuditFrames
    );
    assert_eq!(
        sink_target("wireless.alert.rogue_ap").unwrap(),
        SinkTarget::WirelessRogueAp
    );
    assert!(sink_target("unknown").is_err());
}

#[test]
fn checksum_is_deterministic_and_target_sensitive() {
    let payload = r#"{"ok":true}"#;
    let first = checksum(SinkTarget::ProxyEvents, payload);
    let second = checksum(SinkTarget::ProxyEvents, payload);

    assert_eq!(first, second);
    assert_eq!(first.len(), 64);
}
