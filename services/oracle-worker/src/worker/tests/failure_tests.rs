use crate::worker::{handle_load_with_sink, OracleLoad};

use super::support::{proxy_payload, RecordingSink};

#[test]
fn rejects_unknown_streams() {
    let mut sink = RecordingSink::default();
    let result = handle_load_with_sink(
        OracleLoad {
            job_id: "job-3".to_string(),
            batch_id: "batch-3".to_string(),
            batch_no: 0,
            stream_name: "other.events".to_string(),
            payload_ref: proxy_payload(),
            cursor_start: "20".to_string(),
            cursor_end: "21".to_string(),
            attempt: 1,
        },
        &mut sink,
    );

    assert_eq!(result.status, "failed");
    assert_eq!(result.error_class, "permanent");
    assert!(!result.retryable);
}

#[test]
fn returns_failed_result_when_oracle_insert_fails() {
    let mut sink = RecordingSink {
        error: Some("unique constraint violated".to_string()),
        ..RecordingSink::default()
    };
    let result = handle_load_with_sink(
        OracleLoad {
            job_id: "job-4".to_string(),
            batch_id: "batch-4".to_string(),
            batch_no: 0,
            stream_name: "proxy.events".to_string(),
            payload_ref: proxy_payload(),
            cursor_start: "1".to_string(),
            cursor_end: "2".to_string(),
            attempt: 1,
        },
        &mut sink,
    );

    assert_eq!(result.status, "failed");
    assert_eq!(result.error_class, "permanent");
    assert!(!result.retryable);
}
