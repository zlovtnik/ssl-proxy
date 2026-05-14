use crate::worker::{handle_load_with_sink, OracleLoad};

use super::support::{blocked_payload, proxy_close_payload, proxy_payload, RecordingSink};

#[test]
fn emits_success_result() {
    let mut sink = RecordingSink::default();
    let result = handle_load_with_sink(
        OracleLoad {
            job_id: "job-1".to_string(),
            batch_id: "batch-1".to_string(),
            batch_no: 0,
            stream_name: "proxy.events".to_string(),
            payload_ref: proxy_payload(),
            cursor_start: "1".to_string(),
            cursor_end: "2".to_string(),
            attempt: 1,
        },
        &mut sink,
    );

    assert_eq!(result.status, "success");
    assert_eq!(result.row_count, 1);
    assert!(!result.retryable);
    assert_eq!(sink.batch_ids, vec!["batch-1".to_string()]);
    assert_eq!(sink.rows.len(), 1);
    assert_eq!(sink.rows[0].event_type, "tunnel_open");
    assert_eq!(sink.rows[0].host, "example.com");
    assert_eq!(sink.rows[0].blocked, 0);
    assert_eq!(sink.rows[0].correlation_id.as_deref(), Some("session-1"));
    assert_eq!(sink.rows[0].event_sequence, Some(1));
    assert_eq!(sink.rows[0].reason.as_deref(), Some("allowed_sni"));
    assert!(sink.rows[0].raw_json.contains("\"ja3_lite\":\"ja3-lite\""));
    assert!(sink.blocked_rows.is_empty());
}

#[test]
fn preserves_enriched_tunnel_close_context() {
    let mut sink = RecordingSink::default();
    let result = handle_load_with_sink(
        OracleLoad {
            job_id: "job-1c".to_string(),
            batch_id: "batch-1c".to_string(),
            batch_no: 0,
            stream_name: "proxy.events".to_string(),
            payload_ref: proxy_close_payload(),
            cursor_start: "1".to_string(),
            cursor_end: "2".to_string(),
            attempt: 1,
        },
        &mut sink,
    );

    assert_eq!(result.status, "success");
    let row = &sink.rows[0];
    assert_eq!(row.event_type, "tunnel_close");
    assert_eq!(row.correlation_id.as_deref(), Some("session-1"));
    assert_eq!(row.event_sequence, Some(2));
    assert_eq!(row.duration_ms, Some(789));
    assert_eq!(row.reason.as_deref(), Some("allowed_sni"));
    assert_eq!(row.bytes_up, 123);
    assert_eq!(row.bytes_down, 456);
    assert!(row.raw_json.contains("\"selected_ip\":\"192.0.2.10\""));
    assert!(row.raw_json.contains("\"tls_ver\":\"TLS1.3\""));
}

#[test]
fn emits_blocked_rows_for_blocked_events() {
    let mut sink = RecordingSink::default();
    let result = handle_load_with_sink(
        OracleLoad {
            job_id: "job-1b".to_string(),
            batch_id: "batch-1b".to_string(),
            batch_no: 0,
            stream_name: "proxy.events".to_string(),
            payload_ref: blocked_payload(),
            cursor_start: "1".to_string(),
            cursor_end: "2".to_string(),
            attempt: 1,
        },
        &mut sink,
    );

    assert_eq!(result.status, "success");
    assert_eq!(result.row_count, 1);
    assert_eq!(sink.batch_ids, vec!["batch-1b".to_string()]);
    assert_eq!(sink.blocked_rows.len(), 1);
    assert_eq!(sink.blocked_rows[0].host, "blocked.example");
    assert_eq!(sink.blocked_rows[0].blocked_bytes, 46);
    assert_eq!(sink.blocked_rows[0].category.as_deref(), Some("analytics"));
    assert_eq!(
        sink.blocked_rows[0].verdict.as_deref(),
        Some("HEURISTIC_FLAG_DATA_EXFIL")
    );
    assert_eq!(sink.blocked_rows[0].tls_ver.as_deref(), Some("TLS1.3"));
}
