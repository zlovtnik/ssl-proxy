use std::collections::HashSet;

use crate::worker::{is_proxy_events_batch_row_duplicate, pending_proxy_event_rows};

#[test]
fn pending_proxy_event_rows_includes_all_rows_when_batch_is_new() {
    let existing = HashSet::new();
    assert_eq!(
        pending_proxy_event_rows(3, &existing).unwrap(),
        vec![(0, 1), (1, 2), (2, 3)]
    );
}

#[test]
fn pending_proxy_event_rows_skips_fully_inserted_batch() {
    let existing = HashSet::from([1, 2, 3]);
    assert!(pending_proxy_event_rows(3, &existing).unwrap().is_empty());
}

#[test]
fn pending_proxy_event_rows_keeps_only_missing_retry_rows() {
    let existing = HashSet::from([1, 3]);
    assert_eq!(
        pending_proxy_event_rows(4, &existing).unwrap(),
        vec![(1, 2), (3, 4)]
    );
}

#[test]
fn detects_proxy_events_batch_row_duplicate_error() {
    assert!(is_proxy_events_batch_row_duplicate(
        "OCI Error: ORA-00001: unique constraint (USCIS_APP.PROXY_EVENTS_BATCH_ROW_IDX) violated"
    ));
    assert!(!is_proxy_events_batch_row_duplicate(
        "OCI Error: ORA-00001: unique constraint (USCIS_APP.OTHER_IDX) violated"
    ));
    assert!(!is_proxy_events_batch_row_duplicate(
        "OCI Error: ORA-00060: deadlock detected while waiting for resource"
    ));
}
