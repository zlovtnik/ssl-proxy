use std::collections::HashSet;

use oracle::{sql_type::ToSql, Connection};

use crate::log::error_chain;

use super::blocked_db::upsert_blocked_events_transaction;
use super::proxy_transform::normalized_identity_source;
use super::proxy_types::{BlockedEventInsert, ProxyEventInsert};

pub(crate) fn insert_event_batch_transaction(
    connection: &Connection,
    batch_id: &str,
    rows: &[ProxyEventInsert],
    blocked_rows: &[BlockedEventInsert],
) -> Result<u64, String> {
    const INSERT_SQL: &str = r#"
        insert into proxy_events (
            batch_id,
            row_sequence,
            event_time,
            event_type,
            host,
            peer_ip,
            wg_pubkey,
            device_id,
            identity_source,
            peer_hostname,
            client_ua,
            bytes_up,
            bytes_down,
            status_code,
            blocked,
            obfuscation_profile,
            correlation_id,
            parent_event_id,
            event_sequence,
            duration_ms,
            reason,
            raw_json
        ) values (
            :1,
            :2,
            :3,
            :4,
            :5,
            :6,
            :7,
            :8,
            :9,
            :10,
            :11,
            :12,
            :13,
            :14,
            :15,
            :16,
            :17,
            :18,
            :19,
            :20,
            :21,
            :22
        )
    "#;

    let existing_row_sequences = existing_proxy_row_sequences(connection, batch_id)?;
    let pending_rows = pending_proxy_event_rows(rows.len(), &existing_row_sequences)?;

    if !pending_rows.is_empty() {
        let identity_sources = rows
            .iter()
            .map(|row| normalized_identity_source(row.identity_source.as_deref()))
            .collect::<Vec<_>>();
        let mut batch = connection
            .batch(INSERT_SQL, pending_rows.len())
            .build()
            .map_err(|error| {
                format!("prepare proxy_events batch insert: {}", error_chain(&error))
            })?;

        for (index, row_sequence) in pending_rows {
            let row = &rows[index];
            let params: [&dyn ToSql; 22] = [
                &batch_id,
                &row_sequence,
                &row.event_time,
                &row.event_type,
                &row.host,
                &row.peer_ip,
                &row.wg_pubkey,
                &row.device_id,
                &identity_sources[index],
                &row.peer_hostname,
                &row.client_ua,
                &row.bytes_up,
                &row.bytes_down,
                &row.status_code,
                &row.blocked,
                &row.obfuscation_profile,
                &row.correlation_id,
                &row.parent_event_id,
                &row.event_sequence,
                &row.duration_ms,
                &row.reason,
                &row.raw_json,
            ];
            batch.append_row(&params).map_err(|error| {
                format!(
                    "append proxy_events row host={}: {}",
                    row.host,
                    error_chain(&error)
                )
            })?;
        }
        batch.execute().map_err(|error| {
            format!("execute proxy_events batch insert: {}", error_chain(&error))
        })?;
    }
    upsert_blocked_events_transaction(connection, blocked_rows, &existing_row_sequences)?;
    connection
        .commit()
        .map_err(|error| format!("commit proxy_events batch: {}", error_chain(&error)))?;
    Ok(rows.len() as u64)
}

pub(crate) fn pending_proxy_event_rows(
    row_count: usize,
    existing_row_sequences: &HashSet<i64>,
) -> Result<Vec<(usize, i64)>, String> {
    let mut pending = Vec::with_capacity(row_count);
    for index in 0..row_count {
        let row_number = index
            .checked_add(1)
            .ok_or_else(|| "proxy_events row_sequence exceeds i64".to_string())?;
        let row_sequence = i64::try_from(row_number)
            .map_err(|_| "proxy_events row_sequence exceeds i64".to_string())?;
        if !existing_row_sequences.contains(&row_sequence) {
            pending.push((index, row_sequence));
        }
    }
    Ok(pending)
}

pub(crate) fn is_proxy_events_batch_row_duplicate(message: &str) -> bool {
    let normalized = message.to_ascii_uppercase();
    normalized.contains("ORA-00001") && normalized.contains("PROXY_EVENTS_BATCH_ROW_IDX")
}

fn existing_proxy_row_sequences(
    connection: &Connection,
    batch_id: &str,
) -> Result<HashSet<i64>, String> {
    let mut existing = HashSet::new();
    let rows = connection
        .query(
            "select row_sequence from proxy_events where batch_id = :1",
            &[&batch_id],
        )
        .map_err(|error| {
            format!(
                "query existing proxy_events batch rows: {}",
                error_chain(&error)
            )
        })?;
    for row_result in rows {
        let row = row_result
            .map_err(|error| format!("read existing proxy_events row: {}", error_chain(&error)))?;
        let row_sequence: i64 = row.get(0).map_err(|error| {
            format!(
                "read existing proxy_events row_sequence: {}",
                error_chain(&error)
            )
        })?;
        existing.insert(row_sequence);
    }
    Ok(existing)
}
