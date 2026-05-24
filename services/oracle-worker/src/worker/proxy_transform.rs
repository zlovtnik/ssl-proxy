use chrono::{DateTime, Utc};

use super::payload::payload_rows;
use super::proxy_types::{BlockedEventInsert, ProxyEventInsert, ProxyEventRow};
use super::types::SinkTarget;

pub fn proxy_event_rows_from_payload(
    target: SinkTarget,
    payload: &str,
) -> Result<Vec<ProxyEventInsert>, String> {
    let rows = payload_rows(target, payload)?;
    proxy_event_rows_from_values(target, &rows)
}

#[allow(dead_code)]
pub fn blocked_event_rows_from_payload(
    target: SinkTarget,
    payload: &str,
) -> Result<Vec<BlockedEventInsert>, String> {
    let rows = payload_rows(target, payload)?;
    blocked_event_rows_from_values(target, &rows)
}

pub(crate) fn proxy_event_rows_from_values(
    target: SinkTarget,
    rows: &[serde_json::Value],
) -> Result<Vec<ProxyEventInsert>, String> {
    match target {
        SinkTarget::ProxyEvents => {}
        _ => return Ok(Vec::new()),
    }

    let mut inserts = Vec::with_capacity(rows.len());
    for row in rows {
        inserts.push(proxy_event_insert_from_value(row)?);
    }
    Ok(inserts)
}

pub(crate) fn blocked_event_rows_from_values(
    target: SinkTarget,
    rows: &[serde_json::Value],
) -> Result<Vec<BlockedEventInsert>, String> {
    match target {
        SinkTarget::ProxyEvents => {}
        _ => return Ok(Vec::new()),
    }

    let mut inserts = Vec::with_capacity(rows.len());
    for (index, row) in rows.iter().enumerate() {
        let proxy_row = proxy_event_insert_from_value(row)?;
        if let Some(blocked_row) = blocked_event_insert_from_value(row, &proxy_row)? {
            inserts.push(BlockedEventInsert {
                row_sequence: i64::try_from(index + 1)
                    .map_err(|_| "proxy blocked rollup row_sequence exceeds i64".to_string())?,
                ..blocked_row
            });
        }
    }
    Ok(inserts)
}

fn proxy_event_insert_from_value(row: &serde_json::Value) -> Result<ProxyEventInsert, String> {
    let raw_json = serde_json::to_string(row)
        .map_err(|error| format!("encode raw proxy row json: {error}"))?;
    let parsed: ProxyEventRow = serde_json::from_value(row.clone())
        .map_err(|error| format!("decode proxy.events row: {error}"))?;
    if parsed.event_type.trim().is_empty() || parsed.host.trim().is_empty() {
        return Err("proxy.events row missing event type or host".to_string());
    }
    let event_time = DateTime::parse_from_rfc3339(&parsed.time)
        .map_err(|error| format!("decode proxy.events time: {error}"))?
        .with_timezone(&Utc);

    Ok(ProxyEventInsert {
        event_time,
        event_type: parsed.event_type,
        host: parsed.host,
        peer_ip: parsed.peer_ip,
        wg_pubkey: parsed.wg_pubkey,
        device_id: parsed.device_id,
        identity_source: parsed.identity_source,
        peer_hostname: parsed.peer_hostname,
        client_ua: parsed.client_ua,
        bytes_up: u64_to_i64(parsed.bytes_up.unwrap_or(0), "bytes_up")?,
        bytes_down: u64_to_i64(parsed.bytes_down.unwrap_or(0), "bytes_down")?,
        status_code: parsed.status_code.map(i64::from),
        blocked: if parsed.blocked.unwrap_or(false) {
            1
        } else {
            0
        },
        obfuscation_profile: parsed.obfuscation_profile,
        correlation_id: parsed.correlation_id,
        parent_event_id: parsed.parent_event_id,
        event_sequence: parsed.event_sequence,
        duration_ms: parsed.duration_ms,
        reason: parsed.reason,
        raw_json,
    })
}

fn blocked_event_insert_from_value(
    row: &serde_json::Value,
    proxy_row: &ProxyEventInsert,
) -> Result<Option<BlockedEventInsert>, String> {
    let parsed: ProxyEventRow = serde_json::from_value(row.clone())
        .map_err(|error| format!("decode blocked.events row: {error}"))?;
    if !parsed.blocked.unwrap_or(false) {
        return Ok(None);
    }

    let blocked_bytes = parsed
        .blocked_bytes
        .or_else(|| {
            parsed
                .metrics
                .as_ref()
                .and_then(|metrics| metrics.blocked_bytes)
        })
        .or_else(|| {
            parsed
                .metrics
                .as_ref()
                .and_then(|metrics| metrics.total_blocked_bytes_approx)
        })
        .unwrap_or_else(|| proxy_row.bytes_up.saturating_add(proxy_row.bytes_down));

    let frequency_hz = parsed.frequency_hz.or_else(|| {
        parsed
            .metrics
            .as_ref()
            .and_then(|metrics| metrics.frequency_hz)
    });
    let risk_score = parsed.risk_score.or_else(|| {
        parsed
            .metrics
            .as_ref()
            .and_then(|metrics| metrics.risk_score)
    });
    let consecutive_blocks = parsed
        .consecutive_blocks
        .or_else(|| {
            parsed
                .metrics
                .as_ref()
                .and_then(|metrics| metrics.consecutive_blocks)
        })
        .or(parsed.attempt_count)
        .or_else(|| {
            parsed
                .metrics
                .as_ref()
                .and_then(|metrics| metrics.attempt_count)
        });
    let iat_ms = parsed
        .iat_ms
        .or_else(|| parsed.metrics.as_ref().and_then(|metrics| metrics.iat_ms));
    let tarpit_held_ms = parsed.tarpit_held_ms.unwrap_or(0);
    let fingerprint = parsed.fingerprint.as_ref();
    let category = parsed
        .category
        .clone()
        .or_else(|| Some("unknown".to_string()));
    let verdict = parsed
        .verdict
        .clone()
        .or_else(|| Some("BLOCKED".to_string()));

    Ok(Some(BlockedEventInsert {
        row_sequence: 0,
        host: proxy_row.host.clone(),
        blocked_bytes,
        frequency_hz,
        risk_score,
        category,
        verdict: verdict.clone(),
        tarpit_held_ms,
        iat_ms,
        consecutive_blocks,
        last_verdict: verdict,
        tls_ver: fingerprint.and_then(|value| value.tls_ver.clone()),
        alpn: fingerprint.and_then(|value| value.alpn.clone()),
        ja3_lite: fingerprint.and_then(|value| value.ja3_lite.clone()),
        resolved_ip: parsed.resolved_ip.clone(),
        asn_org: parsed.asn_org.clone(),
    }))
}

pub(crate) fn normalized_identity_source<'a>(identity_source: Option<&'a str>) -> &'a str {
    identity_source.unwrap_or("unknown")
}

pub(crate) fn u64_to_i64(value: u64, field: &str) -> Result<i64, String> {
    i64::try_from(value).map_err(|_| format!("{field} exceeds Oracle NUMBER signed range"))
}

pub(crate) fn summarize_event_types(rows: &[ProxyEventInsert]) -> String {
    let mut event_summary: std::collections::HashMap<&str, usize> =
        std::collections::HashMap::new();
    for row in rows {
        *event_summary.entry(row.event_type.as_str()).or_insert(0) += 1;
    }
    let mut summary = event_summary
        .iter()
        .map(|(event_type, count)| format!("{event_type}={count}"))
        .collect::<Vec<_>>();
    summary.sort();
    summary.join(" ")
}
