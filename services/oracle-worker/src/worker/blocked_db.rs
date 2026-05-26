use std::collections::HashSet;

use oracle::{sql_type::ToSql, Connection};

use crate::log::error_chain;

use super::proxy_types::BlockedEventInsert;

pub(crate) fn upsert_blocked_events_transaction(
    connection: &Connection,
    rows: &[BlockedEventInsert],
    existing_proxy_row_sequences: &HashSet<i64>,
) -> Result<(), String> {
    if rows.is_empty() {
        return Ok(());
    }

    const UPSERT_SQL: &str = r#"
        merge into PROXY_BLOCKED_HOST_ROLLUPS be
        using (
            select
                :1 as host,
                :2 as blocked_bytes,
                :3 as frequency_hz,
                :4 as risk_score,
                :5 as category,
                :6 as verdict,
                :7 as tarpit_held_ms,
                :8 as iat_ms,
                :9 as consecutive_blocks,
                :10 as last_verdict,
                :11 as tls_ver,
                :12 as alpn,
                :13 as ja3_lite,
                :14 as resolved_ip,
                :15 as asn_org
            from dual
        ) src
        on (be.host = src.host)
        when matched then update set
            be.blocked_attempts = be.blocked_attempts + 1,
            be.blocked_bytes = be.blocked_bytes + nvl(src.blocked_bytes, 0),
            be.frequency_hz = nvl(
                src.frequency_hz,
                case
                    when (cast(systimestamp as date) - cast(be.first_seen as date)) * 86400 > 0
                    then (be.blocked_attempts + 1) /
                        ((cast(systimestamp as date) - cast(be.first_seen as date)) * 86400)
                    else be.frequency_hz
                end
            ),
            be.verdict = nvl(src.verdict, be.verdict),
            be.category = nvl(src.category, be.category),
            be.risk_score = nvl(
                src.risk_score,
                (be.blocked_bytes + nvl(src.blocked_bytes, 0)) * nvl(src.frequency_hz, be.frequency_hz)
            ),
            be.tarpit_held_ms = be.tarpit_held_ms + nvl(src.tarpit_held_ms, 0),
            be.iat_ms = nvl(src.iat_ms, be.iat_ms),
            be.consecutive_blocks = nvl(src.consecutive_blocks, be.consecutive_blocks + 1),
            be.last_verdict = nvl(src.last_verdict, nvl(src.verdict, be.last_verdict)),
            be.tls_ver = nvl(src.tls_ver, be.tls_ver),
            be.alpn = nvl(src.alpn, be.alpn),
            be.ja3_lite = nvl(src.ja3_lite, be.ja3_lite),
            be.resolved_ip = nvl(src.resolved_ip, be.resolved_ip),
            be.asn_org = nvl(src.asn_org, be.asn_org),
            be.updated_at = systimestamp
        when not matched then insert (
            host,
            blocked_attempts,
            blocked_bytes,
            frequency_hz,
            verdict,
            category,
            risk_score,
            tarpit_held_ms,
            iat_ms,
            consecutive_blocks,
            last_verdict,
            tls_ver,
            alpn,
            ja3_lite,
            resolved_ip,
            asn_org,
            updated_at,
            first_seen
        ) values (
            src.host,
            1,
            nvl(src.blocked_bytes, 0),
            nvl(src.frequency_hz, 0),
            nvl(src.verdict, 'BLOCKED'),
            nvl(src.category, 'unknown'),
            nvl(src.risk_score, nvl(src.blocked_bytes, 0) * nvl(src.frequency_hz, 0)),
            nvl(src.tarpit_held_ms, 0),
            src.iat_ms,
            nvl(src.consecutive_blocks, 1),
            nvl(src.last_verdict, nvl(src.verdict, 'BLOCKED')),
            src.tls_ver,
            src.alpn,
            src.ja3_lite,
            src.resolved_ip,
            src.asn_org,
            systimestamp,
            systimestamp
        )
    "#;

    for row in rows {
        if existing_proxy_row_sequences.contains(&row.row_sequence) {
            continue;
        }
        let params: [&dyn ToSql; 15] = [
            &row.host,
            &row.blocked_bytes,
            &row.frequency_hz,
            &row.risk_score,
            &row.category,
            &row.verdict,
            &row.tarpit_held_ms,
            &row.iat_ms,
            &row.consecutive_blocks,
            &row.last_verdict,
            &row.tls_ver,
            &row.alpn,
            &row.ja3_lite,
            &row.resolved_ip,
            &row.asn_org,
        ];
        connection.execute(UPSERT_SQL, &params).map_err(|error| {
            format!(
                "upsert PROXY_BLOCKED_HOST_ROLLUPS row host={}: {}",
                row.host,
                error_chain(&error)
            )
        })?;
    }

    Ok(())
}
