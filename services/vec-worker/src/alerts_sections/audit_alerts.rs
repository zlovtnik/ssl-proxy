fn has_termination_token(sequence_tokens: &str, semantic_tokens: Option<&str>) -> bool {
    let raw_has_termination = sequence_tokens.split_whitespace().any(|token| {
        token.eq_ignore_ascii_case("DEAUTH")
            || token.eq_ignore_ascii_case("DEAUTHENTICATION")
            || token.eq_ignore_ascii_case("DISASSOC")
            || token.eq_ignore_ascii_case("DISASSOCIATION")
    });

    raw_has_termination
        || semantic_tokens
            .map(|tokens| {
                tokens
                    .split_whitespace()
                    .any(|token| token.eq_ignore_ascii_case("TERMINATION"))
            })
            .unwrap_or(false)
}

#[instrument(skip(pool))]
pub async fn check_zero_trust_overlay_risk(
    pool: &PgPool,
    config: &AlertConfig,
) -> Result<usize, WorkerError> {
    let result = sqlx::query(
        r#"
        WITH signals AS (
          SELECT
            d.wg_pubkey,
            d.mac_id AS source_mac,
            max(s.sensor_id) AS sensor_id,
            max(s.location_id) AS location_id,
            max(ap.composite_risk) AS high_risk_ap_score,
            0::double precision AS embedding_drift_score,
            array_remove(array_agg(DISTINCT ap.bssid), NULL) AS bssids
          FROM sync_events_expanded s
          JOIN devices d
            ON lower(d.mac_id) = lower(s.source_mac)
          JOIN mv_ap_risk_score ap
            ON ap.bssid = lower(coalesce(nullif(s.bssid, ''), nullif(s.destination_bssid, '')))
          WHERE d.wg_pubkey IS NOT NULL
            AND s.stream_name = 'wireless.audit'
            AND s.status = 'batched'
            AND s.observed_at >= now() - interval '1 hour'
            AND ap.composite_risk > $1
          GROUP BY d.wg_pubkey, d.mac_id

          UNION ALL

          SELECT
            d.wg_pubkey,
            d.mac_id AS source_mac,
            NULL::text AS sensor_id,
            NULL::text AS location_id,
            0::double precision AS high_risk_ap_score,
            max(a.score) AS embedding_drift_score,
            ARRAY[]::text[] AS bssids
          FROM vec_alerts a
          JOIN devices d
            ON lower(d.mac_id) = lower(a.source_mac)
          WHERE d.wg_pubkey IS NOT NULL
            AND a.alert_type = 'embedding_drift'
            AND a.created_at >= now() - interval '1 hour'
          GROUP BY d.wg_pubkey, d.mac_id
        ),
        rolled AS (
          SELECT
            wg_pubkey,
            source_mac,
            max(sensor_id) FILTER (WHERE sensor_id IS NOT NULL) AS sensor_id,
            max(location_id) FILTER (WHERE location_id IS NOT NULL) AS location_id,
            max(high_risk_ap_score) AS high_risk_ap_score,
            max(embedding_drift_score) AS embedding_drift_score,
            array_remove(array_agg(DISTINCT bssid.value), NULL) AS bssids
          FROM signals
          LEFT JOIN LATERAL unnest(signals.bssids) AS bssid(value) ON true
          GROUP BY wg_pubkey, source_mac
        )
        INSERT INTO vec_alerts (alert_type, source_mac, sensor_id, location_id, score, explanation_text, metadata)
        SELECT
          'zero_trust_overlay_risk',
          source_mac,
          sensor_id,
          location_id,
          greatest(coalesce(high_risk_ap_score, 0), coalesce(embedding_drift_score, 0)),
          concat(
            'Zero-trust overlay risk for wg_pubkey ', wg_pubkey,
            ': high_risk_ap_score=', round(coalesce(high_risk_ap_score, 0)::numeric, 3),
            ', embedding_drift_score=', round(coalesce(embedding_drift_score, 0)::numeric, 3)
          ),
          jsonb_build_object(
            'wg_pubkey', wg_pubkey,
            'source_mac', source_mac,
            'bssids', bssids,
            'high_risk_ap_score', high_risk_ap_score,
            'embedding_drift_score', embedding_drift_score,
            'ap_risk_threshold', $1
          )
        FROM rolled
        WHERE greatest(coalesce(high_risk_ap_score, 0), coalesce(embedding_drift_score, 0)) > 0
          AND NOT EXISTS (
            SELECT 1
            FROM vec_alerts a
            WHERE a.alert_type = 'zero_trust_overlay_risk'
              AND a.source_mac IS NOT DISTINCT FROM rolled.source_mac
              AND a.metadata->>'wg_pubkey' = rolled.wg_pubkey
              AND a.created_at > now() - interval '1 hour'
          )
        "#,
    )
    .bind(config.ap_risk_threshold)
    .execute(pool)
    .await
    .map_err(|e| WorkerError::alerts(format!("zero_trust_overlay_risk query failed: {e}")))?;

    let inserted = result.rows_affected() as usize;
    if inserted > 0 {
        info!(inserted, "zero-trust overlay risk alerts inserted");
    }
    Ok(inserted)
}

#[instrument(skip(pool))]
pub async fn check_dns_privacy_leaks(
    pool: &PgPool,
    config: &AlertConfig,
) -> Result<usize, WorkerError> {
    let result = sqlx::query(
        r#"
        WITH policy_devices AS (
          SELECT d.mac_id, d.wg_pubkey, p.allow_mdns
          FROM devices d
          JOIN vec_dns_policy p ON p.wg_pubkey = d.wg_pubkey
          WHERE d.wg_pubkey IS NOT NULL
            AND p.policy = 'secure_required'
        ),
        wireless_dns AS (
          SELECT
            pd.wg_pubkey,
            pd.mac_id AS source_mac,
            s.sensor_id,
            s.location_id,
            s.observed_at,
            CASE
              WHEN nullif(s.dns_query_name, '') IS NOT NULL THEN 'plaintext_dns'
              WHEN nullif(s.mdns_name, '') IS NOT NULL AND NOT pd.allow_mdns THEN 'mdns_disallowed'
            END AS leak_reason,
            lower(coalesce(nullif(s.dns_query_name, ''), nullif(s.mdns_name, ''))) AS query_name
          FROM policy_devices pd
          JOIN sync_events_expanded s
            ON lower(s.source_mac) = lower(pd.mac_id)
          WHERE s.stream_name = 'wireless.audit'
            AND s.status = 'batched'
            AND s.observed_at >= now() - ($1::integer * interval '1 minute')
            AND (
              nullif(s.dns_query_name, '') IS NOT NULL
              OR (nullif(s.mdns_name, '') IS NOT NULL AND NOT pd.allow_mdns)
            )
        ),
        candidates AS (
          SELECT DISTINCT ON (wg_pubkey, source_mac, leak_reason, query_name)
            wd.*,
            EXISTS (
              SELECT 1
              FROM vec_dns_resolver_ledger ledger
              WHERE ledger.wg_pubkey = wd.wg_pubkey
                AND ledger.observed_at >= now() - ($1::integer * interval '1 minute')
                AND ledger.protocol IN ('doh', 'dot', 'wireguard_dns', 'dnscrypt')
                AND (
                  lower(ledger.query_name) = wd.query_name
                  OR ledger.query_name_hash = encode(digest(wd.query_name, 'sha256'), 'hex')
                )
            ) AS resolver_ledger_match
          FROM wireless_dns wd
          WHERE leak_reason IS NOT NULL
          ORDER BY wg_pubkey, source_mac, leak_reason, query_name, observed_at DESC
        )
        INSERT INTO vec_alerts (alert_type, source_mac, sensor_id, location_id, score, explanation_text, metadata)
        SELECT
          'dns_privacy_leak',
          source_mac,
          sensor_id,
          location_id,
          CASE WHEN leak_reason = 'plaintext_dns' THEN 1.0 ELSE 0.5 END,
          concat('DNS privacy leak for wg_pubkey ', wg_pubkey, ': ', leak_reason, ' query=', query_name),
          jsonb_build_object(
            'wg_pubkey', wg_pubkey,
            'source_mac', source_mac,
            'query_name', query_name,
            'reason', leak_reason,
            'resolver_ledger_match', resolver_ledger_match,
            'lookback_minutes', $1
          )
        FROM candidates
        WHERE NOT EXISTS (
          SELECT 1
          FROM vec_alerts a
          WHERE a.alert_type = 'dns_privacy_leak'
            AND a.source_mac IS NOT DISTINCT FROM candidates.source_mac
            AND a.metadata->>'wg_pubkey' = candidates.wg_pubkey
            AND a.metadata->>'query_name' = candidates.query_name
            AND a.metadata->>'reason' = candidates.leak_reason
            AND a.created_at > now() - interval '1 hour'
        )
        "#,
    )
    .bind(config.dns_lookback_minutes)
    .execute(pool)
    .await
    .map_err(|e| WorkerError::alerts(format!("dns_privacy_leak query failed: {e}")))?;

    let inserted = result.rows_affected() as usize;
    if inserted > 0 {
        info!(inserted, "DNS privacy leak alerts inserted");
    }
    Ok(inserted)
}

#[derive(Debug, sqlx::FromRow)]
struct TravelObservation {
    cluster_id: i64,
    source_mac: String,
    sensor_id: String,
    location_id: String,
    observed_at: DateTime<Utc>,
    latitude: f64,
    longitude: f64,
}

#[instrument(skip(pool))]
pub async fn check_rf_impossible_travel(
    pool: &PgPool,
    config: &AlertConfig,
) -> Result<usize, WorkerError> {
    let observations = sqlx::query_as::<_, TravelObservation>(
        r#"
        WITH cluster_macs AS (
          SELECT cluster_id, lower(mac) AS source_mac
          FROM device_identity_clusters
          CROSS JOIN LATERAL unnest(mac_ids) AS cluster_mac(mac)
        ),
        recent AS (
          SELECT DISTINCT ON (
            cm.cluster_id,
            s.sensor_id,
            coalesce(s.location_id, ''),
            date_trunc('minute', s.observed_at)
          )
            cm.cluster_id,
            cm.source_mac,
            loc.sensor_id,
            loc.location_id,
            s.observed_at,
            loc.latitude,
            loc.longitude
          FROM cluster_macs cm
          JOIN sync_events_expanded s
            ON lower(s.source_mac) = cm.source_mac
          JOIN vec_rf_sensor_locations loc
            ON loc.enabled
           AND loc.sensor_id = s.sensor_id
           AND loc.location_id = coalesce(s.location_id, '')
          WHERE s.stream_name = 'wireless.audit'
            AND s.status = 'batched'
            AND s.observed_at >= now() - interval '1 hour'
          ORDER BY
            cm.cluster_id,
            s.sensor_id,
            coalesce(s.location_id, ''),
            date_trunc('minute', s.observed_at),
            s.observed_at ASC
        )
        SELECT *
        FROM recent
        ORDER BY cluster_id, observed_at ASC
        LIMIT 10000
        "#,
    )
    .fetch_all(pool)
    .await
    .map_err(|e| WorkerError::alerts(format!("rf impossible travel query failed: {e}")))?;

    let mut inserted = 0usize;
    let mut previous: Option<&TravelObservation> = None;
    for current in &observations {
        if let Some(prev) = previous {
            if prev.cluster_id == current.cluster_id {
                if let Some(speed_mps) = impossible_travel_speed_mps(prev, current) {
                    if speed_mps > config.impossible_travel_max_speed_mps {
                        inserted += insert_rf_impossible_travel_alert(
                            pool, config, prev, current, speed_mps,
                        )
                        .await?;
                    }
                }
            }
        }
        previous = Some(current);
    }

    if inserted > 0 {
        info!(inserted, "RF impossible travel alerts inserted");
    }
    Ok(inserted)
}

async fn insert_rf_impossible_travel_alert(
    pool: &PgPool,
    config: &AlertConfig,
    prev: &TravelObservation,
    current: &TravelObservation,
    speed_mps: f64,
) -> Result<usize, WorkerError> {
    let distance_m = haversine_meters(
        prev.latitude,
        prev.longitude,
        current.latitude,
        current.longitude,
    );
    let elapsed_secs = (current.observed_at - prev.observed_at).num_seconds();
    let metadata = serde_json::json!({
        "cluster_id": current.cluster_id,
        "source_mac": current.source_mac,
        "from_sensor_id": prev.sensor_id,
        "from_location_id": prev.location_id,
        "to_sensor_id": current.sensor_id,
        "to_location_id": current.location_id,
        "from_observed_at": prev.observed_at,
        "to_observed_at": current.observed_at,
        "distance_m": distance_m,
        "elapsed_secs": elapsed_secs,
        "speed_mps": speed_mps,
        "max_speed_mps": config.impossible_travel_max_speed_mps,
    });

    let result = sqlx::query(
        r#"
        INSERT INTO vec_alerts (alert_type, source_mac, sensor_id, location_id, score, explanation_text, metadata)
        SELECT
          'rf_impossible_travel',
          $1,
          $2,
          $3,
          $4,
          concat('RF impossible travel for cluster ', $5::text, ': speed_mps=', round($4::numeric, 2)),
          $6::jsonb
        WHERE NOT EXISTS (
          SELECT 1
          FROM vec_alerts a
          WHERE a.alert_type = 'rf_impossible_travel'
            AND a.metadata->>'cluster_id' = $5::text
            AND a.created_at > now() - interval '1 hour'
        )
        "#,
    )
    .bind(&current.source_mac)
    .bind(&current.sensor_id)
    .bind(&current.location_id)
    .bind(speed_mps)
    .bind(current.cluster_id)
    .bind(metadata)
    .execute(pool)
    .await
    .map_err(|e| WorkerError::alerts(format!("rf impossible travel insert failed: {e}")))?;

    Ok(result.rows_affected() as usize)
}

fn impossible_travel_speed_mps(
    prev: &TravelObservation,
    current: &TravelObservation,
) -> Option<f64> {
    if prev.sensor_id == current.sensor_id && prev.location_id == current.location_id {
        return None;
    }
    let elapsed_secs = (current.observed_at - prev.observed_at).num_seconds();
    if elapsed_secs <= 0 {
        return None;
    }
    let meters = haversine_meters(
        prev.latitude,
        prev.longitude,
        current.latitude,
        current.longitude,
    );
    Some(meters / elapsed_secs as f64)
}

fn haversine_meters(lat_a: f64, lon_a: f64, lat_b: f64, lon_b: f64) -> f64 {
    const EARTH_RADIUS_M: f64 = 6_371_000.0;
    let d_lat = (lat_b - lat_a).to_radians();
    let d_lon = (lon_b - lon_a).to_radians();
    let lat_a = lat_a.to_radians();
    let lat_b = lat_b.to_radians();

    let a = (d_lat / 2.0).sin().powi(2) + lat_a.cos() * lat_b.cos() * (d_lon / 2.0).sin().powi(2);
    let c = 2.0 * a.sqrt().atan2((1.0 - a).sqrt());
    EARTH_RADIUS_M * c
}
