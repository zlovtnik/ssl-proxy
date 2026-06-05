#[instrument(skip(pool))]
pub async fn check_rogue_rf_paths(
    pool: &PgPool,
    config: &AlertConfig,
) -> Result<usize, WorkerError> {
    let result = sqlx::query(
        r#"
        WITH RECURSIVE seed AS (
          SELECT bssid AS root_bssid, composite_risk
          FROM mv_ap_risk_score
          WHERE composite_risk > $1
        ),
        walk AS (
          SELECT
            root_bssid,
            composite_risk,
            root_bssid AS node,
            'bssid'::text AS node_type,
            ARRAY[root_bssid] AS path,
            0 AS depth
          FROM seed

          UNION ALL

          SELECT
            walk.root_bssid,
            walk.composite_risk,
            edge.next_node,
            edge.next_node_type,
            walk.path || edge.next_node,
            walk.depth + 1
          FROM walk
          JOIN LATERAL (
            SELECT
              node_b AS next_node,
              node_b_type AS next_node_type,
              edge_type
            FROM vec_infrastructure_graph
            WHERE node_a = walk.node
              AND node_a_type = walk.node_type
              AND last_seen >= now() - interval '24 hours'
            UNION ALL
            SELECT
              node_a AS next_node,
              node_a_type AS next_node_type,
              edge_type
            FROM vec_infrastructure_graph
            WHERE node_b = walk.node
              AND node_b_type = walk.node_type
              AND last_seen >= now() - interval '24 hours'
          ) edge ON true
          WHERE walk.depth < $2
            AND edge.edge_type IN ('association', 'roaming', 'rf_proximity')
            AND NOT edge.next_node = ANY(walk.path)
        ),
        candidates AS (
          SELECT DISTINCT ON (root_bssid, node, node_type)
            root_bssid,
            composite_risk,
            node,
            node_type,
            path,
            depth
          FROM walk
          WHERE depth > 0
            AND node_type IN ('client_mac', 'bssid')
          ORDER BY root_bssid, node, node_type, depth ASC
          LIMIT 200
        )
        INSERT INTO vec_alerts (alert_type, source_mac, score, explanation_text, metadata)
        SELECT
          'rogue_rf_path',
          CASE WHEN node_type = 'client_mac' THEN node ELSE root_bssid END,
          composite_risk,
          concat('Rogue RF path from high-risk AP ', root_bssid, ' to ', node_type, ' ', node, ' depth=', depth),
          jsonb_build_object(
            'root_bssid', root_bssid,
            'target_node', node,
            'target_node_type', node_type,
            'path', path,
            'depth', depth,
            'max_depth', $2,
            'composite_risk', composite_risk,
            'ap_risk_threshold', $1
          )
        FROM candidates
        WHERE NOT EXISTS (
          SELECT 1
          FROM vec_alerts a
          WHERE a.alert_type = 'rogue_rf_path'
            AND a.source_mac IS NOT DISTINCT FROM CASE WHEN candidates.node_type = 'client_mac' THEN candidates.node ELSE candidates.root_bssid END
            AND a.metadata->>'root_bssid' = candidates.root_bssid
            AND a.metadata->>'target_node' = candidates.node
            AND a.created_at > now() - interval '1 hour'
        )
        "#,
    )
    .bind(config.ap_risk_threshold)
    .bind(config.graph_max_depth)
    .execute(pool)
    .await
    .map_err(|e| WorkerError::alerts(format!("rogue_rf_path query failed: {e}")))?;

    let inserted = result.rows_affected() as usize;
    if inserted > 0 {
        info!(inserted, "rogue RF path alerts inserted");
    }
    Ok(inserted)
}

/// Run all configured alert checks in the correct order.
///
/// Refreshes `v_device_repetition_score` and `mv_ap_risk_score` (materialized views)
/// at the start of each sweep so that alert queries run against current data,
/// not stale snapshots. The CONCURRENTLY flag allows reads during the refresh
/// (requires the unique index on `source_mac`, which is created in V019).
#[instrument(skip(pool))]
pub async fn run_alert_sweep(pool: &PgPool, config: &AlertConfig) -> Result<(), WorkerError> {
    // Refresh the materialized view before querying it so alerts are based on
    // current data. REFRESH MATERIALIZED VIEW CONCURRENTLY requires a unique
    // index, which V019 creates on (source_mac).
    refresh_materialized_view_with_timeout(
        pool,
        "v_device_repetition_score",
        "REFRESH MATERIALIZED VIEW CONCURRENTLY v_device_repetition_score",
    )
    .await;

    // Refresh the AP risk score materialized view
    refresh_materialized_view_with_timeout(
        pool,
        "mv_ap_risk_score",
        "REFRESH MATERIALIZED VIEW CONCURRENTLY mv_ap_risk_score",
    )
    .await;

    let nd = check_near_duplicates(pool, config)
        .await
        .unwrap_or_else(|e| {
            warn!(error = %e, "near_duplicate check failed");
            0
        });
    debug_assert!(nd <= usize::MAX);

    let rc = check_rogue_clusters(pool).await.unwrap_or_else(|e| {
        warn!(error = %e, "rogue cluster check failed");
        0
    });
    debug_assert!(rc <= usize::MAX);

    let deauth = check_deauth_precursors(pool, config)
        .await
        .unwrap_or_else(|e| {
            warn!(error = %e, "deauth precursor check failed");
            0
        });
    debug_assert!(deauth <= usize::MAX);

    let hra = check_high_risk_aps_with_threshold(pool, config.ap_risk_threshold)
        .await
        .unwrap_or_else(|e| {
            warn!(error = %e, "high_risk_ap check failed");
            0
        });
    debug_assert!(hra <= usize::MAX);

    let drift = check_embedding_drift(pool).await.unwrap_or_else(|e| {
        warn!(error = %e, "embedding_drift check failed");
        0
    });
    debug_assert!(drift <= usize::MAX);

    let zero_trust = check_zero_trust_overlay_risk(pool, config)
        .await
        .unwrap_or_else(|e| {
            warn!(error = %e, "zero_trust_overlay_risk check failed");
            0
        });
    debug_assert!(zero_trust <= usize::MAX);

    let dns = check_dns_privacy_leaks(pool, config)
        .await
        .unwrap_or_else(|e| {
            warn!(error = %e, "dns_privacy_leak check failed");
            0
        });
    debug_assert!(dns <= usize::MAX);

    let travel = check_rf_impossible_travel(pool, config)
        .await
        .unwrap_or_else(|e| {
            warn!(error = %e, "rf_impossible_travel check failed");
            0
        });
    debug_assert!(travel <= usize::MAX);

    let paths = check_rogue_rf_paths(pool, config)
        .await
        .unwrap_or_else(|e| {
            warn!(error = %e, "rogue_rf_path check failed");
            0
        });
    debug_assert!(paths <= usize::MAX);

    Ok(())
}

async fn refresh_materialized_view_with_timeout(
    pool: &PgPool,
    view_name: &'static str,
    statement: &'static str,
) {
    const REFRESH_TIMEOUT: Duration = Duration::from_secs(30);

    match tokio::time::timeout(REFRESH_TIMEOUT, sqlx::query(statement).execute(pool)).await {
        Ok(Ok(_)) => {}
        Ok(Err(e)) => {
            warn!(error = %e, view_name, "failed to refresh materialized view, alert sweep may use stale data");
        }
        Err(_) => {
            warn!(
                view_name,
                timeout_ms = REFRESH_TIMEOUT.as_millis(),
                "timed out refreshing materialized view, alert sweep may use stale data"
            );
        }
    }
}
