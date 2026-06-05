// ---------------------------------------------------------------------------
// Timing profile builder
// ---------------------------------------------------------------------------

#[derive(Debug, sqlx::FromRow)]
struct TimingProfileRow {
    source_mac: String,
    sensor_id: Option<String>,
    location_id: Option<String>,
    window_start: Option<chrono::DateTime<chrono::Utc>>,
    tsft_p50_us: Option<f64>,
    tsft_p95_us: Option<f64>,
    tsft_jitter: Option<f64>,
    wall_p50_ms: Option<f64>,
    wall_jitter_ms: Option<f64>,
    beacon_interval_median_ms: Option<f64>,
    beacon_jitter_ms: Option<f64>,
    embedding_text: Option<String>,
}

#[derive(Debug, sqlx::FromRow)]
struct TimingProfileBatchRow {
    query_key: String,
    source_mac: String,
    sensor_id: Option<String>,
    location_id: Option<String>,
    window_start: Option<chrono::DateTime<chrono::Utc>>,
    tsft_p50_us: Option<f64>,
    tsft_p95_us: Option<f64>,
    tsft_jitter: Option<f64>,
    wall_p50_ms: Option<f64>,
    wall_jitter_ms: Option<f64>,
    beacon_interval_median_ms: Option<f64>,
    beacon_jitter_ms: Option<f64>,
    embedding_text: Option<String>,
}

async fn build_timing_profile(
    pool: &PgPool,
    job: &EmbeddingJob,
) -> Result<EmbeddingInput, WorkerError> {
    let row = sqlx::query_as::<_, TimingProfileRow>(
        r#"
        SELECT
            source_mac,
            sensor_id,
            location_id,
            window_start,
            tsft_p50_us::float8,
            tsft_p95_us::float8,
            tsft_jitter::float8,
            wall_p50_ms::float8,
            wall_jitter_ms::float8,
            beacon_interval_median_ms::float8,
            beacon_jitter_ms::float8,
            embedding_text
        FROM vec_timing_profiles
        WHERE profile_id::text = $1
        "#,
    )
    .bind(&job.source_key)
    .fetch_optional(pool)
    .await
    .map_err(|e| WorkerError::text_build(format!("timing_profile query failed: {e}")))?
    .ok_or_else(|| {
        WorkerError::text_build(format!("timing_profile not found: {}", job.source_key))
    })?;

    Ok(timing_profile_row_to_input(&row))
}

async fn build_timing_profiles_batch(
    pool: &PgPool,
    jobs: &[&EmbeddingJob],
    out: &mut HashMap<String, EmbeddingInput>,
) -> Result<(), WorkerError> {
    let keys: Vec<&str> = jobs.iter().map(|j| j.source_key.as_str()).collect();
    let rows = sqlx::query_as::<_, TimingProfileBatchRow>(
        r#"
        SELECT
            profile_id::text AS query_key,
            source_mac,
            sensor_id,
            location_id,
            window_start,
            tsft_p50_us::float8,
            tsft_p95_us::float8,
            tsft_jitter::float8,
            wall_p50_ms::float8,
            wall_jitter_ms::float8,
            beacon_interval_median_ms::float8,
            beacon_jitter_ms::float8,
            embedding_text
        FROM vec_timing_profiles
        WHERE profile_id::text = ANY($1::text[])
        "#,
    )
    .bind(&keys)
    .fetch_all(pool)
    .await
    .map_err(|e| WorkerError::text_build(format!("timing_profile batch query failed: {e}")))?;

    for row in rows {
        let timing_row = TimingProfileRow {
            source_mac: row.source_mac,
            sensor_id: row.sensor_id,
            location_id: row.location_id,
            window_start: row.window_start,
            tsft_p50_us: row.tsft_p50_us,
            tsft_p95_us: row.tsft_p95_us,
            tsft_jitter: row.tsft_jitter,
            wall_p50_ms: row.wall_p50_ms,
            wall_jitter_ms: row.wall_jitter_ms,
            beacon_interval_median_ms: row.beacon_interval_median_ms,
            beacon_jitter_ms: row.beacon_jitter_ms,
            embedding_text: row.embedding_text,
        };
        out.insert(row.query_key, timing_profile_row_to_input(&timing_row));
    }
    Ok(())
}

fn timing_profile_row_to_input(row: &TimingProfileRow) -> EmbeddingInput {
    let text = row
        .embedding_text
        .as_deref()
        .filter(|text| !text.trim().is_empty())
        .map(|text| {
            let mut lines = Vec::new();
            lines.push("kind: timing_profile".to_string());
            if let Some(dt) = row.window_start {
                lines.extend(temporal_context_lines(dt));
            }
            for line in text.lines() {
                if line.starts_with("kind:") {
                    continue;
                }
                lines.push(line.to_string());
            }
            clamp_text(&lines.join("\n"))
        })
        .unwrap_or_else(|| {
            let mut lines = vec!["kind: timing_profile".to_string()];
            if let Some(dt) = row.window_start {
                lines.extend(temporal_context_lines(dt));
            }
            push_optional_f64(&mut lines, "tsft_p50_us", row.tsft_p50_us);
            push_optional_f64(&mut lines, "tsft_p95_us", row.tsft_p95_us);
            push_optional_f64(&mut lines, "tsft_jitter", row.tsft_jitter);
            push_optional_f64(&mut lines, "wall_p50_ms", row.wall_p50_ms);
            push_optional_f64(&mut lines, "wall_jitter_ms", row.wall_jitter_ms);
            push_optional_f64(
                &mut lines,
                "beacon_interval_ms",
                row.beacon_interval_median_ms,
            );
            push_optional_f64(&mut lines, "beacon_jitter_ms", row.beacon_jitter_ms);
            clamp_text(&lines.join("\n"))
        });

    EmbeddingInput {
        text,
        source_observed_at: row.window_start,
        source_stream_name: None,
        source_sensor_id: row.sensor_id.clone(),
        source_location_id: row.location_id.clone(),
        source_mac: Some(row.source_mac.clone()),
    }
}

fn push_optional_f64(lines: &mut Vec<String>, field: &str, value: Option<f64>) {
    if let Some(value) = value {
        lines.push(format!("{field}: {value:.3}"));
    }
}

// ---------------------------------------------------------------------------
// Infrastructure subgraph builder
// ---------------------------------------------------------------------------

/// Row returned by the ego-graph query for a single BSSID.
#[derive(Debug, sqlx::FromRow)]
struct InfrastructureGraphRow {
    node_a: String,
    node_a_type: String,
    node_b: String,
    node_b_type: String,
    edge_type: String,
    weight: Option<f64>,
    last_seen: Option<chrono::DateTime<chrono::Utc>>,
}

/// Build embedding text for an infrastructure subgraph centered on a BSSID.
///
/// Queries `vec_infrastructure_graph` for all edges where the BSSID appears as
/// either `node_a` or `node_b` and serializes the ego-graph as structured text.
async fn build_infrastructure_subgraph(
    pool: &PgPool,
    job: &EmbeddingJob,
) -> Result<EmbeddingInput, WorkerError> {
    let bssid = &job.source_key;

    let rows = sqlx::query_as::<_, InfrastructureGraphRow>(
        r#"
        SELECT
            node_a, node_a_type,
            node_b, node_b_type,
            edge_type, weight::float8, last_seen
        FROM vec_infrastructure_graph
        WHERE node_a = $1 OR node_b = $1
        ORDER BY weight DESC, last_seen DESC
        "#,
    )
    .bind(bssid)
    .fetch_all(pool)
    .await
    .map_err(|e| WorkerError::text_build(format!("infrastructure_graph query failed: {e}")))?;

    if rows.is_empty() {
        return Err(WorkerError::text_build(format!(
            "infrastructure_subgraph not found: {bssid}"
        )));
    }

    Ok(build_ego_graph_input(bssid, &rows))
}

#[derive(Debug, sqlx::FromRow)]
struct InfrastructureGraphBatchRow {
    query_key: String,
    node_a: String,
    node_a_type: String,
    node_b: String,
    node_b_type: String,
    edge_type: String,
    weight: Option<f64>,
    last_seen: Option<chrono::DateTime<chrono::Utc>>,
}

async fn build_infrastructure_subgraphs_batch(
    pool: &PgPool,
    jobs: &[&EmbeddingJob],
    out: &mut HashMap<String, EmbeddingInput>,
) -> Result<(), WorkerError> {
    let keys: Vec<&str> = jobs.iter().map(|j| j.source_key.as_str()).collect();

    let rows = sqlx::query_as::<_, InfrastructureGraphBatchRow>(
        r#"
        SELECT DISTINCT ON (
            LEAST(node_a, node_b),
            GREATEST(node_a, node_b),
            edge_type,
            endpoint
          )
            endpoint AS query_key,
            node_a, node_a_type,
            node_b, node_b_type,
            edge_type, weight::float8, last_seen
        FROM vec_infrastructure_graph
        CROSS JOIN LATERAL (
          VALUES
            (CASE WHEN node_a = ANY($1::text[]) THEN node_a END),
            (CASE WHEN node_b = ANY($1::text[]) THEN node_b END)
        ) AS endpoints(endpoint)
        WHERE endpoint IS NOT NULL
        ORDER BY
          LEAST(node_a, node_b),
          GREATEST(node_a, node_b),
          edge_type,
          endpoint,
          last_seen DESC
        "#,
    )
    .bind(&keys)
    .fetch_all(pool)
    .await
    .map_err(|e| {
        WorkerError::text_build(format!("infrastructure_graph batch query failed: {e}"))
    })?;

    // Group rows by query_key
    let mut grouped: HashMap<String, Vec<InfrastructureGraphRow>> = HashMap::new();
    for row in rows {
        let graph_row = InfrastructureGraphRow {
            node_a: row.node_a,
            node_a_type: row.node_a_type,
            node_b: row.node_b,
            node_b_type: row.node_b_type,
            edge_type: row.edge_type,
            weight: row.weight,
            last_seen: row.last_seen,
        };
        grouped.entry(row.query_key).or_default().push(graph_row);
    }

    for job in jobs {
        if let Some(rows) = grouped.get(&job.source_key) {
            out.insert(
                job.source_key.clone(),
                build_ego_graph_input(&job.source_key, rows),
            );
        }
    }

    Ok(())
}

/// Build an ego-graph text representation from infrastructure graph edges.
///
/// Format:
/// ```text
/// kind: infrastructure_subgraph
/// center: aa:bb:cc:dd:ee:ff
/// clients: 14
/// vendor_diversity: 3
/// edges: association:14, probe_target:5, roaming:3, ...
/// ```
fn build_ego_graph_input(bssid: &str, rows: &[InfrastructureGraphRow]) -> EmbeddingInput {
    let mut lines = vec![
        "kind: infrastructure_subgraph".to_string(),
        format!("center: {bssid}"),
    ];

    // Count distinct clients (client_mac neighbors via association)
    let mut client_set: std::collections::HashSet<&str> = std::collections::HashSet::new();
    // Count distinct edge types
    let mut edge_type_counts: std::collections::HashMap<&str, usize> =
        std::collections::HashMap::new();
    // Collect all unique SSID neighbors
    let mut ssid_set: std::collections::HashSet<&str> = std::collections::HashSet::new();
    // Collect all unique vendor OUIs
    let mut vendor_set: std::collections::HashSet<&str> = std::collections::HashSet::new();

    for row in rows {
        let neighbor = if row.node_a == bssid {
            (&row.node_b as &str, &row.node_b_type as &str)
        } else {
            (&row.node_a as &str, &row.node_a_type as &str)
        };

        match neighbor.1 {
            "client_mac" if row.edge_type == "association" => {
                client_set.insert(neighbor.0);
            }
            "ssid" if row.edge_type == "probe_target" => {
                ssid_set.insert(neighbor.0);
            }
            "vendor" => {
                vendor_set.insert(neighbor.0);
            }
            _ => {}
        }

        *edge_type_counts.entry(&row.edge_type).or_insert(0) += 1usize;
    }

    if !ssid_set.is_empty() {
        lines.push(format!("ssid: {}", ssid_set.len()));
    }
    if !client_set.is_empty() {
        lines.push(format!("clients: {}", client_set.len()));
    }
    if !vendor_set.is_empty() {
        lines.push(format!("vendor_diversity: {}", vendor_set.len()));
    }

    // Serialize edge type distribution
    let mut edge_parts: Vec<String> = edge_type_counts
        .into_iter()
        .map(|(et, count)| format!("{et}:{count}"))
        .collect();
    edge_parts.sort();
    lines.push(format!("edges: {}", edge_parts.join(",")));

    // Find max last_seen for the source time
    let last_seen = rows.iter().filter_map(|r| r.last_seen).max();

    EmbeddingInput {
        text: clamp_text(&lines.join("\n")),
        source_observed_at: last_seen,
        source_stream_name: None,
        source_sensor_id: None,
        source_location_id: None,
        source_mac: Some(bssid.to_string()),
    }
}
