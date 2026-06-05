/// Build a fallback text from individual snapshot fields when no pre-built text exists.
fn build_snapshot_fallback(row: &BehaviourWindowRow) -> String {
    // Each of the three JSON fields gets at most 1/4 of the content budget.
    // The rest (3/4) is reserved for scalar fields, temporal context, and kind line.
    let json_field_budget = word_budget(CONTENT_TOKEN_BUDGET / 4);

    let mut lines = vec!["kind: behaviour_window".to_string()];
    // Add temporal context right after the kind line.
    if let Some(dt) = row.window_start {
        lines.extend(temporal_context_lines(dt));
    }
    for field in SNAPSHOT_FIELDS {
        let val: Option<String> = match *field {
            "source_mac" => row.source_mac.clone(),
            "location_id" => row.location_id.clone(),
            "sensor_id" => row.sensor_id.clone(),
            "window_start" => row.window_start.as_ref().map(|dt| dt.to_rfc3339()),
            "window_end" => row.window_end.as_ref().map(|dt| dt.to_rfc3339()),
            "event_count" => row.event_count.map(|v| v.to_string()),
            "protocol_mix" => row
                .protocol_mix
                .as_ref()
                .map(|v| truncate_words(&normalize_json(v), json_field_budget)),
            "frame_type_distribution" => row
                .frame_type_distribution
                .as_ref()
                .map(|v| truncate_words(&normalize_json(v), json_field_budget)),
            "signal_min_dbm" => row.signal_min_dbm.map(|v| v.to_string()),
            "signal_max_dbm" => row.signal_max_dbm.map(|v| v.to_string()),
            "signal_avg_dbm" => row.signal_avg_dbm.map(|v| v.to_string()),
            "retry_count" => row.retry_count.map(|v| v.to_string()),
            "protected_count" => row.protected_count.map(|v| v.to_string()),
            "unprotected_count" => row.unprotected_count.map(|v| v.to_string()),
            "unique_bssid_count" => row.unique_bssid_count.map(|v| v.to_string()),
            "mac_rotation_indicators" => row
                .mac_rotation_indicators
                .as_ref()
                .map(|v| truncate_words(&normalize_json(v), json_field_budget)),
            _ => None,
        };
        if let Some(ref v) = val {
            if !v.is_empty() {
                lines.push(format!("{}: {}", field, v));
            }
        }
    }
    // Add burst_velocity at the end.
    if let Some(epm) = events_per_minute(row) {
        lines.push(format!("events_per_minute: {epm:.1}"));
    }
    clamp_text(&lines.join("\n"))
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Append a `"field: value"` line if the value is non-empty and semantically meaningful.
fn append_value(lines: &mut Vec<String>, field: &str, value: Option<&str>) {
    match value {
        Some(v) if !is_empty_value(v) => lines.push(format!("{}: {}", field, v)),
        _ => {}
    }
}

/// Returns `true` for values that carry no semantic signal for an embedding model.
///
/// These are boolean-false, zero-integer, and null-like tokens that would add noise
/// if included in the text representation.
fn is_empty_value(v: &str) -> bool {
    matches!(
        v.to_ascii_lowercase().as_str(),
        "" | "0" | "false" | "none" | "null" | "unknown"
    )
}

/// Normalise a WPS device name for embedding: strip screen-size prefixes,
/// lowercase, and remove brand/trailing suffixes.
///
/// This groups similar devices (e.g. `60" Hisense Roku TV` and `55" Hisense Roku TV`)
/// into the same vector-space region.
fn normalize_wps_name(name: &str) -> String {
    let mut s = name.to_lowercase();

    // Strip leading screen-size patterns like `60"`, `55"`, `65 inch`, etc.
    // Find the first non-digit character to get the full number prefix.
    let digit_end = s.find(|c: char| !c.is_ascii_digit()).unwrap_or(s.len());
    if digit_end > 0 {
        let rest = &s[digit_end..];
        if rest.starts_with('"') || rest.starts_with('\'') {
            s = rest[1..].trim().to_string();
        } else if rest.starts_with(" inch") || rest.starts_with("-inch") {
            s = rest[5..].trim().to_string();
        }
    }

    // Strip trailing brand/type suffixes (case-insensitive already due to lowercasing)
    let suffixes = [
        " tv",
        " smart tv",
        " roku tv",
        " android tv",
        " led tv",
        " lcd tv",
        " 4k tv",
        " hd tv",
        " full hd tv",
        " uhd tv",
        " television",
        " smart television",
        " monitor",
        " display",
    ];
    for suffix in &suffixes {
        if s.ends_with(suffix) {
            s = s[..s.len() - suffix.len()].trim().to_string();
            break;
        }
    }

    s
}

/// Produce four temporal-context lines for a given UTC datetime.
///
/// Returns lines like:
/// ```text
/// hour_of_day: 14
/// day_of_week: Tuesday
/// is_weekend: false
/// is_business_hours: true
/// ```
fn temporal_context_lines(dt: chrono::DateTime<chrono::Utc>) -> Vec<String> {
    use chrono::{Datelike, Timelike};
    let hour = dt.hour();
    let day_name = dt.format("%A").to_string();
    let is_weekend = matches!(dt.weekday(), chrono::Weekday::Sat | chrono::Weekday::Sun);
    let is_business_hours = !is_weekend && hour >= 9 && hour < 17;
    vec![
        format!("hour_of_day: {}", hour),
        format!("day_of_week: {}", day_name),
        format!("is_weekend: {}", is_weekend),
        format!("is_business_hours: {}", is_business_hours),
    ]
}

/// Compute `events_per_minute` for a behaviour window row.
///
/// Returns `None` when `event_count` or `window_start`/`window_end` are missing,
/// or when the window duration is zero.
fn events_per_minute(row: &BehaviourWindowRow) -> Option<f64> {
    let count = row.event_count? as f64;
    let start = row.window_start?;
    let end = row.window_end?;
    let duration_secs = (end - start)
        .to_std()
        .ok()
        .map(|d| d.as_secs_f64())
        .unwrap_or(0.0);
    let duration_mins = duration_secs / 60.0;
    if duration_mins <= 0.0 {
        return None;
    }
    Some(count / duration_mins)
}

/// Normalise a JSON value for text output, matching the Ruby `normalize_json`.
fn normalize_json(value: &serde_json::Value) -> String {
    match value {
        serde_json::Value::Object(map) => {
            let sorted: std::collections::BTreeMap<String, &serde_json::Value> =
                map.iter().map(|(k, v)| (k.clone(), v)).collect();
            serde_json::to_string(&sorted).unwrap_or_default()
        }
        serde_json::Value::Array(arr) => {
            let mut sorted: Vec<String> = arr.iter().map(|v| v.to_string()).collect();
            sorted.sort();
            serde_json::to_string(&sorted).unwrap_or_default()
        }
        other => other.to_string(),
    }
}
