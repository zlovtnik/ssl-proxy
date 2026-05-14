use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use std::path::PathBuf;

use super::types::SinkTarget;

pub fn resolve_payload(payload_ref: &str) -> Result<String, String> {
    if let Some(b64) = payload_ref.strip_prefix("inline://json/") {
        let bytes = URL_SAFE_NO_PAD
            .decode(b64)
            .map_err(|error| format!("base64 decode: {error}"))?;
        return String::from_utf8(bytes).map_err(|error| format!("utf8: {error}"));
    }

    if let Some(path) = payload_ref.strip_prefix("outbox://") {
        let outbox_dir =
            std::env::var("SYNC_OUTBOX_DIR").unwrap_or_else(|_| "/sync-outbox".to_string());
        let outbox_base = PathBuf::from(&outbox_dir)
            .canonicalize()
            .map_err(|error| format!("canonicalize outbox dir: {error}"))?;
        let resolved = outbox_base.join(path);
        let resolved = resolved
            .canonicalize()
            .map_err(|error| format!("resolve outbox path {}: {error}", resolved.display()))?;
        if !resolved.starts_with(&outbox_base) {
            return Err(format!(
                "invalid outbox path escapes base: {}",
                resolved.display()
            ));
        }
        return std::fs::read_to_string(&resolved)
            .map_err(|error| format!("read outbox {}: {error}", resolved.display()));
    }

    Err(format!("unsupported payload_ref scheme: {payload_ref}"))
}

pub(crate) fn payload_rows(
    target: SinkTarget,
    payload: &str,
) -> Result<Vec<serde_json::Value>, String> {
    let value: serde_json::Value =
        serde_json::from_str(payload).map_err(|error| format!("decode payload json: {error}"))?;
    if target == SinkTarget::WirelessProbeRequests {
        if let Some(rows) = value.get("probes").and_then(serde_json::Value::as_array) {
            return Ok(rows.clone());
        }
    }
    if target == SinkTarget::WirelessClientInventory {
        if let Some(clients) = value.get("clients").and_then(serde_json::Value::as_array) {
            let mut rows = Vec::with_capacity(clients.len());
            for client in clients {
                let mut merged = client.as_object().cloned().ok_or_else(|| {
                    "wireless client inventory clients must contain objects".to_string()
                })?;
                if let Some(sensor_id) = value.get("sensor_id") {
                    merged.insert("sensor_id".to_string(), sensor_id.clone());
                }
                if let Some(location_id) = value.get("location_id") {
                    merged.insert("location_id".to_string(), location_id.clone());
                }
                if let Some(snapshot_at) = value
                    .get("snapshot_at")
                    .or_else(|| value.get("observed_at"))
                {
                    merged.insert("snapshot_at".to_string(), snapshot_at.clone());
                }
                rows.push(serde_json::Value::Object(merged));
            }
            return Ok(rows);
        }
    }
    match value {
        serde_json::Value::Array(rows) => Ok(rows),
        other => Ok(vec![other]),
    }
}
