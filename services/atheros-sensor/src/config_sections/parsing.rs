fn audit_layer_stream_from_env() -> AuditLayerStream {
    match std::env::var("ATH_SENSOR_AUDIT_LAYER_STREAM")
        .ok()
        .map(|value| value.trim().to_ascii_lowercase())
        .as_deref()
    {
        Some("stdout") => AuditLayerStream::Stdout,
        Some("stderr") => AuditLayerStream::Stderr,
        _ => AuditLayerStream::Off,
    }
}

fn parse_u64(name: &str, default: u64) -> Result<u64, String> {
    match std::env::var(name) {
        Ok(value) if !value.trim().is_empty() => value.trim().parse::<u64>().map_err(|_| value),
        _ => Ok(default),
    }
}

fn parse_usize(name: &str, default: usize) -> Result<usize, String> {
    match std::env::var(name) {
        Ok(value) if !value.trim().is_empty() => value.trim().parse::<usize>().map_err(|_| value),
        _ => Ok(default),
    }
}

fn read_bool(name: &str, default: bool) -> bool {
    match std::env::var(name) {
        Ok(value) => matches!(
            value.trim().to_ascii_lowercase().as_str(),
            "1" | "true" | "yes" | "on"
        ),
        Err(_) => default,
    }
}

fn read_secret(value_var: &str, file_var: &str) -> Option<String> {
    if let Ok(value) = std::env::var(value_var) {
        let trimmed = value.trim();
        if !trimmed.is_empty() {
            return Some(trimmed.to_string());
        }
    }
    let path = std::env::var(file_var).ok()?;
    let trimmed = std::fs::read_to_string(path).ok()?;
    let trimmed = trimmed.trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed.to_string())
    }
}
