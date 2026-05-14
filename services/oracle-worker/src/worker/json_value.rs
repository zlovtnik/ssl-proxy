use chrono::{DateTime, Utc};

pub(crate) fn row_sequence(index: usize, context: &str) -> Result<i64, String> {
    let row_number = index
        .checked_add(1)
        .ok_or_else(|| format!("{context} row_sequence exceeds i64"))?;
    i64::try_from(row_number).map_err(|_| format!("{context} row_sequence exceeds i64"))
}

pub(crate) fn raw_json(row: &serde_json::Value, context: &str) -> Result<String, String> {
    serde_json::to_string(row).map_err(|error| format!("encode raw {context} json: {error}"))
}

pub(crate) fn required_string(
    row: &serde_json::Value,
    field: &str,
    context: &str,
) -> Result<String, String> {
    optional_string(row, field)
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| format!("{context} row missing {field}"))
}

pub(crate) fn string_alias(
    row: &serde_json::Value,
    first: &str,
    second: &str,
    context: &str,
) -> Result<String, String> {
    optional_string(row, first)
        .or_else(|| optional_string(row, second))
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| format!("{context} row missing {first}/{second}"))
}

pub(crate) fn optional_string(row: &serde_json::Value, field: &str) -> Option<String> {
    row.get(field)
        .and_then(serde_json::Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
}

pub(crate) fn required_i64(
    row: &serde_json::Value,
    field: &str,
    context: &str,
) -> Result<i64, String> {
    optional_i64(row, field).ok_or_else(|| format!("{context} row missing numeric {field}"))
}

pub(crate) fn i64_alias(
    row: &serde_json::Value,
    first: &str,
    second: &str,
    context: &str,
) -> Result<i64, String> {
    optional_i64(row, first)
        .or_else(|| optional_i64(row, second))
        .ok_or_else(|| format!("{context} row missing numeric {first}/{second}"))
}

pub(crate) fn optional_i64(row: &serde_json::Value, field: &str) -> Option<i64> {
    let value = row.get(field)?;
    value
        .as_i64()
        .or_else(|| value.as_u64().and_then(|value| i64::try_from(value).ok()))
}

pub(crate) fn nested_i64(row: &serde_json::Value, object: &str, field: &str) -> Option<i64> {
    let value = row.get(object)?.get(field)?;
    value
        .as_i64()
        .or_else(|| value.as_u64().and_then(|value| i64::try_from(value).ok()))
}

pub(crate) fn bool_flag(row: &serde_json::Value, field: &str) -> i64 {
    i64::from(
        row.get(field)
            .and_then(serde_json::Value::as_bool)
            .unwrap_or(false),
    )
}

pub(crate) fn required_timestamp(
    row: &serde_json::Value,
    field: &str,
    context: &str,
) -> Result<DateTime<Utc>, String> {
    let value = required_string(row, field, context)?;
    parse_rfc3339_utc(&value, field)
}

pub(crate) fn timestamp_alias(
    row: &serde_json::Value,
    first: &str,
    second: &str,
    context: &str,
) -> Result<DateTime<Utc>, String> {
    let value = optional_string(row, first)
        .or_else(|| optional_string(row, second))
        .ok_or_else(|| format!("{context} row missing {first}/{second}"))?;
    parse_rfc3339_utc(&value, first)
}

pub(crate) fn optional_timestamp(
    row: &serde_json::Value,
    field: &str,
) -> Result<Option<DateTime<Utc>>, String> {
    optional_string(row, field)
        .map(|value| parse_rfc3339_utc(&value, field))
        .transpose()
}

pub(crate) fn parse_rfc3339_utc(value: &str, field: &str) -> Result<DateTime<Utc>, String> {
    DateTime::parse_from_rfc3339(value)
        .map(|value| value.with_timezone(&Utc))
        .map_err(|error| format!("decode {field} timestamp: {error}"))
}

pub(crate) fn json_array_string(row: &serde_json::Value, field: &str) -> Result<String, String> {
    match row.get(field) {
        Some(value @ serde_json::Value::Array(_)) => {
            serde_json::to_string(value).map_err(|error| format!("encode {field}: {error}"))
        }
        Some(serde_json::Value::String(value)) => Ok(value.clone()),
        Some(_) => Err(format!("{field} must be a JSON array or string")),
        None => Ok("[]".to_string()),
    }
}
