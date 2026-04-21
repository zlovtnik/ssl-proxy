use chrono::Utc;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct OracleLoad {
    pub job_id: String,
    pub batch_id: String,
    pub batch_no: i32,
    pub stream_name: String,
    pub payload_ref: String,
    pub cursor_start: String,
    pub cursor_end: String,
    pub attempt: i32,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct OracleResult {
    pub job_id: String,
    pub batch_id: String,
    pub status: String,
    pub row_count: i32,
    pub checksum: String,
    pub retryable: bool,
    pub error_class: String,
    pub error_text: String,
    pub finished_at: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OracleErrorClass {
    Retryable,
    Permanent,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SinkTarget {
    ProxyEvents,
    WirelessAudit,
}

pub fn classify_oracle_error(message: &str) -> OracleErrorClass {
    let normalized = message.to_ascii_lowercase();
    if normalized.contains("timeout")
        || normalized.contains("temporarily unavailable")
        || normalized.contains("connection reset")
        || normalized.contains("deadlock")
    {
        OracleErrorClass::Retryable
    } else {
        OracleErrorClass::Permanent
    }
}

pub fn sink_target(stream_name: &str) -> Result<SinkTarget, OracleErrorClass> {
    match stream_name {
        "proxy.events" => Ok(SinkTarget::ProxyEvents),
        "wireless.audit" => Ok(SinkTarget::WirelessAudit),
        _ => Err(OracleErrorClass::Permanent),
    }
}

pub fn handle_load(load: OracleLoad) -> OracleResult {
    let target = match sink_target(&load.stream_name) {
        Ok(target) => target,
        Err(error_class) => {
            return OracleResult {
                job_id: load.job_id,
                batch_id: load.batch_id,
                status: "failed".to_string(),
                row_count: 0,
                checksum: String::new(),
                retryable: false,
                error_class: match error_class {
                    OracleErrorClass::Retryable => "retryable".to_string(),
                    OracleErrorClass::Permanent => "permanent".to_string(),
                },
                error_text: format!("unsupported stream_name {}", load.stream_name),
                finished_at: Utc::now().to_rfc3339(),
            };
        }
    };
    OracleResult {
        job_id: load.job_id,
        batch_id: load.batch_id,
        status: "success".to_string(),
        row_count: 1,
        checksum: format!("{target:?}:{}:{}", load.cursor_start, load.cursor_end),
        retryable: false,
        error_class: String::new(),
        error_text: String::new(),
        finished_at: Utc::now().to_rfc3339(),
    }
}

#[cfg(test)]
mod tests {
    use super::{
        classify_oracle_error, handle_load, sink_target, OracleErrorClass, OracleLoad, SinkTarget,
    };

    #[test]
    fn emits_success_result() {
        let result = handle_load(OracleLoad {
            job_id: "job-1".to_string(),
            batch_id: "batch-1".to_string(),
            batch_no: 0,
            stream_name: "proxy.events".to_string(),
            payload_ref: "inline://payload".to_string(),
            cursor_start: "1".to_string(),
            cursor_end: "2".to_string(),
            attempt: 1,
        });

        assert_eq!(result.status, "success");
        assert_eq!(result.row_count, 1);
        assert!(!result.retryable);
    }

    #[test]
    fn accepts_wireless_audit_loads() {
        let result = handle_load(OracleLoad {
            job_id: "job-2".to_string(),
            batch_id: "batch-2".to_string(),
            batch_no: 0,
            stream_name: "wireless.audit".to_string(),
            payload_ref: "inline://payload".to_string(),
            cursor_start: "20".to_string(),
            cursor_end: "21".to_string(),
            attempt: 1,
        });

        assert_eq!(result.status, "success");
        assert!(result.checksum.contains("WirelessAudit"));
    }

    #[test]
    fn rejects_unknown_streams() {
        let result = handle_load(OracleLoad {
            job_id: "job-3".to_string(),
            batch_id: "batch-3".to_string(),
            batch_no: 0,
            stream_name: "other.events".to_string(),
            payload_ref: "inline://payload".to_string(),
            cursor_start: "20".to_string(),
            cursor_end: "21".to_string(),
            attempt: 1,
        });

        assert_eq!(result.status, "failed");
        assert_eq!(result.error_class, "permanent");
        assert!(!result.retryable);
    }

    #[test]
    fn classifies_retryable_failures() {
        assert_eq!(
            classify_oracle_error("timeout while writing batch"),
            OracleErrorClass::Retryable
        );
    }

    #[test]
    fn classifies_permanent_failures() {
        assert_eq!(
            classify_oracle_error("unique constraint violated"),
            OracleErrorClass::Permanent
        );
    }

    #[test]
    fn resolves_sink_targets() {
        assert_eq!(sink_target("proxy.events").unwrap(), SinkTarget::ProxyEvents);
        assert_eq!(sink_target("wireless.audit").unwrap(), SinkTarget::WirelessAudit);
        assert!(sink_target("unknown").is_err());
    }
}
