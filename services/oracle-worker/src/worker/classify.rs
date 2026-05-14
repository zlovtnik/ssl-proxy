use sha2::{Digest, Sha256};

use super::types::{OracleErrorClass, OracleResult, SinkTarget};

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
        "wireless.audit" => Ok(SinkTarget::WirelessAuditFrames),
        "audit.wireless.bandwidth" => Ok(SinkTarget::WirelessBandwidth),
        "wireless.rogue_ap" | "wireless.alert.rogue_ap" => Ok(SinkTarget::WirelessRogueAp),
        "wireless.deauth_flood" | "wireless.alert.deauth_flood" => {
            Ok(SinkTarget::WirelessDeauthFlood)
        }
        "wireless.signal_anomaly" | "wireless.alert.signal_anomaly" => {
            Ok(SinkTarget::WirelessSignalAnomaly)
        }
        "wireless.pmf_attack" | "wireless.alert.pmf_attack" => Ok(SinkTarget::WirelessPmfAttack),
        "wireless.client_inventory" | "wireless.client.inventory" => {
            Ok(SinkTarget::WirelessClientInventory)
        }
        "wireless.probe_requests" | "wireless.probe.flush" => Ok(SinkTarget::WirelessProbeRequests),
        _ => Err(OracleErrorClass::Permanent),
    }
}

pub(crate) fn checksum(target: SinkTarget, payload: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(target.checksum_tag().as_bytes());
    hasher.update([0]);
    hasher.update(payload.as_bytes());
    format!("{:x}", hasher.finalize())
}

impl SinkTarget {
    pub(crate) fn checksum_tag(self) -> &'static str {
        match self {
            SinkTarget::ProxyEvents => "proxy.events",
            SinkTarget::WirelessAuditFrames => "wireless.audit",
            SinkTarget::WirelessBandwidth => "audit.wireless.bandwidth",
            SinkTarget::WirelessRogueAp => "wireless.alert.rogue_ap",
            SinkTarget::WirelessDeauthFlood => "wireless.alert.deauth_flood",
            SinkTarget::WirelessSignalAnomaly => "wireless.alert.signal_anomaly",
            SinkTarget::WirelessPmfAttack => "wireless.alert.pmf_attack",
            SinkTarget::WirelessClientInventory => "wireless.client.inventory",
            SinkTarget::WirelessProbeRequests => "wireless.probe.flush",
        }
    }
}

pub(crate) fn failure_result(
    job_id: String,
    batch_id: String,
    error_class: OracleErrorClass,
    error_text: String,
) -> OracleResult {
    OracleResult {
        job_id,
        batch_id,
        status: "failed".to_string(),
        row_count: 0,
        checksum: String::new(),
        retryable: matches!(error_class, OracleErrorClass::Retryable),
        error_class: match error_class {
            OracleErrorClass::Retryable => "retryable".to_string(),
            OracleErrorClass::Permanent => "permanent".to_string(),
        },
        error_text,
        finished_at: crate::time::now_rfc3339(),
    }
}
