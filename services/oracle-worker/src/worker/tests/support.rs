use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use std::sync::{Mutex, OnceLock};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::worker::{
    BlockedEventInsert, ProxyEventInsert, ProxyEventSink, WirelessAuditFrameInsert,
    WirelessBandwidthInsert, WirelessClientInventoryInsert, WirelessDeauthFloodInsert,
    WirelessPmfAttackInsert, WirelessProbeRequestInsert, WirelessRogueApInsert,
    WirelessSignalAnomalyInsert,
};

pub(super) static ENV_LOCK: OnceLock<Mutex<()>> = OnceLock::new();

pub(super) fn inline_payload(payload: &str) -> String {
    format!(
        "inline://json/{}",
        URL_SAFE_NO_PAD.encode(payload.as_bytes())
    )
}

pub(super) fn unique_test_name(prefix: &str) -> String {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    format!("{prefix}-{}-{nanos}", std::process::id())
}

pub(super) fn proxy_payload() -> String {
    inline_payload(
        r#"{"type":"tunnel_open","host":"example.com","time":"2026-04-21T00:00:00Z","peer_ip":"10.0.0.2","wg_pubkey":"peer","device_id":"device-1","identity_source":"registered","peer_hostname":"phone.local","client_ua":"UA","bytes_up":0,"bytes_down":0,"blocked":false,"obfuscation_profile":"default","correlation_id":"session-1","event_sequence":1,"kind":"connect","category":"analytics","reason":"allowed_sni","resolved_ips":["192.0.2.10"],"selected_ip":"192.0.2.10","tls_ver":"TLS1.3","alpn":"h2","cipher_suites_count":4,"ja3_lite":"ja3-lite"}"#,
    )
}

pub(super) fn proxy_close_payload() -> String {
    inline_payload(
        r#"{"type":"tunnel_close","host":"example.com","time":"2026-04-21T00:00:01Z","peer_ip":"10.0.0.2","wg_pubkey":"peer","device_id":"device-1","identity_source":"registered","peer_hostname":"phone.local","client_ua":"UA","bytes_up":123,"bytes_down":456,"blocked":false,"obfuscation_profile":"default","correlation_id":"session-1","event_sequence":2,"kind":"connect","category":"analytics","reason":"allowed_sni","duration_ms":789,"resolved_ips":["192.0.2.10"],"selected_ip":"192.0.2.10","tls_ver":"TLS1.3","alpn":"h2","cipher_suites_count":4,"ja3_lite":"ja3-lite"}"#,
    )
}

pub(super) fn proxy_close_payload_with_preview_v2() -> String {
    inline_payload(
        r#"{"type":"tunnel_close","host":"example.com","time":"2026-04-21T00:00:01Z","peer_ip":"10.0.0.2","wg_pubkey":"peer","device_id":"device-1","identity_source":"registered","peer_hostname":"phone.local","client_ua":"UA","bytes_up":123,"bytes_down":456,"blocked":false,"obfuscation_profile":"default","correlation_id":"session-1","event_sequence":2,"kind":"connect","category":"analytics","reason":"allowed_sni","duration_ms":789,"payload_preview":{"schema_version":2,"up":{"format":"text","text":"POST /login HTTP/1.1\r\nHost: example.com\r\n\r\n{}","byte_count":46,"total_bytes":46,"truncated":false},"down":{"format":"omitted","omitted_reason":"empty","byte_count":0,"total_bytes":0,"truncated":false},"redaction":"byte"}} "#,
    )
}

pub(super) fn blocked_payload() -> String {
    inline_payload(
        r#"{"type":"block","host":"blocked.example","time":"2026-04-21T00:00:00Z","peer_ip":"10.0.0.2","wg_pubkey":"peer","device_id":"device-1","identity_source":"registered","peer_hostname":"phone.local","client_ua":"UA","bytes_up":12,"bytes_down":34,"blocked":true,"category":"analytics","verdict":"HEURISTIC_FLAG_DATA_EXFIL","metrics":{"attempt_count":4,"total_blocked_bytes_approx":46,"frequency_hz":2.5,"risk_score":115.0,"iat_ms":88,"consecutive_blocks":4},"fingerprint":{"tls_ver":"TLS1.3","alpn":"h2","ja3_lite":"ja3-lite-hash"}}"#,
    )
}

#[derive(Default)]
pub(super) struct RecordingSink {
    pub(super) batch_ids: Vec<String>,
    pub(super) rows: Vec<ProxyEventInsert>,
    pub(super) blocked_rows: Vec<BlockedEventInsert>,
    pub(super) wireless_audit_rows: Vec<WirelessAuditFrameInsert>,
    pub(super) wireless_bandwidth_rows: Vec<WirelessBandwidthInsert>,
    pub(super) wireless_rogue_ap_rows: Vec<WirelessRogueApInsert>,
    pub(super) wireless_deauth_flood_rows: Vec<WirelessDeauthFloodInsert>,
    pub(super) wireless_signal_anomaly_rows: Vec<WirelessSignalAnomalyInsert>,
    pub(super) wireless_pmf_attack_rows: Vec<WirelessPmfAttackInsert>,
    pub(super) wireless_client_inventory_rows: Vec<WirelessClientInventoryInsert>,
    pub(super) wireless_probe_request_rows: Vec<WirelessProbeRequestInsert>,
    pub(super) error: Option<String>,
}

impl ProxyEventSink for RecordingSink {
    fn insert_proxy_events(
        &mut self,
        batch_id: &str,
        rows: &[ProxyEventInsert],
        blocked_rows: &[BlockedEventInsert],
    ) -> Result<u64, String> {
        self.fail_or_record(batch_id)?;
        self.rows.extend_from_slice(rows);
        self.blocked_rows.extend_from_slice(blocked_rows);
        Ok(rows.len() as u64)
    }

    fn insert_wireless_audit_frames(
        &mut self,
        batch_id: &str,
        rows: &[WirelessAuditFrameInsert],
    ) -> Result<u64, String> {
        self.fail_or_record(batch_id)?;
        self.wireless_audit_rows.extend_from_slice(rows);
        Ok(rows.len() as u64)
    }

    fn insert_wireless_bandwidth(
        &mut self,
        batch_id: &str,
        rows: &[WirelessBandwidthInsert],
    ) -> Result<u64, String> {
        self.fail_or_record(batch_id)?;
        self.wireless_bandwidth_rows.extend_from_slice(rows);
        Ok(rows.len() as u64)
    }

    fn insert_wireless_rogue_ap(
        &mut self,
        batch_id: &str,
        rows: &[WirelessRogueApInsert],
    ) -> Result<u64, String> {
        self.fail_or_record(batch_id)?;
        self.wireless_rogue_ap_rows.extend_from_slice(rows);
        Ok(rows.len() as u64)
    }

    fn insert_wireless_deauth_flood(
        &mut self,
        batch_id: &str,
        rows: &[WirelessDeauthFloodInsert],
    ) -> Result<u64, String> {
        self.fail_or_record(batch_id)?;
        self.wireless_deauth_flood_rows.extend_from_slice(rows);
        Ok(rows.len() as u64)
    }

    fn insert_wireless_signal_anomaly(
        &mut self,
        batch_id: &str,
        rows: &[WirelessSignalAnomalyInsert],
    ) -> Result<u64, String> {
        self.fail_or_record(batch_id)?;
        self.wireless_signal_anomaly_rows.extend_from_slice(rows);
        Ok(rows.len() as u64)
    }

    fn insert_wireless_pmf_attack(
        &mut self,
        batch_id: &str,
        rows: &[WirelessPmfAttackInsert],
    ) -> Result<u64, String> {
        self.fail_or_record(batch_id)?;
        self.wireless_pmf_attack_rows.extend_from_slice(rows);
        Ok(rows.len() as u64)
    }

    fn insert_wireless_client_inventory(
        &mut self,
        batch_id: &str,
        rows: &[WirelessClientInventoryInsert],
    ) -> Result<u64, String> {
        self.fail_or_record(batch_id)?;
        self.wireless_client_inventory_rows.extend_from_slice(rows);
        Ok(rows.len() as u64)
    }

    fn insert_wireless_probe_requests(
        &mut self,
        batch_id: &str,
        rows: &[WirelessProbeRequestInsert],
    ) -> Result<u64, String> {
        self.fail_or_record(batch_id)?;
        self.wireless_probe_request_rows.extend_from_slice(rows);
        Ok(rows.len() as u64)
    }
}

impl RecordingSink {
    fn fail_or_record(&mut self, batch_id: &str) -> Result<(), String> {
        if let Some(error) = &self.error {
            return Err(error.clone());
        }
        self.batch_ids.push(batch_id.to_string());
        Ok(())
    }
}
