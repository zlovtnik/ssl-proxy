use r2d2_oracle::OracleConnectionManager;

use super::classify::{checksum, classify_oracle_error, failure_result, sink_target};
use super::payload::{payload_rows, resolve_payload};
use super::proxy_transform::{
    blocked_event_rows_from_values, proxy_event_rows_from_values, summarize_event_types,
};
use super::proxy_types::{BlockedEventInsert, ProxyEventInsert};
use super::sink::OracleProxyEventSink;
use super::sink_trait::ProxyEventSink;
use super::types::{OracleErrorClass, OracleLoad, OracleResult, SinkTarget};
use super::wireless_alert_transform::{
    wireless_client_inventory_rows_from_values, wireless_deauth_flood_rows_from_values,
    wireless_pmf_attack_rows_from_values, wireless_probe_request_rows_from_values,
    wireless_rogue_ap_rows_from_values, wireless_signal_anomaly_rows_from_values,
};
use super::wireless_transform::{
    wireless_audit_rows_from_values, wireless_bandwidth_rows_from_values,
};
use super::wireless_types::{
    WirelessAuditFrameInsert, WirelessBandwidthInsert, WirelessClientInventoryInsert,
    WirelessDeauthFloodInsert, WirelessPmfAttackInsert, WirelessProbeRequestInsert,
    WirelessRogueApInsert, WirelessSignalAnomalyInsert,
};

#[allow(dead_code)]
pub fn handle_load(load: OracleLoad) -> OracleResult {
    let validated = match validate_load(&load) {
        Ok(validated) => validated,
        Err(error) => {
            let error_class = classify_oracle_error(&error);
            return failure_result(load.job_id, load.batch_id, error_class, error);
        }
    };
    let mut sink = match OracleProxyEventSink::connect_from_env() {
        Ok(sink) => sink,
        Err(error) => {
            let error_class = classify_oracle_error(&error);
            return failure_result(load.job_id, load.batch_id, error_class, error);
        }
    };
    handle_validated_load(load, validated, &mut sink)
}

pub fn handle_load_with_pool(
    load: OracleLoad,
    pool: &r2d2::Pool<OracleConnectionManager>,
) -> OracleResult {
    let validated = match validate_load(&load) {
        Ok(validated) => validated,
        Err(error) => {
            let error_class = classify_oracle_error(&error);
            return failure_result(load.job_id, load.batch_id, error_class, error);
        }
    };
    let mut sink = match OracleProxyEventSink::connect_from_pool(pool) {
        Ok(sink) => sink,
        Err(error) => {
            let error_class = classify_oracle_error(&error);
            return failure_result(load.job_id, load.batch_id, error_class, error);
        }
    };
    handle_validated_load(load, validated, &mut sink)
}

pub fn handle_load_with_sink(load: OracleLoad, sink: &mut dyn ProxyEventSink) -> OracleResult {
    let validated = match validate_load(&load) {
        Ok(validated) => validated,
        Err(error) => {
            let error_class = classify_oracle_error(&error);
            return failure_result(load.job_id, load.batch_id, error_class, error);
        }
    };

    if !validated.rows.is_empty() {
        eprintln!(
            "service=oracle-worker event=batch_validate batch_id={} stream_name={} total_rows={} event_types=\"{}\"",
            load.batch_id,
            load.stream_name,
            validated.rows.len(),
            summarize_event_types(&validated.rows)
        );
    }

    handle_validated_load(load, validated, sink)
}

struct ValidatedLoad {
    target: SinkTarget,
    payload: String,
    rows: Vec<ProxyEventInsert>,
    blocked_rows: Vec<BlockedEventInsert>,
    wireless_audit_rows: Vec<WirelessAuditFrameInsert>,
    wireless_bandwidth_rows: Vec<WirelessBandwidthInsert>,
    wireless_rogue_ap_rows: Vec<WirelessRogueApInsert>,
    wireless_deauth_flood_rows: Vec<WirelessDeauthFloodInsert>,
    wireless_signal_anomaly_rows: Vec<WirelessSignalAnomalyInsert>,
    wireless_pmf_attack_rows: Vec<WirelessPmfAttackInsert>,
    wireless_client_inventory_rows: Vec<WirelessClientInventoryInsert>,
    wireless_probe_request_rows: Vec<WirelessProbeRequestInsert>,
}

fn validate_load(load: &OracleLoad) -> Result<ValidatedLoad, String> {
    if load.job_id.is_empty() {
        return Err("job_id must not be empty".to_string());
    }

    let target = sink_target(&load.stream_name)
        .map_err(|_| format!("unsupported stream_name {}", load.stream_name))?;
    let payload = resolve_payload(&load.payload_ref)?;
    let values = payload_rows(target, &payload)?;
    let rows = proxy_event_rows_from_values(target, &values)?;
    let blocked_rows = blocked_event_rows_from_values(target, &values)?;
    let wireless_audit_rows = wireless_audit_rows_from_values(target, &values)?;
    let wireless_bandwidth_rows = wireless_bandwidth_rows_from_values(target, &values)?;
    let wireless_rogue_ap_rows = wireless_rogue_ap_rows_from_values(target, &values)?;
    let wireless_deauth_flood_rows = wireless_deauth_flood_rows_from_values(target, &values)?;
    let wireless_signal_anomaly_rows = wireless_signal_anomaly_rows_from_values(target, &values)?;
    let wireless_pmf_attack_rows = wireless_pmf_attack_rows_from_values(target, &values)?;
    let wireless_client_inventory_rows =
        wireless_client_inventory_rows_from_values(target, &values)?;
    let wireless_probe_request_rows = wireless_probe_request_rows_from_values(target, &values)?;
    Ok(ValidatedLoad {
        target,
        payload,
        rows,
        blocked_rows,
        wireless_audit_rows,
        wireless_bandwidth_rows,
        wireless_rogue_ap_rows,
        wireless_deauth_flood_rows,
        wireless_signal_anomaly_rows,
        wireless_pmf_attack_rows,
        wireless_client_inventory_rows,
        wireless_probe_request_rows,
    })
}

fn handle_validated_load(
    load: OracleLoad,
    validated: ValidatedLoad,
    sink: &mut dyn ProxyEventSink,
) -> OracleResult {
    let input_row_count = match validated.target {
        SinkTarget::ProxyEvents => validated.rows.len(),
        SinkTarget::WirelessAuditFrames => validated.wireless_audit_rows.len(),
        SinkTarget::WirelessBandwidth => validated.wireless_bandwidth_rows.len(),
        SinkTarget::WirelessRogueAp => validated.wireless_rogue_ap_rows.len(),
        SinkTarget::WirelessDeauthFlood => validated.wireless_deauth_flood_rows.len(),
        SinkTarget::WirelessSignalAnomaly => validated.wireless_signal_anomaly_rows.len(),
        SinkTarget::WirelessPmfAttack => validated.wireless_pmf_attack_rows.len(),
        SinkTarget::WirelessClientInventory => validated.wireless_client_inventory_rows.len(),
        SinkTarget::WirelessProbeRequests => validated.wireless_probe_request_rows.len(),
    };
    eprintln!(
        "service=oracle-worker event=batch_insert_start batch_id={} target={} row_count={} blocked_event_count={}",
        load.batch_id,
        validated.target.checksum_tag(),
        input_row_count,
        validated.blocked_rows.len(),
    );

    let row_count = match validated.target {
        SinkTarget::ProxyEvents => {
            sink.insert_proxy_events(&load.batch_id, &validated.rows, &validated.blocked_rows)
        }
        SinkTarget::WirelessAuditFrames => {
            sink.insert_wireless_audit_frames(&load.batch_id, &validated.wireless_audit_rows)
        }
        SinkTarget::WirelessBandwidth => {
            sink.insert_wireless_bandwidth(&load.batch_id, &validated.wireless_bandwidth_rows)
        }
        SinkTarget::WirelessRogueAp => {
            sink.insert_wireless_rogue_ap(&load.batch_id, &validated.wireless_rogue_ap_rows)
        }
        SinkTarget::WirelessDeauthFlood => {
            sink.insert_wireless_deauth_flood(&load.batch_id, &validated.wireless_deauth_flood_rows)
        }
        SinkTarget::WirelessSignalAnomaly => sink.insert_wireless_signal_anomaly(
            &load.batch_id,
            &validated.wireless_signal_anomaly_rows,
        ),
        SinkTarget::WirelessPmfAttack => {
            sink.insert_wireless_pmf_attack(&load.batch_id, &validated.wireless_pmf_attack_rows)
        }
        SinkTarget::WirelessClientInventory => sink.insert_wireless_client_inventory(
            &load.batch_id,
            &validated.wireless_client_inventory_rows,
        ),
        SinkTarget::WirelessProbeRequests => sink
            .insert_wireless_probe_requests(&load.batch_id, &validated.wireless_probe_request_rows),
    };
    let row_count = match row_count {
        Ok(row_count) => row_count,
        Err(error) => {
            let error_class = classify_oracle_error(&error);
            return failure_result(load.job_id, load.batch_id, error_class, error);
        }
    };
    let row_count = match i32::try_from(row_count) {
        Ok(row_count) => row_count,
        Err(_) => {
            return failure_result(
                load.job_id,
                load.batch_id,
                OracleErrorClass::Permanent,
                "inserted row count exceeds i32 limit".to_string(),
            );
        }
    };

    OracleResult {
        job_id: load.job_id,
        batch_id: load.batch_id,
        status: "success".to_string(),
        row_count,
        checksum: checksum(validated.target, &validated.payload),
        retryable: false,
        error_class: String::new(),
        error_text: String::new(),
        finished_at: crate::time::now_rfc3339(),
    }
}
