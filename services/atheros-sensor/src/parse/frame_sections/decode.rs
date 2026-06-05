use base64::{engine::general_purpose::STANDARD, Engine};
use ieee80211::GenericFrame;
use thiserror::Error;

use crate::model::{
    AnomalyLayer, AuditContext, AuditEntry, CorrelationLayer, EnrichedFrame, MacLayer, RawPacket,
    RfLayer, WifiFrame, WIRELESS_AUDIT_SCHEMA_VERSION,
};

use super::{
    addresses::parse_addresses,
    channel::{decode_channel_flags, frequency_to_channel},
    correlation::{
        adjacent_mac_hint, frame_fingerprint, retransmit_key as build_retransmit_key,
        session_key as build_session_key,
    },
    decap::analyze_payload,
    eapol::{extract_eap_identity, extract_eapol_key_message, extract_pmkid},
    ie::{extract_ie_metadata, extract_ssid},
    oui::oui_lookup,
    qos::parse_qos_control,
    radiotap::strip_radiotap,
    tags::{add_audit_threat_tags, data_direction_tag, tag_probe_response_destination},
};

#[derive(Debug, Error)]
pub enum ParseError {
    #[error("frame too short for radiotap header")]
    MissingRadiotap,
    #[error("frame too short for 802.11 frame header")]
    MissingFrameHeader,
    #[error("unsupported control frame")]
    UnsupportedControlFrame,
    #[error("ieee80211 parser rejected frame")]
    Invalid80211,
}

/// Rejects control frames (type 1), validates with GenericFrame, then builds tags in two
/// passes: first the frame-type/flag/flow tags, then the protocol/anomaly tags after decap.
pub fn decode_frame(packet: &RawPacket) -> Result<WifiFrame, ParseError> {
    let (radiotap, frame_bytes) = strip_radiotap(&packet.data)?;
    if frame_bytes.len() < 24 {
        return Err(ParseError::MissingFrameHeader);
    }

    let frame_control = u16::from_le_bytes([frame_bytes[0], frame_bytes[1]]);
    let duration_id = u16::from_le_bytes([frame_bytes[2], frame_bytes[3]]);
    let frame_type = ((frame_control >> 2) & 0x3) as u8;
    if frame_type == 1 {
        return Err(ParseError::UnsupportedControlFrame);
    }
    if !matches!(frame_type, 0 | 2) {
        return Err(ParseError::Invalid80211);
    }

    let _validated = GenericFrame::new(frame_bytes, false).map_err(|_| ParseError::Invalid80211)?;

    let subtype = ((frame_control >> 4) & 0x0f) as u8;
    let frame_type_name = frame_type_name(frame_type).to_string();
    let frame_subtype = frame_subtype_name(frame_type, subtype).to_string();
    let addresses = parse_addresses(frame_type, frame_control, frame_bytes)?;
    let sequence_control = u16::from_le_bytes([frame_bytes[22], frame_bytes[23]]);
    let sequence_number = Some(sequence_control >> 4);
    let fragment_number = Some((sequence_control & 0x000f) as u8);
    let ssid = extract_ssid(frame_type, subtype, frame_bytes);
    let ie_metadata = extract_ie_metadata(frame_type, subtype, frame_bytes);
    let username_hint = extract_eap_identity(frame_type, frame_control, subtype, frame_bytes);
    let eapol_key_message =
        extract_eapol_key_message(frame_type, frame_control, subtype, frame_bytes);
    let pmkid = extract_pmkid(frame_type, frame_control, subtype, frame_bytes);
    let identity_source_hint = username_hint.as_ref().map(|_| "eap_identity".to_string());
    let retry = frame_control & (1 << 11) != 0;
    let more_data = frame_control & (1 << 13) != 0;
    let power_save = frame_control & (1 << 12) != 0;
    let protected = frame_control & (1 << 14) != 0;
    let to_ds = frame_control & (1 << 8) != 0;
    let from_ds = frame_control & (1 << 9) != 0;
    let destination_bssid = addresses.bssid.clone();
    let qos = parse_qos_control(frame_type, subtype, frame_control, frame_bytes);
    let payload = analyze_payload(frame_type, frame_control, subtype, protected, frame_bytes);
    let channel_number = frequency_to_channel(radiotap.frequency_mhz);
    let channel_flags = decode_channel_flags(radiotap.channel_flags);
    let band = derive_band(
        radiotap.frequency_mhz,
        radiotap.channel_flags,
        channel_number,
    );
    let signal_status = signal_status(&radiotap);
    let adjacent_mac_hint = adjacent_mac_hint(&addresses);
    let session_key = build_session_key(
        addresses.source_mac.as_deref(),
        destination_bssid.as_deref(),
        addresses.destination_mac.as_deref(),
    );
    let retransmit_key = build_retransmit_key(
        addresses.transmitter_mac.as_deref(),
        addresses.receiver_mac.as_deref(),
        sequence_number,
        fragment_number,
    );
    let frame_fingerprint =
        frame_fingerprint(frame_control, &frame_subtype, &addresses, frame_bytes);
    let payload_visibility = payload_visibility(frame_type, protected).to_string();
    let large_frame = frame_bytes.len() > 1000;
    let mut anomaly_reasons = Vec::new();
    if large_frame {
        anomaly_reasons.push("large_frame".to_string());
    }
    let bssid = addresses.bssid.clone();
    let source_mac = addresses.source_mac.clone();
    let destination_mac = addresses.destination_mac.clone();
    let transmitter_mac = addresses.transmitter_mac.clone();
    let receiver_mac = addresses.receiver_mac.clone();

    let vendor_name = bssid
        .as_deref()
        .and_then(oui_lookup)
        .or_else(|| source_mac.as_deref().and_then(oui_lookup))
        .map(|s| s.to_string());

    let mac = MacLayer {
        frame_type: frame_type_name.clone(),
        frame_subtype: frame_subtype.clone(),
        to_ds,
        from_ds,
        protected,
        retry,
        more_data,
        power_save,
        sequence_number,
        fragment_number,
        bssid: destination_bssid.clone().or_else(|| bssid.clone()),
        source_mac: source_mac.clone(),
        destination_mac: destination_mac.clone(),
        transmitter_mac: transmitter_mac.clone(),
        receiver_mac: receiver_mac.clone(),
        adjacent_mac_hint: adjacent_mac_hint.clone(),
    };

    let mut tags = vec![
        "wifi".to_string(),
        frame_type_name.clone(),
        format!("frame_type:{frame_type_name}"),
    ];
    if frame_type == 2 {
        tags.push(data_direction_tag(frame_control).to_string());
    }
    if retry {
        tags.push("retry".to_string());
    }
    if more_data {
        tags.push("more_data".to_string());
    }
    if power_save {
        tags.push("power_save".to_string());
    }
    if protected {
        tags.push("protected".to_string());
    }
    if let (Some(src), Some(dst)) = (
        addresses.source_mac.as_ref(),
        addresses.destination_mac.as_ref(),
    ) {
        tags.push(format!("flow:{src}>{dst}"));
    }
    if username_hint.is_some() || eapol_key_message.is_some() {
        tags.push("eapol".to_string());
    }
    if username_hint.is_some() {
        tags.push("identity:eap_response".to_string());
    }
    if frame_subtype == "probe_response" {
        tag_probe_response_destination(addresses.destination_mac.as_deref(), &mut tags);
    }
    if qos.is_some() {
        tags.push("qos".to_string());
    }
    if let Some(protocol) = payload.app_protocol.as_ref() {
        tags.push(format!("app:{protocol}"));
    }
    if payload.network.is_some() {
        tags.push("network:ipv4".to_string());
    }
    if let Some(ethertype_name) = payload.ethertype_name.as_ref() {
        tags.push(format!("ethertype:{ethertype_name}"));
    }
    if large_frame {
        tags.push("anomaly:large_frame".to_string());
    }

    Ok(WifiFrame {
        schema_version: WIRELESS_AUDIT_SCHEMA_VERSION,
        observed_at: packet.observed_at,
        event_type: match frame_type {
            0 => "wifi_management_frame".to_string(),
            2 => "wifi_data_frame".to_string(),
            _ => "wifi_frame".to_string(),
        },
        frame_type: frame_type_name.clone(),
        frame_type_raw: frame_type,
        frame_subtype_raw: subtype,
        frame_control,
        bssid,
        destination_bssid,
        source_mac,
        destination_mac,
        transmitter_mac,
        receiver_mac,
        ssid,
        frame_subtype,
        tsft: radiotap.tsft,
        signal_dbm: radiotap.signal_dbm,
        noise_dbm: radiotap.noise_dbm,
        frequency_mhz: radiotap.frequency_mhz,
        channel_flags: radiotap.channel_flags,
        data_rate_kbps: radiotap.data_rate_kbps,
        antenna_id: radiotap.antenna_id,
        vht_known: radiotap.vht_known,
        vht_flags: radiotap.vht_flags,
        vht_bandwidth: radiotap.vht_bandwidth,
        he_data: radiotap.he_data.clone(),
        sequence_number,
        fragment_number,
        channel_number,
        signal_status: signal_status.clone(),
        adjacent_mac_hint: adjacent_mac_hint.clone(),
        duration_id,
        frame_control_flags: frame_control,
        more_data,
        retry,
        power_save,
        protected,
        to_ds,
        from_ds,
        raw_len: frame_bytes.len(),
        raw_frame: Some(STANDARD.encode(frame_bytes)),
        band: band.to_string(),
        tags: tags.clone(),
        risk_score: recompute_risk_score(&tags),
        security_flags: ie_metadata.security_flags,
        rsn_capabilities: ie_metadata.rsn_capabilities,
        weak_cipher_advertised: ie_metadata.weak_cipher_advertised,
        wps_device_name: ie_metadata.wps_device_name,
        wps_manufacturer: ie_metadata.wps_manufacturer,
        wps_model_name: ie_metadata.wps_model_name,
        device_fingerprint: ie_metadata.device_fingerprint,
        probe_fingerprint: ie_metadata.probe_fingerprint,
        ie_layout_hash: ie_metadata.ie_layout_hash,
        vendor_name,
        handshake_captured: false,
        eapol_key_message,
        pmkid,
        username_hint,
        identity_source_hint,
        qos_tid: qos.as_ref().map(|value| value.tid),
        qos_eosp: qos.as_ref().map(|value| value.eosp),
        qos_ack_policy: qos.as_ref().map(|value| value.ack_policy),
        qos_ack_policy_label: qos.as_ref().map(|value| value.ack_policy_label.clone()),
        qos_amsdu: qos.as_ref().map(|value| value.amsdu),
        llc_oui: payload.llc_oui.clone(),
        ethertype: payload.ethertype,
        ethertype_name: payload.ethertype_name.clone(),
        src_ip: payload.src_ip.clone(),
        dst_ip: payload.dst_ip.clone(),
        ip_ttl: payload.ip_ttl,
        ip_protocol: payload.ip_protocol,
        ip_protocol_name: payload.ip_protocol_name.clone(),
        src_port: payload.src_port,
        dst_port: payload.dst_port,
        transport_protocol: payload.transport_protocol.clone(),
        transport_length: payload.transport_length,
        transport_checksum: payload.transport_checksum,
        app_protocol: payload.app_protocol.clone(),
        ssdp_message_type: payload.ssdp_message_type.clone(),
        ssdp_st: payload.ssdp_st.clone(),
        ssdp_mx: payload.ssdp_mx.clone(),
        ssdp_usn: payload.ssdp_usn.clone(),
        dhcp_requested_ip: payload.dhcp_requested_ip.clone(),
        dhcp_hostname: payload.dhcp_hostname.clone(),
        dhcp_vendor_class: payload.dhcp_vendor_class.clone(),
        dns_query_name: payload.dns_query_name.clone(),
        mdns_name: payload.mdns_name.clone(),
        session_key: session_key.clone(),
        retransmit_key: retransmit_key.clone(),
        frame_fingerprint: frame_fingerprint.clone(),
        payload_visibility: payload_visibility.clone(),
        tsft_delta_us: None,
        wall_clock_delta_ms: None,
        sequence_delta: None,
        sequence_gap_missing_frames: None,
        clock_skew_delta_us: None,
        large_frame,
        mixed_encryption: None,
        dedupe_or_replay_suspect: false,
        anomaly_reasons: anomaly_reasons.clone(),
        mac,
        rf: RfLayer {
            tsft: radiotap.tsft,
            signal_dbm: radiotap.signal_dbm,
            noise_dbm: radiotap.noise_dbm,
            frequency_mhz: radiotap.frequency_mhz,
            channel_number,
            channel_flags,
            data_rate_kbps: radiotap.data_rate_kbps,
            antenna_id: radiotap.antenna_id,
            raw_len: frame_bytes.len(),
            signal_status,
            vht_known: radiotap.vht_known,
            vht_flags: radiotap.vht_flags,
            vht_bandwidth: radiotap.vht_bandwidth,
            he_data: radiotap.he_data,
        },
        qos,
        llc_snap: payload.llc_snap,
        network: payload.network,
        transport: payload.transport,
        application: payload.application,
        correlation: CorrelationLayer {
            session_key,
            retransmit_key,
            frame_fingerprint,
            payload_visibility,
            tsft_delta_us: None,
            wall_clock_delta_ms: None,
            sequence_delta: None,
            sequence_gap_missing_frames: None,
            clock_skew_delta_us: None,
        },
        anomalies: AnomalyLayer {
            large_frame,
            mixed_encryption: None,
            dedupe_or_replay_suspect: false,
            reasons: anomaly_reasons,
        },
    })
}

pub fn attach_context(frame: WifiFrame, context: &AuditContext) -> EnrichedFrame {
    EnrichedFrame {
        sensor_id: context.sensor_id.clone(),
        location_id: context.location_id.clone(),
        interface: context.interface.clone(),
        channel: context.channel,
        reg_domain: context.reg_domain.clone(),
        frame,
    }
}

/// Recomputes the risk score from the current set of tags.
/// Counts tags starting with `"threat:"` and maps the count to a score:
/// 0 -> None, 1 -> 0.3, 2 -> 0.6, 3+ -> 0.9.
pub fn recompute_risk_score(tags: &[String]) -> Option<f32> {
    let threat_count = tags.iter().filter(|t| t.starts_with("threat:")).count();
    match threat_count {
        0 => None,
        1 => Some(0.3_f32),
        2 => Some(0.6_f32),
        _ => Some(0.9_f32),
    }
}
