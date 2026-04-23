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
    eapol::{extract_eap_identity, extract_eapol_key_message},
    ie::{extract_ie_metadata, extract_ssid},
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
    let frame_fingerprint = frame_fingerprint(frame_control, &frame_subtype, &addresses, frame_bytes);
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
        tags,
        security_flags: ie_metadata.security_flags,
        wps_device_name: ie_metadata.wps_device_name,
        wps_manufacturer: ie_metadata.wps_manufacturer,
        wps_model_name: ie_metadata.wps_model_name,
        device_fingerprint: ie_metadata.device_fingerprint,
        handshake_captured: false,
        eapol_key_message,
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

pub fn to_audit_entry(enriched: EnrichedFrame) -> AuditEntry {
    let mut frame = enriched.frame;
    let mut tags = std::mem::take(&mut frame.tags);
    tags.push(format!("channel:{}", enriched.channel));
    tags.push(format!("reg_domain:{}", enriched.reg_domain));
    add_audit_threat_tags(&frame, &mut tags);
    let username = frame.username_hint.clone();
    let identity_source = match (username.as_ref(), frame.identity_source_hint.clone()) {
        (Some(_), Some(source)) => source,
        (Some(_), None) => "observed_identity".to_string(),
        (None, _) if frame.source_mac.is_some() || frame.bssid.is_some() => {
            "mac_observed".to_string()
        }
        (None, _) => "unknown".to_string(),
    };

    AuditEntry {
        schema_version: frame.schema_version,
        event_type: frame.event_type,
        observed_at: frame.observed_at.to_rfc3339(),
        sensor_id: enriched.sensor_id,
        location_id: enriched.location_id,
        interface: enriched.interface,
        channel: enriched.channel,
        frame_type: Some(frame.frame_type),
        bssid: frame.bssid,
        destination_bssid: frame.destination_bssid,
        source_mac: frame.source_mac,
        destination_mac: frame.destination_mac,
        transmitter_mac: frame.transmitter_mac,
        receiver_mac: frame.receiver_mac,
        ssid: frame.ssid,
        frame_subtype: frame.frame_subtype,
        tsft: frame.tsft,
        signal_dbm: frame.signal_dbm,
        noise_dbm: frame.noise_dbm,
        frequency_mhz: frame.frequency_mhz,
        channel_flags: frame.channel_flags,
        data_rate_kbps: frame.data_rate_kbps,
        antenna_id: frame.antenna_id,
        sequence_number: frame.sequence_number,
        fragment_number: frame.fragment_number,
        channel_number: frame.channel_number,
        signal_status: Some(frame.signal_status),
        adjacent_mac_hint: frame.adjacent_mac_hint,
        duration_id: Some(frame.duration_id),
        frame_control_flags: Some(frame.frame_control_flags),
        more_data: Some(frame.more_data),
        retry: Some(frame.retry),
        power_save: Some(frame.power_save),
        protected: Some(frame.protected),
        to_ds: Some(frame.to_ds),
        from_ds: Some(frame.from_ds),
        raw_len: frame.raw_len,
        raw_frame: frame.raw_frame,
        tags,
        security_flags: frame.security_flags,
        wps_device_name: frame.wps_device_name,
        wps_manufacturer: frame.wps_manufacturer,
        wps_model_name: frame.wps_model_name,
        device_fingerprint: frame.device_fingerprint,
        handshake_captured: frame.handshake_captured,
        qos_tid: frame.qos_tid,
        qos_eosp: frame.qos_eosp,
        qos_ack_policy: frame.qos_ack_policy,
        qos_ack_policy_label: frame.qos_ack_policy_label,
        qos_amsdu: frame.qos_amsdu,
        llc_oui: frame.llc_oui,
        ethertype: frame.ethertype,
        ethertype_name: frame.ethertype_name,
        src_ip: frame.src_ip,
        dst_ip: frame.dst_ip,
        ip_ttl: frame.ip_ttl,
        ip_protocol: frame.ip_protocol,
        ip_protocol_name: frame.ip_protocol_name,
        src_port: frame.src_port,
        dst_port: frame.dst_port,
        transport_protocol: frame.transport_protocol,
        transport_length: frame.transport_length,
        transport_checksum: frame.transport_checksum,
        app_protocol: frame.app_protocol,
        ssdp_message_type: frame.ssdp_message_type,
        ssdp_st: frame.ssdp_st,
        ssdp_mx: frame.ssdp_mx,
        ssdp_usn: frame.ssdp_usn,
        dhcp_requested_ip: frame.dhcp_requested_ip,
        dhcp_hostname: frame.dhcp_hostname,
        dhcp_vendor_class: frame.dhcp_vendor_class,
        dns_query_name: frame.dns_query_name,
        mdns_name: frame.mdns_name,
        session_key: frame.session_key,
        retransmit_key: frame.retransmit_key,
        frame_fingerprint: Some(frame.frame_fingerprint),
        payload_visibility: Some(frame.payload_visibility),
        tsft_delta_us: frame.tsft_delta_us,
        wall_clock_delta_ms: frame.wall_clock_delta_ms,
        large_frame: Some(frame.large_frame),
        mixed_encryption: frame.mixed_encryption,
        dedupe_or_replay_suspect: Some(frame.dedupe_or_replay_suspect),
        anomaly_reasons: frame.anomaly_reasons,
        mac: Some(frame.mac),
        rf: Some(frame.rf),
        qos: frame.qos,
        llc_snap: frame.llc_snap,
        network: frame.network,
        transport: frame.transport,
        application: frame.application,
        correlation: Some(frame.correlation),
        anomalies: Some(frame.anomalies),
        device_id: None,
        username,
        identity_source,
    }
}

fn frame_type_name(frame_type: u8) -> &'static str {
    match frame_type {
        0 => "management",
        1 => "control",
        2 => "data",
        _ => "unknown",
    }
}

fn frame_subtype_name(frame_type: u8, subtype: u8) -> &'static str {
    match frame_type {
        0 => match subtype {
            0 => "association_request",
            1 => "association_response",
            4 => "probe_request",
            5 => "probe_response",
            8 => "beacon",
            10 => "disassociation",
            11 => "authentication",
            12 => "deauthentication",
            _ => "other_management",
        },
        2 => match subtype {
            0 => "data",
            4 => "null_data",
            8 => "qos_data",
            12 => "qos_null",
            _ => "other_data",
        },
        _ => "unknown",
    }
}

fn payload_visibility(frame_type: u8, protected: bool) -> &'static str {
    if protected && frame_type == 2 {
        "ciphertext"
    } else if frame_type == 2 {
        "plaintext"
    } else {
        "header_only"
    }
}

fn signal_status(radiotap: &super::radiotap::RadiotapMetadata) -> String {
    if radiotap.signal_present {
        "present".to_string()
    } else if radiotap.frequency_mhz.is_some()
        || radiotap.channel_flags.is_some()
        || radiotap.data_rate_kbps.is_some()
        || radiotap.antenna_id.is_some()
        || radiotap.tsft.is_some()
        || radiotap.noise_dbm.is_some()
    {
        "stripped".to_string()
    } else {
        "absent".to_string()
    }
}

#[cfg(test)]
mod tests {
    use base64::{engine::general_purpose::STANDARD, Engine};
    use chrono::Utc;
    use serde_json::Value;

    use super::*;
    use crate::{
        model::{AuditContext, RawPacket},
        parse::{
            strip_radiotap, HandshakeMonitor, IEIterator, IdentityCache, ParseError,
            SECURITY_PMF_REQUIRED, SECURITY_RSN_WPA2, SECURITY_WPA, SECURITY_WPA3, SECURITY_WPS,
        },
        testutil::*,
    };

    #[test]
    fn strips_radiotap_and_extracts_signal() {
        let frame = beacon_radiotap_frame();
        let (metadata, payload) = strip_radiotap(&frame).unwrap();
        assert_eq!(metadata.signal_dbm, Some(-42));
        assert_eq!(metadata.noise_dbm, None);
        assert_eq!(metadata.frequency_mhz, None);
        assert_eq!(metadata.channel_flags, None);
        assert_eq!(metadata.data_rate_kbps, None);
        assert!(payload.len() > 24);
    }

    #[test]
    fn strips_radiotap_and_extracts_rf_metadata() {
        let frame = detailed_radiotap_beacon_frame();
        let (metadata, payload) = strip_radiotap(&frame).unwrap();
        assert_eq!(metadata.tsft, None);
        assert_eq!(metadata.signal_dbm, Some(-42));
        assert_eq!(metadata.noise_dbm, Some(-95));
        assert_eq!(metadata.frequency_mhz, Some(2437));
        assert_eq!(metadata.channel_flags, Some(0x00a0));
        assert_eq!(metadata.data_rate_kbps, Some(6_000));
        assert_eq!(metadata.antenna_id, None);
        assert!(payload.len() > 24);
    }

    #[test]
    fn strips_radiotap_and_extracts_tsft_and_antenna() {
        let frame = tsft_antenna_radiotap_beacon_frame();
        let (metadata, payload) = strip_radiotap(&frame).unwrap();
        assert_eq!(metadata.tsft, Some(0x0102_0304_0506_0708));
        assert_eq!(metadata.signal_dbm, Some(-42));
        assert_eq!(metadata.noise_dbm, Some(-95));
        assert_eq!(metadata.frequency_mhz, Some(2437));
        assert_eq!(metadata.channel_flags, Some(0x00a0));
        assert_eq!(metadata.data_rate_kbps, Some(6_000));
        assert_eq!(metadata.antenna_id, Some(3));
        assert!(payload.len() > 24);
    }

    #[test]
    fn decodes_dynamic_channel_flags() {
        let packet = RawPacket {
            observed_at: Utc::now(),
            data: dynamic_channel_beacon_frame(),
        };

        let frame = decode_frame(&packet).unwrap();

        assert_eq!(frame.channel_flags, Some(0x0480));
        assert_eq!(frame.channel_number, Some(6));
        assert_eq!(frame.signal_status, "present");
        let rf = frame.rf;
        let channel_flags = rf.channel_flags.unwrap();
        assert!(channel_flags.is_2ghz);
        assert!(channel_flags.dynamic_cck_ofdm);
        assert!(channel_flags.ofdm);
        assert!(channel_flags.cck);
        assert!(channel_flags.labels.contains(&"dynamic_cck_ofdm".to_string()));
    }

    #[test]
    fn strips_radiotap_with_extended_present_mask() {
        let frame = extended_mask_radiotap_beacon_frame();
        let (metadata, payload) = strip_radiotap(&frame).unwrap();
        assert_eq!(metadata.signal_dbm, Some(-42));
        assert!(payload.len() > 24);
    }

    #[test]
    fn strips_radiotap_with_namespace_marker() {
        let packet = RawPacket {
            observed_at: Utc::now(),
            data: namespace_radiotap_beacon_frame(),
        };

        let (metadata, payload) = strip_radiotap(&packet.data).unwrap();
        let frame = decode_frame(&packet).unwrap();

        assert_eq!(metadata.signal_dbm, Some(-42));
        assert!(payload.len() > 24);
        assert_eq!(frame.frame_subtype, "beacon");
        assert_eq!(frame.signal_dbm, Some(-42));
    }

    #[test]
    fn parses_beacon_frame() {
        let packet = RawPacket {
            observed_at: Utc::now(),
            data: detailed_radiotap_beacon_frame(),
        };
        let (_, payload) = strip_radiotap(&packet.data).unwrap();
        let expected_raw_frame = STANDARD.encode(payload);
        let frame = decode_frame(&packet).unwrap();
        assert_eq!(frame.frame_subtype, "beacon");
        assert_eq!(frame.ssid.as_deref(), Some("CorpWiFi"));
        assert_eq!(frame.source_mac.as_deref(), Some("10:20:30:40:50:60"));
        assert_eq!(frame.destination_mac.as_deref(), Some("ff:ff:ff:ff:ff:ff"));
        assert_eq!(frame.transmitter_mac.as_deref(), Some("10:20:30:40:50:60"));
        assert_eq!(frame.receiver_mac.as_deref(), Some("ff:ff:ff:ff:ff:ff"));
        assert_eq!(frame.signal_dbm, Some(-42));
        assert_eq!(frame.noise_dbm, Some(-95));
        assert_eq!(frame.frequency_mhz, Some(2437));
        assert_eq!(frame.channel_flags, Some(0x00a0));
        assert_eq!(frame.data_rate_kbps, Some(6_000));
        assert_eq!(frame.raw_len, payload.len());
        assert_eq!(
            frame.raw_frame.as_deref(),
            Some(expected_raw_frame.as_str())
        );
    }

    #[test]
    fn parses_tsft_and_antenna_into_wifi_frame() {
        let packet = RawPacket {
            observed_at: Utc::now(),
            data: tsft_antenna_radiotap_beacon_frame(),
        };

        let frame = decode_frame(&packet).unwrap();

        assert_eq!(frame.tsft, Some(0x0102_0304_0506_0708));
        assert_eq!(frame.antenna_id, Some(3));
    }

    #[test]
    fn parses_probe_request_frame() {
        let packet = RawPacket {
            observed_at: Utc::now(),
            data: probe_request_radiotap_frame(),
        };
        let frame = decode_frame(&packet).unwrap();
        assert_eq!(frame.frame_subtype, "probe_request");
        assert_eq!(frame.ssid.as_deref(), Some("CorpWiFi"));
    }

    #[test]
    fn parses_probe_response_frame() {
        let packet = RawPacket {
            observed_at: Utc::now(),
            data: probe_response_radiotap_frame(),
        };
        let frame = decode_frame(&packet).unwrap();
        assert_eq!(frame.frame_subtype, "probe_response");
        assert_eq!(frame.ssid.as_deref(), Some("CorpWiFi"));
        assert!(frame
            .tags
            .contains(&"threat:karma_probe_response".to_string()));
        assert!(frame.tags.contains(&"identity:randomized_mac".to_string()));
    }

    #[test]
    fn parses_data_frame_with_distribution_system_destination() {
        let packet = RawPacket {
            observed_at: Utc::now(),
            data: data_to_distribution_radiotap_frame(vec![0xaa, 0xbb]),
        };
        let frame = decode_frame(&packet).unwrap();
        assert_eq!(frame.event_type, "wifi_data_frame");
        assert_eq!(frame.frame_subtype, "data");
        assert_eq!(frame.source_mac.as_deref(), Some("aa:bb:cc:dd:ee:01"));
        assert_eq!(frame.destination_mac.as_deref(), Some("22:33:44:55:66:77"));
        assert_eq!(frame.bssid.as_deref(), Some("10:20:30:40:50:60"));
        assert_eq!(
            frame.destination_bssid.as_deref(),
            Some("10:20:30:40:50:60")
        );
        assert_eq!(frame.transmitter_mac.as_deref(), Some("aa:bb:cc:dd:ee:01"));
        assert_eq!(frame.receiver_mac.as_deref(), Some("10:20:30:40:50:60"));
        assert!(frame.to_ds);
        assert!(!frame.from_ds);
        assert!(frame.tags.contains(&"direction:to_ds".to_string()));
    }

    #[test]
    fn parses_data_frame_from_distribution_system() {
        let packet = RawPacket {
            observed_at: Utc::now(),
            data: data_from_distribution_radiotap_frame(vec![0xaa, 0xbb]),
        };
        let frame = decode_frame(&packet).unwrap();
        assert_eq!(frame.source_mac.as_deref(), Some("22:33:44:55:66:77"));
        assert_eq!(frame.destination_mac.as_deref(), Some("aa:bb:cc:dd:ee:01"));
        assert_eq!(frame.bssid.as_deref(), Some("10:20:30:40:50:60"));
        assert_eq!(frame.transmitter_mac.as_deref(), Some("10:20:30:40:50:60"));
        assert_eq!(frame.receiver_mac.as_deref(), Some("aa:bb:cc:dd:ee:01"));
        assert!(!frame.to_ds);
        assert!(frame.from_ds);
        assert!(frame.tags.contains(&"direction:from_ds".to_string()));
    }

    #[test]
    fn parses_wds_address_roles() {
        let packet = RawPacket {
            observed_at: Utc::now(),
            data: build_frame(
                0x08,
                0x03,
                AP,
                CLIENT,
                DISTRIBUTION_DST,
                Some([0xde, 0xad, 0xbe, 0xef, 0x00, 0x01]),
                vec![0xaa, 0xbb],
            ),
        };
        let frame = decode_frame(&packet).unwrap();
        assert_eq!(frame.bssid, None);
        assert_eq!(frame.source_mac.as_deref(), Some("de:ad:be:ef:00:01"));
        assert_eq!(frame.destination_mac.as_deref(), Some("22:33:44:55:66:77"));
        assert_eq!(frame.transmitter_mac.as_deref(), Some("aa:bb:cc:dd:ee:01"));
        assert_eq!(frame.receiver_mac.as_deref(), Some("10:20:30:40:50:60"));
        assert!(frame.to_ds);
        assert!(frame.from_ds);
        assert!(frame.tags.contains(&"direction:wds".to_string()));
    }

    #[test]
    fn parses_frame_control_flags() {
        let packet = RawPacket {
            observed_at: Utc::now(),
            data: build_frame(0x08, 0x79, AP, CLIENT, DISTRIBUTION_DST, None, vec![0xaa]),
        };
        let frame = decode_frame(&packet).unwrap();
        assert!(frame.to_ds);
        assert!(!frame.from_ds);
        assert!(frame.retry);
        assert!(frame.more_data);
        assert!(frame.power_save);
        assert!(frame.protected);
        assert_eq!(frame.frame_control_flags, 0x7908);
        assert_eq!(frame.duration_id, 0);
        assert!(frame.tags.contains(&"retry".to_string()));
        assert!(frame.tags.contains(&"more_data".to_string()));
        assert!(frame.tags.contains(&"power_save".to_string()));
        assert!(frame.tags.contains(&"protected".to_string()));
    }

    #[test]
    fn parses_fragment_number() {
        let mut data = data_to_distribution_radiotap_frame(vec![0xaa, 0xbb]);
        data[32] = 0x21;
        data[33] = 0x43;
        let packet = RawPacket {
            observed_at: Utc::now(),
            data,
        };

        let frame = decode_frame(&packet).unwrap();

        assert_eq!(frame.sequence_number, Some(0x0432));
        assert_eq!(frame.fragment_number, Some(1));
    }

    #[test]
    fn parses_qos_ipv4_udp_and_ssdp() {
        let payload = llc_snap_ipv4_udp_payload(
            [192, 168, 1, 10],
            [239, 255, 255, 250],
            49152,
            1900,
            &ssdp_udp_payload(),
        );
        let packet = RawPacket {
            observed_at: Utc::now(),
            data: qos_data_to_distribution_radiotap_frame(0x0083, payload),
        };

        let frame = decode_frame(&packet).unwrap();

        assert_eq!(frame.frame_subtype, "qos_data");
        assert_eq!(frame.qos_tid, Some(3));
        assert_eq!(frame.qos_ack_policy, Some(0));
        assert_eq!(frame.ethertype, Some(0x0800));
        assert_eq!(frame.src_ip.as_deref(), Some("192.168.1.10"));
        assert_eq!(frame.dst_ip.as_deref(), Some("239.255.255.250"));
        assert_eq!(frame.src_port, Some(49152));
        assert_eq!(frame.dst_port, Some(1900));
        assert_eq!(frame.app_protocol.as_deref(), Some("ssdp"));
        assert_eq!(frame.ssdp_message_type.as_deref(), Some("M-SEARCH"));
        assert_eq!(
            frame.ssdp_st.as_deref(),
            Some("urn:schemas-upnp-org:device:MediaRenderer:1")
        );
        assert_eq!(frame.payload_visibility, "plaintext");
        assert!(frame.tags.contains(&"qos".to_string()));
        assert!(frame.tags.contains(&"app:ssdp".to_string()));
    }

    #[test]
    fn parses_dns_and_dhcp_application_fields() {
        let dns_packet = RawPacket {
            observed_at: Utc::now(),
            data: data_to_distribution_radiotap_frame(llc_snap_ipv4_udp_payload(
                [10, 0, 0, 2],
                [8, 8, 8, 8],
                53000,
                53,
                &dns_query_payload("printer.local"),
            )),
        };
        let dns_frame = decode_frame(&dns_packet).unwrap();
        assert_eq!(dns_frame.app_protocol.as_deref(), Some("dns"));
        assert_eq!(dns_frame.dns_query_name.as_deref(), Some("printer.local"));

        let dhcp_packet = RawPacket {
            observed_at: Utc::now(),
            data: data_to_distribution_radiotap_frame(llc_snap_ipv4_udp_payload(
                [0, 0, 0, 0],
                [255, 255, 255, 255],
                68,
                67,
                &dhcp_discover_payload(),
            )),
        };
        let dhcp_frame = decode_frame(&dhcp_packet).unwrap();
        assert_eq!(dhcp_frame.app_protocol.as_deref(), Some("dhcp"));
        assert_eq!(dhcp_frame.dhcp_requested_ip.as_deref(), Some("192.168.1.44"));
        assert_eq!(dhcp_frame.dhcp_hostname.as_deref(), Some("sensor"));
        assert_eq!(dhcp_frame.dhcp_vendor_class.as_deref(), Some("AcmeClient1"));
    }

    #[test]
    fn parses_tcp_transport_header() {
        let packet = RawPacket {
            observed_at: Utc::now(),
            data: data_to_distribution_radiotap_frame(llc_snap_ipv4_tcp_payload(
                [192, 168, 1, 10],
                [192, 168, 1, 20],
                443,
                54_321,
                0x12,
                b"GET / HTTP/1.1\r\n\r\n",
            )),
        };

        let frame = decode_frame(&packet).unwrap();

        assert_eq!(frame.transport_protocol.as_deref(), Some("tcp"));
        assert_eq!(frame.src_port, Some(443));
        assert_eq!(frame.dst_port, Some(54_321));
        let transport = frame.transport.unwrap();
        assert!(transport.tcp_flags.contains(&"syn".to_string()));
        assert!(transport.tcp_flags.contains(&"ack".to_string()));
    }

    #[test]
    fn parses_mdns_and_skips_protected_payload_decoding() {
        let mdns_packet = RawPacket {
            observed_at: Utc::now(),
            data: data_from_distribution_radiotap_frame(llc_snap_ipv4_udp_payload(
                [224, 0, 0, 251],
                [224, 0, 0, 251],
                5353,
                5353,
                &mdns_response_payload("_airplay._tcp.local"),
            )),
        };
        let mdns_frame = decode_frame(&mdns_packet).unwrap();
        assert_eq!(mdns_frame.app_protocol.as_deref(), Some("mdns"));
        assert_eq!(mdns_frame.mdns_name.as_deref(), Some("_airplay._tcp.local"));

        let protected_packet = RawPacket {
            observed_at: Utc::now(),
            data: build_frame(
                0x08,
                0x41,
                AP,
                CLIENT,
                DISTRIBUTION_DST,
                None,
                llc_snap_ipv4_udp_payload(
                    [192, 168, 1, 10],
                    [8, 8, 8, 8],
                    53000,
                    53,
                    &dns_query_payload("blocked.local"),
                ),
            ),
        };
        let protected_frame = decode_frame(&protected_packet).unwrap();
        assert!(protected_frame.protected);
        assert_eq!(protected_frame.payload_visibility, "ciphertext");
        assert_eq!(protected_frame.src_ip, None);
        assert_eq!(protected_frame.app_protocol, None);
    }

    #[test]
    fn parses_eap_identity_and_resolves_username_cache() {
        let mut cache = IdentityCache::default();
        let identity_packet = RawPacket {
            observed_at: Utc::now(),
            data: data_to_distribution_radiotap_frame(eap_identity_payload("alice@corp.example")),
        };
        let identity_frame = decode_frame(&identity_packet).unwrap();
        assert_eq!(
            identity_frame.username_hint.as_deref(),
            Some("alice@corp.example")
        );
        assert!(identity_frame.tags.contains(&"eapol".to_string()));

        let resolved = cache.resolve(&identity_frame).unwrap();
        assert_eq!(resolved.username, "alice@corp.example");
        assert_eq!(resolved.source, "eap_identity");

        let followup_packet = RawPacket {
            observed_at: Utc::now(),
            data: data_to_distribution_radiotap_frame(vec![0x01, 0x02, 0x03]),
        };
        let followup_frame = decode_frame(&followup_packet).unwrap();
        let cached = cache.resolve(&followup_frame).unwrap();
        assert_eq!(cached.username, "alice@corp.example");
        assert_eq!(cached.source, "eap_identity_cache");
    }

    #[test]
    fn iterates_information_elements_and_stops_on_truncation() {
        let bytes = [1, 2, 0xaa, 0xbb, 2, 3, 0xcc];
        let elements: Vec<_> = IEIterator::new(&bytes, 0).collect();
        assert_eq!(elements.len(), 1);
        assert_eq!(elements[0].id, 1);
        assert_eq!(elements[0].len, 2);
        assert_eq!(elements[0].data, &[0xaa, 0xbb]);
    }

    #[test]
    fn parses_security_wps_and_fingerprint_metadata() {
        let mut body = beacon_body();
        body.extend_from_slice(&rsn_ie(true, true));
        body.extend_from_slice(&wpa_vendor_ie());
        body.extend_from_slice(&wps_vendor_ie());
        let packet = RawPacket {
            observed_at: Utc::now(),
            data: build_frame(0x80, 0x00, BROADCAST, AP, AP, None, body),
        };

        let frame = decode_frame(&packet).unwrap();

        assert_eq!(
            frame.security_flags,
            SECURITY_WPA | SECURITY_RSN_WPA2 | SECURITY_WPA3 | SECURITY_WPS | SECURITY_PMF_REQUIRED
        );
        assert_eq!(frame.wps_device_name.as_deref(), Some("Lobby AP"));
        assert_eq!(frame.wps_manufacturer.as_deref(), Some("Acme"));
        assert_eq!(frame.wps_model_name.as_deref(), Some("Model 7"));
        assert_eq!(
            frame.device_fingerprint.as_deref(),
            Some("d9e7757fee253fc7")
        );
    }

    #[test]
    fn detects_handshake_once_per_duplicate_window() {
        let context = AuditContext {
            sensor_id: "sensor-1".to_string(),
            location_id: "lab".to_string(),
            interface: "wlan0".to_string(),
            channel: 6,
            reg_domain: "US".to_string(),
        };
        let mut monitor = HandshakeMonitor::default();
        let mut alerts = Vec::new();

        for (from_ds, message) in [(true, 1), (false, 2), (true, 3), (false, 4)] {
            let data = if from_ds {
                data_from_distribution_radiotap_frame(eapol_key_payload(message))
            } else {
                data_to_distribution_radiotap_frame(eapol_key_payload(message))
            };
            let mut frame = decode_frame(&RawPacket {
                observed_at: Utc::now(),
                data,
            })
            .unwrap();
            if let Some(alert) = monitor.observe(&mut frame, &context) {
                assert!(frame.handshake_captured);
                assert!(frame.tags.contains(&"handshake_captured".to_string()));
                alerts.push(alert);
            }
        }

        assert_eq!(alerts.len(), 1);
        assert_eq!(alerts[0].bssid, "10:20:30:40:50:60");
        assert_eq!(alerts[0].client_mac, "aa:bb:cc:dd:ee:01");

        let mut duplicate = decode_frame(&RawPacket {
            observed_at: Utc::now(),
            data: data_to_distribution_radiotap_frame(eapol_key_payload(4)),
        })
        .unwrap();
        assert!(monitor.observe(&mut duplicate, &context).is_none());
    }

    #[test]
    fn rejects_control_frames() {
        let mut bytes = beacon_radiotap_frame();
        bytes[10] = 0x84;
        let packet = RawPacket {
            observed_at: Utc::now(),
            data: bytes,
        };
        assert!(matches!(
            decode_frame(&packet),
            Err(ParseError::UnsupportedControlFrame)
        ));
    }

    #[test]
    fn rejects_malformed_radiotap() {
        let packet = RawPacket {
            observed_at: Utc::now(),
            data: vec![0, 0, 32, 0],
        };
        assert!(matches!(
            decode_frame(&packet),
            Err(ParseError::MissingRadiotap)
        ));

        let packet = RawPacket {
            observed_at: Utc::now(),
            data: vec![0, 0, 8, 0, 0x20, 0, 0, 0],
        };
        assert!(matches!(
            decode_frame(&packet),
            Err(ParseError::MissingRadiotap)
        ));
    }

    #[test]
    fn serializes_audit_entry() {
        let context = AuditContext {
            sensor_id: "00:11:22:33:44:55".to_string(),
            location_id: "North-Wing-Entry".to_string(),
            interface: "wlan0".to_string(),
            channel: 6,
            reg_domain: "US".to_string(),
        };
        let packet = RawPacket {
            observed_at: Utc::now(),
            data: beacon_radiotap_frame(),
        };
        let (_, payload) = strip_radiotap(&packet.data).unwrap();
        let expected_raw_frame = STANDARD.encode(payload);
        let entry = to_audit_entry(attach_context(decode_frame(&packet).unwrap(), &context));
        let value = serde_json::to_value(entry).unwrap();
        assert_eq!(value["schema_version"], Value::Number(2u64.into()));
        assert_eq!(
            value["event_type"],
            Value::String("wifi_management_frame".to_string())
        );
        assert_eq!(value["channel"], Value::Number(6u64.into()));
        assert_eq!(
            value["transmitter_mac"],
            Value::String("10:20:30:40:50:60".to_string())
        );
        assert_eq!(
            value["receiver_mac"],
            Value::String("ff:ff:ff:ff:ff:ff".to_string())
        );
        assert_eq!(value["signal_dbm"], Value::Number((-42).into()));
        assert_eq!(value["tsft"], Value::Null);
        assert_eq!(value["antenna_id"], Value::Null);
        assert_eq!(value["duration_id"], Value::Number(0u64.into()));
        assert_eq!(
            value["frame_control_flags"],
            Value::Number(0x0080u64.into())
        );
        assert_eq!(value["more_data"], Value::Bool(false));
        assert_eq!(value["retry"], Value::Bool(false));
        assert_eq!(value["power_save"], Value::Bool(false));
        assert_eq!(value["protected"], Value::Bool(false));
        assert_eq!(value["to_ds"], Value::Bool(false));
        assert_eq!(value["from_ds"], Value::Bool(false));
        assert_eq!(value["payload_visibility"], Value::String("header_only".to_string()));
        assert_eq!(value["raw_frame"], Value::String(expected_raw_frame));
        assert_eq!(value["username"], Value::Null);
        assert_eq!(
            value["identity_source"],
            Value::String("mac_observed".to_string())
        );
        assert!(value["device_id"].is_null());
        assert!(value["mac"].is_object());
        assert!(value["rf"].is_object());
        let tags = value["tags"].as_array().unwrap();
        assert!(tags.contains(&Value::String("signal:strong".to_string())));
        assert!(tags.contains(&Value::String("threat:potential_evil_twin".to_string())));
    }

    #[test]
    fn serializes_tsft_and_antenna_in_audit_entry() {
        let context = AuditContext {
            sensor_id: "00:11:22:33:44:55".to_string(),
            location_id: "North-Wing-Entry".to_string(),
            interface: "wlan0".to_string(),
            channel: 6,
            reg_domain: "US".to_string(),
        };
        let packet = RawPacket {
            observed_at: Utc::now(),
            data: tsft_antenna_radiotap_beacon_frame(),
        };
        let entry = to_audit_entry(attach_context(decode_frame(&packet).unwrap(), &context));
        let value = serde_json::to_value(entry).unwrap();

        assert_eq!(
            value["tsft"],
            Value::Number(0x0102_0304_0506_0708u64.into())
        );
        assert_eq!(value["antenna_id"], Value::Number(3u64.into()));
    }

    #[test]
    fn detects_new_bssid_for_known_ssid() {
        let mut cache = IdentityCache::default();
        let first = decode_frame(&RawPacket {
            observed_at: Utc::now(),
            data: beacon_radiotap_frame(),
        })
        .unwrap();
        assert!(cache.resolve(&first).is_none());

        let second = decode_frame(&RawPacket {
            observed_at: Utc::now(),
            data: build_frame(0x80, 0x00, BROADCAST, AP2, AP2, None, beacon_body()),
        })
        .unwrap();
        let resolved = cache.resolve(&second).unwrap();
        assert_eq!(resolved.source, "evil_twin_detection");
        assert!(resolved
            .tags
            .contains(&"threat:potential_evil_twin".to_string()));
    }
}
