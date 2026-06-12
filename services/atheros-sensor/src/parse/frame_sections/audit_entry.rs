pub fn to_audit_entry(enriched: EnrichedFrame) -> AuditEntry {
    let mut frame = enriched.frame;
    let mut tags = std::mem::take(&mut frame.tags);
    tags.push(format!("channel:{}", enriched.channel));
    tags.push(format!("reg_domain:{}", enriched.reg_domain));
    add_audit_threat_tags(&frame, &mut tags);

    let username = frame.username_hint.clone();
    let identity_source = match (username.as_ref(), frame.identity_source_hint) {
        (Some(_), Some(source)) => source,
        (Some(_), None) => IdentitySource::ObservedIdentity,
        (None, _) if frame.source_mac.is_some() || frame.bssid.is_some() => {
            IdentitySource::MacObserved
        }
        (None, _) => IdentitySource::Unknown,
    };

    AuditEntry {
        schema_version: frame.schema_version,
        event_type: frame.event_type,
        observed_at: ssl_proxy::time::rfc3339_from_utc(frame.observed_at),
        sensor_id: enriched.sensor_id,
        location_id: enriched.location_id,
        interface: enriched.interface,
        channel: enriched.channel,
        band: frame.band,
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
        vht_known: frame.vht_known,
        vht_flags: frame.vht_flags,
        vht_bandwidth: frame.vht_bandwidth,
        he_data: frame.he_data,
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
        tags: tags.clone(),
        risk_score: recompute_risk_score(&tags),
        security_flags: frame.security_flags,
        rsn_capabilities: frame.rsn_capabilities,
        weak_cipher_advertised: frame.weak_cipher_advertised,
        wps_device_name: frame.wps_device_name,
        wps_manufacturer: frame.wps_manufacturer,
        wps_model_name: frame.wps_model_name,
        device_fingerprint: frame.device_fingerprint,
        probe_fingerprint: frame.probe_fingerprint,
        ie_layout_hash: frame.ie_layout_hash,
        vendor_name: frame.vendor_name,
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
        sequence_delta: frame.sequence_delta,
        sequence_gap_missing_frames: frame.sequence_gap_missing_frames,
        clock_skew_delta_us: frame.clock_skew_delta_us,
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
            2 => "reassociation_request",
            3 => "reassociation_response",
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

fn derive_band(
    frequency_mhz: Option<u16>,
    channel_flags: Option<u16>,
    channel_number: Option<u16>,
) -> &'static str {
    if let Some(frequency) = frequency_mhz {
        return match frequency {
            2400..=2500 => "2.4ghz",
            4900..=5900 => "5ghz",
            5925..=7125 => "6ghz",
            _ => "unknown",
        };
    }
    if let Some(flags) = channel_flags {
        if flags & 0x0080 != 0 {
            return "2.4ghz";
        }
        if flags & 0x0100 != 0 {
            return "5ghz";
        }
    }
    match channel_number {
        Some(1..=14) => "2.4ghz",
        Some(36..=165) => "5ghz",
        _ => "unknown",
    }
}
