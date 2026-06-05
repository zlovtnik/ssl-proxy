    #[test]
    fn pmf_attack_detection() {
        use super::PmfAttackTracker;
        use crate::model::AuditEntry;

        let mut tracker = PmfAttackTracker::new(3000);
        let mut tags = Vec::new();

        // Beacon from AP with PMF not required
        let beacon = AuditEntry {
            schema_version: 2,
            event_type: "wifi_management_frame".to_string(),
            observed_at: "2024-01-01T12:00:00Z".to_string(),
            sensor_id: "sensor1".to_string(),
            location_id: "loc1".to_string(),
            interface: "wlan0".to_string(),
            channel: 6,
            band: "2.4ghz".to_string(),
            frame_type: Some("management".to_string()),
            bssid: Some("aa:bb:cc:dd:ee:ff".to_string()),
            source_mac: Some("aa:bb:cc:dd:ee:ff".to_string()),
            destination_mac: Some("ff:ff:ff:ff:ff:ff".to_string()),
            transmitter_mac: None,
            receiver_mac: None,
            ssid: None,
            frame_subtype: "beacon".to_string(),
            tsft: None,
            signal_dbm: None,
            noise_dbm: None,
            frequency_mhz: None,
            channel_flags: None,
            data_rate_kbps: None,
            antenna_id: None,
            vht_known: None,
            vht_flags: None,
            vht_bandwidth: None,
            he_data: None,
            sequence_number: None,
            fragment_number: None,
            channel_number: None,
            signal_status: None,
            adjacent_mac_hint: None,
            duration_id: None,
            frame_control_flags: None,
            more_data: None,
            retry: None,
            power_save: None,
            protected: Some(false),
            to_ds: None,
            from_ds: None,
            raw_len: 100,
            raw_frame: None,
            tags: vec![],
            risk_score: None,
            security_flags: 0x02,
            rsn_capabilities: None,
            weak_cipher_advertised: None,
            wps_device_name: None,
            wps_manufacturer: None,
            wps_model_name: None,
            device_fingerprint: None,
            probe_fingerprint: None,
            ie_layout_hash: None,
            vendor_name: None,
            handshake_captured: false,
            qos_tid: None,
            qos_eosp: None,
            qos_ack_policy: None,
            qos_ack_policy_label: None,
            qos_amsdu: None,
            llc_oui: None,
            ethertype: None,
            ethertype_name: None,
            src_ip: None,
            dst_ip: None,
            ip_ttl: None,
            ip_protocol: None,
            ip_protocol_name: None,
            src_port: None,
            dst_port: None,
            transport_protocol: None,
            transport_length: None,
            transport_checksum: None,
            app_protocol: None,
            ssdp_message_type: None,
            ssdp_st: None,
            ssdp_mx: None,
            ssdp_usn: None,
            dhcp_requested_ip: None,
            dhcp_hostname: None,
            dhcp_vendor_class: None,
            dns_query_name: None,
            mdns_name: None,
            session_key: None,
            retransmit_key: None,
            frame_fingerprint: None,
            payload_visibility: None,
            tsft_delta_us: None,
            wall_clock_delta_ms: None,
            sequence_delta: None,
            sequence_gap_missing_frames: None,
            clock_skew_delta_us: None,
            large_frame: None,
            mixed_encryption: None,
            dedupe_or_replay_suspect: None,
            anomaly_reasons: vec![],
            mac: None,
            rf: None,
            qos: None,
            llc_snap: None,
            network: None,
            transport: None,
            application: None,
            correlation: None,
            anomalies: None,
            device_id: None,
            username: None,
            identity_source: "unknown".to_string(),
            destination_bssid: None,
        };
        tracker.observe(&beacon, &mut tags);
        assert!(tags.is_empty());

        // Unprotected deauth from same AP BSSID should not trigger when PMF is not required.
        let mut deauth = beacon.clone();
        deauth.frame_subtype = "deauthentication".to_string();
        deauth.source_mac = Some("aa:bb:cc:dd:ee:ff".to_string());
        deauth.destination_mac = Some("11:22:33:44:55:66".to_string());
        deauth.protected = Some(false);
        deauth.observed_at = "2024-01-01T12:00:01Z".to_string();
        tracker.observe(&deauth, &mut tags);
        assert!(!tags.contains(&"threat:pmf_deauth_attack".to_string()));

        // Client reconnects within 2 seconds
        tags.clear();
        let mut assoc = beacon.clone();
        assoc.frame_subtype = "association_request".to_string();
        assoc.source_mac = Some("11:22:33:44:55:66".to_string());
        assoc.observed_at = "2024-01-01T12:00:02Z".to_string();
        tracker.observe(&assoc, &mut tags);
        assert!(tags.contains(&"threat:pmf_forced_reconnect".to_string()));
    }

    #[test]
    fn pmf_attack_detected_when_pmf_required() {
        use super::PmfAttackTracker;
        use crate::parse::SECURITY_PMF_REQUIRED;

        let mut tracker = PmfAttackTracker::new(3000);
        let mut tags = Vec::new();

        // Beacon with PMF required
        let mut beacon = create_test_audit_entry();
        beacon.bssid = Some("aa:bb:cc:dd:ee:ff".to_string());
        beacon.source_mac = Some("aa:bb:cc:dd:ee:ff".to_string());
        beacon.frame_subtype = "beacon".to_string();
        beacon.protected = Some(false);
        beacon.security_flags = SECURITY_PMF_REQUIRED;
        tracker.observe(&beacon, &mut tags);

        // Unprotected deauth should trigger attack tag
        let mut deauth = beacon.clone();
        deauth.frame_subtype = "deauthentication".to_string();
        deauth.source_mac = Some("aa:bb:cc:dd:ee:ff".to_string());
        deauth.destination_mac = Some("11:22:33:44:55:66".to_string());
        deauth.protected = Some(false);
        tracker.observe(&deauth, &mut tags);
        assert!(tags.contains(&"threat:pmf_deauth_attack".to_string()));
    }

    fn create_test_audit_entry() -> crate::model::AuditEntry {
        crate::model::AuditEntry {
            schema_version: 2,
            event_type: "wifi_management_frame".to_string(),
            observed_at: "2024-01-01T12:00:00Z".to_string(),
            sensor_id: "sensor1".to_string(),
            location_id: "loc1".to_string(),
            interface: "wlan0".to_string(),
            channel: 6,
            band: "2.4ghz".to_string(),
            frame_type: Some("management".to_string()),
            bssid: None,
            source_mac: None,
            destination_mac: None,
            transmitter_mac: None,
            receiver_mac: None,
            ssid: None,
            frame_subtype: "beacon".to_string(),
            tsft: None,
            signal_dbm: None,
            noise_dbm: None,
            frequency_mhz: None,
            channel_flags: None,
            data_rate_kbps: None,
            antenna_id: None,
            vht_known: None,
            vht_flags: None,
            vht_bandwidth: None,
            he_data: None,
            sequence_number: None,
            fragment_number: None,
            channel_number: None,
            signal_status: None,
            adjacent_mac_hint: None,
            duration_id: None,
            frame_control_flags: None,
            more_data: None,
            retry: None,
            power_save: None,
            protected: None,
            to_ds: None,
            from_ds: None,
            raw_len: 100,
            raw_frame: None,
            tags: vec![],
            risk_score: None,
            security_flags: 0,
            rsn_capabilities: None,
            weak_cipher_advertised: None,
            wps_device_name: None,
            wps_manufacturer: None,
            wps_model_name: None,
            device_fingerprint: None,
            probe_fingerprint: None,
            ie_layout_hash: None,
            vendor_name: None,
            handshake_captured: false,
            qos_tid: None,
            qos_eosp: None,
            qos_ack_policy: None,
            qos_ack_policy_label: None,
            qos_amsdu: None,
            llc_oui: None,
            ethertype: None,
            ethertype_name: None,
            src_ip: None,
            dst_ip: None,
            ip_ttl: None,
            ip_protocol: None,
            ip_protocol_name: None,
            src_port: None,
            dst_port: None,
            transport_protocol: None,
            transport_length: None,
            transport_checksum: None,
            app_protocol: None,
            ssdp_message_type: None,
            ssdp_st: None,
            ssdp_mx: None,
            ssdp_usn: None,
            dhcp_requested_ip: None,
            dhcp_hostname: None,
            dhcp_vendor_class: None,
            dns_query_name: None,
            mdns_name: None,
            session_key: None,
            retransmit_key: None,
            frame_fingerprint: None,
            payload_visibility: None,
            tsft_delta_us: None,
            wall_clock_delta_ms: None,
            sequence_delta: None,
            sequence_gap_missing_frames: None,
            clock_skew_delta_us: None,
            large_frame: None,
            mixed_encryption: None,
            dedupe_or_replay_suspect: None,
            anomaly_reasons: vec![],
            mac: None,
            rf: None,
            qos: None,
            llc_snap: None,
            network: None,
            transport: None,
            application: None,
            correlation: None,
            anomalies: None,
            device_id: None,
            username: None,
            identity_source: "unknown".to_string(),
            destination_bssid: None,
        }
    }
