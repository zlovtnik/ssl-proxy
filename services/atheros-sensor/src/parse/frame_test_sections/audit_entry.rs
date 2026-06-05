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
        assert_eq!(frame.rsn_capabilities, Some(RSN_CAP_PMF_REQUIRED));
        assert_eq!(frame.weak_cipher_advertised, Some(false));
        assert_eq!(frame.wps_device_name.as_deref(), Some("Lobby AP"));
        assert_eq!(frame.wps_manufacturer.as_deref(), Some("Acme"));
        assert_eq!(frame.wps_model_name.as_deref(), Some("Model 7"));
        assert_eq!(
            frame.device_fingerprint.as_deref(),
            Some("d9e7757fee253fc7")
        );
        assert!(frame.ie_layout_hash.is_some());
    }

    #[test]
    fn ie_layout_hash_includes_element_lengths_without_changing_device_fingerprint() {
        let mut short_body = vec![0; 8];
        short_body.extend_from_slice(&100u16.to_le_bytes());
        short_body.extend_from_slice(&0x0431u16.to_le_bytes());
        short_body.extend_from_slice(&[0x00, 0x04]);
        short_body.extend_from_slice(b"Corp");
        short_body.extend_from_slice(&[0x01, 0x01, 0x82]);

        let mut long_body = vec![0; 8];
        long_body.extend_from_slice(&100u16.to_le_bytes());
        long_body.extend_from_slice(&0x0431u16.to_le_bytes());
        long_body.extend_from_slice(&[0x00, 0x08]);
        long_body.extend_from_slice(b"CorpWiFi");
        long_body.extend_from_slice(&[0x01, 0x01, 0x82]);

        let short = decode_frame(&RawPacket {
            observed_at: Utc::now(),
            data: build_frame(0x80, 0x00, BROADCAST, AP, AP, None, short_body),
        })
        .unwrap();
        let long = decode_frame(&RawPacket {
            observed_at: Utc::now(),
            data: build_frame(0x80, 0x00, BROADCAST, AP, AP, None, long_body),
        })
        .unwrap();

        assert_eq!(short.device_fingerprint, long.device_fingerprint);
        assert_ne!(short.ie_layout_hash, long.ie_layout_hash);
    }

    #[test]
    fn tags_wpa3_without_pmf_required_as_downgrade_suspect() {
        let context = AuditContext {
            sensor_id: "00:11:22:33:44:55".to_string(),
            location_id: "North-Wing-Entry".to_string(),
            interface: "wlan0".to_string(),
            channel: 6,
            reg_domain: "US".to_string(),
        };
        let mut body = beacon_body();
        body.extend_from_slice(&rsn_ie_with_capabilities(true, RSN_CAP_PMF_CAPABLE, false));
        let entry = to_audit_entry(attach_context(
            decode_frame(&RawPacket {
                observed_at: Utc::now(),
                data: build_frame(0x80, 0x00, BROADCAST, AP, AP, None, body),
            })
            .unwrap(),
            &context,
        ));

        assert_eq!(entry.rsn_capabilities, Some(RSN_CAP_PMF_CAPABLE));
        assert!(entry
            .tags
            .contains(&"threat:pmf_downgrade_suspect".to_string()));
    }

    #[test]
    fn channel_number_fallback_does_not_classify_6ghz_as_5ghz() {
        assert_eq!(derive_band(None, None, Some(6)), "2.4ghz");
        assert_eq!(derive_band(None, None, Some(36)), "5ghz");
        assert_eq!(derive_band(None, None, Some(177)), "unknown");
    }

    #[test]
    fn tags_weak_rsn_cipher_advertisements() {
        let context = AuditContext {
            sensor_id: "00:11:22:33:44:55".to_string(),
            location_id: "North-Wing-Entry".to_string(),
            interface: "wlan0".to_string(),
            channel: 6,
            reg_domain: "US".to_string(),
        };
        let mut body = beacon_body();
        body.extend_from_slice(&rsn_ie_with_capabilities(false, 0, true));
        let entry = to_audit_entry(attach_context(
            decode_frame(&RawPacket {
                observed_at: Utc::now(),
                data: build_frame(0x80, 0x00, BROADCAST, AP, AP, None, body),
            })
            .unwrap(),
            &context,
        ));

        assert_eq!(entry.weak_cipher_advertised, Some(true));
        assert!(entry
            .tags
            .contains(&"threat:weak_cipher_advertised".to_string()));
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
            if let Some(alert) = monitor.observe(
                &mut frame,
                &context,
                None,
                None,
                "type mgt or type data",
                Duration::from_secs(60),
            ) {
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
        assert!(monitor
            .observe(
                &mut duplicate,
                &context,
                None,
                None,
                "type mgt or type data",
                Duration::from_secs(60)
            )
            .is_none());
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
        assert_eq!(
            value["payload_visibility"],
            Value::String("header_only".to_string())
        );
        assert_eq!(value["raw_frame"], Value::String(expected_raw_frame));
        assert!(value["ie_layout_hash"].is_string());
        assert!(value["sequence_delta"].is_null());
        assert!(value["sequence_gap_missing_frames"].is_null());
        assert!(value["clock_skew_delta_us"].is_null());
        assert!(value["correlation"]["sequence_delta"].is_null());
        assert!(value["correlation"]["clock_skew_delta_us"].is_null());
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
    fn sanitizes_nul_bytes_from_ssid_before_json_payload() {
        let context = AuditContext {
            sensor_id: "00:11:22:33:44:55".to_string(),
            location_id: "North-Wing-Entry".to_string(),
            interface: "wlan0".to_string(),
            channel: 6,
            reg_domain: "US".to_string(),
        };
        let mut body = vec![0; 8];
        body.extend_from_slice(&100u16.to_le_bytes());
        body.extend_from_slice(&0x0431u16.to_le_bytes());
        body.extend_from_slice(&[0x00, 0x09]);
        body.extend_from_slice(b"\0CorpWiFi");
        let packet = RawPacket {
            observed_at: Utc::now(),
            data: build_frame(0x80, 0x00, BROADCAST, AP, AP, None, body),
        };

        let entry = to_audit_entry(attach_context(decode_frame(&packet).unwrap(), &context));
        let payload = serde_json::to_string(&entry).unwrap();

        assert_eq!(entry.ssid.as_deref(), Some("CorpWiFi"));
        assert!(!payload.contains("\\u0000"));
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
