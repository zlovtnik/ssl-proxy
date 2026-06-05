    use base64::{engine::general_purpose::STANDARD, Engine};
    use chrono::Utc;
    use serde_json::Value;
    use std::time::Duration;

    use super::*;
    use crate::{
        model::{AuditContext, RawPacket},
        parse::{
            strip_radiotap, HandshakeMonitor, IEIterator, IdentityCache, ParseError,
            RSN_CAP_PMF_CAPABLE, RSN_CAP_PMF_REQUIRED, SECURITY_PMF_REQUIRED, SECURITY_RSN_WPA2,
            SECURITY_WPA, SECURITY_WPA3, SECURITY_WPS,
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
        assert!(channel_flags
            .labels
            .contains(&"dynamic_cck_ofdm".to_string()));
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
    fn strips_radiotap_with_vendor_namespace_skip() {
        let frame = vendor_namespace_before_signal_beacon_frame();
        let (metadata, payload) = strip_radiotap(&frame).unwrap();
        assert_eq!(metadata.signal_dbm, Some(-42));
        assert!(payload.len() > 24);
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
        // Beacons should NOT have probe_fingerprint
        assert!(frame.probe_fingerprint.is_none());
        // But should have device_fingerprint
        assert!(frame.device_fingerprint.is_some());
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
        // Probe requests should have probe_fingerprint
        assert!(frame.probe_fingerprint.is_some());
        // Should also have device_fingerprint
        assert!(frame.device_fingerprint.is_some());
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
        assert_eq!(
            dhcp_frame.dhcp_requested_ip.as_deref(),
            Some("192.168.1.44")
        );
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
