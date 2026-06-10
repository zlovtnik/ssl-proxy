    use super::edit_distance_limited;

    #[test]
    fn edit_distance_limits_typosquats() {
        assert_eq!(edit_distance_limited("corpwifi", "corp-wifi", 2), 1);
        assert!(edit_distance_limited("corpwifi", "guest", 2) > 2);
    }

    #[test]
    fn edit_distance_counts_unicode_chars() {
        assert_eq!(edit_distance_limited("cafe", "caf\u{00E9}", 2), 1);
    }

    #[test]
    fn link_probe_to_network_matches_ssid() {
        use super::{AuthorizedNetworkCache, ClientInventory};
        use crate::backlog::AuthorizedWirelessNetwork;

        let mut cache = AuthorizedNetworkCache::default();
        cache.entries = vec![AuthorizedWirelessNetwork {
            ssid: Some("CorpWiFi".to_string()),
            bssid: Some("aa:bb:cc:dd:ee:ff".to_string()),
            location_id: Some("loc1".to_string()),
            psk: None,
        }];

        let inventory = ClientInventory::default();
        let mut entry = create_test_audit_entry();
        entry.frame_subtype = "probe_request".to_string();
        entry.source_mac = Some("11:22:33:44:55:66".to_string());
        entry.ssid = Some("CorpWiFi".to_string());

        let result = inventory.link_probe_to_network(&entry, &cache);
        assert!(result.is_some());
        let (bssid, client_mac, ssid) = result.unwrap();
        assert_eq!(bssid, "aa:bb:cc:dd:ee:ff");
        assert_eq!(client_mac, "11:22:33:44:55:66");
        assert_eq!(ssid, Some("CorpWiFi".to_string()));
    }

    #[test]
    fn link_probe_to_network_case_insensitive() {
        use super::{AuthorizedNetworkCache, ClientInventory};
        use crate::backlog::AuthorizedWirelessNetwork;

        let mut cache = AuthorizedNetworkCache::default();
        cache.entries = vec![AuthorizedWirelessNetwork {
            ssid: Some("CorpWiFi".to_string()),
            bssid: Some("aa:bb:cc:dd:ee:ff".to_string()),
            location_id: Some("loc1".to_string()),
            psk: None,
        }];

        let inventory = ClientInventory::default();
        let mut entry = create_test_audit_entry();
        entry.frame_subtype = "probe_request".to_string();
        entry.source_mac = Some("11:22:33:44:55:66".to_string());
        entry.ssid = Some("corpwifi".to_string());

        let result = inventory.link_probe_to_network(&entry, &cache);
        assert!(result.is_some());
    }

    #[test]
    fn link_probe_to_network_no_match() {
        use super::{AuthorizedNetworkCache, ClientInventory};
        use crate::backlog::AuthorizedWirelessNetwork;

        let mut cache = AuthorizedNetworkCache::default();
        cache.entries = vec![AuthorizedWirelessNetwork {
            ssid: Some("CorpWiFi".to_string()),
            bssid: Some("aa:bb:cc:dd:ee:ff".to_string()),
            location_id: Some("loc1".to_string()),
            psk: None,
        }];

        let inventory = ClientInventory::default();
        let mut entry = create_test_audit_entry();
        entry.frame_subtype = "probe_request".to_string();
        entry.source_mac = Some("11:22:33:44:55:66".to_string());
        entry.ssid = Some("GuestNetwork".to_string());

        let result = inventory.link_probe_to_network(&entry, &cache);
        assert!(result.is_none());
    }

    #[test]
    fn client_inventory_records_roaming_history_and_learns_normal_roams() {
        use super::ClientInventory;

        let mut inventory = ClientInventory::default();

        let mut entry = create_test_audit_entry();
        entry.frame_subtype = "association_request".to_string();
        entry.source_mac = Some("11:22:33:44:55:66".to_string());
        entry.bssid = Some("aa:bb:cc:dd:ee:01".to_string());
        inventory.observe(&mut entry);
        assert!(!entry.tags.contains(&"threat:unusual_roam".to_string()));

        let mut entry = create_test_audit_entry();
        entry.frame_subtype = "association_request".to_string();
        entry.source_mac = Some("11:22:33:44:55:66".to_string());
        entry.bssid = Some("aa:bb:cc:dd:ee:02".to_string());
        inventory.observe(&mut entry);
        assert!(entry.tags.contains(&"threat:unusual_roam".to_string()));

        let mut entry = create_test_audit_entry();
        entry.frame_subtype = "association_request".to_string();
        entry.source_mac = Some("11:22:33:44:55:66".to_string());
        entry.bssid = Some("aa:bb:cc:dd:ee:01".to_string());
        inventory.observe(&mut entry);
        assert!(entry.tags.contains(&"threat:unusual_roam".to_string()));

        let mut entry = create_test_audit_entry();
        entry.frame_subtype = "association_request".to_string();
        entry.source_mac = Some("11:22:33:44:55:66".to_string());
        entry.bssid = Some("aa:bb:cc:dd:ee:02".to_string());
        inventory.observe(&mut entry);
        assert!(!entry.tags.contains(&"threat:unusual_roam".to_string()));

        let snapshot = inventory.snapshot();
        assert_eq!(snapshot.clients.len(), 1);
        assert_eq!(snapshot.clients[0].roaming_history.len(), 4);
        assert_eq!(
            snapshot.clients[0].roaming_history[0].bssid,
            "aa:bb:cc:dd:ee:01"
        );
        assert_eq!(
            snapshot.clients[0].roaming_history[1].bssid,
            "aa:bb:cc:dd:ee:02"
        );
    }

    #[test]
    fn client_inventory_bounds_randomized_mac_state() {
        use super::ClientInventory;
        use crate::state_key::DetectorLimits;

        let limits = DetectorLimits {
            mac_state_capacity: 8,
            ..DetectorLimits::default()
        };
        let mut inventory = ClientInventory::new(limits);

        for index in 0..32 {
            let mut entry = create_test_audit_entry();
            entry.frame_subtype = "probe_request".to_string();
            entry.source_mac = Some(format!("02:00:00:00:00:{index:02x}"));
            entry.ssid = Some("CorpWiFi".to_string());
            inventory.observe(&mut entry);
        }

        assert!(inventory.len() <= limits.mac_state_capacity);
    }

    #[test]
    fn client_inventory_tags_shared_device_fingerprints() {
        use super::ClientInventory;

        let mut inventory = ClientInventory::default();
        let mut first = create_test_audit_entry();
        first.source_mac = Some("02:00:00:00:00:01".to_string());
        first.device_fingerprint = Some("fingerprint-a".to_string());
        inventory.observe(&mut first);
        assert!(!first
            .tags
            .contains(&"identity:shared_device_fingerprint".to_string()));

        let mut second = create_test_audit_entry();
        second.source_mac = Some("02:00:00:00:00:02".to_string());
        second.device_fingerprint = Some("fingerprint-a".to_string());
        inventory.observe(&mut second);
        assert!(second
            .tags
            .contains(&"identity:shared_device_fingerprint".to_string()));

        let mut repeated_first = create_test_audit_entry();
        repeated_first.source_mac = first.source_mac;
        repeated_first.device_fingerprint = Some("fingerprint-a".to_string());
        inventory.observe(&mut repeated_first);
        assert!(repeated_first
            .tags
            .contains(&"identity:shared_device_fingerprint".to_string()));
    }

    #[test]
    fn authorization_status_is_unknown_until_cache_loads() {
        use super::{AuthorizationStatus, AuthorizedNetworkCache};

        let cache = AuthorizedNetworkCache::default();

        assert_eq!(
            cache.authorization_status(Some("CorpWiFi"), Some("aa:bb:cc:dd:ee:ff"), "loc1"),
            AuthorizationStatus::Unknown
        );
    }

    #[test]
    fn authorization_status_distinguishes_authorized_and_unauthorized() {
        use super::{AuthorizationStatus, AuthorizedNetworkCache};
        use crate::backlog::AuthorizedWirelessNetwork;

        let mut cache = AuthorizedNetworkCache::default();
        cache.has_loaded = true;
        cache.entries = vec![AuthorizedWirelessNetwork {
            ssid: Some("CorpWiFi".to_string()),
            bssid: Some("aa:bb:cc:dd:ee:ff".to_string()),
            location_id: Some("loc1".to_string()),
            psk: None,
        }];

        assert_eq!(
            cache.authorization_status(Some("CorpWiFi"), Some("aa:bb:cc:dd:ee:ff"), "loc1"),
            AuthorizationStatus::Authorized
        );
        assert_eq!(
            cache.authorization_status(Some("Guest"), Some("aa:bb:cc:dd:ee:ff"), "loc1"),
            AuthorizationStatus::Unauthorized
        );
    }

    #[test]
    fn ie_layout_tracker_tags_structural_evil_twin_after_authorized_baseline() {
        use super::{AuthorizationStatus, IeLayoutTracker};

        let mut tracker = IeLayoutTracker::default();
        let mut authorized = create_test_audit_entry();
        authorized.frame_subtype = "beacon".to_string();
        authorized.ssid = Some("CorpWiFi".to_string());
        authorized.bssid = Some("aa:bb:cc:dd:ee:01".to_string());
        authorized.ie_layout_hash = Some("feedface00000001".to_string());
        tracker.observe(&mut authorized, AuthorizationStatus::Authorized);
        assert!(!authorized
            .tags
            .contains(&"threat:structural_evil_twin".to_string()));

        let mut rogue = authorized.clone();
        rogue.tags.clear();
        rogue.bssid = Some("aa:bb:cc:dd:ee:02".to_string());
        tracker.observe(&mut rogue, AuthorizationStatus::Unauthorized);
        assert!(rogue
            .tags
            .contains(&"threat:structural_evil_twin".to_string()));
    }

    #[test]
    fn ie_layout_tracker_does_not_tag_authorized_member_as_structural_evil_twin() {
        use super::{AuthorizationStatus, IeLayoutTracker};

        let mut tracker = IeLayoutTracker::default();
        let mut first = create_test_audit_entry();
        first.frame_subtype = "beacon".to_string();
        first.ssid = Some("CorpWiFi".to_string());
        first.bssid = Some("aa:bb:cc:dd:ee:01".to_string());
        first.ie_layout_hash = Some("feedface00000001".to_string());
        tracker.observe(&mut first, AuthorizationStatus::Authorized);

        let mut second = first.clone();
        second.bssid = Some("aa:bb:cc:dd:ee:02".to_string());
        tracker.observe(&mut second, AuthorizationStatus::Authorized);

        let mut current = first.clone();
        current.tags.clear();
        tracker.observe(&mut current, AuthorizationStatus::Unauthorized);

        assert!(!current
            .tags
            .contains(&"threat:structural_evil_twin".to_string()));
    }

    #[test]
    fn ie_layout_tracker_state_is_bounded() {
        use super::{AuthorizationStatus, IeLayoutTracker};
        use crate::state_key::DetectorLimits;

        let limits = DetectorLimits {
            ssid_state_capacity: 1,
            ..DetectorLimits::default()
        };
        let mut tracker = IeLayoutTracker::new(limits);
        for suffix in 0..3 {
            let mut entry = create_test_audit_entry();
            entry.frame_subtype = "beacon".to_string();
            entry.ssid = Some(format!("CorpWiFi-{suffix}"));
            entry.bssid = Some(format!("aa:bb:cc:dd:ee:{suffix:02x}"));
            entry.ie_layout_hash = Some(format!("feedface{suffix:08x}"));
            tracker.observe(&mut entry, AuthorizationStatus::Authorized);
        }

        assert_eq!(tracker.authorized_bssids_by_layout.len(), 1);
    }

    #[test]
    fn mac_sequence_delta_tracker_marks_gaps_and_duplicates() {
        use super::MacSequenceDeltaTracker;
        use crate::model::{AnomalyLayer, CorrelationLayer};

        let mut tracker = MacSequenceDeltaTracker::default();
        let mut first = sequence_entry(10);
        tracker.observe(&mut first);
        assert_eq!(first.sequence_delta, None);

        let mut gap = sequence_entry(13);
        gap.correlation = Some(test_correlation());
        tracker.observe(&mut gap);
        assert_eq!(gap.sequence_delta, Some(3));
        assert_eq!(gap.sequence_gap_missing_frames, Some(2));
        assert!(gap.tags.contains(&"anomaly:sequence_jump".to_string()));
        assert_eq!(
            gap.correlation
                .as_ref()
                .and_then(|value| value.sequence_delta),
            Some(3)
        );
        assert_eq!(
            gap.correlation
                .as_ref()
                .and_then(|value| value.sequence_gap_missing_frames),
            Some(2)
        );

        let mut duplicate = sequence_entry(13);
        duplicate.correlation = Some(test_correlation());
        duplicate.anomalies = Some(AnomalyLayer {
            large_frame: false,
            mixed_encryption: None,
            dedupe_or_replay_suspect: false,
            reasons: Vec::new(),
        });
        tracker.observe(&mut duplicate);
        assert_eq!(duplicate.sequence_delta, Some(0));
        assert_eq!(duplicate.dedupe_or_replay_suspect, Some(true));
        assert!(duplicate
            .tags
            .contains(&"anomaly:sequence_duplicate".to_string()));
        assert!(duplicate
            .anomaly_reasons
            .contains(&"sequence_duplicate".to_string()));
        assert!(duplicate
            .anomalies
            .as_ref()
            .is_some_and(|value| value.dedupe_or_replay_suspect
                && value.reasons.contains(&"sequence_duplicate".to_string())));

        fn sequence_entry(sequence_number: u16) -> crate::model::AuditEntry {
            let mut entry = create_test_audit_entry();
            entry.frame_type = Some("management".to_string());
            entry.frame_subtype = "beacon".to_string();
            entry.transmitter_mac = Some("aa:bb:cc:dd:ee:ff".to_string());
            entry.sequence_number = Some(sequence_number);
            entry
        }

        fn test_correlation() -> CorrelationLayer {
            CorrelationLayer {
                session_key: None,
                retransmit_key: None,
                frame_fingerprint: "fp".to_string(),
                payload_visibility: "header_only".to_string(),
                tsft_delta_us: None,
                wall_clock_delta_ms: None,
                sequence_delta: None,
                sequence_gap_missing_frames: None,
                clock_skew_delta_us: None,
            }
        }
    }

    #[test]
    fn mac_sequence_delta_tracker_state_is_bounded() {
        use super::MacSequenceDeltaTracker;
        use crate::state_key::DetectorLimits;

        let limits = DetectorLimits {
            session_state_capacity: 1,
            ..DetectorLimits::default()
        };
        let mut tracker = MacSequenceDeltaTracker::new(limits);
        for suffix in 1..=3 {
            let mut entry = create_test_audit_entry();
            entry.frame_type = Some("management".to_string());
            entry.transmitter_mac = Some(format!("aa:bb:cc:dd:ee:{suffix:02x}"));
            entry.sequence_number = Some(suffix);
            tracker.observe(&mut entry);
        }

        assert_eq!(tracker.last_sequence_by_key.len(), 1);
    }

    #[test]
    fn attack_timeline_correlates_karma_and_bssid_spoofing() {
        use super::AttackTimelineCorrelator;

        let mut correlator = AttackTimelineCorrelator::default();
        let mut entry = create_test_audit_entry();
        entry.ssid = Some("CorpWiFi".to_string());
        entry.observed_at = "2024-01-01T12:00:00Z".to_string();

        assert!(correlator.observe(&entry, "karma_probe_response").is_none());

        entry.observed_at = "2024-01-01T12:01:00Z".to_string();
        let alert = correlator
            .observe(&entry, "bssid_spoofing")
            .expect("second correlated attack type should emit sequence alert");

        assert_eq!(alert.event_type, "wireless_attack_sequence");
        assert_eq!(alert.ssid, "CorpWiFi");
        assert_eq!(
            alert.attack_chain,
            vec![
                "bssid_spoofing".to_string(),
                "karma_probe_response".to_string()
            ]
        );
    }

    #[test]
    fn deauth_flood_uses_bucketed_frame_time_cooldown() {
        use super::DeauthFloodTracker;

        let mut tracker = DeauthFloodTracker::default();
        let mut entry = create_test_audit_entry();
        entry.frame_subtype = "deauthentication".to_string();
        entry.bssid = Some("aa:bb:cc:dd:ee:ff".to_string());

        entry.observed_at = "2024-01-01T12:00:00Z".to_string();
        assert!(tracker.observe(&entry, 3, 10, 60).is_none());
        entry.observed_at = "2024-01-01T12:00:01Z".to_string();
        assert!(tracker.observe(&entry, 3, 10, 60).is_none());
        entry.observed_at = "2024-01-01T12:00:02Z".to_string();
        let first = tracker
            .observe(&entry, 3, 10, 60)
            .expect("third frame in bucketed window should alert");
        assert_eq!(first.frame_count, 3);

        entry.observed_at = "2024-01-01T12:00:03Z".to_string();
        assert!(tracker.observe(&entry, 3, 10, 60).is_none());

        entry.observed_at = "2024-01-01T12:01:10Z".to_string();
        assert!(tracker.observe(&entry, 3, 10, 60).is_none());
        entry.observed_at = "2024-01-01T12:01:11Z".to_string();
        assert!(tracker.observe(&entry, 3, 10, 60).is_none());
        entry.observed_at = "2024-01-01T12:01:12Z".to_string();
        let second = tracker
            .observe(&entry, 3, 10, 60)
            .expect("cooldown should expire using frame time");
        assert_eq!(second.observed_at, "2024-01-01T12:01:12Z");
    }

    #[test]
    fn deauth_flood_groups_unparseable_bssid_by_source_identity() {
        use super::DeauthFloodTracker;

        for bssids in [
            [None, None, None],
            [
                Some("malformed-bssid-1"),
                Some("malformed-bssid-2"),
                Some("malformed-bssid-3"),
            ],
        ] {
            let mut tracker = DeauthFloodTracker::default();
            let mut entry = create_test_audit_entry();
            entry.frame_subtype = "deauthentication".to_string();
            entry.source_mac = Some("AA:BB:CC:DD:EE:FF".to_string());

            entry.bssid = bssids[0].map(str::to_string);
            entry.observed_at = "2024-01-01T12:00:00Z".to_string();
            entry.sequence_number = Some(10);
            assert!(tracker.observe(&entry, 3, 10, 60).is_none());

            entry.bssid = bssids[1].map(str::to_string);
            entry.observed_at = "2024-01-01T12:00:01Z".to_string();
            entry.sequence_number = Some(11);
            assert!(tracker.observe(&entry, 3, 10, 60).is_none());

            entry.bssid = bssids[2].map(str::to_string);
            entry.observed_at = "2024-01-01T12:00:02Z".to_string();
            entry.sequence_number = Some(12);
            let alert = tracker
                .observe(&entry, 3, 10, 60)
                .expect("unparseable-BSSID frames from the same source should share a bucket");
            assert_eq!(alert.frame_count, 3);
        }
    }
