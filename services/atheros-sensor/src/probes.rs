//! Probe request accumulation and batch backpressure.

use chrono::{DateTime, Utc};
use lru::LruCache;

use crate::{
    backlog::ProbeFlushObservation,
    detect_state::{AuthorizedNetworkCache, ClientInventory},
    model::AuditEntry,
    state_key::{DetectorLimits, MacAddr, SsidKey},
};

pub struct ProbeAccumulator {
    observations: LruCache<ProbeKey, ProbeObservation>,
    max_size: usize,
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
struct ProbeKey {
    ssid: SsidKey,
    client_mac: MacAddr,
}

#[derive(Clone, Debug)]
struct ProbeObservation {
    ssid: String,
    known_bssid: Option<String>,
    first_seen: DateTime<Utc>,
    last_seen: DateTime<Utc>,
    probe_count: u32,
}

pub struct ProbeFlushBatch {
    observations: Vec<(ProbeKey, ProbeObservation)>,
}

impl ProbeAccumulator {
    pub fn new() -> Self {
        Self::new_with_limits(DetectorLimits::default())
    }

    pub fn new_with_limits(limits: DetectorLimits) -> Self {
        let max_size = limits.clamp().pipeline_queue_capacity.max(1);
        Self {
            observations: LruCache::new(
                std::num::NonZeroUsize::new(max_size)
                    .expect("probe accumulator capacity is non-zero"),
            ),
            max_size,
        }
    }

    pub fn observe(
        &mut self,
        entry: &AuditEntry,
        client_inventory: &ClientInventory,
        authorized_network_cache: &AuthorizedNetworkCache,
    ) {
        if entry.frame_subtype != "probe_request" {
            return;
        }
        let (Some(client_mac), Some(ssid)) = (
            entry.source_mac.as_deref().and_then(MacAddr::parse),
            entry
                .ssid
                .as_deref()
                .map(str::trim)
                .filter(|ssid| !ssid.is_empty()),
        ) else {
            return;
        };

        let observed_at = DateTime::parse_from_rfc3339(&entry.observed_at)
            .ok()
            .map(|observed_at| observed_at.with_timezone(&Utc))
            .unwrap_or_else(Utc::now);
        let linked_bssid = client_inventory
            .link_probe_to_network(entry, authorized_network_cache)
            .map(|(bssid, _, _)| bssid);
        let Some(ssid_key) = SsidKey::new(ssid) else {
            return;
        };
        let key = ProbeKey {
            ssid: ssid_key,
            client_mac,
        };
        if let Some(observation) = self.observations.get_mut(&key) {
            if observation.known_bssid.is_none() {
                observation.known_bssid = linked_bssid.clone().or_else(|| entry.bssid.clone());
            }
            observation.first_seen = observation.first_seen.min(observed_at);
            observation.last_seen = observation.last_seen.max(observed_at);
            observation.probe_count = observation.probe_count.saturating_add(1);
        } else {
            self.observations.put(
                key,
                ProbeObservation {
                    ssid: ssid.to_string(),
                    known_bssid: linked_bssid.or_else(|| entry.bssid.clone()),
                    first_seen: observed_at,
                    last_seen: observed_at,
                    probe_count: 1,
                },
            );
        }
    }

    pub fn len(&self) -> usize {
        self.observations.len()
    }

    pub fn should_flush_early(&self) -> bool {
        self.observations.len() >= self.max_size
    }

    pub fn take_ready_batches(&mut self) -> Vec<ProbeFlushBatch> {
        if self.observations.is_empty() {
            Vec::new()
        } else {
            vec![self.drain_all()]
        }
    }

    pub fn restore(&mut self, batch: ProbeFlushBatch) {
        for (key, observation) in batch.observations {
            self.observations.put(key, observation);
        }
    }

    pub fn restore_priority_half(&mut self, mut batch: ProbeFlushBatch) {
        batch.observations.sort_by_key(|(_, observation)| {
            (
                observation.last_seen - observation.first_seen,
                observation.last_seen,
            )
        });
        let keep = batch.observations.len() / 2;
        for (key, observation) in batch.observations.into_iter().skip(keep) {
            self.observations.put(key, observation);
        }
    }

    fn drain_all(&mut self) -> ProbeFlushBatch {
        let mut observations = Vec::with_capacity(self.observations.len());
        while let Some(entry) = self.observations.pop_lru() {
            observations.push(entry);
        }
        ProbeFlushBatch { observations }
    }
}

impl Default for ProbeAccumulator {
    fn default() -> Self {
        Self::new()
    }
}

impl ProbeFlushBatch {
    pub fn len(&self) -> usize {
        self.observations.len()
    }

    pub fn to_backlog_observations(&self) -> Vec<ProbeFlushObservation> {
        self.observations
            .iter()
            .map(|(key, observation)| ProbeFlushObservation {
                ssid: observation.ssid.clone(),
                client_mac: key.client_mac.to_string(),
                known_bssid: observation.known_bssid.clone(),
                first_seen: observation.first_seen,
                last_seen: observation.last_seen,
                probe_count: observation.probe_count,
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::backlog::AuthorizedWirelessNetwork;

    fn entry(ssid: &str, client_mac: &str, observed_at: &str) -> AuditEntry {
        AuditEntry {
            schema_version: 2,
            event_type: "wifi_management_frame".to_string(),
            observed_at: observed_at.to_string(),
            sensor_id: "sensor1".to_string(),
            location_id: "loc1".to_string(),
            interface: "wlan0".to_string(),
            channel: 6,
            band: "2.4ghz".to_string(),
            frame_type: Some("management".to_string()),
            bssid: None,
            destination_bssid: None,
            source_mac: Some(client_mac.to_string()),
            destination_mac: None,
            transmitter_mac: None,
            receiver_mac: None,
            ssid: Some(ssid.to_string()),
            frame_subtype: "probe_request".to_string(),
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
            identity_source: crate::model::IdentitySource::Unknown,
        }
    }

    #[test]
    fn accumulates_probe_observations_by_ssid_and_client() {
        let mut accumulator = ProbeAccumulator::new();
        let inventory = ClientInventory::default();
        let cache = AuthorizedNetworkCache::default();

        accumulator.observe(
            &entry("CorpWiFi", "AA:BB:CC:DD:EE:FF", "2024-01-01T12:00:00Z"),
            &inventory,
            &cache,
        );
        accumulator.observe(
            &entry("CorpWiFi", "aa:bb:cc:dd:ee:ff", "2024-01-01T12:00:05Z"),
            &inventory,
            &cache,
        );

        let batch = accumulator.take_ready_batches().pop().unwrap();
        let observations = batch.to_backlog_observations();
        assert_eq!(observations.len(), 1);
        assert_eq!(observations[0].ssid, "CorpWiFi");
        assert_eq!(observations[0].client_mac, "aa:bb:cc:dd:ee:ff");
        assert_eq!(observations[0].probe_count, 2);
        assert_eq!(
            observations[0].first_seen,
            DateTime::parse_from_rfc3339("2024-01-01T12:00:00Z")
                .unwrap()
                .with_timezone(&Utc)
        );
        assert_eq!(
            observations[0].last_seen,
            DateTime::parse_from_rfc3339("2024-01-01T12:00:05Z")
                .unwrap()
                .with_timezone(&Utc)
        );
    }

    #[test]
    fn links_probe_to_authorized_bssid() {
        let mut accumulator = ProbeAccumulator::new();
        let inventory = ClientInventory::default();
        let cache =
            AuthorizedNetworkCache::with_entries_for_test(vec![AuthorizedWirelessNetwork {
                ssid: Some("CorpWiFi".to_string()),
                bssid: Some("aa:bb:cc:dd:ee:ff".to_string()),
                location_id: Some("loc1".to_string()),
                psk: None,
            }]);

        accumulator.observe(
            &entry("CorpWiFi", "11:22:33:44:55:66", "2024-01-01T12:00:00Z"),
            &inventory,
            &cache,
        );

        let observations = accumulator
            .take_ready_batches()
            .pop()
            .unwrap()
            .to_backlog_observations();
        assert_eq!(
            observations[0].known_bssid,
            Some("aa:bb:cc:dd:ee:ff".to_string())
        );
    }

    #[test]
    fn backpressure_restore_preserves_long_running_and_recent_observations() {
        let mut accumulator = ProbeAccumulator::new();
        let inventory = ClientInventory::default();
        let cache = AuthorizedNetworkCache::default();
        accumulator.observe(
            &entry("short-old", "00:00:00:00:00:01", "2024-01-01T12:00:00Z"),
            &inventory,
            &cache,
        );
        accumulator.observe(
            &entry("short-new", "00:00:00:00:00:02", "2024-01-01T12:00:10Z"),
            &inventory,
            &cache,
        );
        accumulator.observe(
            &entry("long-run", "00:00:00:00:00:03", "2024-01-01T12:00:00Z"),
            &inventory,
            &cache,
        );
        accumulator.observe(
            &entry("long-run", "00:00:00:00:00:03", "2024-01-01T12:10:00Z"),
            &inventory,
            &cache,
        );
        accumulator.observe(
            &entry("recent", "00:00:00:00:00:04", "2024-01-01T12:10:01Z"),
            &inventory,
            &cache,
        );

        let batch = accumulator.take_ready_batches().pop().unwrap();
        accumulator.restore_priority_half(batch);

        let retained = accumulator
            .take_ready_batches()
            .pop()
            .unwrap()
            .to_backlog_observations();
        let retained_ssids = retained
            .iter()
            .map(|observation| observation.ssid.as_str())
            .collect::<Vec<_>>();
        assert!(retained_ssids.contains(&"long-run"));
        assert!(retained_ssids.contains(&"recent"));
        assert_eq!(retained.len(), 2);
    }

    #[test]
    fn accumulator_bounds_randomized_probe_state() {
        use crate::state_key::DetectorLimits;

        let mut accumulator = ProbeAccumulator::new_with_limits(DetectorLimits {
            pipeline_queue_capacity: 4,
            ..DetectorLimits::default()
        });
        let inventory = ClientInventory::default();
        let cache = AuthorizedNetworkCache::default();

        for index in 0..16 {
            let entry = entry(
                &format!("SSID-{index}"),
                &format!("02:00:00:00:00:{index:02x}"),
                "2024-01-01T12:00:00Z",
            );
            accumulator.observe(&entry, &inventory, &cache);
        }

        assert!(accumulator.len() <= 4);
        assert!(accumulator.should_flush_early());
    }
}
