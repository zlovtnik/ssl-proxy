use std::{
    collections::{HashSet, VecDeque},
    num::NonZeroUsize,
    time::{Duration, Instant},
};

use chrono::{DateTime, Utc};
use lru::LruCache;
use serde::Serialize;

use crate::backlog::{AuthorizedWirelessNetwork, RedpandaBacklog};
use crate::model::AuditEntry;
use crate::parse::SECURITY_PMF_REQUIRED;
use crate::state_key::{DetectorLimits, FrameSubtype, MacAddr, SsidKey};

/// Structured explanation for a single detection factor. Each entry captures
/// what was observed, what was expected (baseline), and how much this factor
/// contributed to the alert (0.0-1.0).
#[derive(Clone, Debug, Serialize)]
pub struct AlertExplanation {
    pub factor: String,
    pub observed: f64,
    pub baseline: f64,
    pub contribution: f64,
}

const ROGUE_AP_ALERT_TTL: Duration = Duration::from_secs(60);
const ATTACK_CORRELATION_WINDOW: Duration = Duration::from_secs(300);
const ATTACK_SEQUENCE_COOLDOWN: Duration = Duration::from_secs(60);
const CLIENT_ROAM_HISTORY_LIMIT: usize = 32;
const CLIENT_ROAM_PAIR_LIMIT: usize = 128;
const FINGERPRINT_MAC_LIMIT: usize = 16;
const SEQUENCE_FRAME_LIMIT: usize = 32;
const SEQUENCE_AUTH_WINDOW_SECS: i64 = 10;

#[derive(Clone, Debug, Default)]
struct ChannelSet {
    bits: [u64; 4],
}

impl ChannelSet {
    fn insert(&mut self, channel: u8) {
        let index = usize::from(channel / 64);
        let bit = u64::from(channel % 64);
        self.bits[index] |= 1u64 << bit;
    }

    fn len(&self) -> usize {
        self.bits
            .iter()
            .map(|bits| bits.count_ones() as usize)
            .sum()
    }

    fn values(&self) -> Vec<u8> {
        let mut values = Vec::new();
        for channel in 0u16..=u8::MAX as u16 {
            let channel = channel as u8;
            let index = usize::from(channel / 64);
            let bit = u64::from(channel % 64);
            if self.bits[index] & (1u64 << bit) != 0 {
                values.push(channel);
            }
        }
        values
    }
}

#[derive(Clone, Debug, Default)]
struct BucketCounter {
    buckets: VecDeque<(i64, u64)>,
    total: u64,
}

impl BucketCounter {
    fn record(&mut self, observed_at: DateTime<Utc>, window_secs: u64) -> u64 {
        let second = observed_at.timestamp();
        if self
            .buckets
            .back()
            .is_some_and(|(bucket_second, _)| *bucket_second == second)
        {
            if let Some((_, count)) = self.buckets.back_mut() {
                *count = count.saturating_add(1);
            }
        } else if self
            .buckets
            .back()
            .is_some_and(|(bucket_second, _)| *bucket_second > second)
        {
            self.buckets.clear();
            self.buckets.push_back((second, 1));
            self.total = 1;
            self.prune(observed_at, window_secs);
            return self.total;
        } else {
            self.buckets.push_back((second, 1));
        }

        self.total = self.total.saturating_add(1);
        self.prune(observed_at, window_secs);
        self.total
    }

    fn prune(&mut self, observed_at: DateTime<Utc>, window_secs: u64) {
        let cutoff = observed_at.timestamp() - window_secs as i64;
        while self
            .buckets
            .front()
            .is_some_and(|(bucket_second, _)| *bucket_second < cutoff)
        {
            if let Some((_, count)) = self.buckets.pop_front() {
                self.total = self.total.saturating_sub(count);
            }
        }
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct ClientInventorySnapshot {
    pub schema_version: u32,
    pub event_type: String,
    pub observed_at: String,
    pub clients: Vec<ClientProfileSnapshot>,
}

#[derive(Clone, Debug, Serialize)]
pub struct ClientProfileSnapshot {
    pub source_mac: String,
    pub first_seen: String,
    pub last_seen: String,
    pub probe_ssids: Vec<String>,
    pub probe_count: u64,
    pub excessive_probing: bool,
    pub channels: Vec<u8>,
    pub last_signal_dbm: Option<i8>,
    pub roaming_history: Vec<ClientRoamingSnapshot>,
}

#[derive(Clone, Debug, Serialize)]
pub struct ClientRoamingSnapshot {
    pub bssid: String,
    pub channel: u8,
    pub observed_at: String,
}

#[derive(Clone, Debug)]
struct RoamEvent {
    pub bssid: MacAddr,
    pub channel: u8,
    pub observed_at: DateTime<Utc>,
}

struct ClientProfile {
    first_seen: DateTime<Utc>,
    last_seen: DateTime<Utc>,
    probe_ssids: VecDeque<String>,
    probe_count: u64,
    recent_probes: VecDeque<DateTime<Utc>>,
    excessive_probing: bool,
    channels: ChannelSet,
    last_signal_dbm: Option<i8>,
    roaming_history: VecDeque<RoamEvent>,
    normal_roaming_pairs: LruCache<(MacAddr, MacAddr), ()>,
    roam_transition_counts: LruCache<(MacAddr, MacAddr), u32>,
    last_bssid: Option<MacAddr>,
}

impl ClientProfile {
    fn new(observed_at: DateTime<Utc>) -> Self {
        let roam_pair_limit =
            NonZeroUsize::new(CLIENT_ROAM_PAIR_LIMIT).expect("roam pair limit is non-zero");
        Self {
            first_seen: observed_at,
            last_seen: observed_at,
            probe_ssids: VecDeque::new(),
            probe_count: 0,
            recent_probes: VecDeque::new(),
            excessive_probing: false,
            channels: ChannelSet::default(),
            last_signal_dbm: None,
            roaming_history: VecDeque::new(),
            normal_roaming_pairs: LruCache::new(roam_pair_limit),
            roam_transition_counts: LruCache::new(roam_pair_limit),
            last_bssid: None,
        }
    }
}

pub struct ClientInventory {
    clients: LruCache<MacAddr, ClientProfile>,
    /// Maps device_fingerprint strings to the list of MAC addresses that have
    /// exhibited that fingerprint. Used to detect MAC address sharing or
    /// spoofing when the same fingerprint appears from different MACs.
    fingerprint_to_macs: LruCache<SsidKey, Vec<MacAddr>>,
    probe_ssid_limit: usize,
}

impl Default for ClientInventory {
    fn default() -> Self {
        Self::new(DetectorLimits::default())
    }
}

impl ClientInventory {
    pub fn new(limits: DetectorLimits) -> Self {
        let limits = limits.clamp();
        Self {
            clients: LruCache::new(limits.mac_capacity()),
            fingerprint_to_macs: LruCache::new(limits.ssid_capacity()),
            probe_ssid_limit: limits.probe_ssid_capacity(),
        }
    }

    pub fn len(&self) -> usize {
        self.clients.len()
    }

    fn remember_probe_ssid(profile: &mut ClientProfile, ssid: &str, limit: usize) {
        if profile.probe_ssids.iter().any(|known| known == ssid) {
            return;
        }
        if profile.probe_ssids.len() >= limit {
            profile.probe_ssids.pop_front();
        }
        profile.probe_ssids.push_back(ssid.to_string());
    }
}

impl ClientInventory {
    /// Cross-references probe request SSID against known networks and returns (bssid, client_mac, ssid)
    /// tuple when a match is found. Returns None for non-probe frames or unmatched SSIDs.
    pub fn link_probe_to_network(
        &self,
        entry: &AuditEntry,
        authorized: &AuthorizedNetworkCache,
    ) -> Option<(String, String, Option<String>)> {
        if entry.frame_subtype != "probe_request" {
            return None;
        }
        let client_mac = entry
            .source_mac
            .as_deref()
            .and_then(MacAddr::parse)?
            .to_string();
        let probe_ssid = entry
            .ssid
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())?;

        for network in &authorized.entries {
            if let Some(known_ssid) = &network.ssid {
                if known_ssid.trim().eq_ignore_ascii_case(probe_ssid)
                    && network.location_id.as_deref() == Some(entry.location_id.as_str())
                {
                    if let Some(bssid) = &network.bssid {
                        return Some((bssid.clone(), client_mac, Some(probe_ssid.to_string())));
                    }
                }
            }
        }
        None
    }

    /// Observes a frame and updates client profile. The excessive_probing flag latches to true
    /// once a client sends >=20 probe requests within any 60-second window and is never reset
    /// to false within the same session (inventory flush required to clear).
    pub fn observe(&mut self, entry: &mut AuditEntry) {
        let Some(source_mac) = entry.source_mac.as_deref().and_then(MacAddr::parse) else {
            return;
        };
        let observed_at = parse_observed_at(&entry.observed_at).unwrap_or_else(Utc::now);
        let probe_ssid_limit = self.probe_ssid_limit;
        if self.clients.get(&source_mac).is_none() {
            self.clients
                .put(source_mac, ClientProfile::new(observed_at));
        }
        if let Some(profile) = self.clients.get_mut(&source_mac) {
            profile.last_seen = observed_at;
            profile.channels.insert(entry.channel);
            profile.last_signal_dbm = entry.signal_dbm;

            let association_bssid = entry
                .bssid
                .as_deref()
                .or(entry.destination_bssid.as_deref())
                .and_then(MacAddr::parse);
            if matches!(entry.frame_subtype.as_str(), "association_request") {
                if let Some(bssid) = association_bssid {
                    if let Some(prev_bssid) = profile.last_bssid {
                        if prev_bssid != bssid {
                            let pair = (prev_bssid, bssid);
                            let count = profile
                                .roam_transition_counts
                                .get(&pair)
                                .copied()
                                .unwrap_or(0)
                                .saturating_add(1);
                            profile.roam_transition_counts.put(pair, count);
                            if count >= 2 {
                                profile.normal_roaming_pairs.put(pair, ());
                            }
                            if profile.normal_roaming_pairs.get(&pair).is_none()
                                && !entry.tags.contains(&"threat:unusual_roam".to_string())
                            {
                                entry.tags.push("threat:unusual_roam".to_string());
                            }
                        }
                    }

                    profile.last_bssid = Some(bssid);
                    profile.roaming_history.push_back(RoamEvent {
                        bssid,
                        channel: entry.channel,
                        observed_at,
                    });
                    while profile.roaming_history.len() > CLIENT_ROAM_HISTORY_LIMIT {
                        profile.roaming_history.pop_front();
                    }
                }
            }

            if entry.frame_subtype == "probe_request" {
                profile.probe_count = profile.probe_count.saturating_add(1);
                if let Some(ssid) = entry
                    .ssid
                    .as_deref()
                    .map(str::trim)
                    .filter(|ssid| !ssid.is_empty())
                {
                    Self::remember_probe_ssid(profile, ssid, probe_ssid_limit);
                }
                profile.recent_probes.push_back(observed_at);
                let cutoff = observed_at - chrono::Duration::seconds(60);
                while profile
                    .recent_probes
                    .front()
                    .is_some_and(|time| *time < cutoff)
                {
                    profile.recent_probes.pop_front();
                }
                if profile.recent_probes.len() >= 20 {
                    profile.excessive_probing = true;
                }
            }
        }

        // Track device_fingerprint -> MAC correlations.
        if let Some(fp) = entry.device_fingerprint.as_deref() {
            if let Some(normalized_fp) = SsidKey::new(fp) {
                if self.fingerprint_to_macs.get(&normalized_fp).is_none() {
                    self.fingerprint_to_macs
                        .put(normalized_fp.clone(), Vec::new());
                }
                if let Some(macs) = self.fingerprint_to_macs.get_mut(&normalized_fp) {
                    if macs.iter().any(|mac| *mac != source_mac) {
                        push_detector_tag(&mut entry.tags, "identity:shared_device_fingerprint");
                    }
                    if !macs.contains(&source_mac) {
                        if macs.len() >= FINGERPRINT_MAC_LIMIT {
                            macs.remove(0);
                        }
                        macs.push(source_mac);
                        tracing::info!(
                            device_fingerprint = %fp,
                            mac = %source_mac,
                            known_macs = macs.len(),
                            "device_fingerprint shared by new MAC"
                        );
                    }
                    if macs.len() > 1 {
                        push_detector_tag(&mut entry.tags, "identity:shared_device_fingerprint");
                    }
                }
            }
        }
    }

    pub fn snapshot(&self) -> ClientInventorySnapshot {
        let mut clients = self
            .clients
            .iter()
            .map(|(source_mac, profile)| {
                let mut probe_ssids: Vec<_> = profile.probe_ssids.iter().cloned().collect();
                probe_ssids.sort();
                let mut channels = profile.channels.values();
                channels.sort_unstable();
                let roaming_history = profile
                    .roaming_history
                    .iter()
                    .map(|event| ClientRoamingSnapshot {
                        bssid: event.bssid.to_string(),
                        channel: event.channel,
                        observed_at: ssl_proxy::time::rfc3339_from_utc(event.observed_at),
                    })
                    .collect();
                ClientProfileSnapshot {
                    source_mac: source_mac.to_string(),
                    first_seen: ssl_proxy::time::rfc3339_from_utc(profile.first_seen),
                    last_seen: ssl_proxy::time::rfc3339_from_utc(profile.last_seen),
                    probe_ssids,
                    probe_count: profile.probe_count,
                    excessive_probing: profile.excessive_probing,
                    channels,
                    last_signal_dbm: profile.last_signal_dbm,
                    roaming_history,
                }
            })
            .collect::<Vec<_>>();
        clients.sort_by(|left, right| left.source_mac.cmp(&right.source_mac));
        ClientInventorySnapshot {
            schema_version: 1,
            event_type: "wireless_client_inventory".to_string(),
            observed_at: ssl_proxy::time::rfc3339_from_utc(Utc::now()),
            clients,
        }
    }
}

fn push_detector_tag(tags: &mut Vec<String>, tag: &str) {
    if !tags.iter().any(|existing| existing == tag) {
        tags.push(tag.to_string());
    }
}

pub struct SignalTracker {
    last_by_bssid: LruCache<MacAddr, i8>,
}

impl Default for SignalTracker {
    fn default() -> Self {
        Self::new(DetectorLimits::default())
    }
}

impl SignalTracker {
    pub fn new(limits: DetectorLimits) -> Self {
        Self {
            last_by_bssid: LruCache::new(limits.clamp().mac_capacity()),
        }
    }
}
