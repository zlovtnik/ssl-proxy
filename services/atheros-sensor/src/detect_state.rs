//! Per-frame stateful detectors for wireless threat detection.
//!
//! Six detectors run against every decoded frame, all held in PipelineState:
//! ClientInventory tracks probe requests, channel history, and excessive-probing flags per MAC;
//! SignalTracker fires a signal_anomaly tag when a BSSID's signal jumps beyond the configured
//! dBm delta, indicating a possible AP impersonation or physical movement event;
//! RogueApTracker checks beacons and probe responses for open authorized SSIDs, SSID typosquats
//! (edit distance <= 2), BSSID-to-SSID mapping changes, and multi-channel conflicts;
//! DeauthFloodTracker counts deauthentication and disassociation frames per BSSID in a sliding
//! window and fires an alert when the threshold is exceeded, with a cooldown to suppress repeats;
//! AuthorizedNetworkCache holds the Redpanda-backed list of known SSIDs/BSSIDs and is
//! invalidated by the Redpanda generation counter when the console pushes a config change;
//! evil-twin detection runs through IdentityCache (in parse/) which correlates adjacent MACs
//! and session keys to surface impersonation across frames.
//!
//! # Type notes
//!
//! [`ClientInventory`] / [`ClientProfile`]: per-MAC observation state; `excessive_probing`
//! latches to `true` once a client sends >= 20 probe requests within any 60-second window
//! and is never reset to `false` within the same session (inventory flush required).
//!
//! [`RogueApTracker`]: fires [`RogueApAlert`] for beacons/probe-responses that match rogue
//! heuristics; the per-key `recent_alerts` map enforces a 60-second cooldown so a single
//! misbehaving AP cannot produce an unbounded alert storm.
//!
//! [`DeauthFloodTracker`]: maintains two independent clocks per BSSID - a sliding
//! `chrono::DateTime` window that counts frames within `window_secs`, and a separate
//! `Instant`-based cooldown that suppresses repeat alerts for `cooldown_secs` after firing.
//!
//! [`AuthorizedNetworkCache`]: `invalidate()` sets `loaded_at` to `None` without touching
//! `entries`; the stale data remains readable until the next `refresh_if_needed` call
//! successfully reloads from the coordinator.

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
                if known_ssid.trim().eq_ignore_ascii_case(probe_ssid) {
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
        if let Some(fp) = &entry.device_fingerprint {
            if let Some(normalized_fp) = SsidKey::new(fp) {
                if self.fingerprint_to_macs.get(&normalized_fp).is_none() {
                    self.fingerprint_to_macs
                        .put(normalized_fp.clone(), Vec::new());
                }
                if let Some(macs) = self.fingerprint_to_macs.get_mut(&normalized_fp) {
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

#[derive(Clone, Debug, Serialize)]
pub struct SignalAnomalyAlert {
    pub schema_version: u32,
    pub event_type: String,
    pub observed_at: String,
    pub sensor_id: String,
    pub location_id: String,
    pub source_mac: String,
    pub bssid: Option<String>,
    pub ssid: Option<String>,
    pub channel: u8,
    pub baseline_dbm: i8,
    pub observed_dbm: i8,
    pub dbm_delta: i16,
    pub configured_delta: i8,
}

impl SignalTracker {
    /// Observes a frame and returns an alert when the signal delta exceeds threshold.
    pub fn observe(&mut self, entry: &AuditEntry, threshold: i8) -> Option<SignalAnomalyAlert> {
        if threshold <= 0 {
            return None;
        }
        let (Some(bssid), Some(signal)) = (
            entry.bssid.as_deref().and_then(MacAddr::parse),
            entry.signal_dbm,
        ) else {
            return None;
        };
        let source_mac = entry
            .source_mac
            .as_deref()
            .or(entry.bssid.as_deref())
            .and_then(MacAddr::parse)?
            .to_string();
        let previous = self.last_by_bssid.put(bssid, signal);
        let baseline = previous?;
        let delta = i16::from(signal) - i16::from(baseline);
        if delta.abs() < i16::from(threshold) {
            return None;
        }

        Some(SignalAnomalyAlert {
            schema_version: 1,
            event_type: "wireless_signal_anomaly".to_string(),
            observed_at: entry.observed_at.clone(),
            sensor_id: entry.sensor_id.clone(),
            location_id: entry.location_id.clone(),
            source_mac,
            bssid: Some(bssid.to_string()),
            ssid: entry.ssid.clone(),
            channel: entry.channel,
            baseline_dbm: baseline,
            observed_dbm: signal,
            dbm_delta: delta.abs(),
            configured_delta: threshold,
        })
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct RogueApAlert {
    pub schema_version: u32,
    pub event_type: String,
    pub observed_at: String,
    pub sensor_id: String,
    pub location_id: String,
    pub interface: String,
    pub bssid: Option<String>,
    pub ssid: Option<String>,
    pub channel: u8,
    pub reasons: Vec<String>,
    /// Structured factor breakdown for each detection reason.
    #[serde(default)]
    pub factor_breakdown: Vec<AlertExplanation>,
    /// Human-readable explanations for each reason, populated at alert creation.
    #[serde(default)]
    pub explanation: Vec<String>,
}

#[derive(Clone, Debug, Default)]
struct ApState {
    ssid: Option<String>,
    channels: ChannelSet,
    first_channel: Option<u8>,
    vendor_oui: Option<[u8; 3]>,
}

pub struct RogueApTracker {
    aps: LruCache<MacAddr, ApState>,
    recent_alerts: LruCache<String, DateTime<Utc>>,
    typosquat_cache: LruCache<SsidKey, bool>,
}

impl Default for RogueApTracker {
    fn default() -> Self {
        Self::new(DetectorLimits::default())
    }
}

impl RogueApTracker {
    pub fn new(limits: DetectorLimits) -> Self {
        let limits = limits.clamp();
        Self {
            aps: LruCache::new(limits.mac_capacity()),
            recent_alerts: LruCache::new(limits.ssid_capacity()),
            typosquat_cache: LruCache::new(limits.ssid_capacity()),
        }
    }

    /// Observes a beacon or probe response and returns a RogueApAlert when any of four detection
    /// reasons fire: open_authorized_ssid (known SSID with no encryption), ssid_typosquat
    /// (edit distance <=2 from known SSID), bssid_spoofing (BSSID changed SSID mapping), or
    /// channel_conflict (same BSSID seen on multiple channels).
    pub fn observe(
        &mut self,
        entry: &AuditEntry,
        authorized: &AuthorizedNetworkCache,
    ) -> Option<RogueApAlert> {
        if !FrameSubtype::parse(&entry.frame_subtype).is_ap_observation() {
            return None;
        }
        let observed_at = parse_observed_at(&entry.observed_at).unwrap_or_else(Utc::now);
        let mut reasons = Vec::new();
        let ssid = entry
            .ssid
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty());
        let bssid = entry.bssid.as_deref().and_then(MacAddr::parse);
        if ssid.is_some_and(|value| authorized.is_known_ssid(value)) && entry.security_flags == 0 {
            reasons.push("open_authorized_ssid".to_string());
        }
        if let Some(ssid) = ssid {
            let Some(key) = SsidKey::new(ssid) else {
                return None;
            };
            let typosquat = if let Some(cached) = self.typosquat_cache.get(&key) {
                *cached
            } else {
                let verdict = authorized.is_typosquat(ssid);
                self.typosquat_cache.put(key, verdict);
                verdict
            };
            if typosquat {
                reasons.push("ssid_typosquat".to_string());
            }
        }
        if let Some(bssid) = bssid {
            if self.aps.get(&bssid).is_none() {
                self.aps.put(bssid, ApState::default());
            }
            if let Some(ssid) = ssid {
                if let Some(state) = self.aps.get_mut(&bssid) {
                    if state
                        .ssid
                        .as_deref()
                        .is_some_and(|previous| previous != ssid)
                    {
                        reasons.push("bssid_spoofing".to_string());
                    }
                    state.ssid = Some(ssid.to_string());
                }
            }
            if let Some(state) = self.aps.get_mut(&bssid) {
                state.channels.insert(entry.channel);
                if state.channels.len() > 1 {
                    reasons.push("channel_conflict".to_string());
                }

                if let Some(first_ch) = state.first_channel {
                    let first_is_5ghz = first_ch >= 36;
                    let current_is_2ghz = entry.channel >= 1 && entry.channel <= 14;
                    if first_is_5ghz && current_is_2ghz {
                        reasons.push("channel_band_conflict".to_string());
                    }
                } else {
                    state.first_channel = Some(entry.channel);
                }
                state.vendor_oui = Some(bssid.oui());
            }

            if let Some(ssid) = ssid {
                let current_oui = bssid.oui();
                let has_conflict = self.aps.iter().any(|(other_bssid, state)| {
                    *other_bssid != bssid
                        && state.ssid.as_deref() == Some(ssid)
                        && state.vendor_oui.is_some_and(|oui| oui != current_oui)
                });
                if has_conflict {
                    reasons.push("vendor_conflict".to_string());
                }
            }
        }
        if reasons.is_empty() {
            return None;
        }
        let key = format!(
            "{}|{}|{}",
            bssid
                .map(|value| value.to_string())
                .unwrap_or_else(|| "unknown".to_string()),
            ssid.unwrap_or("unknown"),
            reasons.join(",")
        );
        let ttl = chrono::Duration::from_std(ROGUE_AP_ALERT_TTL).ok()?;
        if let Some(last) = self.recent_alerts.get(&key) {
            let delta = observed_at.signed_duration_since(*last);
            if delta >= chrono::Duration::zero() && delta < ttl {
                return None;
            }
        }
        self.recent_alerts.put(key, observed_at);
        Some(RogueApAlert {
            schema_version: 1,
            event_type: "wireless_rogue_ap".to_string(),
            observed_at: entry.observed_at.clone(),
            sensor_id: entry.sensor_id.clone(),
            location_id: entry.location_id.clone(),
            interface: entry.interface.clone(),
            bssid: bssid.map(|value| value.to_string()),
            ssid: ssid.map(str::to_string),
            channel: entry.channel,
            factor_breakdown: reasons.iter().map(|r| rogue_ap_explanation(r)).collect(),
            explanation: reasons.iter().map(|r| explain_reason(r)).collect(),
            reasons,
        })
    }
}

/// Builds a structured `AlertExplanation` for a single rogue-AP detection reason.
/// Uses fixed baselines where applicable (e.g. normal encryption = present, single channel = 1).
fn rogue_ap_explanation(reason: &str) -> AlertExplanation {
    let (baseline, observed, contribution) = match reason {
        "open_authorized_ssid" => (1.0, 0.0, 1.0), // expected encrypted (1), found open (0)
        "ssid_typosquat" => (1.0, 0.0, 0.9),       // expected exact match (1), found typosquat (0)
        "bssid_spoofing" => (1.0, 0.0, 0.8),       // expected stable mapping (1), found changed (0)
        "channel_conflict" => (1.0, 2.0, 0.7), // expected single channel (1), found multiple (≥2)
        "channel_band_conflict" => (1.0, 2.0, 0.6), // expected consistent band (1), found band switch (2)
        "vendor_conflict" => (1.0, 2.0, 0.5), // expected single vendor (1), found multiple (≥2)
        _ => (1.0, 1.0, 0.0),
    };
    AlertExplanation {
        factor: reason.to_string(),
        observed,
        baseline,
        contribution,
    }
}

/// Maps a detection reason tag to a human-readable explanation.
fn explain_reason(reason: &str) -> String {
    match reason {
        "open_authorized_ssid" => "Known SSID broadcasting without encryption".into(),
        "ssid_typosquat" => {
            "SSID is an edit-distance match to a known network (potential typosquatting)".into()
        }
        "bssid_spoofing" => "BSSID changed its SSID mapping since last observation".into(),
        "channel_conflict" => "Same BSSID observed on multiple channels".into(),
        "channel_band_conflict" => "BSSID originally on 5 GHz now seen on 2.4 GHz".into(),
        "vendor_conflict" => "Same SSID served by different hardware vendors".into(),
        other => format!("Unrecognised detection reason: {other}"),
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct DeauthFloodAlert {
    pub schema_version: u32,
    pub event_type: String,
    pub observed_at: String,
    pub sensor_id: String,
    pub location_id: String,
    pub interface: String,
    pub bssid: Option<String>,
    pub frame_count: u64,
    pub window_secs: u64,
    /// Structured factor breakdown for each detection factor.
    #[serde(default)]
    pub factor_breakdown: Vec<AlertExplanation>,
    /// Human-readable explanations for each detection factor.
    #[serde(default)]
    pub explanation: Vec<String>,
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
enum DeauthKey {
    Bssid(MacAddr),
    Unknown,
}

pub struct DeauthFloodTracker {
    windows: LruCache<DeauthKey, BucketCounter>,
    last_alerts: LruCache<DeauthKey, DateTime<Utc>>,
}

impl Default for DeauthFloodTracker {
    fn default() -> Self {
        Self::new(DetectorLimits::default())
    }
}

impl DeauthFloodTracker {
    pub fn new(limits: DetectorLimits) -> Self {
        let limits = limits.clamp();
        Self {
            windows: LruCache::new(limits.mac_capacity()),
            last_alerts: LruCache::new(limits.mac_capacity()),
        }
    }

    /// Observes a deauth or disassociation frame and returns a DeauthFloodAlert when the frame
    /// count exceeds threshold within window_secs. Uses per-second buckets and frame-time
    /// cooldowns so replayed PCAPs are deterministic.
    pub fn observe(
        &mut self,
        entry: &AuditEntry,
        threshold: u64,
        window_secs: u64,
        cooldown_secs: u64,
    ) -> Option<DeauthFloodAlert> {
        if threshold == 0 || window_secs == 0 {
            return None;
        }
        if !matches!(
            entry.frame_subtype.as_str(),
            "deauthentication" | "disassociation"
        ) {
            return None;
        }
        let key = entry
            .bssid
            .as_deref()
            .and_then(MacAddr::parse)
            .map(DeauthKey::Bssid)
            .unwrap_or(DeauthKey::Unknown);
        let observed_at = parse_observed_at(&entry.observed_at).unwrap_or_else(Utc::now);
        if self.windows.get(&key).is_none() {
            self.windows.put(key, BucketCounter::default());
        }
        let frame_count = self
            .windows
            .get_mut(&key)
            .map(|window| window.record(observed_at, window_secs))
            .unwrap_or(0);
        if frame_count == 0 {
            self.windows.pop(&key);
            self.last_alerts.pop(&key);
            return None;
        }
        if frame_count < threshold {
            return None;
        }
        let cooldown = chrono::Duration::seconds(cooldown_secs as i64);
        if let Some(last) = self.last_alerts.get(&key) {
            let delta = observed_at.signed_duration_since(*last);
            if delta >= chrono::Duration::zero() && delta < cooldown {
                return None;
            }
        }
        self.last_alerts.put(key, observed_at);
        let contribution = if threshold > 0 {
            (frame_count as f64) / (threshold as f64).min(frame_count as f64)
        } else {
            1.0
        };
        Some(DeauthFloodAlert {
            schema_version: 1,
            event_type: "wireless_deauth_flood".to_string(),
            observed_at: entry.observed_at.clone(),
            sensor_id: entry.sensor_id.clone(),
            location_id: entry.location_id.clone(),
            interface: entry.interface.clone(),
            bssid: entry.bssid.clone(),
            frame_count,
            window_secs,
            factor_breakdown: vec![AlertExplanation {
                factor: "deauth_frame_count".to_string(),
                observed: frame_count as f64,
                baseline: threshold as f64,
                contribution: contribution.min(1.0),
            }],
            explanation: vec![format!(
                "deauth_frame_count: {} in {}s window (threshold: {})",
                frame_count, window_secs, threshold
            )],
        })
    }
}

pub struct AuthorizedNetworkCache {
    entries: Vec<AuthorizedWirelessNetwork>,
    has_loaded: bool,
    loaded_at: Option<Instant>,
    last_failure: Option<Instant>,
    failure_count: u32,
    backoff_ms: u64,
    last_logged_failure_count: u32,
}

impl Default for AuthorizedNetworkCache {
    fn default() -> Self {
        Self::new(30_000)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AuthorizationStatus {
    Authorized,
    Unauthorized,
    Unknown,
}

impl AuthorizedNetworkCache {
    pub fn new(backoff_ms: u64) -> Self {
        Self {
            entries: Vec::new(),
            has_loaded: false,
            loaded_at: None,
            last_failure: None,
            failure_count: 0,
            backoff_ms: backoff_ms.max(1),
            last_logged_failure_count: 0,
        }
    }

    #[cfg(test)]
    pub(crate) fn with_entries_for_test(entries: Vec<AuthorizedWirelessNetwork>) -> Self {
        let mut cache = Self::default();
        cache.entries = entries;
        cache.has_loaded = true;
        cache
    }

    #[allow(dead_code)]
    pub fn invalidate(&mut self) {
        self.loaded_at = None;
    }

    fn failure_backoff(&self) -> Duration {
        if self.failure_count == 0 {
            return Duration::from_secs(0);
        }
        let exponent = self.failure_count.saturating_sub(1).min(63);
        let multiplier = 1u64.checked_shl(exponent).unwrap_or(u64::MAX);
        Duration::from_millis(self.backoff_ms.saturating_mul(multiplier).min(300_000))
    }

    /// Returns true when the caller should emit a log for this failure.
    /// True only on first failure, backoff escalation, or recovery (failure_count resets).
    pub fn should_log_failure(&mut self, is_failure: bool) -> bool {
        if is_failure {
            if self.failure_count != self.last_logged_failure_count {
                self.last_logged_failure_count = self.failure_count;
                return true;
            }
            return false;
        }
        // Recovery: logged externally via info-level on success
        self.last_logged_failure_count = 0;
        false
    }

    pub async fn refresh_if_needed(
        &mut self,
        backlog: &RedpandaBacklog,
        ttl: Duration,
    ) -> Result<(), crate::backlog::BacklogError> {
        if self
            .loaded_at
            .is_some_and(|loaded_at| loaded_at.elapsed() < ttl)
        {
            return Ok(());
        }

        if let Some(last_failure) = self.last_failure {
            let backoff = self.failure_backoff();
            if last_failure.elapsed() < backoff {
                if self.loaded_at.is_some() {
                    return Ok(());
                }
                return Err(crate::backlog::BacklogError::Redpanda {
                    operation: "refresh_if_needed",
                    message: format!(
                        "previous authorized network refresh failed; retry backoff {}ms",
                        backoff.as_millis()
                    ),
                });
            }
        }

        match backlog.list_authorized_wireless_networks().await {
            Ok(entries) => {
                self.entries = entries;
                self.has_loaded = true;
                self.loaded_at = Some(Instant::now());
                self.last_failure = None;
                self.failure_count = 0;
                Ok(())
            }
            Err(err) => {
                self.last_failure = Some(Instant::now());
                self.failure_count = self.failure_count.saturating_add(1);
                if self.loaded_at.is_some() {
                    Ok(())
                } else {
                    Err(err)
                }
            }
        }
    }

    /// Checks if a network is authorized using three-field AND logic: location_id, SSID, and
    /// BSSID. A None field on the stored entry acts as a wildcard (matches any value). At least
    /// one of SSID or BSSID must be non-None on the stored entry to match.
    pub fn authorization_status(
        &self,
        ssid: Option<&str>,
        bssid: Option<&str>,
        location_id: &str,
    ) -> AuthorizationStatus {
        if !self.has_loaded {
            return AuthorizationStatus::Unknown;
        }
        let normalized_ssid = ssid.map(|value| value.trim().to_ascii_lowercase());
        let normalized_bssid = bssid.map(normalize_mac);
        let is_authorized = self.entries.iter().any(|entry| {
            entry
                .location_id
                .as_deref()
                .map_or(true, |location| location == location_id)
                && entry.ssid.as_deref().map_or(true, |known| {
                    normalized_ssid.as_deref() == Some(known.trim().to_ascii_lowercase().as_str())
                })
                && entry.bssid.as_deref().map_or(true, |known| {
                    normalized_bssid.as_deref() == Some(known.trim().to_ascii_lowercase().as_str())
                })
                && (entry.ssid.is_some() || entry.bssid.is_some())
        });
        if is_authorized {
            AuthorizationStatus::Authorized
        } else {
            AuthorizationStatus::Unauthorized
        }
    }

    pub fn is_authorized(
        &self,
        ssid: Option<&str>,
        bssid: Option<&str>,
        location_id: &str,
    ) -> bool {
        self.authorization_status(ssid, bssid, location_id) == AuthorizationStatus::Authorized
    }

    pub fn entries(&self) -> &[AuthorizedWirelessNetwork] {
        &self.entries
    }

    pub fn is_known_ssid(&self, ssid: &str) -> bool {
        let ssid = ssid.trim().to_ascii_lowercase();
        self.entries.iter().any(|entry| {
            entry
                .ssid
                .as_deref()
                .is_some_and(|known| known.trim().eq_ignore_ascii_case(&ssid))
        })
    }

    /// Returns true when the candidate SSID has edit distance <= 2 from any known SSID.
    /// Early exit when length difference exceeds the limit (2) to skip expensive DP.
    pub fn is_typosquat(&self, ssid: &str) -> bool {
        let ssid = ssid.trim().to_ascii_lowercase();
        if ssid.is_empty() || self.is_known_ssid(&ssid) {
            return false;
        }
        self.entries.iter().any(|entry| {
            entry
                .ssid
                .as_deref()
                .map(|known| edit_distance_limited(&known.to_ascii_lowercase(), &ssid, 2) <= 2)
                .unwrap_or(false)
        })
    }
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
struct IeLayoutKey {
    ssid: SsidKey,
    layout_hash: Box<str>,
}

impl IeLayoutKey {
    fn new(ssid: &str, layout_hash: &str) -> Option<Self> {
        let layout_hash = layout_hash.trim();
        if layout_hash.is_empty() {
            return None;
        }
        Some(Self {
            ssid: SsidKey::new(ssid)?,
            layout_hash: layout_hash.into(),
        })
    }
}

pub struct IeLayoutTracker {
    authorized_bssids_by_layout: LruCache<IeLayoutKey, Vec<MacAddr>>,
}

impl Default for IeLayoutTracker {
    fn default() -> Self {
        Self::new(DetectorLimits::default())
    }
}

impl IeLayoutTracker {
    pub fn new(limits: DetectorLimits) -> Self {
        Self {
            authorized_bssids_by_layout: LruCache::new(limits.clamp().ssid_capacity()),
        }
    }

    pub fn observe(&mut self, entry: &mut AuditEntry, authorization_status: AuthorizationStatus) {
        if !FrameSubtype::parse(&entry.frame_subtype).is_ap_observation() {
            return;
        }
        let (Some(ssid), Some(layout_hash), Some(bssid)) = (
            entry
                .ssid
                .as_deref()
                .map(str::trim)
                .filter(|value| !value.is_empty()),
            entry.ie_layout_hash.as_deref(),
            entry.bssid.as_deref().and_then(MacAddr::parse),
        ) else {
            return;
        };
        let Some(key) = IeLayoutKey::new(ssid, layout_hash) else {
            return;
        };

        match authorization_status {
            AuthorizationStatus::Authorized => {
                if self.authorized_bssids_by_layout.get(&key).is_none() {
                    self.authorized_bssids_by_layout
                        .put(key.clone(), Vec::new());
                }
                if let Some(bssids) = self.authorized_bssids_by_layout.get_mut(&key) {
                    if !bssids.contains(&bssid) {
                        if bssids.len() >= FINGERPRINT_MAC_LIMIT {
                            bssids.remove(0);
                        }
                        bssids.push(bssid);
                    }
                }
            }
            AuthorizationStatus::Unauthorized => {
                if self
                    .authorized_bssids_by_layout
                    .get(&key)
                    .is_some_and(|bssids| bssids.iter().any(|known| *known != bssid))
                {
                    push_unique(&mut entry.tags, "threat:structural_evil_twin");
                }
            }
            AuthorizationStatus::Unknown => {}
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
struct MacSequenceKey {
    transmitter: MacAddr,
    frame_type: u8,
    qos_tid: Option<u8>,
}

pub struct MacSequenceDeltaTracker {
    last_sequence_by_key: LruCache<MacSequenceKey, u16>,
}

impl Default for MacSequenceDeltaTracker {
    fn default() -> Self {
        Self::new(DetectorLimits::default())
    }
}

impl MacSequenceDeltaTracker {
    pub fn new(limits: DetectorLimits) -> Self {
        Self {
            last_sequence_by_key: LruCache::new(limits.clamp().session_capacity()),
        }
    }

    pub fn observe(&mut self, entry: &mut AuditEntry) {
        let (Some(transmitter), Some(current_sequence)) = (
            entry.transmitter_mac.as_deref().and_then(MacAddr::parse),
            entry.sequence_number,
        ) else {
            return;
        };
        let key = MacSequenceKey {
            transmitter,
            frame_type: frame_type_code(entry.frame_type.as_deref()),
            qos_tid: entry.qos_tid,
        };
        let current_sequence = current_sequence & 0x0fff;
        let previous_sequence = self.last_sequence_by_key.put(key, current_sequence);
        let Some(previous_sequence) = previous_sequence else {
            return;
        };

        let delta = if current_sequence >= previous_sequence {
            current_sequence - previous_sequence
        } else {
            4096 - previous_sequence + current_sequence
        };
        entry.sequence_delta = Some(delta);
        if let Some(correlation) = entry.correlation.as_mut() {
            correlation.sequence_delta = Some(delta);
        }

        if delta == 0 {
            entry.dedupe_or_replay_suspect = Some(true);
            if let Some(anomalies) = entry.anomalies.as_mut() {
                anomalies.dedupe_or_replay_suspect = true;
            }
            push_unique(&mut entry.tags, "anomaly:sequence_duplicate");
            push_anomaly_reason(entry, "sequence_duplicate");
        } else if delta > 1 && delta < 4000 {
            let missing = delta - 1;
            entry.sequence_gap_missing_frames = Some(missing);
            if let Some(correlation) = entry.correlation.as_mut() {
                correlation.sequence_gap_missing_frames = Some(missing);
            }
            push_unique(&mut entry.tags, "anomaly:sequence_jump");
            push_anomaly_reason(entry, "sequence_jump");
        }
    }
}

fn frame_type_code(frame_type: Option<&str>) -> u8 {
    match frame_type {
        Some("management") => 0,
        Some("data") => 2,
        _ => u8::MAX,
    }
}

fn parse_observed_at(value: &str) -> Option<DateTime<Utc>> {
    DateTime::parse_from_rfc3339(value)
        .ok()
        .map(|value| value.with_timezone(&Utc))
}

fn normalize_mac(value: &str) -> String {
    value.trim().to_ascii_lowercase()
}

fn push_unique(values: &mut Vec<String>, value: &str) {
    if !values.iter().any(|existing| existing == value) {
        values.push(value.to_string());
    }
}

fn push_anomaly_reason(entry: &mut AuditEntry, reason: &str) {
    push_unique(&mut entry.anomaly_reasons, reason);
    if let Some(anomalies) = entry.anomalies.as_mut() {
        push_unique(&mut anomalies.reasons, reason);
    }
}

/// Levenshtein distance with early exit: returns limit+1 when any row minimum exceeds
/// limit, avoiding full DP computation for strings that cannot possibly match.
/// Levenshtein distance with early-exit optimization. Returns limit+1 when the length
/// difference exceeds limit or any row minimum exceeds limit, avoiding full DP computation.
/// The limit of 2 distinguishes most typosquats (one character substitution or insertion).
fn edit_distance_limited(left: &str, right: &str, limit: usize) -> usize {
    if left.len().abs_diff(right.len()) > limit {
        return limit + 1;
    }
    let mut previous: Vec<usize> = (0..=right.len()).collect();
    let mut current = vec![0; right.len() + 1];
    for (i, left_ch) in left.chars().enumerate() {
        current[0] = i + 1;
        let mut row_min = current[0];
        for (j, right_ch) in right.chars().enumerate() {
            let cost = usize::from(left_ch != right_ch);
            current[j + 1] = (previous[j + 1] + 1)
                .min(current[j] + 1)
                .min(previous[j] + cost);
            row_min = row_min.min(current[j + 1]);
        }
        if row_min > limit {
            return limit + 1;
        }
        previous.clone_from(&current);
    }
    previous[right.len()]
}

#[derive(Clone, Debug, Serialize)]
pub struct AttackSequenceAlert {
    pub schema_version: u32,
    pub event_type: String,
    pub observed_at: String,
    pub sensor_id: String,
    pub location_id: String,
    pub ssid: String,
    pub attack_chain: Vec<String>,
    pub first_event_at: String,
    pub last_event_at: String,
    /// Structured factor breakdown for each detection factor.
    #[serde(default)]
    pub factor_breakdown: Vec<AlertExplanation>,
    /// Human-readable explanations for each detection factor.
    #[serde(default)]
    pub explanation: Vec<String>,
}

#[derive(Clone, Debug, Serialize)]
pub struct SequenceAlert {
    pub schema_version: u32,
    pub event_type: String,
    pub observed_at: String,
    pub sensor_id: String,
    pub location_id: String,
    pub session_key: String,
    pub source_mac: Option<String>,
    pub bssid: Option<String>,
    pub ssid: Option<String>,
    pub attack_tag: String,
    pub sequence: Vec<String>,
    pub first_event_at: String,
    pub last_event_at: String,
    /// Structured factor breakdown for each detection factor.
    #[serde(default)]
    pub factor_breakdown: Vec<AlertExplanation>,
    /// Human-readable explanations for each detection factor.
    #[serde(default)]
    pub explanation: Vec<String>,
}

#[derive(Clone, Debug)]
struct SessionSequence {
    frames: VecDeque<FrameSubtype>,
    first_seen: DateTime<Utc>,
    last_seen: DateTime<Utc>,
    seen_beacon_bssids: VecDeque<MacAddr>,
    auth_deauth_events: VecDeque<(DateTime<Utc>, FrameSubtype)>,
    emitted_tags: HashSet<String>,
}

pub struct SequenceTracker {
    sessions: LruCache<String, SessionSequence>,
}

impl Default for SequenceTracker {
    fn default() -> Self {
        Self::new(DetectorLimits::default())
    }
}

impl SequenceTracker {
    pub fn new(limits: DetectorLimits) -> Self {
        Self {
            sessions: LruCache::new(limits.clamp().session_capacity()),
        }
    }

    pub fn observe(&mut self, entry: &AuditEntry) -> Option<SequenceAlert> {
        let session_key = entry
            .session_key
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())?;
        let observed_at = parse_observed_at(&entry.observed_at).unwrap_or_else(Utc::now);
        let session_key_owned = session_key.to_string();
        if self.sessions.get(&session_key_owned).is_none() {
            self.sessions.put(
                session_key_owned.clone(),
                SessionSequence {
                    frames: VecDeque::new(),
                    first_seen: observed_at,
                    last_seen: observed_at,
                    seen_beacon_bssids: VecDeque::new(),
                    auth_deauth_events: VecDeque::new(),
                    emitted_tags: HashSet::new(),
                },
            );
        }
        let sequence = self.sessions.get_mut(&session_key_owned)?;
        sequence.last_seen = observed_at;

        let subtype = FrameSubtype::parse(&entry.frame_subtype);
        if let Some(bssid) = entry.bssid.as_deref().and_then(MacAddr::parse) {
            if matches!(subtype, FrameSubtype::Beacon)
                && !sequence.seen_beacon_bssids.contains(&bssid)
            {
                if sequence.seen_beacon_bssids.len() >= SEQUENCE_FRAME_LIMIT {
                    sequence.seen_beacon_bssids.pop_front();
                }
                sequence.seen_beacon_bssids.push_back(bssid);
            }
        }

        let mut alert_tag = None;
        if matches!(subtype, FrameSubtype::ProbeResponse) {
            if let Some(bssid) = entry.bssid.as_deref().and_then(MacAddr::parse) {
                if !sequence.seen_beacon_bssids.contains(&bssid) {
                    alert_tag = Some("threat:silent_rogue_ap".to_string());
                }
            }
        }

        sequence.frames.push_back(subtype.clone());
        while sequence.frames.len() > SEQUENCE_FRAME_LIMIT {
            sequence.frames.pop_front();
        }

        if matches!(
            subtype,
            FrameSubtype::Authentication | FrameSubtype::Deauthentication
        ) {
            sequence
                .auth_deauth_events
                .push_back((observed_at, subtype.clone()));
            let cutoff = observed_at - chrono::Duration::seconds(SEQUENCE_AUTH_WINDOW_SECS);
            while sequence
                .auth_deauth_events
                .front()
                .is_some_and(|(timestamp, _)| *timestamp < cutoff)
            {
                sequence.auth_deauth_events.pop_front();
            }
        }

        if alert_tag.is_none() {
            alert_tag = SequenceTracker::check_roaming_suppression(sequence);
        }
        if alert_tag.is_none() {
            alert_tag = SequenceTracker::check_auth_flood(sequence);
        }

        if let Some(tag) = alert_tag {
            if !sequence.emitted_tags.insert(tag.clone()) {
                return None;
            }

            // Extract data needed for the alert while we still hold the mutable
            // borrow to `sequence`. This ensures `prune_stale_sessions()` can
            // borrow `&mut self` without triggering E0499.
            let sequence_tokens = series_to_tokens(&sequence.frames);
            let first_seen = sequence.first_seen;
            let last_seen = sequence.last_seen;

            return Some(SequenceTracker::build_sequence_alert(
                sequence_tokens,
                session_key,
                entry,
                tag,
                first_seen,
                last_seen,
            ));
        }

        None
    }

    fn check_roaming_suppression(sequence: &SessionSequence) -> Option<String> {
        let pattern = [
            FrameSubtype::ProbeRequest,
            FrameSubtype::ProbeResponse,
            FrameSubtype::Deauthentication,
            FrameSubtype::ReassociationRequest,
            FrameSubtype::Deauthentication,
        ];
        if ends_with_pattern(&sequence.frames, &pattern) {
            return Some("threat:roaming_suppression".to_string());
        }
        None
    }

    fn check_auth_flood(sequence: &SessionSequence) -> Option<String> {
        if sequence.auth_deauth_events.len() < 6 {
            return None;
        }
        let pattern = [
            FrameSubtype::Authentication,
            FrameSubtype::Deauthentication,
            FrameSubtype::Authentication,
            FrameSubtype::Deauthentication,
            FrameSubtype::Authentication,
            FrameSubtype::Deauthentication,
        ];
        if sequence
            .auth_deauth_events
            .iter()
            .rev()
            .take(6)
            .map(|(_, subtype)| subtype)
            .collect::<Vec<_>>()
            .into_iter()
            .rev()
            .eq(pattern.iter())
        {
            return Some("threat:auth_flood".to_string());
        }
        None
    }

    fn build_sequence_alert(
        sequence_tokens: Vec<String>,
        session_key: &str,
        entry: &AuditEntry,
        attack_tag: String,
        first_seen: DateTime<Utc>,
        last_seen: DateTime<Utc>,
    ) -> SequenceAlert {
        let seq_contribution = (sequence_tokens.len() as f64).min(32.0) / 32.0;
        SequenceAlert {
            schema_version: 1,
            event_type: "wireless_sequence_alert".to_string(),
            observed_at: entry.observed_at.clone(),
            sensor_id: entry.sensor_id.clone(),
            location_id: entry.location_id.clone(),
            session_key: session_key.to_string(),
            source_mac: entry.source_mac.clone(),
            bssid: entry.bssid.clone(),
            ssid: entry.ssid.clone(),
            attack_tag: attack_tag.clone(),
            sequence: sequence_tokens.clone(),
            first_event_at: ssl_proxy::time::rfc3339_from_utc(first_seen),
            last_event_at: ssl_proxy::time::rfc3339_from_utc(last_seen),
            factor_breakdown: vec![AlertExplanation {
                factor: attack_tag.clone(),
                observed: sequence_tokens.len() as f64,
                baseline: 1.0,
                contribution: seq_contribution,
            }],
            explanation: vec![format!(
                "attack_tag: {} with {} frames in sequence (session: {})",
                attack_tag,
                sequence_tokens.len(),
                session_key
            )],
        }
    }
}

fn ends_with_pattern(frames: &VecDeque<FrameSubtype>, pattern: &[FrameSubtype]) -> bool {
    if frames.len() < pattern.len() {
        return false;
    }
    frames
        .iter()
        .rev()
        .zip(pattern.iter().rev())
        .all(|(actual, expected)| actual == expected)
}

fn series_to_tokens(frames: &VecDeque<FrameSubtype>) -> Vec<String> {
    frames.iter().map(FrameSubtype::token).collect()
}

#[derive(Debug)]
struct AttackEvent {
    timestamp: DateTime<Utc>,
    attack_type: String,
}

pub struct AttackTimelineCorrelator {
    events_by_ssid: LruCache<SsidKey, VecDeque<AttackEvent>>,
    recent_alerts: LruCache<SsidKey, DateTime<Utc>>,
}

impl Default for AttackTimelineCorrelator {
    fn default() -> Self {
        Self::new(DetectorLimits::default())
    }
}

impl AttackTimelineCorrelator {
    pub fn new(limits: DetectorLimits) -> Self {
        let limits = limits.clamp();
        Self {
            events_by_ssid: LruCache::new(limits.ssid_capacity()),
            recent_alerts: LruCache::new(limits.ssid_capacity()),
        }
    }

    /// Records an attack event (karma_probe_response or bssid_spoofing) and returns an
    /// AttackSequenceAlert if both attack types occurred for the same SSID within the
    /// correlation window. Enforces a cooldown per SSID to suppress duplicate alerts.
    pub fn observe(
        &mut self,
        entry: &AuditEntry,
        attack_type: &str,
    ) -> Option<AttackSequenceAlert> {
        if !matches!(attack_type, "karma_probe_response" | "bssid_spoofing") {
            return None;
        }
        let ssid = entry
            .ssid
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())?;
        let observed_at = parse_observed_at(&entry.observed_at).unwrap_or_else(Utc::now);
        let alert_key = SsidKey::new(ssid)?;
        if let Some(last_alert) = self.recent_alerts.get(&alert_key) {
            let delta = observed_at.signed_duration_since(*last_alert);
            let cooldown = chrono::Duration::from_std(ATTACK_SEQUENCE_COOLDOWN).ok()?;
            if delta >= chrono::Duration::zero() && delta < cooldown {
                return None;
            }
        }
        if self.events_by_ssid.get(&alert_key).is_none() {
            self.events_by_ssid.put(alert_key.clone(), VecDeque::new());
        }
        let events = self.events_by_ssid.get_mut(&alert_key)?;
        events.push_back(AttackEvent {
            timestamp: observed_at,
            attack_type: attack_type.to_string(),
        });
        let cutoff =
            observed_at - chrono::Duration::seconds(ATTACK_CORRELATION_WINDOW.as_secs() as i64);
        while events.front().is_some_and(|event| event.timestamp < cutoff) {
            events.pop_front();
        }
        let has_karma = events
            .iter()
            .any(|e| e.attack_type == "karma_probe_response");
        let has_spoofing = events.iter().any(|e| e.attack_type == "bssid_spoofing");
        if has_karma && has_spoofing {
            self.recent_alerts.put(alert_key, observed_at);
            let first = events.iter().map(|e| e.timestamp).min()?;
            let last = events.iter().map(|e| e.timestamp).max()?;
            let mut chain: Vec<_> = events.iter().map(|e| e.attack_type.clone()).collect();
            chain.sort();
            chain.dedup();
            let chain_str = chain.join(", ");
            let _contribution = if has_karma && has_spoofing { 1.0 } else { 0.0 };
            Some(AttackSequenceAlert {
                schema_version: 1,
                event_type: "wireless_attack_sequence".to_string(),
                observed_at: ssl_proxy::time::rfc3339_from_utc(observed_at),
                sensor_id: entry.sensor_id.clone(),
                location_id: entry.location_id.clone(),
                ssid: ssid.to_string(),
                attack_chain: chain,
                first_event_at: ssl_proxy::time::rfc3339_from_utc(first),
                last_event_at: ssl_proxy::time::rfc3339_from_utc(last),
                factor_breakdown: vec![
                    AlertExplanation {
                        factor: "karma_probe_response".to_string(),
                        observed: if has_karma { 1.0 } else { 0.0 },
                        baseline: 0.0,
                        contribution: if has_karma { 0.5 } else { 0.0 },
                    },
                    AlertExplanation {
                        factor: "bssid_spoofing".to_string(),
                        observed: if has_spoofing { 1.0 } else { 0.0 },
                        baseline: 0.0,
                        contribution: if has_spoofing { 0.5 } else { 0.0 },
                    },
                ],
                explanation: vec![format!(
                    "combined_attacks: {} against SSID '{}' within {}s window",
                    chain_str,
                    ssid,
                    ATTACK_CORRELATION_WINDOW.as_secs()
                )],
            })
        } else {
            None
        }
    }
}

pub struct PmfAttackTracker {
    ap_pmf_state: LruCache<MacAddr, bool>,
    client_deauth_times: LruCache<MacAddr, DateTime<Utc>>,
    reconnect_window_ms: i64,
    forced_reconnects: LruCache<(MacAddr, MacAddr), DateTime<Utc>>,
}

impl Default for PmfAttackTracker {
    fn default() -> Self {
        Self::new(3000)
    }
}

impl PmfAttackTracker {
    pub fn new(reconnect_window_ms: i64) -> Self {
        Self::with_limits(reconnect_window_ms, DetectorLimits::default())
    }

    pub fn new_with_limits(reconnect_window_ms: i64, limits: DetectorLimits) -> Self {
        Self::with_limits(reconnect_window_ms, limits)
    }

    fn with_limits(reconnect_window_ms: i64, limits: DetectorLimits) -> Self {
        let limits = limits.clamp();
        Self {
            ap_pmf_state: LruCache::new(limits.mac_capacity()),
            client_deauth_times: LruCache::new(limits.mac_capacity()),
            reconnect_window_ms,
            forced_reconnects: LruCache::new(limits.mac_capacity()),
        }
    }
}

impl PmfAttackTracker {
    pub fn observe(&mut self, entry: &AuditEntry, tags: &mut Vec<String>) {
        let observed = parse_observed_at(&entry.observed_at).unwrap_or_else(Utc::now);

        // Learn PMF state from beacons and probe responses
        if matches!(entry.frame_subtype.as_str(), "beacon" | "probe_response") {
            if let Some(bssid) = entry.bssid.as_deref().and_then(MacAddr::parse) {
                let pmf_required = entry.security_flags & SECURITY_PMF_REQUIRED != 0;
                self.ap_pmf_state.put(bssid, pmf_required);
            }
        }

        // Detect spoofed deauth/disassoc and track client deauth times
        if matches!(
            entry.frame_subtype.as_str(),
            "deauthentication" | "disassociation"
        ) {
            if let Some(src_norm) = entry.source_mac.as_deref().and_then(MacAddr::parse) {
                if let Some(&pmf_required) = self.ap_pmf_state.get(&src_norm) {
                    if !entry.protected.unwrap_or(false) && !pmf_required {
                        if !tags.contains(&"threat:pmf_deauth_attack".to_string()) {
                            tags.push("threat:pmf_deauth_attack".to_string());
                        }
                    }
                }
            }

            // Track deauth destination (client MAC) for reconnect correlation
            if let Some(dst) = entry.destination_mac.as_deref().and_then(MacAddr::parse) {
                self.client_deauth_times.put(dst, observed);
            }
        }

        // Detect forced reconnect within configurable window
        if matches!(
            entry.frame_subtype.as_str(),
            "association_request" | "reassociation_request"
        ) {
            if let Some(src_norm) = entry.source_mac.as_deref().and_then(MacAddr::parse) {
                if let Some(&deauth_time) = self.client_deauth_times.get(&src_norm) {
                    let delta = (observed - deauth_time).num_milliseconds();
                    if delta >= 0 && delta <= self.reconnect_window_ms {
                        if !tags.contains(&"threat:pmf_forced_reconnect".to_string()) {
                            tags.push("threat:pmf_forced_reconnect".to_string());
                        }
                        // Track forced reconnect for handshake correlation
                        if let Some(bssid) = entry
                            .bssid
                            .as_deref()
                            .or(entry.destination_bssid.as_deref())
                            .and_then(MacAddr::parse)
                        {
                            let key = (bssid, src_norm);
                            self.forced_reconnects.put(key, observed);
                        }
                    }
                }
            }
        }

        // Detect handshake harvest attack: forced reconnect + handshake within 10s
        if entry.handshake_captured {
            if let (Some(bssid), Some(client)) = (
                entry
                    .bssid
                    .as_deref()
                    .or(entry.destination_bssid.as_deref())
                    .and_then(MacAddr::parse),
                entry
                    .source_mac
                    .as_deref()
                    .or(entry.destination_mac.as_deref())
                    .and_then(MacAddr::parse),
            ) {
                let key = (bssid, client);
                if let Some(&reconnect_time) = self.forced_reconnects.get(&key) {
                    let delta = (observed - reconnect_time).num_milliseconds();
                    if delta >= 0 && delta <= 10_000 {
                        if !tags.contains(&"threat:handshake_harvest_attack".to_string()) {
                            tags.push("threat:handshake_harvest_attack".to_string());
                        }
                    }
                }
            }
        }
    }
}

#[derive(Serialize)]
pub struct PmfAttackAlert {
    pub schema_version: u32,
    pub event_type: String,
    pub observed_at: String,
    pub sensor_id: String,
    pub location_id: String,
    pub target_mac: String,
    pub target_bssid: Option<String>,
    pub ssid: Option<String>,
    pub channel: Option<u8>,
    pub attack_tag: String,
    pub reconnect_window_ms: Option<i64>,
}

pub fn pmf_attack_alert_from_entry(
    entry: &AuditEntry,
    attack_tag: &str,
    reconnect_window_ms: i64,
) -> Option<PmfAttackAlert> {
    if !attack_tag.starts_with("threat:pmf_") && attack_tag != "threat:handshake_harvest_attack" {
        return None;
    }

    let target_mac = if attack_tag == "threat:pmf_forced_reconnect" {
        entry.source_mac.as_deref()
    } else {
        entry
            .destination_mac
            .as_deref()
            .or(entry.source_mac.as_deref())
    }
    .or(entry.bssid.as_deref())?
    .trim()
    .to_ascii_lowercase();

    Some(PmfAttackAlert {
        schema_version: 1,
        event_type: "wireless_pmf_attack".to_string(),
        observed_at: entry.observed_at.clone(),
        sensor_id: entry.sensor_id.clone(),
        location_id: entry.location_id.clone(),
        target_mac,
        target_bssid: entry
            .bssid
            .clone()
            .or_else(|| entry.destination_bssid.clone()),
        ssid: entry.ssid.clone(),
        channel: Some(entry.channel),
        attack_tag: attack_tag.to_string(),
        reconnect_window_ms: Some(reconnect_window_ms),
    })
}

#[cfg(test)]
mod tests {
    use super::edit_distance_limited;

    #[test]
    fn edit_distance_limits_typosquats() {
        assert_eq!(edit_distance_limited("corpwifi", "corp-wifi", 2), 1);
        assert!(edit_distance_limited("corpwifi", "guest", 2) > 2);
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

        // Unprotected deauth from same AP BSSID
        let mut deauth = beacon.clone();
        deauth.frame_subtype = "deauthentication".to_string();
        deauth.source_mac = Some("aa:bb:cc:dd:ee:ff".to_string());
        deauth.destination_mac = Some("11:22:33:44:55:66".to_string());
        deauth.protected = Some(false);
        deauth.observed_at = "2024-01-01T12:00:01Z".to_string();
        tracker.observe(&deauth, &mut tags);
        assert!(tags.contains(&"threat:pmf_deauth_attack".to_string()));

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
    fn pmf_attack_not_detected_when_pmf_required() {
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

        // Unprotected deauth should NOT trigger attack tag
        let mut deauth = beacon.clone();
        deauth.frame_subtype = "deauthentication".to_string();
        deauth.source_mac = Some("aa:bb:cc:dd:ee:ff".to_string());
        deauth.destination_mac = Some("11:22:33:44:55:66".to_string());
        deauth.protected = Some(false);
        tracker.observe(&deauth, &mut tags);
        assert!(!tags.contains(&"threat:pmf_deauth_attack".to_string()));
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
}
