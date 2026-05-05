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
//! AuthorizedNetworkCache holds the NATS-backed list of known SSIDs/BSSIDs and is
//! invalidated by the NATS generation counter when the console pushes a config change;
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

use std::collections::{HashMap, HashSet};
use std::time::{Duration, Instant};

use chrono::{DateTime, Utc};
use serde::Serialize;

use crate::backlog::{AuthorizedWirelessNetwork, NatsBacklog};
use crate::model::AuditEntry;
use crate::parse::SECURITY_PMF_REQUIRED;

pub const CLIENT_INVENTORY_SUBJECT: &str = "sync.scan.request";
pub const ROGUE_AP_SUBJECT: &str = "sync.oracle.load";
pub const DEAUTH_FLOOD_SUBJECT: &str = "sync.oracle.result";
pub const ATTACK_SEQUENCE_SUBJECT: &str = "sync.oracle.result";
const ROGUE_AP_ALERT_TTL: Duration = Duration::from_secs(60);
const ATTACK_CORRELATION_WINDOW: Duration = Duration::from_secs(300);
const ATTACK_SEQUENCE_COOLDOWN: Duration = Duration::from_secs(60);

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
}

#[derive(Clone, Debug)]
struct ClientProfile {
    first_seen: DateTime<Utc>,
    last_seen: DateTime<Utc>,
    probe_ssids: HashSet<String>,
    probe_count: u64,
    recent_probes: Vec<DateTime<Utc>>,
    excessive_probing: bool,
    channels: HashSet<u8>,
    last_signal_dbm: Option<i8>,
}

#[derive(Default)]
pub struct ClientInventory {
    clients: HashMap<String, ClientProfile>,
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
        let client_mac = entry.source_mac.as_deref().map(normalize_mac)?;
        let probe_ssid = entry
            .ssid
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())?;

        for network in &authorized.entries {
            if let Some(known_ssid) = &network.ssid {
                if known_ssid.trim().eq_ignore_ascii_case(probe_ssid) {
                    if let Some(bssid) = &network.bssid {
                        return Some((
                            bssid.clone(),
                            client_mac,
                            Some(probe_ssid.to_string()),
                        ));
                    }
                }
            }
        }
        None
    }

    /// Observes a frame and updates client profile. The excessive_probing flag latches to true
    /// once a client sends >=20 probe requests within any 60-second window and is never reset
    /// to false within the same session (inventory flush required to clear).
    pub fn observe(&mut self, entry: &AuditEntry) {
        let Some(source_mac) = entry.source_mac.as_deref().map(normalize_mac) else {
            return;
        };
        let observed_at = parse_observed_at(&entry.observed_at).unwrap_or_else(Utc::now);
        let profile = self
            .clients
            .entry(source_mac)
            .or_insert_with(|| ClientProfile {
                first_seen: observed_at,
                last_seen: observed_at,
                probe_ssids: HashSet::new(),
                probe_count: 0,
                recent_probes: Vec::new(),
                excessive_probing: false,
                channels: HashSet::new(),
                last_signal_dbm: None,
            });
        profile.last_seen = observed_at;
        profile.channels.insert(entry.channel);
        profile.last_signal_dbm = entry.signal_dbm;
        if entry.frame_subtype == "probe_request" {
            profile.probe_count = profile.probe_count.saturating_add(1);
            if let Some(ssid) = entry
                .ssid
                .as_deref()
                .map(str::trim)
                .filter(|ssid| !ssid.is_empty())
            {
                profile.probe_ssids.insert(ssid.to_string());
            }
            profile.recent_probes.push(observed_at);
            let cutoff = observed_at - chrono::Duration::seconds(60);
            profile.recent_probes.retain(|time| *time >= cutoff);
            if profile.recent_probes.len() >= 20 {
                profile.excessive_probing = true;
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
                let mut channels: Vec<_> = profile.channels.iter().copied().collect();
                channels.sort_unstable();
                ClientProfileSnapshot {
                    source_mac: source_mac.clone(),
                    first_seen: ssl_proxy::time::rfc3339_from_utc(profile.first_seen),
                    last_seen: ssl_proxy::time::rfc3339_from_utc(profile.last_seen),
                    probe_ssids,
                    probe_count: profile.probe_count,
                    excessive_probing: profile.excessive_probing,
                    channels,
                    last_signal_dbm: profile.last_signal_dbm,
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

#[derive(Default)]
pub struct SignalTracker {
    last_by_bssid: HashMap<String, i8>,
}

impl SignalTracker {
    /// Observes a frame and returns true when the signal delta exceeds threshold. Returns true
    /// on the second observation of a BSSID when the delta exceeds threshold; the first
    /// observation has no baseline to compare against.
    pub fn observe(&mut self, entry: &AuditEntry, threshold: i8) -> bool {
        if threshold <= 0 {
            return false;
        }
        let (Some(bssid), Some(signal)) =
            (entry.bssid.as_deref().map(normalize_mac), entry.signal_dbm)
        else {
            return false;
        };
        let previous = self.last_by_bssid.insert(bssid, signal);
        previous
            .is_some_and(|last| (i16::from(signal) - i16::from(last)).abs() >= i16::from(threshold))
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
}

#[derive(Default)]
pub struct RogueApTracker {
    ssid_by_bssid: HashMap<String, String>,
    channels_by_bssid: HashMap<String, HashSet<u8>>,
    recent_alerts: HashMap<String, Instant>,
}

impl RogueApTracker {
    /// Observes a beacon or probe response and returns a RogueApAlert when any of four detection
    /// reasons fire: open_authorized_ssid (known SSID with no encryption), ssid_typosquat
    /// (edit distance <=2 from known SSID), bssid_spoofing (BSSID changed SSID mapping), or
    /// channel_conflict (same BSSID seen on multiple channels).
    pub fn observe(
        &mut self,
        entry: &AuditEntry,
        authorized: &AuthorizedNetworkCache,
    ) -> Option<RogueApAlert> {
        if !matches!(entry.frame_subtype.as_str(), "beacon" | "probe_response") {
            return None;
        }
        let mut reasons = Vec::new();
        let ssid = entry
            .ssid
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty());
        let bssid = entry.bssid.as_deref().map(normalize_mac);
        if ssid.is_some_and(|value| authorized.is_known_ssid(value)) && entry.security_flags == 0 {
            reasons.push("open_authorized_ssid".to_string());
        }
        if let Some(ssid) = ssid {
            if authorized.is_typosquat(ssid) {
                reasons.push("ssid_typosquat".to_string());
            }
        }
        if let (Some(bssid), Some(ssid)) = (bssid.as_ref(), ssid) {
            if let Some(previous) = self.ssid_by_bssid.insert(bssid.clone(), ssid.to_string()) {
                if previous != ssid {
                    reasons.push("bssid_spoofing".to_string());
                }
            }
        }
        if let Some(bssid) = bssid.as_ref() {
            let channels = self.channels_by_bssid.entry(bssid.clone()).or_default();
            channels.insert(entry.channel);
            if channels.len() > 1 {
                reasons.push("channel_conflict".to_string());
            }
        }
        if reasons.is_empty() {
            return None;
        }
        let key = format!(
            "{}|{}|{}",
            bssid.as_deref().unwrap_or("unknown"),
            ssid.unwrap_or("unknown"),
            reasons.join(",")
        );
        let now = Instant::now();
        self.recent_alerts
            .retain(|_, last| now.saturating_duration_since(*last) < ROGUE_AP_ALERT_TTL);
        if self
            .recent_alerts
            .get(&key)
            .is_some_and(|last| now.saturating_duration_since(*last) < ROGUE_AP_ALERT_TTL)
        {
            return None;
        }
        self.recent_alerts.insert(key, now);
        Some(RogueApAlert {
            schema_version: 1,
            event_type: "wireless_rogue_ap".to_string(),
            observed_at: entry.observed_at.clone(),
            sensor_id: entry.sensor_id.clone(),
            location_id: entry.location_id.clone(),
            interface: entry.interface.clone(),
            bssid,
            ssid: ssid.map(str::to_string),
            channel: entry.channel,
            reasons,
        })
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
}

#[derive(Default)]
pub struct DeauthFloodTracker {
    windows: HashMap<String, Vec<DateTime<Utc>>>,
    last_alerts: HashMap<String, Instant>,
}

impl DeauthFloodTracker {
    /// Observes a deauth or disassociation frame and returns a DeauthFloodAlert when the frame
    /// count exceeds threshold within window_secs. Uses a sliding window that retains timestamps
    /// and a separate Instant-based cooldown clock (wall-time, not frame timestamps) to suppress
    /// repeat alerts for cooldown_secs after firing.
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
            .map(normalize_mac)
            .unwrap_or_else(|| "unknown".to_string());
        let observed_at = parse_observed_at(&entry.observed_at).unwrap_or_else(Utc::now);
        let window = self.windows.entry(key.clone()).or_default();
        window.push(observed_at);
        let cutoff = observed_at - chrono::Duration::seconds(window_secs as i64);
        window.retain(|time| *time >= cutoff);
        let frame_count = window.len();
        if frame_count == 0 {
            self.windows.remove(&key);
            self.last_alerts.remove(&key);
            return None;
        }
        let now = Instant::now();
        let retention = Duration::from_secs(cooldown_secs.max(window_secs));
        self.last_alerts
            .retain(|_, last| now.saturating_duration_since(*last) <= retention);
        if frame_count < threshold as usize {
            return None;
        }
        if self.last_alerts.get(&key).is_some_and(|last| {
            now.saturating_duration_since(*last) < Duration::from_secs(cooldown_secs)
        }) {
            return None;
        }
        self.last_alerts.insert(key, now);
        Some(DeauthFloodAlert {
            schema_version: 1,
            event_type: "wireless_deauth_flood".to_string(),
            observed_at: entry.observed_at.clone(),
            sensor_id: entry.sensor_id.clone(),
            location_id: entry.location_id.clone(),
            interface: entry.interface.clone(),
            bssid: entry.bssid.clone(),
            frame_count: frame_count as u64,
            window_secs,
        })
    }
}

#[derive(Default)]
pub struct AuthorizedNetworkCache {
    entries: Vec<AuthorizedWirelessNetwork>,
    loaded_at: Option<Instant>,
}

impl AuthorizedNetworkCache {
    #[allow(dead_code)]
    pub fn invalidate(&mut self) {
        self.loaded_at = None;
    }

    pub async fn refresh_if_needed(
        &mut self,
        backlog: &NatsBacklog,
        ttl: Duration,
    ) -> Result<(), crate::backlog::BacklogError> {
        if self
            .loaded_at
            .is_some_and(|loaded_at| loaded_at.elapsed() < ttl)
        {
            return Ok(());
        }
        self.entries = backlog.list_authorized_wireless_networks().await?;
        self.loaded_at = Some(Instant::now());
        Ok(())
    }

    /// Checks if a network is authorized using three-field AND logic: location_id, SSID, and
    /// BSSID. A None field on the stored entry acts as a wildcard (matches any value). At least
    /// one of SSID or BSSID must be non-None on the stored entry to match.
    pub fn is_authorized(
        &self,
        ssid: Option<&str>,
        bssid: Option<&str>,
        location_id: &str,
    ) -> bool {
        let normalized_ssid = ssid.map(|value| value.trim().to_ascii_lowercase());
        let normalized_bssid = bssid.map(normalize_mac);
        self.entries.iter().any(|entry| {
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
        })
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

fn parse_observed_at(value: &str) -> Option<DateTime<Utc>> {
    DateTime::parse_from_rfc3339(value)
        .ok()
        .map(|value| value.with_timezone(&Utc))
}

fn normalize_mac(value: &str) -> String {
    value.trim().to_ascii_lowercase()
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
}

#[derive(Debug)]
struct AttackEvent {
    timestamp: DateTime<Utc>,
    attack_type: String,
}

#[derive(Default)]
pub struct AttackTimelineCorrelator {
    events_by_ssid: HashMap<String, Vec<AttackEvent>>,
    recent_alerts: HashMap<String, Instant>,
}

impl AttackTimelineCorrelator {
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
        let ssid = entry.ssid.as_deref().map(str::trim).filter(|s| !s.is_empty())?;
        let observed_at = parse_observed_at(&entry.observed_at).unwrap_or_else(Utc::now);
        let alert_key = ssid.to_string();
        if let Some(last_alert) = self.recent_alerts.get(&alert_key) {
            if last_alert.elapsed() < ATTACK_SEQUENCE_COOLDOWN {
                return None;
            }
        }
        let events = self.events_by_ssid.entry(ssid.to_string()).or_default();
        events.push(AttackEvent {
            timestamp: observed_at,
            attack_type: attack_type.to_string(),
        });
        let cutoff = observed_at - chrono::Duration::seconds(ATTACK_CORRELATION_WINDOW.as_secs() as i64);
        events.retain(|e| e.timestamp >= cutoff);
        let has_karma = events.iter().any(|e| e.attack_type == "karma_probe_response");
        let has_spoofing = events.iter().any(|e| e.attack_type == "bssid_spoofing");
        if has_karma && has_spoofing {
            self.recent_alerts.insert(alert_key, Instant::now());
            let first = events.iter().map(|e| e.timestamp).min()?;
            let last = events.iter().map(|e| e.timestamp).max()?;
            let mut chain: Vec<_> = events.iter().map(|e| e.attack_type.clone()).collect();
            chain.sort();
            chain.dedup();
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
            })
        } else {
            None
        }
    }
}

#[derive(Default)]
pub struct PmfAttackTracker {
    ap_pmf_state: HashMap<String, bool>,
    client_deauth_times: HashMap<String, DateTime<Utc>>,
    reconnect_window_ms: i64,
    forced_reconnects: HashMap<(String, String), DateTime<Utc>>,  // (bssid, client) -> timestamp
}

impl PmfAttackTracker {
    pub fn new(reconnect_window_ms: i64) -> Self {
        Self {
            ap_pmf_state: HashMap::new(),
            client_deauth_times: HashMap::new(),
            reconnect_window_ms,
            forced_reconnects: HashMap::new(),
        }
    }
}

impl PmfAttackTracker {
    pub fn observe(&mut self, entry: &AuditEntry, tags: &mut Vec<String>) {
        let observed = parse_observed_at(&entry.observed_at).unwrap_or_else(Utc::now);

        // Learn PMF state from beacons and probe responses
        if matches!(entry.frame_subtype.as_str(), "beacon" | "probe_response") {
            if let Some(bssid) = entry.bssid.as_deref() {
                let pmf_required = entry.security_flags & SECURITY_PMF_REQUIRED != 0;
                self.ap_pmf_state.insert(normalize_mac(bssid), pmf_required);
            }
        }

        // Detect spoofed deauth/disassoc and track client deauth times
        if matches!(entry.frame_subtype.as_str(), "deauthentication" | "disassociation") {
            if let Some(src) = entry.source_mac.as_deref() {
                let src_norm = normalize_mac(src);
                
                if let Some(&pmf_required) = self.ap_pmf_state.get(&src_norm) {
                    if !entry.protected.unwrap_or(false) && !pmf_required {
                        if !tags.contains(&"threat:pmf_deauth_attack".to_string()) {
                            tags.push("threat:pmf_deauth_attack".to_string());
                        }
                    }
                }
            }

            // Track deauth destination (client MAC) for reconnect correlation
            if let Some(dst) = entry.destination_mac.as_deref() {
                self.client_deauth_times.insert(normalize_mac(dst), observed);
            }
        }

        // Detect forced reconnect within configurable window
        if matches!(entry.frame_subtype.as_str(), "association_request" | "reassociation_request") {
            if let Some(src) = entry.source_mac.as_deref() {
                let src_norm = normalize_mac(src);
                if let Some(&deauth_time) = self.client_deauth_times.get(&src_norm) {
                    let delta = (observed - deauth_time).num_milliseconds();
                    if delta >= 0 && delta <= self.reconnect_window_ms {
                        if !tags.contains(&"threat:pmf_forced_reconnect".to_string()) {
                            tags.push("threat:pmf_forced_reconnect".to_string());
                        }
                        // Track forced reconnect for handshake correlation
                        if let Some(bssid) = entry.bssid.as_deref().or(entry.destination_bssid.as_deref()) {
                            let key = (normalize_mac(bssid), src_norm);
                            self.forced_reconnects.insert(key, observed);
                        }
                    }
                }
            }
        }

        // Detect handshake harvest attack: forced reconnect + handshake within 10s
        if entry.handshake_captured {
            if let (Some(bssid), Some(client)) = (
                entry.bssid.as_deref().or(entry.destination_bssid.as_deref()),
                entry.source_mac.as_deref().or(entry.destination_mac.as_deref()),
            ) {
                let key = (normalize_mac(bssid), normalize_mac(client));
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

        // Cleanup expired state
        let ttl_ms = self.reconnect_window_ms.max(30_000);
        let cutoff = observed - chrono::Duration::milliseconds(ttl_ms);
        self.client_deauth_times.retain(|_, &mut time| time >= cutoff);
        self.forced_reconnects.retain(|_, &mut time| time >= cutoff);
    }
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
        use crate::model::AuditEntry;

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
        use crate::model::AuditEntry;

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
        use crate::model::AuditEntry;

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
            security_flags: 0x02,
            wps_device_name: None,
            wps_manufacturer: None,
            wps_model_name: None,
            device_fingerprint: None,
            probe_fingerprint: None,
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
        use crate::model::AuditEntry;
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
            security_flags: 0,
            wps_device_name: None,
            wps_manufacturer: None,
            wps_model_name: None,
            device_fingerprint: None,
            probe_fingerprint: None,
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
