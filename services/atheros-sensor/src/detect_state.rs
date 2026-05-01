use std::collections::{HashMap, HashSet};
use std::time::{Duration, Instant};

use chrono::{DateTime, Utc};
use serde::Serialize;

use crate::backlog::{AuthorizedWirelessNetwork, PostgresBacklog};
use crate::model::AuditEntry;

pub const CLIENT_INVENTORY_SUBJECT: &str = "sync.scan.request";
pub const ROGUE_AP_SUBJECT: &str = "sync.oracle.load";
pub const DEAUTH_FLOOD_SUBJECT: &str = "sync.oracle.result";
const ROGUE_AP_ALERT_TTL: Duration = Duration::from_secs(60);

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
        backlog: &PostgresBacklog,
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

#[cfg(test)]
mod tests {
    use super::edit_distance_limited;

    #[test]
    fn edit_distance_limits_typosquats() {
        assert_eq!(edit_distance_limited("corpwifi", "corp-wifi", 2), 1);
        assert!(edit_distance_limited("corpwifi", "guest", 2) > 2);
    }
}
