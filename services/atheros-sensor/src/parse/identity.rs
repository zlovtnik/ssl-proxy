//! Per-frame identity resolution and threat detection cache.
//!
//! mac_to_username is an LRU (capacity 4096) populated when an EAP Identity response is
//! observed; subsequent frames from the same source MAC are enriched with the cached username
//! under source "eap_identity_cache" without requiring another EAP exchange.
//! ssid_to_bssids is an LRU that maps each SSID to the set of BSSIDs seen advertising it;
//! when a new BSSID appears for a known SSID, a "threat:potential_evil_twin" tag is emitted
//! and a ResolvedIdentity with source "evil_twin_detection" is returned.
//! deauth_counts is an LRU tracking deauthentication/disassociation frame counts per BSSID
//! within a 10-second sliding window; exceeding DEAUTH_FLOOD_THRESHOLD (5) fires a
//! "threat:deauth_flood" tag once per window via the alerted flag.

use std::time::Duration;

use lru::LruCache;

use crate::{
    model::WifiFrame,
    state_key::{DetectorLimits, MacAddr, SsidKey},
};

use super::tags::push_tag;

const MAX_BSSIDS_PER_SSID: usize = 16;
const DEAUTH_FLOOD_WINDOW: Duration = Duration::from_secs(10);
const DEAUTH_FLOOD_THRESHOLD: u32 = 5;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ResolvedIdentity {
    pub username: String,
    pub source: String,
    pub tags: Vec<String>,
}

pub struct IdentityCache {
    mac_to_username: LruCache<MacAddr, String>,
    ssid_to_bssids: LruCache<SsidKey, Vec<MacAddr>>,
    deauth_counts: LruCache<MacAddr, DeauthCount>,
}

#[derive(Clone, Debug)]
struct DeauthCount {
    count: u32,
    window_started: chrono::DateTime<chrono::Utc>,
    alerted: bool,
}

impl DeauthCount {
    fn new(count: u32, window_started: chrono::DateTime<chrono::Utc>) -> Self {
        Self {
            count,
            window_started,
            alerted: false,
        }
    }
}

impl Default for IdentityCache {
    fn default() -> Self {
        Self::new(DetectorLimits::default())
    }
}

impl IdentityCache {
    pub fn new(limits: DetectorLimits) -> Self {
        let limits = limits.clamp();
        Self {
            mac_to_username: LruCache::new(limits.mac_capacity()),
            ssid_to_bssids: LruCache::new(limits.ssid_capacity()),
            deauth_counts: LruCache::new(limits.mac_capacity()),
        }
    }
}

impl IdentityCache {
    pub fn resolve(&mut self, frame: &WifiFrame) -> Option<ResolvedIdentity> {
        let mut threat_tags = Vec::new();
        let mut detection_identity = None;

        if matches!(frame.frame_subtype.as_str(), "beacon" | "probe_response") {
            if let (Some(ssid), Some(bssid)) = (frame.ssid.as_ref(), frame.bssid.as_ref()) {
                if let (Some(known_key), Some(bssid_key)) =
                    (SsidKey::new(ssid), MacAddr::parse(bssid))
                {
                    if let Some(known) = self.ssid_to_bssids.get_mut(&known_key) {
                        let already_seen = known.contains(&bssid_key);
                        if !already_seen && !known.is_empty() {
                            push_tag(&mut threat_tags, "threat:potential_evil_twin");
                            detection_identity = Some(ResolvedIdentity {
                                username: format!("SUSPECT_EVIL_TWIN:{bssid}"),
                                source: "evil_twin_detection".to_string(),
                                tags: threat_tags.clone(),
                            });
                        }
                        if !already_seen {
                            if known.len() >= MAX_BSSIDS_PER_SSID {
                                known.remove(0);
                            }
                            known.push(bssid_key);
                        }
                    } else {
                        self.ssid_to_bssids.put(known_key, vec![bssid_key]);
                    }
                }
            }
        }

        if matches!(
            frame.frame_subtype.as_str(),
            "deauthentication" | "disassociation"
        ) {
            if let Some(bssid) = frame.bssid.as_ref() {
                if let Some(bssid_key) = MacAddr::parse(bssid) {
                    if let Some(entry) = self.deauth_counts.get_mut(&bssid_key) {
                        let window = chrono::Duration::from_std(DEAUTH_FLOOD_WINDOW).ok()?;
                        if frame
                            .observed_at
                            .signed_duration_since(entry.window_started)
                            > window
                        {
                            *entry = DeauthCount::new(1, frame.observed_at);
                        } else {
                            entry.count += 1;
                            if entry.count > DEAUTH_FLOOD_THRESHOLD && !entry.alerted {
                                push_tag(&mut threat_tags, "threat:deauth_flood");
                                detection_identity = Some(ResolvedIdentity {
                                    username: format!("SUSPECT_DEAUTH_FLOOD:{bssid}"),
                                    source: "deauth_flood_detection".to_string(),
                                    tags: threat_tags.clone(),
                                });
                                entry.alerted = true;
                            }
                        }
                    } else {
                        self.deauth_counts
                            .put(bssid_key, DeauthCount::new(1, frame.observed_at));
                    }
                }
            }
        }

        if let Some(username) = frame.username_hint.clone() {
            if let Some(mac) = frame.source_mac.as_ref() {
                if let Some(mac) = MacAddr::parse(mac) {
                    self.mac_to_username.put(mac, username.clone());
                }
            }
            return Some(ResolvedIdentity {
                username,
                source: frame
                    .identity_source_hint
                    .clone()
                    .unwrap_or_else(|| "observed_identity".to_string()),
                tags: threat_tags,
            });
        }

        for candidate in [frame.source_mac.as_ref(), frame.destination_mac.as_ref()] {
            let Some(candidate) = candidate else {
                continue;
            };
            let Some(key) = MacAddr::parse(candidate) else {
                continue;
            };
            if let Some(username) = self.mac_to_username.get(&key) {
                return Some(ResolvedIdentity {
                    username: username.clone(),
                    source: "eap_identity_cache".to_string(),
                    tags: threat_tags,
                });
            }
        }

        detection_identity
    }
}
