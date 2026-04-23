use std::{
    num::NonZeroUsize,
    time::{Duration, Instant},
};

use lru::LruCache;

use crate::model::WifiFrame;

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
    mac_to_username: LruCache<String, String>,
    ssid_to_bssids: LruCache<String, Vec<String>>,
    deauth_counts: LruCache<String, DeauthCount>,
}

#[derive(Clone, Debug)]
struct DeauthCount {
    count: u32,
    window_started: Instant,
    alerted: bool,
}

impl DeauthCount {
    fn new(count: u32) -> Self {
        Self {
            count,
            window_started: Instant::now(),
            alerted: false,
        }
    }
}

impl Default for IdentityCache {
    fn default() -> Self {
        Self {
            mac_to_username: LruCache::new(
                NonZeroUsize::new(4_096).expect("identity cache capacity must be non-zero"),
            ),
            ssid_to_bssids: LruCache::new(
                NonZeroUsize::new(4_096).expect("ssid cache capacity must be non-zero"),
            ),
            deauth_counts: LruCache::new(
                NonZeroUsize::new(4_096).expect("deauth cache capacity must be non-zero"),
            ),
        }
    }
}

impl IdentityCache {
    pub fn resolve(&mut self, frame: &WifiFrame) -> Option<ResolvedIdentity> {
        let mut threat_tags = Vec::new();
        let mut detection_identity = None;

        if matches!(frame.frame_subtype.as_str(), "beacon" | "probe_response") {
            if let (Some(ssid), Some(bssid)) = (frame.ssid.as_ref(), frame.bssid.as_ref()) {
                let known_key = ssid.to_ascii_lowercase();
                let bssid_key = bssid.to_ascii_lowercase();
                if let Some(known) = self.ssid_to_bssids.get_mut(&known_key) {
                    let already_seen = known
                        .iter()
                        .any(|known_bssid| known_bssid.eq_ignore_ascii_case(&bssid_key));
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

        if matches!(
            frame.frame_subtype.as_str(),
            "deauthentication" | "disassociation"
        ) {
            if let Some(bssid) = frame.bssid.as_ref() {
                let bssid_key = bssid.to_ascii_lowercase();
                if let Some(entry) = self.deauth_counts.get_mut(&bssid_key) {
                    if entry.window_started.elapsed() > DEAUTH_FLOOD_WINDOW {
                        *entry = DeauthCount::new(1);
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
                    self.deauth_counts.put(bssid_key, DeauthCount::new(1));
                }
            }
        }

        if let Some(username) = frame.username_hint.clone() {
            if let Some(mac) = frame.source_mac.as_ref() {
                self.mac_to_username
                    .put(mac.to_ascii_lowercase(), username.clone());
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
            let key = candidate.to_ascii_lowercase();
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
