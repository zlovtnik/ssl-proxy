//! 4-way WPA2 handshake state machine with dedup and optional file export.
//!
//! HandshakeMonitor tracks per-(bssid, client_mac) state using a bitmask of the four EAPOL
//! key messages seen. A handshake is considered complete when all four bits are set (0x0f).
//! A configurable dedup window prevents the same pair from generating repeated alerts during
//! retransmission storms; on suppression only last_alerts is updated, state.messages remains
//! intact. When ATH_SENSOR_EXPORT_HANDSHAKES is enabled, the complete frame bundle is written
//! to SYNC_OUTBOX_DIR/handshakes/ and partial handshakes (msg 1+2) are exported immediately
//! to SYNC_OUTBOX_DIR/handshakes/partial/ via spawn_blocking.
//!
//! # Type notes
//!
//! [`HandshakeMonitor`]: the top-level tracker; holds per-pair [`HandshakeState`] entries
//! and a separate `last_alerts` map for dedup suppression.
//!
//! [`HandshakeState`]: `messages` is a bitmask where bit N (0-indexed) represents EAPOL
//! key message N+1 — bit 0 = message 1, bit 1 = message 2, bit 2 = message 3, bit 3 =
//! message 4; all four bits set (`0x0f`) means the full 4-way handshake has been captured.

use std::{
    collections::HashMap,
    fs,
    path::Path,
    time::{Duration, Instant},
};

use crate::{
    capture::CaptureControl,
    model::{AuditContext, HandshakeAlert, WifiFrame},
};
use chrono::Utc;

use super::{eapol::eapol_key_observation, tags::push_tag};

const PARTIAL_HANDSHAKE_GRACE: Duration = Duration::from_secs(120);

#[derive(Default)]
pub struct HandshakeMonitor {
    pub(crate) states: HashMap<String, HandshakeState>,
    last_alerts: HashMap<String, Instant>,
    pinned_pairs: HashMap<String, u8>,
}

#[derive(Clone, Debug)]
pub(crate) struct HandshakeState {
    messages: u8,
    frames: Vec<HandshakeFrame>,
    pmkid: Option<String>,
    last_seen: Instant,
    replay_counter: Option<u64>,
    partial_exported: bool,
    pub(crate) anonce: Option<[u8; 32]>,
    pub(crate) snonce: Option<[u8; 32]>,
}

#[derive(Clone, Debug, serde::Serialize)]
struct HandshakeFrame {
    message: u8,
    observed_at: String,
    raw_frame: Option<String>,
}

impl HandshakeState {
    fn new() -> Self {
        Self {
            messages: 0,
            frames: Vec::new(),
            pmkid: None,
            last_seen: Instant::now(),
            replay_counter: None,
            partial_exported: false,
            anonce: None,
            snonce: None,
        }
    }
}

impl HandshakeMonitor {
    pub fn cleanup_expired(&mut self, ttl: Duration, capture_control: Option<&CaptureControl>) {
        let now = Instant::now();
        let mut stalled_pairs = Vec::new();
        self.states.retain(|key, state| {
            let age = now.saturating_duration_since(state.last_seen);
            let should_retain = if state.messages != 0 {
                age <= PARTIAL_HANDSHAKE_GRACE
            } else {
                age <= ttl
            };
            if !should_retain && state.messages != 0 && state.messages != 0x0f {
                stalled_pairs.push((key.clone(), state.messages, age));
            }
            should_retain
        });
        for (key, messages, age) in stalled_pairs {
            let parts: Vec<&str> = key.split('|').collect();
            if parts.len() == 2 {
                let msg_list: Vec<u8> = (0..4)
                    .filter(|i| messages & (1 << i) != 0)
                    .map(|i| i + 1)
                    .collect();
                tracing::warn!(
                    bssid = parts[0],
                    client_mac = parts[1],
                    messages = ?msg_list,
                    age_secs = age.as_secs(),
                    "partial handshake stalled and expired"
                );
            }
        }
        self.last_alerts
            .retain(|_, last| now.saturating_duration_since(*last) <= ttl);
        if self.pinned_pairs.is_empty() {
            return;
        }
        self.pinned_pairs
            .retain(|key, _| self.states.contains_key(key));
        if self.pinned_pairs.is_empty() {
            if let Some(control) = capture_control {
                control.apply_filter("type mgt or type data".to_string());
                tracing::debug!("restored normal scan filter after last pinned pair expired");
            }
        }
    }

    /// Accumulates EAPOL key messages into a per-pair bitmask (bit N = message N+1);
    /// fires alert when all four bits are set (0x0f). Dedup window suppresses repeat alerts
    /// without clearing state. When export_dir is Some, spawns blocking tasks to write
    /// handshake bundles. Pins to channel on Message 1, exports partial on Message 2.
    pub fn observe(
        &mut self,
        frame: &mut WifiFrame,
        context: &AuditContext,
        export_dir: Option<&str>,
        capture_control: Option<&CaptureControl>,
        ttl: Duration,
    ) -> Option<HandshakeAlert> {
        let observation = eapol_key_observation(frame)?;
        let key = format!(
            "{}|{}",
            observation.bssid.to_ascii_lowercase(),
            observation.client_mac.to_ascii_lowercase()
        );
        let now = Instant::now();
        let msg_idx = (observation.message - 1) as usize;
        let (complete, should_export_partial) = {
            let state = self
                .states
                .entry(key.clone())
                .or_insert_with(HandshakeState::new);
            let was_messages = state.messages;

            if let Some(rc) = observation.replay_counter {
                if let Some(prev) = state.replay_counter {
                    if rc != prev {
                        *state = HandshakeState::new();
                        state.replay_counter = Some(rc);
                    }
                } else {
                    state.replay_counter = Some(rc);
                }
            }

            if msg_idx == 0 {
                if let Some(nonce) = observation.nonce {
                    state.anonce = Some(nonce);
                }
            } else if msg_idx == 1 {
                if let Some(nonce) = observation.nonce {
                    state.snonce = Some(nonce);
                }
            }

            state.last_seen = now;
            state.messages |= 1 << msg_idx;
            if state
                .frames
                .iter()
                .all(|f| f.message != observation.message)
            {
                state.frames.push(HandshakeFrame {
                    message: observation.message,
                    observed_at: ssl_proxy::time::rfc3339_from_utc(frame.observed_at),
                    raw_frame: frame.raw_frame.clone(),
                });
            }
            if state.pmkid.is_none() {
                state.pmkid = observation.pmkid.clone();
            }

            if msg_idx == 0 && was_messages == 0 {
                if let Some(channel) = frame.channel_number {
                    if let Some(control) = capture_control {
                        let filter = pinned_handshake_filter(channel);
                        control.apply_filter(filter);
                        self.pinned_pairs.insert(key.clone(), channel as u8);
                        tracing::debug!(
                            bssid = %observation.bssid,
                            client_mac = %observation.client_mac,
                            channel,
                            "pinned capture to channel for handshake"
                        );
                    }
                }
            }

            let should_export_partial = msg_idx == 1
                && (was_messages & 0x01) != 0
                && (was_messages & 0x02) == 0
                && !state.partial_exported;
            if should_export_partial {
                state.partial_exported = true;
            }

            (state.messages & 0x0f == 0x0f, should_export_partial)
        };
        if should_export_partial {
            if let Some(dir) = export_dir {
                let (frames, pmkid) = self
                    .states
                    .get(&key)
                    .map(|state| (state.frames.clone(), state.pmkid.clone()))
                    .unwrap_or_default();
                spawn_partial_handshake_export(
                    dir.to_string(),
                    context.clone(),
                    observation.bssid.clone(),
                    observation.client_mac.clone(),
                    frames,
                    pmkid,
                );
            }
        }

        if !complete {
            return None;
        }

        if let Some(last) = self.last_alerts.get_mut(&key) {
            if now.saturating_duration_since(*last) < ttl {
                *last = now;
                return None;
            }
        }

        self.pinned_pairs.remove(&key);
        if self.pinned_pairs.is_empty() {
            if let Some(control) = capture_control {
                control.apply_filter("type mgt or type data".to_string());
                tracing::debug!("restored normal scan filter after handshake completion");
            }
        }

        self.last_alerts.insert(key.clone(), now);
        let (frames, pmkid) = self
            .states
            .get(&key)
            .map(|state| (state.frames.clone(), state.pmkid.clone()))
            .unwrap_or_default();

        frame.handshake_captured = true;
        push_tag(&mut frame.tags, "handshake_captured");
        if let Some(dir) = export_dir {
            spawn_handshake_export(
                dir.to_string(),
                context.clone(),
                observation.bssid.clone(),
                observation.client_mac.clone(),
                frames.clone(),
                pmkid.clone(),
            );
        }
        Some(HandshakeAlert {
            schema_version: 1,
            observed_at: ssl_proxy::time::rfc3339_from_utc(frame.observed_at),
            sensor_id: context.sensor_id.clone(),
            location_id: context.location_id.clone(),
            interface: context.interface.clone(),
            bssid: observation.bssid,
            client_mac: observation.client_mac,
            signal_dbm: frame.signal_dbm,
            pmkid,
        })
    }
}

fn pinned_handshake_filter(_channel: u16) -> String {
    "(wlan[0] & 0x0c) == 0x08 and (wlan[0] & 0xf0) == 0x80 and (wlan[1] & 0x40) == 0".to_string()
}

fn spawn_handshake_export(
    dir: String,
    context: AuditContext,
    bssid: String,
    client_mac: String,
    frames: Vec<HandshakeFrame>,
    pmkid: Option<String>,
) {
    let export = move || {
        export_handshake_bundle(
            &dir,
            &context,
            &bssid,
            &client_mac,
            &frames,
            pmkid.as_deref(),
            false,
        );
    };
    if let Ok(handle) = tokio::runtime::Handle::try_current() {
        handle.spawn_blocking(export);
    } else {
        std::thread::spawn(export);
    }
}

#[cfg(test)]
mod tests {
    use super::pinned_handshake_filter;
    use pcap::{Capture, Linktype};

    #[test]
    fn pinned_handshake_filter_compiles_with_libbpf() {
        let filter = pinned_handshake_filter(6);
        let capture = Capture::dead(Linktype::IEEE802_11_RADIOTAP).unwrap();

        assert_eq!(
            filter,
            "(wlan[0] & 0x0c) == 0x08 and (wlan[0] & 0xf0) == 0x80 and (wlan[1] & 0x40) == 0"
        );
        assert!(!filter.contains("subtype 0x08"));
        capture.compile(&filter, true).unwrap();
    }
}

fn spawn_partial_handshake_export(
    dir: String,
    context: AuditContext,
    bssid: String,
    client_mac: String,
    frames: Vec<HandshakeFrame>,
    pmkid: Option<String>,
) {
    let export = move || {
        export_handshake_bundle(
            &dir,
            &context,
            &bssid,
            &client_mac,
            &frames,
            pmkid.as_deref(),
            true,
        );
    };
    if let Ok(handle) = tokio::runtime::Handle::try_current() {
        handle.spawn_blocking(export);
    } else {
        std::thread::spawn(export);
    }
}

fn export_handshake_bundle(
    dir: &str,
    context: &AuditContext,
    bssid: &str,
    client_mac: &str,
    frames: &[HandshakeFrame],
    pmkid: Option<&str>,
    partial: bool,
) {
    let path = if partial {
        Path::new(dir).join("handshakes").join("partial")
    } else {
        Path::new(dir).join("handshakes")
    };
    if let Err(error) = fs::create_dir_all(&path) {
        tracing::warn!(%error, export_dir = %path.display(), "failed to create handshake export directory");
        return;
    }
    let filename = format!(
        "{}_{}_{}.json",
        bssid.replace(':', ""),
        client_mac.replace(':', ""),
        Utc::now().timestamp_millis()
    );
    let event_type = if partial {
        "wireless_partial_handshake_bundle"
    } else {
        "wireless_handshake_bundle"
    };
    let payload = serde_json::json!({
        "schema_version": 1,
        "event_type": event_type,
        "observed_at": ssl_proxy::time::rfc3339_from_utc(Utc::now()),
        "sensor_id": context.sensor_id,
        "location_id": context.location_id,
        "interface": context.interface,
        "bssid": bssid,
        "client_mac": client_mac,
        "pmkid": pmkid,
        "frames": frames,
    });
    if let Err(error) = fs::write(path.join(filename), payload.to_string()) {
        tracing::warn!(%error, "failed to write handshake export bundle");
    }
}
