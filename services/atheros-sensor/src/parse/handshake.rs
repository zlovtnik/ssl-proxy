//! 4-way WPA2 handshake state machine with dedup and optional file export.
//!
//! HandshakeMonitor tracks per-(bssid, client_mac) state using a bitmask of the four EAPOL
//! key messages seen. A handshake is considered complete when all four bits are set (0x0f).
//! A 60-second dedup window (HANDSHAKE_DUP_WINDOW) prevents the same pair from generating
//! repeated alerts during retransmission storms; on suppression the state is reset so the
//! next genuine handshake can be captured. When ATH_SENSOR_EXPORT_HANDSHAKES is enabled,
//! the complete frame bundle (base64 raw frames + PMKID) is written as a JSON file to
//! SYNC_OUTBOX_DIR/handshakes/ via spawn_blocking, keeping the export off the async hot path.
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

use crate::model::{AuditContext, HandshakeAlert, WifiFrame};
use chrono::Utc;

use super::{eapol::eapol_key_observation, tags::push_tag};

const HANDSHAKE_DUP_WINDOW: Duration = Duration::from_secs(60);

#[derive(Default)]
pub struct HandshakeMonitor {
    states: HashMap<String, HandshakeState>,
    last_alerts: HashMap<String, Instant>,
}

#[derive(Clone, Debug)]
struct HandshakeState {
    messages: u8,
    frames: Vec<HandshakeFrame>,
    pmkid: Option<String>,
    last_seen: Instant,
}

#[derive(Clone, Debug, serde::Serialize)]
struct HandshakeFrame {
    message: u8,
    observed_at: String,
    raw_frame: Option<String>,
}

impl HandshakeState {
    fn new(now: Instant) -> Self {
        Self {
            messages: 0,
            frames: Vec::new(),
            pmkid: None,
            last_seen: now,
        }
    }
}

impl HandshakeMonitor {
    pub fn cleanup_expired(&mut self, ttl: Duration) {
        let now = Instant::now();
        self.states
            .retain(|_, state| now.saturating_duration_since(state.last_seen) <= ttl);
        self.last_alerts
            .retain(|_, last| now.saturating_duration_since(*last) <= ttl);
    }

    /// Accumulates EAPOL key messages into a per-pair bitmask (bit N = message N+1);
    /// fires alert when all four bits are set (0x0f). A 60-second dedup window suppresses
    /// repeat alerts; on suppression the state is reset. When export_dir is Some, spawns
    /// a blocking task to write the handshake bundle JSON to SYNC_OUTBOX_DIR/handshakes/.
    pub fn observe(
        &mut self,
        frame: &mut WifiFrame,
        context: &AuditContext,
        export_dir: Option<&str>,
    ) -> Option<HandshakeAlert> {
        let observation = eapol_key_observation(frame)?;
        let key = format!(
            "{}|{}",
            observation.bssid.to_ascii_lowercase(),
            observation.client_mac.to_ascii_lowercase()
        );
        let now = Instant::now();
        let complete = {
            let state = self
                .states
                .entry(key.clone())
                .or_insert_with(|| HandshakeState::new(now));
            state.last_seen = now;
            state.messages |= 1 << (observation.message - 1);
            if state
                .frames
                .iter()
                .all(|frame| frame.message != observation.message)
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
            state.messages & 0x0f == 0x0f
        };
        if !complete {
            return None;
        }

        if self
            .last_alerts
            .get(&key)
            .is_some_and(|last| now.saturating_duration_since(*last) < HANDSHAKE_DUP_WINDOW)
        {
            if let Some(state) = self.states.get_mut(&key) {
                state.messages = 0;
                state.frames.clear();
                state.pmkid = None;
                state.last_seen = now;
            }
            return None;
        }

        self.last_alerts.insert(key.clone(), now);
        let (frames, pmkid) = self
            .states
            .get(&key)
            .map(|state| (state.frames.clone(), state.pmkid.clone()))
            .unwrap_or_default();
        if let Some(state) = self.states.get_mut(&key) {
            state.messages = 0;
            state.frames.clear();
            state.pmkid = None;
            state.last_seen = now;
        }
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
) {
    let path = Path::new(dir).join("handshakes");
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
    let payload = serde_json::json!({
        "schema_version": 1,
        "event_type": "wireless_handshake_bundle",
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
