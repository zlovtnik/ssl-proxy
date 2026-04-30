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
            export_handshake_bundle(
                dir,
                context,
                &observation.bssid,
                &observation.client_mac,
                &frames,
                pmkid.as_deref(),
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
