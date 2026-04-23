use std::{
    collections::HashMap,
    time::{Duration, Instant},
};

use crate::model::{AuditContext, HandshakeAlert, WifiFrame};

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
    last_seen: Instant,
}

impl HandshakeState {
    fn new(now: Instant) -> Self {
        Self {
            messages: 0,
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
        if let Some(state) = self.states.get_mut(&key) {
            state.messages = 0;
            state.last_seen = now;
        }
        frame.handshake_captured = true;
        push_tag(&mut frame.tags, "handshake_captured");
        Some(HandshakeAlert {
            observed_at: frame.observed_at.to_rfc3339(),
            sensor_id: context.sensor_id.clone(),
            location_id: context.location_id.clone(),
            interface: context.interface.clone(),
            bssid: observation.bssid,
            client_mac: observation.client_mac,
            signal_dbm: frame.signal_dbm,
        })
    }
}
