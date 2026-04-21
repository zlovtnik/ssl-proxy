//! Flow-timing analysis and mitigation signaling for forensic sentry hooks.
//!
//! This module keeps packet-timing analysis out of the hot-path policy code.
//! Tunnel handlers can feed chunk observations into the shared state and react
//! only when a sustained, low-jitter pattern crosses a clear threshold.

use dashmap::DashMap;
use sha2::{Digest, Sha256};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::sync::mpsc;
use tracing::{debug, warn};

use crate::state::SharedState;

const FLOW_WINDOW: Duration = Duration::from_secs(300);
const ALERT_COOLDOWN: Duration = Duration::from_secs(60);
const MIN_PACKETS_FOR_ALERT: u64 = 12;
const MIN_LOW_JITTER_STREAK: u32 = 8;
const MIN_REGULARITY_SCORE: f64 = 0.85;
const MIN_UPSTREAM_BYTES_FOR_ALERT: u64 = 32 * 1024;
const MONITOR_INTERFACE_TYPE: u32 = 803;

pub type SharedForensicState = Arc<ForensicState>;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PacketDirection {
    Upstream,
    Downstream,
}

impl PacketDirection {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Upstream => "upstream",
            Self::Downstream => "downstream",
        }
    }
}

#[derive(Clone, Debug)]
pub struct ForensicFinding {
    pub peer_hash: String,
    pub host: String,
    pub category: &'static str,
    pub direction: PacketDirection,
    pub packet_count: u64,
    pub bytes_up: u64,
    pub bytes_down: u64,
    pub iat_ema_ms: Option<u64>,
    pub jitter_ema_ms: Option<u64>,
    pub low_jitter_streak: u32,
    pub regularity_score: f64,
    pub ja3_lite: Option<String>,
    pub reason: &'static str,
}

#[derive(Clone, Debug)]
pub enum HardwareCmd {
    ContainFlow {
        peer_hash: String,
        host: String,
        reason: &'static str,
    },
}

struct FlowState {
    peer_hash: String,
    host: String,
    category: &'static str,
    first_seen: Instant,
    last_seen: Instant,
    packet_count: u64,
    bytes_up: u64,
    bytes_down: u64,
    iat_ema_ms: Option<u64>,
    jitter_ema_ms: Option<u64>,
    low_jitter_streak: u32,
    last_alert_at: Option<Instant>,
    ja3_lite: Option<String>,
}

impl FlowState {
    fn new(peer_hash: String, host: &str, category: &'static str) -> Self {
        let now = Instant::now();
        Self {
            peer_hash,
            host: host.to_string(),
            category,
            first_seen: now,
            last_seen: now,
            packet_count: 0,
            bytes_up: 0,
            bytes_down: 0,
            iat_ema_ms: None,
            jitter_ema_ms: None,
            low_jitter_streak: 0,
            last_alert_at: None,
            ja3_lite: None,
        }
    }

    fn reset(&mut self, category: &'static str) {
        let now = Instant::now();
        self.category = category;
        self.first_seen = now;
        self.last_seen = now;
        self.packet_count = 0;
        self.bytes_up = 0;
        self.bytes_down = 0;
        self.iat_ema_ms = None;
        self.jitter_ema_ms = None;
        self.low_jitter_streak = 0;
        self.last_alert_at = None;
    }

    fn regularity_score(&self) -> Option<f64> {
        let iat = self.iat_ema_ms?;
        if iat == 0 {
            return None;
        }
        let jitter = self.jitter_ema_ms.unwrap_or(iat);
        Some(1.0 - (jitter.min(iat) as f64 / iat as f64))
    }

    fn observe(
        &mut self,
        direction: PacketDirection,
        bytes: usize,
        category: &'static str,
        ja3_lite: Option<&str>,
    ) {
        let now = Instant::now();
        if now.duration_since(self.last_seen) > FLOW_WINDOW {
            self.reset(category);
        }

        let iat_ms = now.duration_since(self.last_seen).as_millis() as u64;
        self.last_seen = now;
        self.category = category;
        self.packet_count = self.packet_count.saturating_add(1);
        if let Some(ja3_lite) = ja3_lite {
            self.ja3_lite = Some(ja3_lite.to_string());
        }

        match direction {
            PacketDirection::Upstream => {
                self.bytes_up = self.bytes_up.saturating_add(bytes as u64);
            }
            PacketDirection::Downstream => {
                self.bytes_down = self.bytes_down.saturating_add(bytes as u64);
            }
        }

        if self.packet_count == 1 {
            return;
        }

        self.iat_ema_ms = Some(match self.iat_ema_ms {
            Some(previous) => weighted_ema(previous, iat_ms, 4),
            None => iat_ms,
        });
        let baseline = self.iat_ema_ms.unwrap_or(iat_ms);
        let delta = baseline.abs_diff(iat_ms);
        self.jitter_ema_ms = Some(match self.jitter_ema_ms {
            Some(previous) => weighted_ema(previous, delta, 4),
            None => delta,
        });

        let low_jitter_cutoff = (baseline / 5).max(5);
        if delta <= low_jitter_cutoff {
            self.low_jitter_streak = self.low_jitter_streak.saturating_add(1);
        } else {
            self.low_jitter_streak = 0;
        }
    }

    fn finding(&mut self, direction: PacketDirection) -> Option<ForensicFinding> {
        let regularity_score = self.regularity_score()?;
        if self.packet_count < MIN_PACKETS_FOR_ALERT
            || self.low_jitter_streak < MIN_LOW_JITTER_STREAK
            || regularity_score < MIN_REGULARITY_SCORE
            || self.bytes_up < MIN_UPSTREAM_BYTES_FOR_ALERT
        {
            return None;
        }

        if self
            .last_alert_at
            .map(|at| at.elapsed() < ALERT_COOLDOWN)
            .unwrap_or(false)
        {
            return None;
        }

        self.last_alert_at = Some(Instant::now());
        Some(ForensicFinding {
            peer_hash: self.peer_hash.clone(),
            host: self.host.clone(),
            category: self.category,
            direction,
            packet_count: self.packet_count,
            bytes_up: self.bytes_up,
            bytes_down: self.bytes_down,
            iat_ema_ms: self.iat_ema_ms,
            jitter_ema_ms: self.jitter_ema_ms,
            low_jitter_streak: self.low_jitter_streak,
            regularity_score,
            ja3_lite: self.ja3_lite.clone(),
            reason: "mechanical_low_jitter_upload",
        })
    }
}

pub struct ForensicState {
    enabled: bool,
    flows: DashMap<String, FlowState>,
    hardware_tx: Mutex<Option<mpsc::Sender<HardwareCmd>>>,
}

impl ForensicState {
    pub fn new(enabled: bool) -> SharedForensicState {
        Arc::new(Self {
            enabled,
            flows: DashMap::new(),
            hardware_tx: Mutex::new(None),
        })
    }

    pub fn enabled(&self) -> bool {
        self.enabled
    }

    pub fn install_hardware_sender(&self, tx: mpsc::Sender<HardwareCmd>) {
        if let Ok(mut guard) = self.hardware_tx.lock() {
            *guard = Some(tx);
        }
    }

    pub fn observe_chunk(
        &self,
        host: &str,
        category: &'static str,
        peer_ip: Option<&str>,
        wg_pubkey: Option<&str>,
        direction: PacketDirection,
        bytes: usize,
        ja3_lite: Option<&str>,
    ) -> Option<ForensicFinding> {
        if !self.enabled || bytes == 0 || host.is_empty() {
            return None;
        }

        let peer_hash = fingerprint_identity(peer_ip, wg_pubkey);
        let flow_key = format!("{peer_hash}|{host}");

        let mut state = self
            .flows
            .entry(flow_key)
            .or_insert_with(|| FlowState::new(peer_hash, host, category));
        state.observe(direction, bytes, category, ja3_lite);
        state.finding(direction)
    }

    pub fn queue_hardware_command(&self, finding: &ForensicFinding) {
        let tx = self
            .hardware_tx
            .lock()
            .ok()
            .and_then(|guard| guard.as_ref().cloned());
        let Some(tx) = tx else {
            return;
        };

        if let Err(error) = tx.try_send(HardwareCmd::ContainFlow {
            peer_hash: finding.peer_hash.clone(),
            host: finding.host.clone(),
            reason: finding.reason,
        }) {
            debug!(%error, host = %finding.host, "forensic hardware queue unavailable");
        }
    }

    pub fn evict_stale_flows(&self) {
        let now = Instant::now();
        self.flows
            .retain(|_, flow| now.duration_since(flow.last_seen) < FLOW_WINDOW);
    }
}

pub fn spawn_hardware_worker(state: SharedState) {
    if !state.config.proxy.forensic_sentry_enabled {
        return;
    }

    let Some(interface) = state.config.proxy.forensic_monitor_interface.clone() else {
        warn!("FORENSIC_SENTRY_ENABLED=true but FORENSIC_MONITOR_INTERFACE is unset; mitigation worker stays disabled");
        return;
    };

    let (tx, mut rx) = mpsc::channel(64);
    state.forensic.install_hardware_sender(tx);

    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(Duration::from_secs(60));
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

        loop {
            tokio::select! {
                _ = ticker.tick() => {
                    state.forensic.evict_stale_flows();
                    if let Err(error) = verify_monitor_interface(&interface) {
                        warn!(interface = %interface, %error, "forensic monitor interface verification failed");
                    }
                }
                command = rx.recv() => {
                    let Some(command) = command else {
                        break;
                    };
                    if let Err(error) = handle_hardware_command(&interface, command) {
                        warn!(interface = %interface, %error, "forensic containment command failed");
                    }
                }
            }
        }
    });
}

fn handle_hardware_command(interface: &str, command: HardwareCmd) -> Result<(), String> {
    verify_monitor_interface(interface)?;
    match command {
        HardwareCmd::ContainFlow {
            peer_hash,
            host,
            reason,
        } => {
            warn!(
                interface = %interface,
                %peer_hash,
                %host,
                %reason,
                "forensic containment requested; raw frame injection remains an operator-owned follow-up"
            );
            Ok(())
        }
    }
}

fn verify_monitor_interface(interface: &str) -> Result<(), String> {
    nix::net::if_::if_nametoindex(interface)
        .map_err(|error| format!("interface lookup failed: {error}"))?;

    let type_path = format!("/sys/class/net/{interface}/type");
    let link_type = std::fs::read_to_string(&type_path)
        .map_err(|error| format!("failed to read {type_path}: {error}"))?;
    let link_type = link_type
        .trim()
        .parse::<u32>()
        .map_err(|error| format!("invalid interface type: {error}"))?;

    if link_type != MONITOR_INTERFACE_TYPE {
        return Err(format!(
            "expected monitor interface type {MONITOR_INTERFACE_TYPE}, found {link_type}"
        ));
    }

    Ok(())
}

fn fingerprint_identity(peer_ip: Option<&str>, wg_pubkey: Option<&str>) -> String {
    let raw = wg_pubkey
        .or(peer_ip)
        .filter(|value| !value.is_empty())
        .unwrap_or("anonymous");
    let digest = Sha256::digest(raw.as_bytes());
    let mut out = String::with_capacity(16);
    for byte in &digest[..8] {
        use std::fmt::Write;
        let _ = write!(&mut out, "{byte:02x}");
    }
    out
}

fn weighted_ema(previous: u64, current: u64, weight: u64) -> u64 {
    if weight <= 1 {
        return current;
    }
    ((previous * (weight - 1)) + current) / weight
}

#[cfg(test)]
mod tests {
    use super::{fingerprint_identity, ForensicState, PacketDirection};
    use std::time::{Duration, Instant};

    #[test]
    fn flow_alerts_only_after_sustained_low_jitter_upload() {
        let state = ForensicState::new(true);
        let peer_hash = fingerprint_identity(Some("10.0.0.2"), None);

        assert!(state
            .observe_chunk(
                "example.com",
                "analytics",
                Some("10.0.0.2"),
                None,
                PacketDirection::Upstream,
                4096,
                Some("771,1-2,0,29,0"),
            )
            .is_none());

        {
            let key = format!("{peer_hash}|example.com");
            let mut flow = state.flows.get_mut(&key).unwrap();
            flow.packet_count = 20;
            flow.bytes_up = 64 * 1024;
            flow.bytes_down = 1024;
            flow.iat_ema_ms = Some(100);
            flow.jitter_ema_ms = Some(4);
            flow.low_jitter_streak = 12;
            flow.last_seen = Instant::now() - Duration::from_millis(100);
        }

        let finding = state.observe_chunk(
            "example.com",
            "analytics",
            Some("10.0.0.2"),
            None,
            PacketDirection::Upstream,
            4096,
            Some("771,1-2,0,29,0"),
        );

        let finding = finding.expect("expected a sustained low-jitter finding");
        assert_eq!(finding.reason, "mechanical_low_jitter_upload");
        assert!(finding.regularity_score >= 0.85);
        assert_eq!(finding.peer_hash, peer_hash);
    }

    #[test]
    fn disabled_state_never_alerts() {
        let state = ForensicState::new(false);
        assert!(state
            .observe_chunk(
                "example.com",
                "analytics",
                Some("10.0.0.2"),
                None,
                PacketDirection::Upstream,
                4096,
                None,
            )
            .is_none());
    }
}
