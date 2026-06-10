//! Cumulative counters since startup, shared via atomics, exposed both on heartbeat log and the
//! /metrics endpoint.

use std::sync::atomic::{AtomicU64, Ordering};

use tracing::info;

use crate::config::AppConfig;

const NO_BANDWIDTH_WINDOW_LAG_MS: u64 = u64::MAX;

/// Cumulative capture statistics; audit_window_drops counts packets dropped before decode, pipeline_errors counts post-decode failures.
pub(crate) struct CaptureStats {
    packets_seen: AtomicU64,
    decoded_frames: AtomicU64,
    /// Expected unsupported control frames.
    unsupported_frames: AtomicU64,
    /// Malformed frames that failed structural 802.11 parsing.
    malformed_frames: AtomicU64,
    /// Packets dropped before decode due to audit window overflow.
    audit_window_drops: AtomicU64,
    capture_errors: AtomicU64,
    /// Post-decode failures in the processing pipeline.
    pipeline_errors: AtomicU64,
    mac_lookup_failures: AtomicU64,
    /// Number of successful channel hops since process startup.
    channel_hop_count: AtomicU64,
    /// Cumulative milliseconds of (now - observed_at) for decoded frames, used to compute
    /// average publish lag. Reset to 0 after each heartbeat log.
    lag_total_ms: AtomicU64,
    /// Number of decoded frames contributing to lag_total_ms. Reset to 0 after each heartbeat log.
    lag_count: AtomicU64,
    /// Median (publish_time - window_end) in milliseconds across the last bandwidth flush cycle.
    /// Gauge, replaced each flush. None when no bandwidth events were flushed.
    bandwidth_window_lag_ms: AtomicU64,
    /// Snapshot of the memory backlog length at the last bandwidth flush. Gauge, updated
    /// each flush cycle. Exposed as `atheros_memory_backlog_len`.
    memory_backlog_len: AtomicU64,
    /// Current probe accumulator length, updated when probe state changes or flushes run.
    probe_accumulator_len: AtomicU64,
}

/// Immutable point-in-time view of [`CaptureStats`] for metrics rendering and heartbeat payloads.
#[derive(Clone, Default)]
pub(crate) struct CaptureStatsSnapshot {
    pub(crate) packets_seen: u64,
    pub(crate) decoded_frames: u64,
    pub(crate) unsupported_frames: u64,
    pub(crate) malformed_frames: u64,
    pub(crate) audit_window_drops: u64,
    pub(crate) capture_errors: u64,
    pub(crate) pipeline_errors: u64,
    pub(crate) mac_lookup_failures: u64,
    pub(crate) channel_hop_count: u64,
    pub(crate) lag_total_ms: u64,
    pub(crate) lag_count: u64,
    pub(crate) bandwidth_window_lag_ms: Option<u64>,
    pub(crate) memory_backlog_len: u64,
    pub(crate) probe_accumulator_len: u64,
}

impl CaptureStats {
    pub(crate) fn increment_packets_seen(&self) {
        self.packets_seen.fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn increment_decoded_frames(&self) {
        self.decoded_frames.fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn increment_unsupported_frames(&self) {
        self.unsupported_frames.fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn increment_malformed_frames(&self) {
        self.malformed_frames.fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn increment_audit_window_drops(&self) {
        self.audit_window_drops.fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn increment_capture_errors(&self) {
        self.capture_errors.fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn increment_pipeline_errors(&self) {
        self.pipeline_errors.fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn increment_mac_lookup_failures(&self) {
        self.mac_lookup_failures.fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn increment_channel_hop_count(&self) {
        self.channel_hop_count.fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn observe_publish_lag_ms(&self, lag_ms: u64) {
        let _ = self
            .lag_total_ms
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |current| {
                Some(current.saturating_add(lag_ms))
            });
        self.lag_count.fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn set_bandwidth_window_lag_ms(&self, lag_ms: Option<u64>) {
        self.bandwidth_window_lag_ms.store(
            lag_ms.unwrap_or(NO_BANDWIDTH_WINDOW_LAG_MS),
            Ordering::Relaxed,
        );
    }

    pub(crate) fn set_memory_backlog_len(&self, len: usize) {
        self.memory_backlog_len.store(len as u64, Ordering::Relaxed);
    }

    pub(crate) fn set_probe_accumulator_len(&self, len: usize) {
        self.probe_accumulator_len
            .store(len as u64, Ordering::Relaxed);
    }

    pub(crate) fn snapshot(&self) -> CaptureStatsSnapshot {
        let bandwidth_window_lag_ms = match self.bandwidth_window_lag_ms.load(Ordering::Relaxed) {
            NO_BANDWIDTH_WINDOW_LAG_MS => None,
            ms => Some(ms),
        };

        CaptureStatsSnapshot {
            packets_seen: self.packets_seen.load(Ordering::Relaxed),
            decoded_frames: self.decoded_frames.load(Ordering::Relaxed),
            unsupported_frames: self.unsupported_frames.load(Ordering::Relaxed),
            malformed_frames: self.malformed_frames.load(Ordering::Relaxed),
            audit_window_drops: self.audit_window_drops.load(Ordering::Relaxed),
            capture_errors: self.capture_errors.load(Ordering::Relaxed),
            pipeline_errors: self.pipeline_errors.load(Ordering::Relaxed),
            mac_lookup_failures: self.mac_lookup_failures.load(Ordering::Relaxed),
            channel_hop_count: self.channel_hop_count.load(Ordering::Relaxed),
            lag_total_ms: self.lag_total_ms.load(Ordering::Relaxed),
            lag_count: self.lag_count.load(Ordering::Relaxed),
            bandwidth_window_lag_ms,
            memory_backlog_len: self.memory_backlog_len.load(Ordering::Relaxed),
            probe_accumulator_len: self.probe_accumulator_len.load(Ordering::Relaxed),
        }
    }

    /// Logs all counters at info level; called on every heartbeat tick.
    /// Computes publish_lag_ms as the average (Utc::now() - observed_at) across decoded frames
    /// since the last heartbeat.
    pub(crate) fn log(&self, device: &str, config: &AppConfig) -> CaptureStatsSnapshot {
        let mut snapshot = self.snapshot();
        snapshot.lag_total_ms = self.lag_total_ms.swap(0, Ordering::Relaxed);
        snapshot.lag_count = self.lag_count.swap(0, Ordering::Relaxed);
        let publish_lag_ms = snapshot.lag_total_ms / snapshot.lag_count.max(1);
        info!(
            interface = %device,
            channel = config.channel,
            bpf = %config.bpf,
            packets_seen = snapshot.packets_seen,
            decoded_frames = snapshot.decoded_frames,
            unsupported_frames = snapshot.unsupported_frames,
            malformed_frames = snapshot.malformed_frames,
            audit_window_drops = snapshot.audit_window_drops,
            capture_errors = snapshot.capture_errors,
            pipeline_errors = snapshot.pipeline_errors,
            mac_lookup_failures = snapshot.mac_lookup_failures,
            channel_hop_count = snapshot.channel_hop_count,
            memory_backlog_len = snapshot.memory_backlog_len,
            probe_accumulator_len = snapshot.probe_accumulator_len,
            publish_lag_ms = publish_lag_ms,
            "atheros sensor capture heartbeat"
        );
        snapshot
    }
}

impl Default for CaptureStats {
    fn default() -> Self {
        Self {
            packets_seen: AtomicU64::new(0),
            decoded_frames: AtomicU64::new(0),
            unsupported_frames: AtomicU64::new(0),
            malformed_frames: AtomicU64::new(0),
            audit_window_drops: AtomicU64::new(0),
            capture_errors: AtomicU64::new(0),
            pipeline_errors: AtomicU64::new(0),
            mac_lookup_failures: AtomicU64::new(0),
            channel_hop_count: AtomicU64::new(0),
            lag_total_ms: AtomicU64::new(0),
            lag_count: AtomicU64::new(0),
            bandwidth_window_lag_ms: AtomicU64::new(NO_BANDWIDTH_WINDOW_LAG_MS),
            memory_backlog_len: AtomicU64::new(0),
            probe_accumulator_len: AtomicU64::new(0),
        }
    }
}

/// Returned from process_packet; DecodedFrame for successfully decoded frames, UnsupportedFrame for frames that cannot be decoded.
pub(crate) enum PipelineOutcome {
    DecodedFrame,
    UnsupportedFrame,
}
