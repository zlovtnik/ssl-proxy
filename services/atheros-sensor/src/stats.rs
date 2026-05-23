//! Cumulative counters since startup, shared via Arc<Mutex<>>, exposed both on heartbeat log and the /metrics endpoint.

use tracing::info;

use crate::config::AppConfig;

/// Cumulative capture statistics; audit_window_drops counts packets dropped before decode, pipeline_errors counts post-decode failures.
#[derive(Clone, Default)]
pub(crate) struct CaptureStats {
    pub(crate) packets_seen: u64,
    pub(crate) decoded_frames: u64,
    /// Expected unsupported control frames.
    pub(crate) unsupported_frames: u64,
    /// Malformed frames that failed structural 802.11 parsing.
    pub(crate) malformed_frames: u64,
    /// Packets dropped before decode due to audit window overflow.
    pub(crate) audit_window_drops: u64,
    pub(crate) capture_errors: u64,
    /// Post-decode failures in the processing pipeline.
    pub(crate) pipeline_errors: u64,
    pub(crate) mac_lookup_failures: u64,
    /// Number of successful channel hops since process startup.
    pub(crate) channel_hop_count: u64,
    /// Cumulative milliseconds of (now - observed_at) for decoded frames, used to compute
    /// average publish lag. Reset to 0 after each heartbeat log.
    pub(crate) lag_total_ms: u64,
    /// Number of decoded frames contributing to lag_total_ms. Reset to 0 after each heartbeat log.
    pub(crate) lag_count: u64,
    /// Median (publish_time - window_end) in milliseconds across the last bandwidth flush cycle.
    /// Gauge, replaced each flush. None when no bandwidth events were flushed.
    pub(crate) bandwidth_window_lag_ms: Option<u64>,
    /// Snapshot of the memory backlog length at the last bandwidth flush. Gauge, updated
    /// each flush cycle. Exposed as `atheros_memory_backlog_len`.
    pub(crate) memory_backlog_len: usize,
    /// Current probe accumulator length, updated when probe state changes or flushes run.
    pub(crate) probe_accumulator_len: usize,
}

impl CaptureStats {
    /// Logs all counters at info level; called on every heartbeat tick.
    /// Computes publish_lag_ms as the average (Utc::now() - observed_at) across decoded frames
    /// since the last heartbeat.
    pub(crate) fn log(&mut self, device: &str, config: &AppConfig) {
        let publish_lag_ms = self.lag_total_ms / self.lag_count.max(1);
        info!(
            interface = %device,
            channel = config.channel,
            bpf = %config.bpf,
            packets_seen = self.packets_seen,
            decoded_frames = self.decoded_frames,
            unsupported_frames = self.unsupported_frames,
            malformed_frames = self.malformed_frames,
            audit_window_drops = self.audit_window_drops,
            capture_errors = self.capture_errors,
            pipeline_errors = self.pipeline_errors,
            mac_lookup_failures = self.mac_lookup_failures,
            channel_hop_count = self.channel_hop_count,
            memory_backlog_len = self.memory_backlog_len,
            probe_accumulator_len = self.probe_accumulator_len,
            publish_lag_ms = publish_lag_ms,
            "atheros sensor capture heartbeat"
        );
        self.lag_total_ms = 0;
        self.lag_count = 0;
    }
}

/// Returned from process_packet; DecodedFrame for successfully decoded frames, UnsupportedFrame for frames that cannot be decoded.
pub(crate) enum PipelineOutcome {
    DecodedFrame,
    UnsupportedFrame,
}
