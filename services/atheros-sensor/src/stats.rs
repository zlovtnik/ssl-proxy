//! Cumulative counters since startup, shared via Arc<Mutex<>>, exposed both on heartbeat log and the /metrics endpoint.

use tracing::info;

use crate::config::AppConfig;

/// Cumulative capture statistics; audit_window_drops counts packets dropped before decode, pipeline_errors counts post-decode failures.
#[derive(Clone, Default)]
pub(crate) struct CaptureStats {
    pub(crate) packets_seen: u64,
    pub(crate) decoded_frames: u64,
    pub(crate) unsupported_frames: u64,
    /// Packets dropped before decode due to audit window overflow.
    pub(crate) audit_window_drops: u64,
    pub(crate) capture_errors: u64,
    /// Post-decode failures in the processing pipeline.
    pub(crate) pipeline_errors: u64,
    pub(crate) mac_lookup_failures: u64,
    /// Number of successful channel hops since process startup.
    pub(crate) channel_hop_count: u64,
}

impl CaptureStats {
    /// Logs all counters at info level; called on every heartbeat tick.
    pub(crate) fn log(&self, device: &str, config: &AppConfig) {
        info!(
            interface = %device,
            channel = config.channel,
            bpf = %config.bpf,
            packets_seen = self.packets_seen,
            decoded_frames = self.decoded_frames,
            unsupported_frames = self.unsupported_frames,
            audit_window_drops = self.audit_window_drops,
            capture_errors = self.capture_errors,
            pipeline_errors = self.pipeline_errors,
            mac_lookup_failures = self.mac_lookup_failures,
            channel_hop_count = self.channel_hop_count,
            "atheros sensor capture heartbeat"
        );
    }
}

/// Returned from process_packet; DecodedFrame for successfully decoded frames, UnsupportedFrame for frames that cannot be decoded.
pub(crate) enum PipelineOutcome {
    DecodedFrame,
    UnsupportedFrame,
}
