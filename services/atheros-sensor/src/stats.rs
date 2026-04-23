use tracing::info;

use crate::config::AppConfig;

#[derive(Default)]
pub(crate) struct CaptureStats {
    pub(crate) packets_seen: u64,
    pub(crate) decoded_frames: u64,
    pub(crate) unsupported_frames: u64,
    pub(crate) audit_window_drops: u64,
    pub(crate) capture_errors: u64,
    pub(crate) pipeline_errors: u64,
}

impl CaptureStats {
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
            "atheros sensor capture heartbeat"
        );
    }
}

pub(crate) enum PipelineOutcome {
    DecodedFrame,
    UnsupportedFrame,
}
