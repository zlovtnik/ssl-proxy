//! Sliding-window traffic accumulator for bandwidth monitoring.
//!
//! Aggregates protected WiFi data frames into time-bucketed summaries keyed by
//! (sensor, location, interface, channel, source_mac, destination_bssid, ssid).
//! EXTERNAL_BANDWIDTH_THRESHOLD_BYTES triggers alerts when external BSSID traffic
//! exceeds 500 MB per window, indicating potential rogue AP or data exfiltration.
//!
//! [`TrafficBucket`]: accumulates frame counters for the current window; a
//! wall-clock [`Instant`] drives the flush decision, while the frame-level
//! `observed_at` timestamp is used only for window attribution in the emitted
//! event. This decouples flush timing from potentially-skewed or replayed frame
//! timestamps.
//!
//! [`WirelessBandwidthEvent`]: the flushed summary for one (source_mac, destination_bssid)
//! pair; `external_bssid` is true when the BSSID is not in the authorized network list, and
//! `threshold_exceeded` is the actionable field that signals a potential exfiltration event.
//! `wall_clock_delta_ms` reports how far behind the frame timestamp is from wall clock,
//! giving operators a per-window health signal. `window_is_partial` is true when the flush
//! was triggered by the periodic timer rather than by an incoming frame crossing the boundary.

#[cfg(test)]
#[path = "bandwidth_tests.rs"]
mod tests;

include!("bandwidth_sections/bucket.rs");
include!("bandwidth_sections/metrics.rs");
