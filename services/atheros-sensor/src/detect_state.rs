//! Per-frame stateful detectors for wireless threat detection.
//!
//! Six detectors run against every decoded frame, all held in PipelineState:
//! ClientInventory tracks probe requests, channel history, and excessive-probing flags per MAC;
//! SignalTracker fires a signal_anomaly tag when a BSSID's signal jumps beyond the configured
//! dBm delta, indicating a possible AP impersonation or physical movement event;
//! RogueApTracker checks beacons and probe responses for open authorized SSIDs, SSID typosquats
//! (edit distance <= 2), BSSID-to-SSID mapping changes, and multi-channel conflicts;
//! DeauthFloodTracker counts deauthentication and disassociation frames per BSSID in a sliding
//! window and fires an alert when the threshold is exceeded, with a cooldown to suppress repeats;
//! AuthorizedNetworkCache holds the Redpanda-backed list of known SSIDs/BSSIDs and is
//! invalidated by the Redpanda generation counter when the console pushes a config change;
//! evil-twin detection runs through IdentityCache (in parse/) which correlates adjacent MACs
//! and session keys to surface impersonation across frames.
//!
//! # Type notes
//!
//! [`ClientInventory`] / [`ClientProfile`]: per-MAC observation state; `excessive_probing`
//! latches to `true` once a client sends >= 20 probe requests within any 60-second window
//! and is never reset to `false` within the same session (inventory flush required).
//!
//! [`RogueApTracker`]: fires [`RogueApAlert`] for beacons/probe-responses that match rogue
//! heuristics; the per-key `recent_alerts` map enforces a 60-second cooldown so a single
//! misbehaving AP cannot produce an unbounded alert storm.
//!
//! [`DeauthFloodTracker`]: maintains two independent clocks per BSSID - a sliding
//! `chrono::DateTime` window that counts frames within `window_secs`, and a separate
//! `Instant`-based cooldown that suppresses repeat alerts for `cooldown_secs` after firing.
//!
//! [`AuthorizedNetworkCache`]: `invalidate()` sets `loaded_at` to `None` without touching
//! `entries`; the stale data remains readable until the next `refresh_if_needed` call
//! successfully reloads from the coordinator.

#[cfg(test)]
#[path = "detect_state_tests.rs"]
mod tests;

include!("detect_state_sections/client_inventory.rs");
include!("detect_state_sections/rogue_deauth.rs");
include!("detect_state_sections/authorization.rs");
include!("detect_state_sections/sequences.rs");
include!("detect_state_sections/pmf.rs");
