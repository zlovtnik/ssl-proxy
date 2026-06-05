//! Redpanda topic names emitted by the wireless sensor.

pub const CLIENT_INVENTORY_TOPIC: &str = "wireless.client.inventory";
pub const ROGUE_AP_TOPIC: &str = "wireless.alert.rogue_ap";
pub const DEAUTH_FLOOD_TOPIC: &str = "wireless.alert.deauth_flood";
pub const ATTACK_SEQUENCE_TOPIC: &str = "wireless.alert.attack_sequence";
pub const SEQUENCE_ALERT_TOPIC: &str = "wireless.alert.sequence";
pub const SIGNAL_ANOMALY_TOPIC: &str = "wireless.alert.signal_anomaly";
pub const PMF_ATTACK_TOPIC: &str = "wireless.alert.pmf_attack";
pub const SENSOR_HEARTBEAT_TOPIC: &str = "wireless.sensor.heartbeat";
