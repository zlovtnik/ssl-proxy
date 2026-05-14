use super::proxy_types::{BlockedEventInsert, ProxyEventInsert};
use super::wireless_types::{
    WirelessAuditFrameInsert, WirelessBandwidthInsert, WirelessClientInventoryInsert,
    WirelessDeauthFloodInsert, WirelessPmfAttackInsert, WirelessProbeRequestInsert,
    WirelessRogueApInsert, WirelessSignalAnomalyInsert,
};

pub trait ProxyEventSink {
    fn insert_proxy_events(
        &mut self,
        batch_id: &str,
        rows: &[ProxyEventInsert],
        blocked_rows: &[BlockedEventInsert],
    ) -> Result<u64, String>;

    fn insert_wireless_audit_frames(
        &mut self,
        batch_id: &str,
        rows: &[WirelessAuditFrameInsert],
    ) -> Result<u64, String>;

    fn insert_wireless_bandwidth(
        &mut self,
        batch_id: &str,
        rows: &[WirelessBandwidthInsert],
    ) -> Result<u64, String>;

    fn insert_wireless_rogue_ap(
        &mut self,
        batch_id: &str,
        rows: &[WirelessRogueApInsert],
    ) -> Result<u64, String>;

    fn insert_wireless_deauth_flood(
        &mut self,
        batch_id: &str,
        rows: &[WirelessDeauthFloodInsert],
    ) -> Result<u64, String>;

    fn insert_wireless_signal_anomaly(
        &mut self,
        batch_id: &str,
        rows: &[WirelessSignalAnomalyInsert],
    ) -> Result<u64, String>;

    fn insert_wireless_pmf_attack(
        &mut self,
        batch_id: &str,
        rows: &[WirelessPmfAttackInsert],
    ) -> Result<u64, String>;

    fn insert_wireless_client_inventory(
        &mut self,
        batch_id: &str,
        rows: &[WirelessClientInventoryInsert],
    ) -> Result<u64, String>;

    fn insert_wireless_probe_requests(
        &mut self,
        batch_id: &str,
        rows: &[WirelessProbeRequestInsert],
    ) -> Result<u64, String>;
}
