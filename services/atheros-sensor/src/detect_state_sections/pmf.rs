impl PmfAttackTracker {
    pub fn observe(&mut self, entry: &AuditEntry, tags: &mut Vec<String>) {
        let observed = parse_observed_at(&entry.observed_at).unwrap_or_else(Utc::now);

        // Learn PMF state from beacons and probe responses
        if matches!(entry.frame_subtype.as_str(), "beacon" | "probe_response") {
            if let Some(bssid) = entry.bssid.as_deref().and_then(MacAddr::parse) {
                let pmf_required = entry.security_flags & SECURITY_PMF_REQUIRED != 0;
                self.ap_pmf_state.put(bssid, pmf_required);
            }
        }

        // Detect spoofed deauth/disassoc and track client deauth times
        if matches!(
            entry.frame_subtype.as_str(),
            "deauthentication" | "disassociation"
        ) {
            if let Some(src_norm) = entry.source_mac.as_deref().and_then(MacAddr::parse) {
                if let Some(&pmf_required) = self.ap_pmf_state.get(&src_norm) {
                    if !entry.protected.unwrap_or(false) && !pmf_required {
                        if !tags.contains(&"threat:pmf_deauth_attack".to_string()) {
                            tags.push("threat:pmf_deauth_attack".to_string());
                        }
                    }
                }
            }

            // Track deauth destination (client MAC) for reconnect correlation
            if let Some(dst) = entry.destination_mac.as_deref().and_then(MacAddr::parse) {
                self.client_deauth_times.put(dst, observed);
            }
        }

        // Detect forced reconnect within configurable window
        if matches!(
            entry.frame_subtype.as_str(),
            "association_request" | "reassociation_request"
        ) {
            if let Some(src_norm) = entry.source_mac.as_deref().and_then(MacAddr::parse) {
                if let Some(&deauth_time) = self.client_deauth_times.get(&src_norm) {
                    let delta = (observed - deauth_time).num_milliseconds();
                    if delta >= 0 && delta <= self.reconnect_window_ms {
                        if !tags.contains(&"threat:pmf_forced_reconnect".to_string()) {
                            tags.push("threat:pmf_forced_reconnect".to_string());
                        }
                        // Track forced reconnect for handshake correlation
                        if let Some(bssid) = entry
                            .bssid
                            .as_deref()
                            .or(entry.destination_bssid.as_deref())
                            .and_then(MacAddr::parse)
                        {
                            let key = (bssid, src_norm);
                            self.forced_reconnects.put(key, observed);
                        }
                    }
                }
            }
        }

        // Detect handshake harvest attack: forced reconnect + handshake within 10s
        if entry.handshake_captured {
            if let (Some(bssid), Some(client)) = (
                entry
                    .bssid
                    .as_deref()
                    .or(entry.destination_bssid.as_deref())
                    .and_then(MacAddr::parse),
                entry
                    .source_mac
                    .as_deref()
                    .or(entry.destination_mac.as_deref())
                    .and_then(MacAddr::parse),
            ) {
                let key = (bssid, client);
                if let Some(&reconnect_time) = self.forced_reconnects.get(&key) {
                    let delta = (observed - reconnect_time).num_milliseconds();
                    if delta >= 0 && delta <= 10_000 {
                        if !tags.contains(&"threat:handshake_harvest_attack".to_string()) {
                            tags.push("threat:handshake_harvest_attack".to_string());
                        }
                    }
                }
            }
        }
    }
}

#[derive(Serialize)]
pub struct PmfAttackAlert {
    pub schema_version: u32,
    pub event_type: String,
    pub observed_at: String,
    pub sensor_id: String,
    pub location_id: String,
    pub target_mac: String,
    pub target_bssid: Option<String>,
    pub ssid: Option<String>,
    pub channel: Option<u8>,
    pub attack_tag: String,
    pub reconnect_window_ms: Option<i64>,
}

pub fn pmf_attack_alert_from_entry(
    entry: &AuditEntry,
    attack_tag: &str,
    reconnect_window_ms: i64,
) -> Option<PmfAttackAlert> {
    if !attack_tag.starts_with("threat:pmf_") && attack_tag != "threat:handshake_harvest_attack" {
        return None;
    }

    let target_mac = if attack_tag == "threat:pmf_forced_reconnect" {
        entry.source_mac.as_deref()
    } else {
        entry
            .destination_mac
            .as_deref()
            .or(entry.source_mac.as_deref())
    }
    .or(entry.bssid.as_deref())?
    .trim()
    .to_ascii_lowercase();

    Some(PmfAttackAlert {
        schema_version: 1,
        event_type: "wireless_pmf_attack".to_string(),
        observed_at: entry.observed_at.clone(),
        sensor_id: entry.sensor_id.clone(),
        location_id: entry.location_id.clone(),
        target_mac,
        target_bssid: entry
            .bssid
            .clone()
            .or_else(|| entry.destination_bssid.clone()),
        ssid: entry.ssid.clone(),
        channel: Some(entry.channel),
        attack_tag: attack_tag.to_string(),
        reconnect_window_ms: Some(reconnect_window_ms),
    })
}
