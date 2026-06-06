#[derive(Clone, Debug, Serialize)]
pub struct SignalAnomalyAlert {
    pub schema_version: u32,
    pub event_type: String,
    pub observed_at: String,
    pub sensor_id: String,
    pub location_id: String,
    pub source_mac: String,
    pub bssid: Option<String>,
    pub ssid: Option<String>,
    pub channel: u8,
    pub baseline_dbm: i8,
    pub observed_dbm: i8,
    pub dbm_delta: i16,
    pub configured_delta: i8,
}

impl SignalTracker {
    /// Observes a frame and returns an alert when the signal delta exceeds threshold.
    pub fn observe(&mut self, entry: &AuditEntry, threshold: i8) -> Option<SignalAnomalyAlert> {
        if threshold <= 0 {
            return None;
        }
        let (Some(bssid), Some(signal)) = (
            entry.bssid.as_deref().and_then(MacAddr::parse),
            entry.signal_dbm,
        ) else {
            return None;
        };
        let source_mac = entry
            .source_mac
            .as_deref()
            .or(entry.bssid.as_deref())
            .and_then(MacAddr::parse)?
            .to_string();
        let previous = self.last_by_bssid.put(bssid, signal);
        let baseline = previous?;
        let delta = i16::from(signal) - i16::from(baseline);
        if delta.abs() < i16::from(threshold) {
            return None;
        }

        Some(SignalAnomalyAlert {
            schema_version: 1,
            event_type: "wireless_signal_anomaly".to_string(),
            observed_at: entry.observed_at.clone(),
            sensor_id: entry.sensor_id.clone(),
            location_id: entry.location_id.clone(),
            source_mac,
            bssid: Some(bssid.to_string()),
            ssid: entry.ssid.clone(),
            channel: entry.channel,
            baseline_dbm: baseline,
            observed_dbm: signal,
            dbm_delta: delta.abs(),
            configured_delta: threshold,
        })
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct RogueApAlert {
    pub schema_version: u32,
    pub event_type: String,
    pub observed_at: String,
    pub sensor_id: String,
    pub location_id: String,
    pub interface: String,
    pub bssid: Option<String>,
    pub ssid: Option<String>,
    pub channel: u8,
    pub reasons: Vec<String>,
    /// Structured factor breakdown for each detection reason.
    #[serde(default)]
    pub factor_breakdown: Vec<AlertExplanation>,
    /// Human-readable explanations for each reason, populated at alert creation.
    #[serde(default)]
    pub explanation: Vec<String>,
}

#[derive(Clone, Debug, Default)]
struct ApState {
    ssid: Option<String>,
    channels: ChannelSet,
    first_channel: Option<u8>,
    vendor_oui: Option<[u8; 3]>,
}

pub struct RogueApTracker {
    aps: LruCache<MacAddr, ApState>,
    recent_alerts: LruCache<String, DateTime<Utc>>,
    typosquat_cache: LruCache<SsidKey, bool>,
}

impl Default for RogueApTracker {
    fn default() -> Self {
        Self::new(DetectorLimits::default())
    }
}

impl RogueApTracker {
    pub fn new(limits: DetectorLimits) -> Self {
        let limits = limits.clamp();
        Self {
            aps: LruCache::new(limits.mac_capacity()),
            recent_alerts: LruCache::new(limits.ssid_capacity()),
            typosquat_cache: LruCache::new(limits.ssid_capacity()),
        }
    }

    pub fn clear_typosquat_cache(&mut self) {
        self.typosquat_cache.clear();
    }

    /// Observes a beacon or probe response and returns a RogueApAlert when any of four detection
    /// reasons fire: open_authorized_ssid (known SSID with no encryption), ssid_typosquat
    /// (edit distance <=2 from known SSID), bssid_spoofing (BSSID changed SSID mapping), or
    /// channel_conflict (same BSSID seen on multiple channels).
    pub fn observe(
        &mut self,
        entry: &AuditEntry,
        authorized: &AuthorizedNetworkCache,
    ) -> Option<RogueApAlert> {
        if !FrameSubtype::parse(&entry.frame_subtype).is_ap_observation() {
            return None;
        }
        let observed_at = parse_observed_at(&entry.observed_at).unwrap_or_else(Utc::now);
        let mut reasons = Vec::new();
        let ssid = entry
            .ssid
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty());
        let bssid = entry.bssid.as_deref().and_then(MacAddr::parse);
        if ssid.is_some_and(|value| authorized.is_known_ssid(value)) && entry.security_flags == 0 {
            reasons.push("open_authorized_ssid".to_string());
        }
        if let Some(ssid) = ssid {
            if let Some(key) = SsidKey::new(ssid) {
                let typosquat = if let Some(cached) = self.typosquat_cache.get(&key) {
                    *cached
                } else {
                    let verdict = authorized.is_typosquat(ssid);
                    self.typosquat_cache.put(key, verdict);
                    verdict
                };
                if typosquat {
                    reasons.push("ssid_typosquat".to_string());
                }
            }
        }
        if let Some(bssid) = bssid {
            if self.aps.get(&bssid).is_none() {
                self.aps.put(bssid, ApState::default());
            }
            if let Some(ssid) = ssid {
                if let Some(state) = self.aps.get_mut(&bssid) {
                    if state
                        .ssid
                        .as_deref()
                        .is_some_and(|previous| previous != ssid)
                    {
                        reasons.push("bssid_spoofing".to_string());
                    }
                    state.ssid = Some(ssid.to_string());
                }
            }
            if let Some(state) = self.aps.get_mut(&bssid) {
                state.channels.insert(entry.channel);
                if state.channels.len() > 1 {
                    reasons.push("channel_conflict".to_string());
                }

                if let Some(first_ch) = state.first_channel {
                    let first_is_5ghz = first_ch >= 36;
                    let current_is_2ghz = entry.channel >= 1 && entry.channel <= 14;
                    if first_is_5ghz && current_is_2ghz {
                        reasons.push("channel_band_conflict".to_string());
                    }
                } else {
                    state.first_channel = Some(entry.channel);
                }
                state.vendor_oui = Some(bssid.oui());
            }

            if let Some(ssid) = ssid {
                let current_oui = bssid.oui();
                let has_conflict = self.aps.iter().any(|(other_bssid, state)| {
                    *other_bssid != bssid
                        && state.ssid.as_deref() == Some(ssid)
                        && state.vendor_oui.is_some_and(|oui| oui != current_oui)
                });
                if has_conflict {
                    reasons.push("vendor_conflict".to_string());
                }
            }
        }
        if reasons.is_empty() {
            return None;
        }
        let key = format!(
            "{}|{}|{}",
            bssid
                .map(|value| value.to_string())
                .unwrap_or_else(|| "unknown".to_string()),
            ssid.unwrap_or("unknown"),
            reasons.join(",")
        );
        let ttl = chrono::Duration::from_std(ROGUE_AP_ALERT_TTL).ok()?;
        if let Some(last) = self.recent_alerts.get(&key) {
            let delta = observed_at.signed_duration_since(*last);
            if delta >= chrono::Duration::zero() && delta < ttl {
                return None;
            }
        }
        self.recent_alerts.put(key, observed_at);
        Some(RogueApAlert {
            schema_version: 1,
            event_type: "wireless_rogue_ap".to_string(),
            observed_at: entry.observed_at.clone(),
            sensor_id: entry.sensor_id.clone(),
            location_id: entry.location_id.clone(),
            interface: entry.interface.clone(),
            bssid: bssid.map(|value| value.to_string()),
            ssid: ssid.map(str::to_string),
            channel: entry.channel,
            factor_breakdown: reasons.iter().map(|r| rogue_ap_explanation(r)).collect(),
            explanation: reasons.iter().map(|r| explain_reason(r)).collect(),
            reasons,
        })
    }
}

/// Builds a structured `AlertExplanation` for a single rogue-AP detection reason.
/// Uses fixed baselines where applicable (e.g. normal encryption = present, single channel = 1).
fn rogue_ap_explanation(reason: &str) -> AlertExplanation {
    let (baseline, observed, contribution) = match reason {
        "open_authorized_ssid" => (1.0, 0.0, 1.0), // expected encrypted (1), found open (0)
        "ssid_typosquat" => (1.0, 0.0, 0.9),       // expected exact match (1), found typosquat (0)
        "bssid_spoofing" => (1.0, 0.0, 0.8),       // expected stable mapping (1), found changed (0)
        "channel_conflict" => (1.0, 2.0, 0.7), // expected single channel (1), found multiple (≥2)
        "channel_band_conflict" => (1.0, 2.0, 0.6), // expected consistent band (1), found band switch (2)
        "vendor_conflict" => (1.0, 2.0, 0.5), // expected single vendor (1), found multiple (≥2)
        _ => (1.0, 1.0, 0.0),
    };
    AlertExplanation {
        factor: reason.to_string(),
        observed,
        baseline,
        contribution,
    }
}

/// Maps a detection reason tag to a human-readable explanation.
fn explain_reason(reason: &str) -> String {
    match reason {
        "open_authorized_ssid" => "Known SSID broadcasting without encryption".into(),
        "ssid_typosquat" => {
            "SSID is an edit-distance match to a known network (potential typosquatting)".into()
        }
        "bssid_spoofing" => "BSSID changed its SSID mapping since last observation".into(),
        "channel_conflict" => "Same BSSID observed on multiple channels".into(),
        "channel_band_conflict" => "BSSID originally on 5 GHz now seen on 2.4 GHz".into(),
        "vendor_conflict" => "Same SSID served by different hardware vendors".into(),
        other => format!("Unrecognised detection reason: {other}"),
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct DeauthFloodAlert {
    pub schema_version: u32,
    pub event_type: String,
    pub observed_at: String,
    pub sensor_id: String,
    pub location_id: String,
    pub interface: String,
    pub bssid: Option<String>,
    pub frame_count: u64,
    pub window_secs: u64,
    /// Structured factor breakdown for each detection factor.
    #[serde(default)]
    pub factor_breakdown: Vec<AlertExplanation>,
    /// Human-readable explanations for each detection factor.
    #[serde(default)]
    pub explanation: Vec<String>,
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
enum DeauthKey {
    Bssid(MacAddr),
    Raw(String),
}

pub struct DeauthFloodTracker {
    windows: LruCache<DeauthKey, BucketCounter>,
    last_alerts: LruCache<DeauthKey, DateTime<Utc>>,
}

impl Default for DeauthFloodTracker {
    fn default() -> Self {
        Self::new(DetectorLimits::default())
    }
}

impl DeauthFloodTracker {
    pub fn new(limits: DetectorLimits) -> Self {
        let limits = limits.clamp();
        Self {
            windows: LruCache::new(limits.mac_capacity()),
            last_alerts: LruCache::new(limits.mac_capacity()),
        }
    }

    /// Observes a deauth or disassociation frame and returns a DeauthFloodAlert when the frame
    /// count exceeds threshold within window_secs. Uses per-second buckets and frame-time
    /// cooldowns so replayed PCAPs are deterministic. Frames without a parseable BSSID fall
    /// back to a stable transmitter/source identity so malformed floods still share a bucket.
    pub fn observe(
        &mut self,
        entry: &AuditEntry,
        threshold: u64,
        window_secs: u64,
        cooldown_secs: u64,
    ) -> Option<DeauthFloodAlert> {
        if threshold == 0 || window_secs == 0 {
            return None;
        }
        if !matches!(
            entry.frame_subtype.as_str(),
            "deauthentication" | "disassociation"
        ) {
            return None;
        }
        let key = entry
            .bssid
            .as_deref()
            .and_then(MacAddr::parse)
            .map(DeauthKey::Bssid)
            .unwrap_or_else(|| DeauthKey::Raw(raw_deauth_key(entry)));
        let observed_at = parse_observed_at(&entry.observed_at).unwrap_or_else(Utc::now);
        if self.windows.get(&key).is_none() {
            self.windows.put(key.clone(), BucketCounter::default());
        }
        let frame_count = self
            .windows
            .get_mut(&key)
            .map(|window| window.record(observed_at, window_secs))
            .unwrap_or(0);
        if frame_count == 0 {
            self.windows.pop(&key);
            self.last_alerts.pop(&key);
            return None;
        }
        if frame_count < threshold {
            return None;
        }
        let cooldown = chrono::Duration::seconds(cooldown_secs as i64);
        if let Some(last) = self.last_alerts.get(&key) {
            let delta = observed_at.signed_duration_since(*last);
            if delta >= chrono::Duration::zero() && delta < cooldown {
                return None;
            }
        }
        self.last_alerts.put(key, observed_at);
        let contribution = if threshold > 0 {
            (frame_count as f64) / (threshold as f64).min(frame_count as f64)
        } else {
            1.0
        };
        Some(DeauthFloodAlert {
            schema_version: 1,
            event_type: "wireless_deauth_flood".to_string(),
            observed_at: entry.observed_at.clone(),
            sensor_id: entry.sensor_id.clone(),
            location_id: entry.location_id.clone(),
            interface: entry.interface.clone(),
            bssid: entry.bssid.clone(),
            frame_count,
            window_secs,
            factor_breakdown: vec![AlertExplanation {
                factor: "deauth_frame_count".to_string(),
                observed: frame_count as f64,
                baseline: threshold as f64,
                contribution: contribution.min(1.0),
            }],
            explanation: vec![format!(
                "deauth_frame_count: {} in {}s window (threshold: {})",
                frame_count, window_secs, threshold
            )],
        })
    }
}

fn raw_deauth_key(entry: &AuditEntry) -> String {
    if let Some(source) = entry
        .source_mac
        .as_deref()
        .or(entry.transmitter_mac.as_deref())
        .or(entry.receiver_mac.as_deref())
        .map(normalize_mac)
    {
        return format!("unparseable_bssid|{}|{}", source, entry.frame_subtype);
    }
    if let Some(raw_bssid) = entry
        .bssid
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
    {
        return format!(
            "unparseable_bssid|{}|{}",
            normalize_mac(raw_bssid),
            entry.frame_subtype
        );
    }
    format!("unparseable_bssid|unknown|{}", entry.frame_subtype)
}

pub struct AuthorizedNetworkCache {
    entries: Vec<AuthorizedWirelessNetwork>,
    has_loaded: bool,
    loaded_at: Option<Instant>,
    last_failure: Option<Instant>,
    failure_count: u32,
    backoff_ms: u64,
    last_logged_failure_count: u32,
}

impl Default for AuthorizedNetworkCache {
    fn default() -> Self {
        Self::new(30_000)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AuthorizationStatus {
    Authorized,
    Unauthorized,
    Unknown,
}
