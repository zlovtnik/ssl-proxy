impl AuthorizedNetworkCache {
    pub fn new(backoff_ms: u64) -> Self {
        Self {
            entries: Vec::new(),
            has_loaded: false,
            loaded_at: None,
            last_failure: None,
            failure_count: 0,
            backoff_ms: backoff_ms.max(1),
            last_logged_failure_count: 0,
        }
    }

    #[cfg(test)]
    pub(crate) fn with_entries_for_test(entries: Vec<AuthorizedWirelessNetwork>) -> Self {
        let mut cache = Self::default();
        cache.entries = entries;
        cache.has_loaded = true;
        cache
    }

    #[allow(dead_code)]
    pub fn invalidate(&mut self) {
        self.loaded_at = None;
    }

    fn failure_backoff(&self) -> Duration {
        if self.failure_count == 0 {
            return Duration::from_secs(0);
        }
        let exponent = self.failure_count.saturating_sub(1).min(63);
        let multiplier = 1u64.checked_shl(exponent).unwrap_or(u64::MAX);
        Duration::from_millis(self.backoff_ms.saturating_mul(multiplier).min(300_000))
    }

    /// Returns true when the caller should emit a log for this failure.
    /// True only on first failure, backoff escalation, or recovery (failure_count resets).
    pub fn should_log_failure(&mut self, is_failure: bool) -> bool {
        if is_failure {
            if self.failure_count != self.last_logged_failure_count {
                self.last_logged_failure_count = self.failure_count;
                return true;
            }
            return false;
        }
        // Recovery: logged externally via info-level on success
        self.last_logged_failure_count = 0;
        false
    }

    pub async fn refresh_if_needed(
        &mut self,
        backlog: &RedpandaBacklog,
        ttl: Duration,
    ) -> Result<(), crate::backlog::BacklogError> {
        if self
            .loaded_at
            .is_some_and(|loaded_at| loaded_at.elapsed() < ttl)
        {
            return Ok(());
        }

        if let Some(last_failure) = self.last_failure {
            let backoff = self.failure_backoff();
            if last_failure.elapsed() < backoff {
                if self.loaded_at.is_some() {
                    return Ok(());
                }
                return Err(crate::backlog::BacklogError::Redpanda {
                    operation: "refresh_if_needed",
                    message: format!(
                        "previous authorized network refresh failed; retry backoff {}ms",
                        backoff.as_millis()
                    ),
                });
            }
        }

        match backlog.list_authorized_wireless_networks().await {
            Ok(entries) => {
                self.entries = entries;
                self.has_loaded = true;
                self.loaded_at = Some(Instant::now());
                self.last_failure = None;
                self.failure_count = 0;
                Ok(())
            }
            Err(err) => {
                self.last_failure = Some(Instant::now());
                self.failure_count = self.failure_count.saturating_add(1);
                if self.loaded_at.is_some() {
                    Ok(())
                } else {
                    Err(err)
                }
            }
        }
    }

    /// Checks if a network is authorized using three-field AND logic: location_id, SSID, and
    /// BSSID. A None field on the stored entry acts as a wildcard (matches any value). At least
    /// one of SSID or BSSID must be non-None on the stored entry to match.
    pub fn authorization_status(
        &self,
        ssid: Option<&str>,
        bssid: Option<&str>,
        location_id: &str,
    ) -> AuthorizationStatus {
        if !self.has_loaded {
            return AuthorizationStatus::Unknown;
        }
        let normalized_ssid = ssid.map(|value| value.trim().to_ascii_lowercase());
        let normalized_bssid = bssid.map(normalize_mac);
        let is_authorized = self.entries.iter().any(|entry| {
            entry
                .location_id
                .as_deref()
                .map_or(true, |location| location == location_id)
                && entry.ssid.as_deref().map_or(true, |known| {
                    normalized_ssid.as_deref() == Some(known.trim().to_ascii_lowercase().as_str())
                })
                && entry.bssid.as_deref().map_or(true, |known| {
                    normalized_bssid.as_deref() == Some(known.trim().to_ascii_lowercase().as_str())
                })
                && (entry.ssid.is_some() || entry.bssid.is_some())
        });
        if is_authorized {
            AuthorizationStatus::Authorized
        } else {
            AuthorizationStatus::Unauthorized
        }
    }

    pub fn is_authorized(
        &self,
        ssid: Option<&str>,
        bssid: Option<&str>,
        location_id: &str,
    ) -> bool {
        self.authorization_status(ssid, bssid, location_id) == AuthorizationStatus::Authorized
    }

    pub fn entries(&self) -> &[AuthorizedWirelessNetwork] {
        &self.entries
    }

    pub fn is_known_ssid(&self, ssid: &str) -> bool {
        let ssid = ssid.trim().to_ascii_lowercase();
        self.entries.iter().any(|entry| {
            entry
                .ssid
                .as_deref()
                .is_some_and(|known| known.trim().eq_ignore_ascii_case(&ssid))
        })
    }

    /// Returns true when the candidate SSID has edit distance <= 2 from any known SSID.
    /// Early exit when length difference exceeds the limit (2) to skip expensive DP.
    pub fn is_typosquat(&self, ssid: &str) -> bool {
        let ssid = ssid.trim().to_ascii_lowercase();
        if ssid.is_empty() || self.is_known_ssid(&ssid) {
            return false;
        }
        self.entries.iter().any(|entry| {
            entry
                .ssid
                .as_deref()
                .map(|known| edit_distance_limited(&known.to_ascii_lowercase(), &ssid, 2) <= 2)
                .unwrap_or(false)
        })
    }
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
struct IeLayoutKey {
    ssid: SsidKey,
    layout_hash: Box<str>,
}

impl IeLayoutKey {
    fn new(ssid: &str, layout_hash: &str) -> Option<Self> {
        let layout_hash = layout_hash.trim();
        if layout_hash.is_empty() {
            return None;
        }
        Some(Self {
            ssid: SsidKey::new(ssid)?,
            layout_hash: layout_hash.into(),
        })
    }
}

pub struct IeLayoutTracker {
    authorized_bssids_by_layout: LruCache<IeLayoutKey, Vec<MacAddr>>,
}

impl Default for IeLayoutTracker {
    fn default() -> Self {
        Self::new(DetectorLimits::default())
    }
}

impl IeLayoutTracker {
    pub fn new(limits: DetectorLimits) -> Self {
        Self {
            authorized_bssids_by_layout: LruCache::new(limits.clamp().ssid_capacity()),
        }
    }

    pub fn observe(&mut self, entry: &mut AuditEntry, authorization_status: AuthorizationStatus) {
        if !FrameSubtype::parse(&entry.frame_subtype).is_ap_observation() {
            return;
        }
        let (Some(ssid), Some(layout_hash), Some(bssid)) = (
            entry
                .ssid
                .as_deref()
                .map(str::trim)
                .filter(|value| !value.is_empty()),
            entry.ie_layout_hash.as_deref(),
            entry.bssid.as_deref().and_then(MacAddr::parse),
        ) else {
            return;
        };
        let Some(key) = IeLayoutKey::new(ssid, layout_hash) else {
            return;
        };

        match authorization_status {
            AuthorizationStatus::Authorized => {
                if self.authorized_bssids_by_layout.get(&key).is_none() {
                    self.authorized_bssids_by_layout
                        .put(key.clone(), Vec::new());
                }
                if let Some(bssids) = self.authorized_bssids_by_layout.get_mut(&key) {
                    if !bssids.contains(&bssid) {
                        if bssids.len() >= FINGERPRINT_MAC_LIMIT {
                            bssids.remove(0);
                        }
                        bssids.push(bssid);
                    }
                }
            }
            AuthorizationStatus::Unauthorized => {
                if self
                    .authorized_bssids_by_layout
                    .get(&key)
                    .is_some_and(|bssids| bssids.iter().any(|known| *known != bssid))
                {
                    push_unique(&mut entry.tags, "threat:structural_evil_twin");
                }
            }
            AuthorizationStatus::Unknown => {}
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
struct MacSequenceKey {
    transmitter: MacAddr,
    frame_type: u8,
    qos_tid: Option<u8>,
}

pub struct MacSequenceDeltaTracker {
    last_sequence_by_key: LruCache<MacSequenceKey, u16>,
}

impl Default for MacSequenceDeltaTracker {
    fn default() -> Self {
        Self::new(DetectorLimits::default())
    }
}

impl MacSequenceDeltaTracker {
    pub fn new(limits: DetectorLimits) -> Self {
        Self {
            last_sequence_by_key: LruCache::new(limits.clamp().session_capacity()),
        }
    }

    pub fn observe(&mut self, entry: &mut AuditEntry) {
        let (Some(transmitter), Some(current_sequence)) = (
            entry.transmitter_mac.as_deref().and_then(MacAddr::parse),
            entry.sequence_number,
        ) else {
            return;
        };
        let key = MacSequenceKey {
            transmitter,
            frame_type: frame_type_code(entry.frame_type.as_deref()),
            qos_tid: entry.qos_tid,
        };
        let current_sequence = current_sequence & 0x0fff;
        let previous_sequence = self.last_sequence_by_key.put(key, current_sequence);
        let Some(previous_sequence) = previous_sequence else {
            return;
        };

        let delta = if current_sequence >= previous_sequence {
            current_sequence - previous_sequence
        } else {
            4096 - previous_sequence + current_sequence
        };
        entry.sequence_delta = Some(delta);
        if let Some(correlation) = entry.correlation.as_mut() {
            correlation.sequence_delta = Some(delta);
        }

        if delta == 0 {
            entry.dedupe_or_replay_suspect = Some(true);
            if let Some(anomalies) = entry.anomalies.as_mut() {
                anomalies.dedupe_or_replay_suspect = true;
            }
            push_unique(&mut entry.tags, "anomaly:sequence_duplicate");
            push_anomaly_reason(entry, "sequence_duplicate");
        } else if delta > 1 && delta < 4000 {
            let missing = delta - 1;
            entry.sequence_gap_missing_frames = Some(missing);
            if let Some(correlation) = entry.correlation.as_mut() {
                correlation.sequence_gap_missing_frames = Some(missing);
            }
            push_unique(&mut entry.tags, "anomaly:sequence_jump");
            push_anomaly_reason(entry, "sequence_jump");
        }
    }
}

fn frame_type_code(frame_type: Option<&str>) -> u8 {
    match frame_type {
        Some("management") => 0,
        Some("data") => 2,
        _ => u8::MAX,
    }
}

fn parse_observed_at(value: &str) -> Option<DateTime<Utc>> {
    DateTime::parse_from_rfc3339(value)
        .ok()
        .map(|value| value.with_timezone(&Utc))
}

fn normalize_mac(value: &str) -> String {
    value.trim().to_ascii_lowercase()
}

fn push_unique(values: &mut Vec<String>, value: &str) {
    if !values.iter().any(|existing| existing == value) {
        values.push(value.to_string());
    }
}

fn push_anomaly_reason(entry: &mut AuditEntry, reason: &str) {
    push_unique(&mut entry.anomaly_reasons, reason);
    if let Some(anomalies) = entry.anomalies.as_mut() {
        push_unique(&mut anomalies.reasons, reason);
    }
}

/// Levenshtein distance with early exit: returns limit+1 when any row minimum exceeds
/// limit, avoiding full DP computation for strings that cannot possibly match.
/// Levenshtein distance with early-exit optimization. Returns limit+1 when the length
/// difference exceeds limit or any row minimum exceeds limit, avoiding full DP computation.
/// The limit of 2 distinguishes most typosquats (one character substitution or insertion).
fn edit_distance_limited(left: &str, right: &str, limit: usize) -> usize {
    if left.len().abs_diff(right.len()) > limit {
        return limit + 1;
    }
    let mut previous: Vec<usize> = (0..=right.len()).collect();
    let mut current = vec![0; right.len() + 1];
    for (i, left_ch) in left.chars().enumerate() {
        current[0] = i + 1;
        let mut row_min = current[0];
        for (j, right_ch) in right.chars().enumerate() {
            let cost = usize::from(left_ch != right_ch);
            current[j + 1] = (previous[j + 1] + 1)
                .min(current[j] + 1)
                .min(previous[j] + cost);
            row_min = row_min.min(current[j + 1]);
        }
        if row_min > limit {
            return limit + 1;
        }
        previous.clone_from(&current);
    }
    previous[right.len()]
}

#[derive(Clone, Debug, Serialize)]
pub struct AttackSequenceAlert {
    pub schema_version: u32,
    pub event_type: String,
    pub observed_at: String,
    pub sensor_id: String,
    pub location_id: String,
    pub ssid: String,
    pub attack_chain: Vec<String>,
    pub first_event_at: String,
    pub last_event_at: String,
    /// Structured factor breakdown for each detection factor.
    #[serde(default)]
    pub factor_breakdown: Vec<AlertExplanation>,
    /// Human-readable explanations for each detection factor.
    #[serde(default)]
    pub explanation: Vec<String>,
}

#[derive(Clone, Debug, Serialize)]
pub struct SequenceAlert {
    pub schema_version: u32,
    pub event_type: String,
    pub observed_at: String,
    pub sensor_id: String,
    pub location_id: String,
    pub session_key: String,
    pub source_mac: Option<String>,
    pub bssid: Option<String>,
    pub ssid: Option<String>,
    pub attack_tag: String,
    pub sequence: Vec<String>,
    pub first_event_at: String,
    pub last_event_at: String,
    /// Structured factor breakdown for each detection factor.
    #[serde(default)]
    pub factor_breakdown: Vec<AlertExplanation>,
    /// Human-readable explanations for each detection factor.
    #[serde(default)]
    pub explanation: Vec<String>,
}
