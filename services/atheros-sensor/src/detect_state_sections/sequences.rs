#[derive(Clone, Debug)]
struct SessionSequence {
    frames: VecDeque<FrameSubtype>,
    first_seen: DateTime<Utc>,
    last_seen: DateTime<Utc>,
    seen_beacon_bssids: VecDeque<MacAddr>,
    auth_deauth_events: VecDeque<(DateTime<Utc>, FrameSubtype)>,
    emitted_tags: HashSet<String>,
}

pub struct SequenceTracker {
    sessions: LruCache<String, SessionSequence>,
}

impl Default for SequenceTracker {
    fn default() -> Self {
        Self::new(DetectorLimits::default())
    }
}

impl SequenceTracker {
    pub fn new(limits: DetectorLimits) -> Self {
        Self {
            sessions: LruCache::new(limits.clamp().session_capacity()),
        }
    }

    pub fn observe(&mut self, entry: &AuditEntry) -> Option<SequenceAlert> {
        let session_key = entry
            .session_key
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())?;
        let observed_at = parse_observed_at(&entry.observed_at).unwrap_or_else(Utc::now);
        let session_key_owned = session_key.to_string();
        if self.sessions.get(&session_key_owned).is_none() {
            self.sessions.put(
                session_key_owned.clone(),
                SessionSequence {
                    frames: VecDeque::new(),
                    first_seen: observed_at,
                    last_seen: observed_at,
                    seen_beacon_bssids: VecDeque::new(),
                    auth_deauth_events: VecDeque::new(),
                    emitted_tags: HashSet::new(),
                },
            );
        }
        let sequence = self.sessions.get_mut(&session_key_owned)?;
        sequence.last_seen = observed_at;

        let subtype = FrameSubtype::parse(&entry.frame_subtype);
        if let Some(bssid) = entry.bssid.as_deref().and_then(MacAddr::parse) {
            if matches!(subtype, FrameSubtype::Beacon)
                && !sequence.seen_beacon_bssids.contains(&bssid)
            {
                if sequence.seen_beacon_bssids.len() >= SEQUENCE_FRAME_LIMIT {
                    sequence.seen_beacon_bssids.pop_front();
                }
                sequence.seen_beacon_bssids.push_back(bssid);
            }
        }

        let mut alert_tag = None;
        if matches!(subtype, FrameSubtype::ProbeResponse) {
            if let Some(bssid) = entry.bssid.as_deref().and_then(MacAddr::parse) {
                if !sequence.seen_beacon_bssids.contains(&bssid) {
                    alert_tag = Some("threat:silent_rogue_ap".to_string());
                }
            }
        }

        sequence.frames.push_back(subtype.clone());
        while sequence.frames.len() > SEQUENCE_FRAME_LIMIT {
            sequence.frames.pop_front();
        }

        if matches!(
            subtype,
            FrameSubtype::Authentication | FrameSubtype::Deauthentication
        ) {
            sequence
                .auth_deauth_events
                .push_back((observed_at, subtype.clone()));
            let cutoff = observed_at - chrono::Duration::seconds(SEQUENCE_AUTH_WINDOW_SECS);
            while sequence
                .auth_deauth_events
                .front()
                .is_some_and(|(timestamp, _)| *timestamp < cutoff)
            {
                sequence.auth_deauth_events.pop_front();
            }
        }

        if alert_tag.is_none() {
            alert_tag = SequenceTracker::check_roaming_suppression(sequence);
        }
        if alert_tag.is_none() {
            alert_tag = SequenceTracker::check_auth_flood(sequence);
        }

        if let Some(tag) = alert_tag {
            if !sequence.emitted_tags.insert(tag.clone()) {
                return None;
            }

            // Extract data needed for the alert while we still hold the mutable
            // borrow to `sequence`. This ensures `prune_stale_sessions()` can
            // borrow `&mut self` without triggering E0499.
            let sequence_tokens = series_to_tokens(&sequence.frames);
            let first_seen = sequence.first_seen;
            let last_seen = sequence.last_seen;

            return Some(SequenceTracker::build_sequence_alert(
                sequence_tokens,
                session_key,
                entry,
                tag,
                first_seen,
                last_seen,
            ));
        }

        None
    }

    fn check_roaming_suppression(sequence: &SessionSequence) -> Option<String> {
        let pattern = [
            FrameSubtype::ProbeRequest,
            FrameSubtype::ProbeResponse,
            FrameSubtype::Deauthentication,
            FrameSubtype::ReassociationRequest,
            FrameSubtype::Deauthentication,
        ];
        if ends_with_pattern(&sequence.frames, &pattern) {
            return Some("threat:roaming_suppression".to_string());
        }
        None
    }

    fn check_auth_flood(sequence: &SessionSequence) -> Option<String> {
        if sequence.auth_deauth_events.len() < 6 {
            return None;
        }
        let pattern = [
            FrameSubtype::Authentication,
            FrameSubtype::Deauthentication,
            FrameSubtype::Authentication,
            FrameSubtype::Deauthentication,
            FrameSubtype::Authentication,
            FrameSubtype::Deauthentication,
        ];
        if sequence
            .auth_deauth_events
            .iter()
            .rev()
            .take(6)
            .map(|(_, subtype)| subtype)
            .collect::<Vec<_>>()
            .into_iter()
            .rev()
            .eq(pattern.iter())
        {
            return Some("threat:auth_flood".to_string());
        }
        None
    }

    fn build_sequence_alert(
        sequence_tokens: Vec<String>,
        session_key: &str,
        entry: &AuditEntry,
        attack_tag: String,
        first_seen: DateTime<Utc>,
        last_seen: DateTime<Utc>,
    ) -> SequenceAlert {
        let seq_contribution = (sequence_tokens.len() as f64).min(32.0) / 32.0;
        SequenceAlert {
            schema_version: 1,
            event_type: "wireless_sequence_alert".to_string(),
            observed_at: entry.observed_at.clone(),
            sensor_id: entry.sensor_id.clone(),
            location_id: entry.location_id.clone(),
            session_key: session_key.to_string(),
            source_mac: entry.source_mac.clone(),
            bssid: entry.bssid.clone(),
            ssid: entry.ssid.clone(),
            attack_tag: attack_tag.clone(),
            sequence: sequence_tokens.clone(),
            first_event_at: crate::timing::rfc3339_from_utc(first_seen),
            last_event_at: crate::timing::rfc3339_from_utc(last_seen),
            factor_breakdown: vec![AlertExplanation {
                factor: attack_tag.clone(),
                observed: sequence_tokens.len() as f64,
                baseline: 1.0,
                contribution: seq_contribution,
            }],
            explanation: vec![format!(
                "attack_tag: {} with {} frames in sequence (session: {})",
                attack_tag,
                sequence_tokens.len(),
                session_key
            )],
        }
    }
}

fn ends_with_pattern(frames: &VecDeque<FrameSubtype>, pattern: &[FrameSubtype]) -> bool {
    if frames.len() < pattern.len() {
        return false;
    }
    frames
        .iter()
        .rev()
        .zip(pattern.iter().rev())
        .all(|(actual, expected)| actual == expected)
}

fn series_to_tokens(frames: &VecDeque<FrameSubtype>) -> Vec<String> {
    frames.iter().map(FrameSubtype::token).collect()
}

#[derive(Debug)]
struct AttackEvent {
    timestamp: DateTime<Utc>,
    attack_type: String,
}

pub struct AttackTimelineCorrelator {
    events_by_ssid: LruCache<SsidKey, VecDeque<AttackEvent>>,
    recent_alerts: LruCache<SsidKey, DateTime<Utc>>,
}

impl Default for AttackTimelineCorrelator {
    fn default() -> Self {
        Self::new(DetectorLimits::default())
    }
}

impl AttackTimelineCorrelator {
    pub fn new(limits: DetectorLimits) -> Self {
        let limits = limits.clamp();
        Self {
            events_by_ssid: LruCache::new(limits.ssid_capacity()),
            recent_alerts: LruCache::new(limits.ssid_capacity()),
        }
    }

    /// Records an attack event (karma_probe_response or bssid_spoofing) and returns an
    /// AttackSequenceAlert if both attack types occurred for the same SSID within the
    /// correlation window. Enforces a cooldown per SSID to suppress duplicate alerts.
    pub fn observe(
        &mut self,
        entry: &AuditEntry,
        attack_type: &str,
    ) -> Option<AttackSequenceAlert> {
        if !matches!(attack_type, "karma_probe_response" | "bssid_spoofing") {
            return None;
        }
        let ssid = entry
            .ssid
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())?;
        let observed_at = parse_observed_at(&entry.observed_at).unwrap_or_else(Utc::now);
        let alert_key = SsidKey::new(ssid)?;
        if let Some(last_alert) = self.recent_alerts.get(&alert_key) {
            let delta = observed_at.signed_duration_since(*last_alert);
            let cooldown = chrono::Duration::from_std(ATTACK_SEQUENCE_COOLDOWN).ok()?;
            if delta >= chrono::Duration::zero() && delta < cooldown {
                return None;
            }
        }
        if self.events_by_ssid.get(&alert_key).is_none() {
            self.events_by_ssid.put(alert_key.clone(), VecDeque::new());
        }
        let events = self.events_by_ssid.get_mut(&alert_key)?;
        events.push_back(AttackEvent {
            timestamp: observed_at,
            attack_type: attack_type.to_string(),
        });
        let cutoff =
            observed_at - chrono::Duration::seconds(ATTACK_CORRELATION_WINDOW.as_secs() as i64);
        while events.front().is_some_and(|event| event.timestamp < cutoff) {
            events.pop_front();
        }
        let has_karma = events
            .iter()
            .any(|e| e.attack_type == "karma_probe_response");
        let has_spoofing = events.iter().any(|e| e.attack_type == "bssid_spoofing");
        if has_karma && has_spoofing {
            self.recent_alerts.put(alert_key, observed_at);
            let first = events.iter().map(|e| e.timestamp).min()?;
            let last = events.iter().map(|e| e.timestamp).max()?;
            let mut chain: Vec<_> = events.iter().map(|e| e.attack_type.clone()).collect();
            chain.sort();
            chain.dedup();
            let chain_str = chain.join(", ");
            let _contribution = if has_karma && has_spoofing { 1.0 } else { 0.0 };
            Some(AttackSequenceAlert {
                schema_version: 1,
                event_type: "wireless_attack_sequence".to_string(),
                observed_at: crate::timing::rfc3339_from_utc(observed_at),
                sensor_id: entry.sensor_id.clone(),
                location_id: entry.location_id.clone(),
                ssid: ssid.to_string(),
                attack_chain: chain,
                first_event_at: crate::timing::rfc3339_from_utc(first),
                last_event_at: crate::timing::rfc3339_from_utc(last),
                factor_breakdown: vec![
                    AlertExplanation {
                        factor: "karma_probe_response".to_string(),
                        observed: if has_karma { 1.0 } else { 0.0 },
                        baseline: 0.0,
                        contribution: if has_karma { 0.5 } else { 0.0 },
                    },
                    AlertExplanation {
                        factor: "bssid_spoofing".to_string(),
                        observed: if has_spoofing { 1.0 } else { 0.0 },
                        baseline: 0.0,
                        contribution: if has_spoofing { 0.5 } else { 0.0 },
                    },
                ],
                explanation: vec![format!(
                    "combined_attacks: {} against SSID '{}' within {}s window",
                    chain_str,
                    ssid,
                    ATTACK_CORRELATION_WINDOW.as_secs()
                )],
            })
        } else {
            None
        }
    }
}

pub struct PmfAttackTracker {
    ap_pmf_state: LruCache<MacAddr, bool>,
    client_deauth_times: LruCache<MacAddr, DateTime<Utc>>,
    reconnect_window_ms: i64,
    forced_reconnects: LruCache<(MacAddr, MacAddr), DateTime<Utc>>,
}

impl Default for PmfAttackTracker {
    fn default() -> Self {
        Self::new(3000)
    }
}

impl PmfAttackTracker {
    pub fn new(reconnect_window_ms: i64) -> Self {
        Self::with_limits(reconnect_window_ms, DetectorLimits::default())
    }

    pub fn new_with_limits(reconnect_window_ms: i64, limits: DetectorLimits) -> Self {
        Self::with_limits(reconnect_window_ms, limits)
    }

    fn with_limits(reconnect_window_ms: i64, limits: DetectorLimits) -> Self {
        let limits = limits.clamp();
        Self {
            ap_pmf_state: LruCache::new(limits.mac_capacity()),
            client_deauth_times: LruCache::new(limits.mac_capacity()),
            reconnect_window_ms,
            forced_reconnects: LruCache::new(limits.mac_capacity()),
        }
    }
}
