impl TrafficBucket {
    pub fn new(window_secs: i64) -> Self {
        Self::with_entry_limit(window_secs, DEFAULT_TRAFFIC_BUCKET_MAX_ENTRIES)
    }

    fn with_entry_limit(window_secs: i64, max_entries: usize) -> Self {
        Self {
            window: Duration::seconds(window_secs.max(1)),
            window_start: None,
            wall_clock_start: None,
            entries: HashMap::new(),
            max_entries: max_entries.max(1),
            burst_macs: HashSet::new(),
        }
    }

    /// Returns the set of source MACs that exhibited low inter-arrival CV (< 0.05)
    /// in the most recent drain, indicating automated burst traffic. Clears the
    /// set after returning so each burst set is consumed exactly once.
    pub fn take_burst_macs(&mut self) -> HashSet<String> {
        std::mem::take(&mut self.burst_macs)
    }

    /// Counts raw bytes for frames that cannot be parsed into structured audit entries.
    /// Uses a fixed "unknown" key for source_mac and destination_bssid since the frame
    /// structure is unsupported and no MAC addresses can be extracted.
    pub fn observe_raw(
        &mut self,
        bytes: u64,
        observed_at: DateTime<Utc>,
        sensor_id: &str,
        location_id: &str,
        interface: &str,
        channel: u8,
    ) -> Vec<WirelessBandwidthEvent> {
        let flushed = self.flush_if_elapsed(observed_at);

        if self.window_start.is_none() {
            self.window_start = Some(observed_at);
            self.wall_clock_start = Some(Instant::now());
        }

        // Count raw bytes against unknown bucket for unsupported frames
        let key = TrafficKey {
            sensor_id: sensor_id.to_string(),
            location_id: location_id.to_string(),
            interface: interface.to_string(),
            channel,
            source_mac: "unknown".to_string(),
            destination_bssid: "unknown".to_string(),
            ssid: None,
            external_bssid: false,
        };

        let counters = self.entries.entry(key).or_default();
        counters.bytes = counters.bytes.saturating_add(bytes);
        counters.frame_count = counters.frame_count.saturating_add(1);
        self.enforce_entry_limit();

        flushed
    }

    /// Accumulates frame counters for the current window; when the wall-clock elapsed
    /// time reaches or exceeds the window duration, the old window is flushed and
    /// returned before recording the new observation. The frame `observed_at` timestamp
    /// is used only for window attribution, not for the flush decision.
    pub fn observe(
        &mut self,
        entry: &AuditEntry,
        external_bssid: bool,
    ) -> Result<Vec<WirelessBandwidthEvent>, TrafficBucketError> {
        let observed_at = DateTime::parse_from_rfc3339(&entry.observed_at).map_err(|source| {
            TrafficBucketError::InvalidObservedAt {
                observed_at: entry.observed_at.clone(),
                source,
            }
        })?;
        let observed_at = observed_at.with_timezone(&Utc);
        let flushed = self.flush_if_elapsed(observed_at);
        if !is_bandwidth_candidate(entry) {
            return Ok(flushed);
        }

        if self.window_start.is_none() {
            self.window_start = Some(observed_at);
            self.wall_clock_start = Some(Instant::now());
        }

        let Some(source_mac) = entry.source_mac.as_deref().map(normalize_mac) else {
            return Ok(flushed);
        };
        let Some(destination_bssid) = entry
            .destination_bssid
            .as_deref()
            .or(entry.bssid.as_deref())
            .map(normalize_mac)
        else {
            return Ok(flushed);
        };
        let key = TrafficKey {
            sensor_id: entry.sensor_id.clone(),
            location_id: entry.location_id.clone(),
            interface: entry.interface.clone(),
            channel: entry.channel,
            source_mac,
            destination_bssid,
            ssid: entry.ssid.clone(),
            external_bssid,
        };
        let counters = self.entries.entry(key).or_default();
        counters.bytes = counters.bytes.saturating_add(entry.raw_len as u64);
        counters.frame_count = counters.frame_count.saturating_add(1);
        if entry.retry.unwrap_or(false) {
            counters.retry_count = counters.retry_count.saturating_add(1);
        }
        if entry.more_data.unwrap_or(false) {
            counters.more_data_count = counters.more_data_count.saturating_add(1);
        }
        if entry.power_save.unwrap_or(false) {
            counters.power_save_count = counters.power_save_count.saturating_add(1);
        }
        if let Some(signal) = entry.signal_dbm {
            counters.strongest_signal_dbm = Some(
                counters
                    .strongest_signal_dbm
                    .map(|current| current.max(signal))
                    .unwrap_or(signal),
            );
        }
        if let Some(score) = entry.risk_score {
            counters.max_risk_score = Some(match counters.max_risk_score {
                Some(current) => current.max(score),
                None => score,
            });
        }
        let size = entry.raw_len as u64;
        match size {
            0..=99 => counters.histogram[0] += 1,
            100..=499 => counters.histogram[1] += 1,
            500..=999 => counters.histogram[2] += 1,
            1000..=1500 => counters.histogram[3] += 1,
            _ => {}
        }
        let observed_at_ms = observed_at.timestamp_millis();
        counters.arrival_samples_seen = counters.arrival_samples_seen.saturating_add(1);
        if counters.arrival_times_ms.len() < counters.arrival_reservoir_size {
            counters.arrival_times_ms.push(observed_at_ms);
        } else if counters.arrival_reservoir_size > 0 {
            let sample_index = fastrand::u64(..counters.arrival_samples_seen);
            if sample_index < counters.arrival_reservoir_size as u64 {
                counters.arrival_times_ms[sample_index as usize] = observed_at_ms;
            }
        }
        self.enforce_entry_limit();
        Ok(flushed)
    }

    /// Timer-triggered flush: drains the current window unconditionally and resets
    /// both wall-clock and frame-time starts. Sets `window_is_partial = true` since
    /// this is not driven by an incoming frame crossing the boundary.
    pub fn flush_current(&mut self) -> Vec<WirelessBandwidthEvent> {
        let Some(window_start) = self.window_start.take() else {
            return Vec::new();
        };
        let _ = self.wall_clock_start.take();
        let wall_clock_delta_ms = (Utc::now() - window_start).num_milliseconds();
        self.drain_window(window_start, wall_clock_delta_ms, true)
    }

    /// Checks if the wall-clock elapsed time has reached the window duration; if so,
    /// advances both the wall-clock and frame-time starts, then drains all accumulated
    /// counters into events. The `observed_at` parameter is used for attribution
    /// (setting the new `window_start`), but the flush decision is based on wall clock.
    fn flush_if_elapsed(&mut self, observed_at: DateTime<Utc>) -> Vec<WirelessBandwidthEvent> {
        let Some(window_start) = self.window_start else {
            self.window_start = Some(observed_at);
            self.wall_clock_start = Some(Instant::now());
            return Vec::new();
        };
        let Some(wall_clock_start) = self.wall_clock_start else {
            // Should not happen if window_start is Some, but be defensive.
            self.window_start = Some(observed_at);
            self.wall_clock_start = Some(Instant::now());
            return Vec::new();
        };

        // Convert chrono::Duration to std::time::Duration for comparison.
        let window_std = match self.window.to_std() {
            Ok(d) => d,
            Err(_) => {
                // Negative or zero duration should not happen (new() clamps to >= 1),
                // but if it does, treat as elapsed.
                let delta = (Utc::now() - window_start).num_milliseconds();
                self.window_start = Some(observed_at);
                self.wall_clock_start = Some(Instant::now());
                return self.drain_window(window_start, delta, false);
            }
        };

        if wall_clock_start.elapsed() >= window_std {
            let delta = (Utc::now() - window_start).num_milliseconds();
            self.window_start = Some(observed_at);
            self.wall_clock_start = Some(Instant::now());
            self.drain_window(window_start, delta, false)
        } else {
            Vec::new()
        }
    }

    /// Drains all accumulated counters into bandwidth events and clears the entries map.
    fn drain_window(
        &mut self,
        window_start: DateTime<Utc>,
        wall_clock_delta_ms: i64,
        window_is_partial: bool,
    ) -> Vec<WirelessBandwidthEvent> {
        let window_end = window_start + self.window;
        // Cap at Utc::now() to avoid future timestamps from clock skew.
        let window_end = window_end.min(Utc::now());
        self.burst_macs.clear();
        let mut events = Vec::with_capacity(self.entries.len());
        for (key, counters) in self.entries.drain() {
            let inter_arrival_p50_ms = calculate_p50_inter_arrival(&counters.arrival_times_ms);
            let inter_arrival_cv = calculate_inter_arrival_cv(&counters.arrival_times_ms);
            // Track source MACs with very low CV - they indicate automated burst traffic.
            if let Some(cv) = inter_arrival_cv {
                if cv < 0.05 {
                    self.burst_macs.insert(key.source_mac.clone());
                }
            }
            events.push(WirelessBandwidthEvent {
                schema_version: 1,
                event_type: "wireless_bandwidth_window".to_string(),
                window_start: ssl_proxy::time::rfc3339_from_utc(window_start),
                window_end: ssl_proxy::time::rfc3339_from_utc(window_end),
                sensor_id: key.sensor_id,
                location_id: key.location_id,
                interface: key.interface,
                channel: key.channel,
                source_mac: key.source_mac,
                destination_bssid: key.destination_bssid,
                ssid: key.ssid,
                bytes: counters.bytes,
                frame_count: counters.frame_count,
                retry_count: counters.retry_count,
                more_data_count: counters.more_data_count,
                power_save_count: counters.power_save_count,
                strongest_signal_dbm: counters.strongest_signal_dbm,
                external_bssid: key.external_bssid,
                threshold_exceeded: key.external_bssid
                    && counters.bytes > EXTERNAL_BANDWIDTH_THRESHOLD_BYTES,
                frame_size_histogram: FrameSizeHistogram {
                    under_100: counters.histogram[0],
                    range_100_500: counters.histogram[1],
                    range_500_1000: counters.histogram[2],
                    range_1000_1500: counters.histogram[3],
                },
                inter_arrival_p50_ms,
                inter_arrival_cv,
                wall_clock_delta_ms: Some(wall_clock_delta_ms),
                window_is_partial,
                max_risk_score: counters.max_risk_score,
                published_at: None,
            });
        }
        events
    }

    fn enforce_entry_limit(&mut self) {
        if self.entries.len() <= self.max_entries {
            return;
        }

        warn!(
            entry_count = self.entries.len(),
            limit = self.max_entries,
            "traffic bucket entry limit reached; entry dropped"
        );
        if let Some(drop_key) = self.entries.keys().next().cloned() {
            self.entries.remove(&drop_key);
        }
    }
}

fn is_bandwidth_candidate(entry: &AuditEntry) -> bool {
    entry.event_type == "wifi_data_frame"
        && entry.protected.unwrap_or(false)
        && entry.raw_len > 0
        && entry.source_mac.is_some()
        && (entry.destination_bssid.is_some() || entry.bssid.is_some())
}

fn normalize_mac(value: &str) -> String {
    value.trim().to_ascii_lowercase()
}

fn calculate_p50_inter_arrival(times_ms: &[i64]) -> Option<u64> {
    if times_ms.len() < 2 {
        return None;
    }
    let mut sorted_times = times_ms.to_vec();
    sorted_times.sort_unstable();
    let mut intervals: Vec<u64> = sorted_times
        .windows(2)
        .filter_map(|w| {
            let delta = w[1] - w[0];
            if delta >= 0 {
                Some(delta as u64)
            } else {
                None
            }
        })
        .collect();
    if intervals.is_empty() {
        return None;
    }
    intervals.sort_unstable();
    Some(intervals[intervals.len() / 2])
}

/// Computes the coefficient of variation (CV = stddev / mean) of inter-arrival
/// intervals from a reservoir of arrival timestamps (millisecond epoch values).
/// Returns `None` when there are fewer than 2 timestamps.
fn calculate_inter_arrival_cv(times_ms: &[i64]) -> Option<f64> {
    if times_ms.len() < 2 {
        return None;
    }
    let mut sorted = times_ms.to_vec();
    sorted.sort_unstable();
    let intervals: Vec<u64> = sorted
        .windows(2)
        .filter_map(|w| {
            let delta = w[1] - w[0];
            if delta >= 0 {
                Some(delta as u64)
            } else {
                None
            }
        })
        .collect();
    if intervals.len() < 2 {
        return None;
    }
    let n = intervals.len() as f64;
    let sum: u64 = intervals.iter().sum();
    let mean = sum as f64 / n;
    if mean <= 0.0 {
        return None;
    }
    let variance = intervals
        .iter()
        .map(|v| {
            let diff = *v as f64 - mean;
            diff * diff
        })
        .sum::<f64>()
        / n;
    let stddev = variance.sqrt();
    Some(stddev / mean)
}
