/// Hot path: decodes raw packet -> extracts handshake -> resolves identity -> checks
/// authorized network -> tags threats -> enriches with MAC device lookup -> observes
/// bandwidth -> publishes to Redpanda.
async fn process_packet(
    packet: RawPacket,
    context: &AuditContext,
    config: &AppConfig,
    backlog: &RedpandaBacklog,
    publish_client: &dyn PublishClient,
    publish_state: &SharedPublishState,
    current_filter: &SharedFilter,
    pipeline: &mut PipelineState,
    stats: &metrics::SharedStats,
    authorized_config_generation: &AtomicU64,
    capture_control: &CaptureControl,
    inline_request_reply_enabled: bool,
) -> Result<PipelineOutcome, SensorError> {
    let packet_len = packet.data.len() as u64;

    let mut wifi_frame = match decode_frame(&packet) {
        Ok(frame) => frame,
        Err(error) => {
            trace!(
                error = %error,
                packet_len,
                first_bytes = %hex_prefix(&packet.data, 8),
                observed_at = %packet.observed_at,
                "unsupported frame -- bytes counted to raw bucket"
            );
            match &error {
                ParseError::UnsupportedControlFrame => {
                    stats.increment_unsupported_frames();
                }
                _ => {
                    stats.increment_malformed_frames();
                    debug!(
                        error = %error,
                        packet_len,
                        first_bytes = %hex_prefix(&packet.data, 8),
                        "malformed 802.11 frame dropped"
                    );
                }
            }
            pipeline.traffic_bucket.observe_raw(
                packet_len,
                packet.observed_at,
                &context.sensor_id,
                &context.location_id,
                &context.interface,
                context.channel,
            );
            return Ok(PipelineOutcome::UnsupportedFrame);
        }
    };

    // For successfully decoded frames we will get proper classification
    // via the existing traffic_bucket.observe() call below

    let handshake_export_dir = config
        .export_handshakes
        .then_some(config.sync.outbox_dir.as_str());
    let handshake_ttl = Duration::from_secs(config.handshake_ttl_secs);
    let restore_filter = filter_snapshot(current_filter, &config.bpf);
    let handshake_alert = pipeline.handshake_monitor.observe(
        &mut wifi_frame,
        context,
        handshake_export_dir,
        Some(capture_control),
        &restore_filter,
        handshake_ttl,
    );
    let latest_generation = authorized_config_generation.load(Ordering::Relaxed);
    if latest_generation != pipeline.seen_authorized_config_generation {
        pipeline.authorized_network_cache.invalidate();
        pipeline.rogue_ap_tracker.clear_typosquat_cache();
        pipeline.seen_authorized_config_generation = latest_generation;
    }
    if inline_request_reply_enabled {
        let refresh_result = pipeline
            .authorized_network_cache
            .refresh_if_needed(
                backlog,
                Duration::from_secs(config.authorized_network_cache_ttl_secs),
            )
            .await;
        if refresh_result.is_err() && pipeline.authorized_network_cache.should_log_failure(true) {
            warn!(
                error = %refresh_result.as_ref().unwrap_err(),
                "authorized wireless network cache refresh failed"
            );
        } else if refresh_result.is_ok() {
            pipeline.authorized_network_cache.should_log_failure(false);
        }
    }
    if try_decrypt_frame(
        &mut wifi_frame,
        &pipeline.handshake_monitor,
        pipeline.authorized_network_cache.entries(),
    ) {
        debug!("protected data frame decrypted using authorized network PSK");
    }
    pipeline
        .timing_tracker
        .attach_deltas(&mut wifi_frame, config.clock_skew_anomaly_us);
    let resolved_identity = pipeline.identity_cache.resolve(&wifi_frame);
    let enriched: EnrichedFrame = attach_context(wifi_frame, context);
    let mut entry = to_audit_entry(enriched);
    let frame_id = pipeline.allocate_frame_id();
    let detector_lane = pipeline
        .detector_router
        .lane_for(detector_route_key(&entry));
    trace!(
        frame_id,
        detector_lane,
        detector_lanes = pipeline.detector_router.lanes(),
        detector_queue_capacity = pipeline.detector_router.queue_capacity(),
        "decoded frame assigned to detector route"
    );
    if let Some(alert) = handshake_alert.as_ref() {
        if let Err(error) = publish_handshake_alert(publish_client, alert).await {
            warn!(%error, "handshake alert publish failed; continuing audit publish");
        }
    }
    if let Some(identity) = resolved_identity {
        entry.username = Some(identity.username);
        entry.identity_source = identity.source;
        entry.tags.extend(identity.tags);
    }
    let authorization_status = pipeline.authorized_network_cache.authorization_status(
        entry.ssid.as_deref(),
        entry
            .bssid
            .as_deref()
            .or(entry.destination_bssid.as_deref()),
        &entry.location_id,
    );
    let is_authorized_network = pipeline.authorized_network_cache.is_authorized(
        entry.ssid.as_deref(),
        entry
            .bssid
            .as_deref()
            .or(entry.destination_bssid.as_deref()),
        &entry.location_id,
    );
    let external_bssid =
        authorization_status == AuthorizationStatus::Unauthorized && !is_authorized_network;
    if entry.ssid.is_some() && authorization_status == AuthorizationStatus::Unauthorized {
        entry.tags.push("threat:unauthorized_bssid".to_string());
    } else if entry.ssid.is_some() && authorization_status == AuthorizationStatus::Unknown {
        entry
            .tags
            .push("enrichment:authorized_network_unknown".to_string());
    }
    pipeline
        .ie_layout_tracker
        .observe(&mut entry, authorization_status);
    pipeline.mac_sequence_delta_tracker.observe(&mut entry);
    pipeline.client_inventory.observe(&mut entry);
    if let Some(alert) = pipeline.sequence_tracker.observe(&entry) {
        if let Err(error) = publish_oracle_json_durable(
            publish_state,
            backlog,
            publish_client,
            "publish_sequence_alert",
            SEQUENCE_ALERT_TOPIC,
            &alert,
            &alert.observed_at,
        )
        .await
        {
            warn!(%error, "sequence alert publish failed");
        }
    }

    if entry.frame_subtype == "probe_request" {
        pipeline.probe_accumulator.observe(
            &entry,
            &pipeline.client_inventory,
            &pipeline.authorized_network_cache,
        );
        stats.set_probe_accumulator_len(pipeline.probe_accumulator.len());
    }

    if pipeline.probe_accumulator.should_flush_early() {
        for batch in pipeline.probe_accumulator.take_ready_batches() {
            match flush_probe_batch(backlog, batch).await {
                Ok(probe_count) => debug!(probe_count, "probe batch flushed"),
                Err((batch, error)) => {
                    warn!(
                        %error,
                        probe_count = batch.len(),
                        "probe batch early flush failed; retaining priority half to prevent unbounded growth"
                    );
                    pipeline.probe_accumulator.restore_priority_half(batch);
                }
            }
            stats.set_probe_accumulator_len(pipeline.probe_accumulator.len());
        }
    }
    if entry
        .tags
        .iter()
        .any(|tag| tag == "threat:karma_probe_response")
    {
        if let Some(alert) = pipeline
            .attack_timeline_correlator
            .observe(&entry, "karma_probe_response")
        {
            if let Err(error) = publish_oracle_json_durable(
                publish_state,
                backlog,
                publish_client,
                "publish_attack_sequence_alert",
                ATTACK_SEQUENCE_TOPIC,
                &alert,
                &alert.observed_at,
            )
            .await
            {
                warn!(%error, "attack sequence alert publish failed");
            }
        }
    }
    if let Some(alert) = pipeline
        .signal_tracker
        .observe(&entry, config.signal_anomaly_dbm_delta)
    {
        entry.tags.push("threat:signal_anomaly".to_string());
        entry.anomaly_reasons.push("signal_anomaly".to_string());
        if let Err(error) = publish_oracle_json_durable(
            publish_state,
            backlog,
            publish_client,
            "publish_signal_anomaly_alert",
            SIGNAL_ANOMALY_TOPIC,
            &alert,
            &alert.observed_at,
        )
        .await
        {
            warn!(%error, "signal anomaly alert publish failed");
        }
    }
    if let Some(alert) = pipeline
        .rogue_ap_tracker
        .observe(&entry, &pipeline.authorized_network_cache)
    {
        if alert
            .reasons
            .iter()
            .any(|reason| reason == "bssid_spoofing")
        {
            if let Some(sequence_alert) = pipeline
                .attack_timeline_correlator
                .observe(&entry, "bssid_spoofing")
            {
                if let Err(error) = publish_oracle_json_durable(
                    publish_state,
                    backlog,
                    publish_client,
                    "publish_attack_sequence_alert",
                    ATTACK_SEQUENCE_TOPIC,
                    &sequence_alert,
                    &sequence_alert.observed_at,
                )
                .await
                {
                    warn!(%error, "attack sequence alert publish failed");
                }
            }
        }
        if let Err(error) = publish_oracle_json_durable(
            publish_state,
            backlog,
            publish_client,
            "publish_rogue_ap_alert",
            ROGUE_AP_TOPIC,
            &alert,
            &alert.observed_at,
        )
        .await
        {
            warn!(%error, "rogue AP alert publish failed");
        }
    }
    if let Some(alert) = pipeline.deauth_flood_tracker.observe(
        &entry,
        config.deauth_flood_threshold,
        config.deauth_flood_window_secs,
        config.deauth_flood_cooldown_secs,
    ) {
        if let Err(error) = publish_oracle_json_durable(
            publish_state,
            backlog,
            publish_client,
            "publish_deauth_flood_alert",
            DEAUTH_FLOOD_TOPIC,
            &alert,
            &alert.observed_at,
        )
        .await
        {
            warn!(%error, "deauth flood alert publish failed");
        }
    }
    let mut pmf_tags = Vec::new();
    pipeline.pmf_attack_tracker.observe(&entry, &mut pmf_tags);
    for tag in &pmf_tags {
        if let Some(alert) =
            pmf_attack_alert_from_entry(&entry, tag, pipeline.pmf_reconnect_window_ms)
        {
            if let Err(error) = publish_oracle_json_durable(
                publish_state,
                backlog,
                publish_client,
                "publish_pmf_attack_alert",
                PMF_ATTACK_TOPIC,
                &alert,
                &alert.observed_at,
            )
            .await
            {
                warn!(%error, "PMF attack alert publish failed");
            }
        }
    }
    entry.tags.extend(pmf_tags);
    // Backpressure guard: if the memory backlog is >80% full, skip the MAC device lookup
    // (which adds async I/O per packet) to prevent the backlog from growing further.
    let backlog_pct = {
        let ps = publish_state.lock().unwrap();
        let capacity = ps.memory_backlog_capacity().get();
        if capacity > 0 {
            ps.memory_backlog_len() * 100 / capacity
        } else {
            0
        }
    };
    let skip_mac_lookup =
        backlog_pct > 80 || !config.mac_device_lookup_enabled || !inline_request_reply_enabled;
    if skip_mac_lookup {
        if entry.identity_source.is_mac_lookup_pending() {
            entry.identity_source = if !config.mac_device_lookup_enabled || !inline_request_reply_enabled {
                IdentitySource::MacLookupDisabled
            } else {
                IdentitySource::MacLookupSkippedBackpressure
            };
        }
    } else if let Some(mac) = entry.source_mac.clone().or_else(|| entry.bssid.clone()) {
        let cache_key = mac.to_ascii_lowercase();
        let lookup = match pipeline.device_registry_cache.lookup_decision(
            &cache_key,
            Duration::from_secs(config.mac_lookup_error_ttl_secs),
        ) {
            DeviceRegistryCacheDecision::UseCached(lookup) => lookup,
            DeviceRegistryCacheDecision::SkipRecentFailure => None,
            DeviceRegistryCacheDecision::Fetch => {
                match backlog.lookup_device_by_mac(&cache_key).await {
                    Ok(lookup) => {
                        pipeline
                            .device_registry_cache
                            .remember_success(cache_key.clone(), lookup.clone());
                        lookup
                    }
                    Err(error) => {
                        stats.increment_mac_lookup_failures();
                        pipeline
                            .device_registry_cache
                            .remember_failure(cache_key.clone());
                        warn!(%error, mac = %cache_key, "MAC device lookup failed; publishing unenriched audit entry");
                        None
                    }
                }
            }
        };
        if let Some((device_id, username)) = lookup {
            entry.device_id = Some(device_id);
            if entry.username.is_none() {
                entry.username = username;
            }
            if entry.identity_source.is_mac_lookup_pending() {
                entry.identity_source = IdentitySource::DeviceRegistry;
            }
        }
    }
    // First, let the traffic bucket observe the current frame so it can
    // compute risk scores and detect low-CV burst traffic. Then obtain
    // burst MACs from the *previous* drain window for tagging.
    let bandwidth_events = match pipeline.traffic_bucket.observe(&entry, external_bssid) {
        Ok(events) => events,
        Err(error) => {
            error!(
                %error,
                frame_subtype = %entry.frame_subtype,
                observed_at = %entry.observed_at,
                sensor_id = %entry.sensor_id,
                "bandwidth bucket rejected frame -- timestamp unparseable; frame not counted"
            );
            Vec::new()
        }
    };
    let burst_macs = pipeline.traffic_bucket.take_burst_macs();
    // Tag the current frame if its source MAC had a low CV in the drained window.
    if let Some(ref src_mac) = entry.source_mac {
        let normalized = src_mac.trim().to_ascii_lowercase();
        if burst_macs.contains(&normalized)
            && !entry.tags.contains(&"threat:burst_automated".to_string())
        {
            entry.tags.push("threat:burst_automated".to_string());
        }
    }
    publish_bandwidth_events(publish_state, backlog, publish_client, bandwidth_events).await;
    info!(
        target: "wireless_audit",
        event_type = %entry.event_type,
        frame_subtype = %entry.frame_subtype,
        bssid = ?entry.bssid,
        ssid = ?entry.ssid,
        "captured wifi frame"
    );
    entry.risk_score = crate::parse::recompute_risk_score(&entry.tags);
    match publish_entry(publish_state, backlog, publish_client, entry).await {
        Ok(()) | Err(PublishError::Queued(_)) => {}
        Err(error) => return Err(error.into()),
    }
    Ok(PipelineOutcome::DecodedFrame)
}
