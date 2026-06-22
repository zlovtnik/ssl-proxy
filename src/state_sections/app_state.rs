impl AppState {
    pub fn new(
        client: crate::proxy::ProxyClient,
        resolver: hickory_resolver::TokioAsyncResolver,
        stats_tx: broadcast::Sender<String>,
        events_tx: broadcast::Sender<String>,
        config: crate::config::Config,
    ) -> SharedState {
        let seed = SEED.iter().map(|s| s.to_string()).collect();
        Arc::new(Self {
            client,
            resolver,
            stats_tx,
            events_tx,
            bytes_up: AtomicU64::new(0),
            bytes_down: AtomicU64::new(0),
            active_tunnels: AtomicU64::new(0),
            tunnels_opened: AtomicU64::new(0),
            blocked_count: AtomicU64::new(0),
            allowed_count: AtomicU64::new(0),
            obfuscated_count: AtomicU64::new(0),
            host_stats_dropped: AtomicU64::new(0),
            blocklist: ArcSwap::from_pointee(seed),
            host_stats: DashMap::new(),
            peer_counters: DashMap::new(),
            bandwidth_cursors: DashMap::new(),
            bandwidth_cursor_snapshot_lock: Mutex::new(()),
            wg_peers: ArcSwap::from_pointee(WgPeersSnapshot::default()),
            devices: DashMap::new(),
            claim_tokens: DashMap::new(),
            device_claims: DashMap::new(),
            tarpit_sem: crate::tunnel::tarpit_semaphore(config.proxy.tarpit_max_connections),
            dns_cache: DashMap::new(),
            dns_negative_cache: DashMap::new(),
            ptr_cache: DashMap::new(),
            publisher: std::sync::Arc::new(sync_plane::SyncPublisher::new(&config.sync)),
            forensic: crate::forensic::ForensicState::new(config.proxy.forensic_sentry_enabled),
            wg_relay_metrics: Arc::new(crate::wg_relay::RelayMetrics::default()),
            event_dedup: DashMap::new(),
            dashboard_event_queue: Mutex::new(VecDeque::with_capacity(
                DASHBOARD_EVENT_QUEUE_CAPACITY,
            )),
            config,

            last_bytes_up: AtomicU64::new(0),
            last_bytes_down: AtomicU64::new(0),
            last_sample_instant: Mutex::new(Instant::now()),
        })
    }

    pub fn dashboard_event_queue_len(&self) -> usize {
        self.dashboard_event_queue.lock().unwrap().len()
    }

    pub fn should_emit_deduped_event(
        &self,
        event_name: &str,
        host: &str,
        peer_ip: Option<&str>,
        wg_pubkey: Option<&str>,
        device_id: Option<&str>,
    ) -> bool {
        let now = Instant::now();
        if self.event_dedup.len() >= EVENT_DEDUP_MAX_KEYS {
            let expired = self
                .event_dedup
                .iter()
                .filter_map(|entry| {
                    (now.duration_since(*entry.value()) >= EVENT_DEDUP_WINDOW)
                        .then(|| entry.key().clone())
                })
                .collect::<Vec<_>>();
            for key in expired {
                self.event_dedup.remove(&key);
            }
        }
        if self.event_dedup.len() >= EVENT_DEDUP_MAX_KEYS {
            return false;
        }

        let key = format!(
            "{}|{}|{}|{}|{}",
            event_name,
            host,
            peer_ip.unwrap_or(""),
            wg_pubkey.unwrap_or(""),
            device_id.unwrap_or("")
        );

        if let Some(mut seen_at) = self.event_dedup.get_mut(&key) {
            if now.duration_since(*seen_at) < EVENT_DEDUP_WINDOW {
                return false;
            }
            *seen_at = now;
            return true;
        }

        self.event_dedup.insert(key, now);
        true
    }

    pub fn queue_dashboard_event(&self, raw: &str, event_name: &str, host: &str) {
        let mut queue = self.dashboard_event_queue.lock().unwrap();
        if queue.len() >= DASHBOARD_EVENT_QUEUE_CAPACITY {
            if let Some(dropped) = queue.pop_front() {
                warn!(
                    dropped_event_name = %dropped.event_name,
                    dropped_host = %dropped.host,
                    "dashboard event retry queue full; dropping oldest queued event"
                );
            }
        }

        queue.push_back(DashboardEventRetry {
            raw: raw.to_string(),
            event_name: event_name.to_string(),
            host: host.to_string(),
            attempt_count: 0,
        });

        warn!(
            event_name = event_name,
            %host,
            queue_len = queue.len(),
            "dashboard event broadcast failed; queued for retry"
        );
    }

    pub fn flush_dashboard_event_queue(&self) {
        let mut pending = std::mem::take(&mut *self.dashboard_event_queue.lock().unwrap());
        if pending.is_empty() {
            return;
        }

        let mut remaining = VecDeque::with_capacity(pending.len());
        while let Some(mut event) = pending.pop_front() {
            if self.events_tx.send(event.raw.clone()).is_ok() {
                continue;
            }

            event.attempt_count = event.attempt_count.saturating_add(1);
            if event.attempt_count >= DASHBOARD_EVENT_MAX_RETRY_ATTEMPTS {
                error!(
                    event_name = %event.event_name,
                    host = %event.host,
                    attempt_count = event.attempt_count,
                    "dashboard event delivery failed after retry limit; event dropped"
                );
            } else {
                remaining.push_back(event);
            }
        }

        let mut queue = self.dashboard_event_queue.lock().unwrap();
        let mut new_queue = std::mem::take(&mut *queue);
        remaining.append(&mut new_queue);
        *queue = remaining;
    }

    #[allow(dead_code)]
    pub fn record_tunnel_open(&self) {
        self.record_tunnel_open_for_peer(None);
    }

    pub fn record_tunnel_open_for_peer(&self, wg_pubkey: Option<&str>) {
        self.active_tunnels.fetch_add(1, Ordering::Relaxed);
        self.tunnels_opened.fetch_add(1, Ordering::Relaxed);
        if let Some(key) = wg_pubkey {
            let counters = self.peer_counters.entry(key.to_string()).or_default();
            counters.sessions_open.fetch_add(1, Ordering::Relaxed);
            counters.touch();
        }
    }

    pub fn snapshot_and_swap_bandwidth_cursor(
        &self,
        wg_pubkey: &str,
    ) -> (BandwidthCursor, BandwidthCursor, u64) {
        let _guard = self
            .bandwidth_cursor_snapshot_lock
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());

        let (current, sessions_active) = self
            .peer_counters
            .get(wg_pubkey)
            .map(|value| {
                (
                    BandwidthCursor {
                        bytes_up: value.bytes_up.load(Ordering::Relaxed),
                        bytes_down: value.bytes_down.load(Ordering::Relaxed),
                        blocked_bytes_approx: value.blocked_bytes_approx.load(Ordering::Relaxed),
                        allowed_bytes: value.allowed_bytes.load(Ordering::Relaxed),
                        blocked_count: value.blocked_count.load(Ordering::Relaxed),
                        allowed_count: value.allowed_count.load(Ordering::Relaxed),
                    },
                    value.sessions_open.load(Ordering::Relaxed),
                )
            })
            .unwrap_or_default();
        let previous = self
            .bandwidth_cursors
            .insert(wg_pubkey.to_string(), current)
            .unwrap_or_default();
        (current, previous, sessions_active)
    }

    #[allow(dead_code)]
    pub fn record_tunnel_close(&self, up: u64, down: u64) {
        self.record_tunnel_close_for_peer(None, up, down);
    }

    pub fn record_tunnel_close_for_peer(&self, wg_pubkey: Option<&str>, up: u64, down: u64) {
        self.bytes_up.fetch_add(up, Ordering::Relaxed);
        self.bytes_down.fetch_add(down, Ordering::Relaxed);
        self.active_tunnels
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |v| {
                Some(v.saturating_sub(1))
            })
            .ok();

        if let Some(counters) = wg_pubkey.and_then(|key| self.peer_counters.get(key)) {
            counters.bytes_up.fetch_add(up, Ordering::Relaxed);
            counters.bytes_down.fetch_add(down, Ordering::Relaxed);
            counters
                .allowed_bytes
                .fetch_add(up + down, Ordering::Relaxed);
            counters.allowed_count.fetch_add(1, Ordering::Relaxed);
            counters
                .sessions_open
                .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |v| {
                    Some(v.saturating_sub(1))
                })
                .ok();
            counters.touch();
        }
    }

    pub fn record_blocked(&self) {
        self.blocked_count.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_allowed(&self) {
        self.allowed_count.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_peer_block(&self, wg_pubkey: Option<&str>, approx_bytes: u64) {
        if let Some(key) = wg_pubkey {
            let counters = self.peer_counters.entry(key.to_string()).or_default();
            counters
                .blocked_bytes_approx
                .fetch_add(approx_bytes, Ordering::Relaxed);
            counters.blocked_count.fetch_add(1, Ordering::Relaxed);
            counters.touch();
        }
    }

    pub fn record_host_block(
        &self,
        host: &str,
        connect_header_bytes: u64,
        category: &'static str,
    ) -> Option<(&'static str, &'static str)> {
        const MAX_TRACKED_HOSTS: usize = 100_000;
        let now = Instant::now();
        if let Some(mut s) = self.host_stats.get_mut(host) {
            let iat = now.duration_since(s.last_seen).as_millis() as u64;
            s.observe_iat(iat);
            s.blocked_attempts += 1;
            s.blocked_bytes_approx += connect_header_bytes;
            s.last_seen = now;
            s.category = category;
            s.consecutive_blocks = s.consecutive_blocks.saturating_add(1);
            let prev = s.last_verdict;
            let next = s.verdict();
            if prev != next {
                s.last_verdict = next;
                return Some((prev, next));
            }
            None
        } else if self.host_stats.len() < MAX_TRACKED_HOSTS {
            self.host_stats
                .entry(host.to_string())
                .or_insert_with(|| HostStats::new(connect_header_bytes, category));
            None
        } else {
            warn!(%host, count = self.host_stats.len(), "MAX_TRACKED_HOSTS limit reached, dropping host statistics");
            self.host_stats_dropped.fetch_add(1, Ordering::Relaxed);
            None
        }
    }

    pub fn record_host_allow(&self, host: &str) {
        if let Some(mut s) = self.host_stats.get_mut(host) {
            s.consecutive_blocks = 0;
            s.low_jitter_streak = 0;
        }
    }

    pub fn record_host_reason(&self, host: &str, reason: &'static str) {
        if let Some(mut s) = self.host_stats.get_mut(host) {
            s.last_reason = Some(reason);
        }
    }

    pub fn record_tls_fingerprint(
        &self,
        host: &str,
        tls_ver: Option<String>,
        alpn: Option<String>,
        cipher_suites_count: Option<u8>,
        ja3_lite: Option<String>,
    ) {
        if let Some(mut s) = self.host_stats.get_mut(host) {
            s.tls_ver = tls_ver;
            s.alpn = alpn;
            s.cipher_suites_count = cipher_suites_count;
            s.ja3_lite = ja3_lite;
        }
    }

    pub fn record_resolved(&self, host: &str, resolved_ips: Vec<String>, asn_org: Option<String>) {
        if let Some(mut s) = self.host_stats.get_mut(host) {
            s.resolved_ip = resolved_ips.first().cloned();
            s.asn_org = asn_org.clone();
        }
        self.dns_cache.insert(
            host.to_string(),
            ResolvedMeta {
                resolved_at: Instant::now(),
                resolved_ips,
                ptr_hostname: None,
                asn_org,
            },
        );
    }

    pub fn record_peer_hostname(&self, peer_ip: &str, hostname: Option<String>) {
        self.ptr_cache.insert(
            peer_ip.to_string(),
            ResolvedMeta {
                resolved_at: Instant::now(),
                resolved_ips: vec![peer_ip.to_string()],
                ptr_hostname: hostname,
                asn_org: None,
            },
        );
    }

    pub fn record_tarpit_held(&self, host: &str, held_ms: u64) {
        if let Some(mut s) = self.host_stats.get_mut(host) {
            s.tarpit_held_ms = s.tarpit_held_ms.saturating_add(held_ms);
        }
    }

    pub fn evict_stale_hosts(&self, ttl_secs: u64) {
        self.host_stats
            .retain(|_, v| v.last_seen.elapsed().as_secs() < ttl_secs);
    }

    pub fn evict_stale_dns_entries(&self, ttl_secs: u64) {
        self.dns_cache
            .retain(|_, v| v.resolved_at.elapsed().as_secs() < ttl_secs);
        self.ptr_cache
            .retain(|_, v| v.resolved_at.elapsed().as_secs() < ttl_secs);
        self.dns_negative_cache
            .retain(|_, v| v.elapsed().as_secs() < ttl_secs);
    }

    pub fn evict_expired_claims(&self) {
        self.device_claims.retain(|_, claim| claim.active());
    }

    pub fn upsert_device(&self, device: DeviceInfo) {
        if let Some(hash) = device.claim_token_hash.as_ref() {
            self.claim_tokens
                .insert(hash.clone(), device.device_id.clone());
        }
        self.devices.insert(device.device_id.clone(), device);
    }

    pub fn find_device_by_claim_hash(&self, claim_token_hash: &str) -> Option<DeviceInfo> {
        let device_id = self.claim_tokens.get(claim_token_hash)?.clone();
        self.devices.get(&device_id).map(|entry| entry.clone())
    }

    pub fn list_devices(&self, wg_pubkey: Option<&str>) -> Vec<DeviceInfo> {
        let mut devices: Vec<_> = self
            .devices
            .iter()
            .filter(|entry| {
                wg_pubkey
                    .map(|key| entry.wg_pubkey.as_deref() == Some(key))
                    .unwrap_or(true)
            })
            .map(|entry| entry.clone())
            .collect();
        devices.sort_by(|a, b| b.last_seen.cmp(&a.last_seen));
        devices
    }

    pub fn get_device(&self, device_id: &str) -> Option<DeviceInfo> {
        self.devices.get(device_id).map(|entry| entry.clone())
    }

    pub fn wg_peers_snapshot(&self) -> Arc<WgPeersSnapshot> {
        self.wg_peers.load_full()
    }

    pub fn resolve_wg_pubkey(&self, peer_ip: Option<&str>) -> Option<String> {
        let peer_ip = peer_ip?;
        let wg_peers = self.wg_peers_snapshot();
        wg_peers.pubkey_by_ip.get(peer_ip).cloned()
    }

    pub fn refresh_claim(
        &self,
        device_id: &str,
        wg_pubkey: &str,
        peer_ip: &str,
    ) -> Option<DeviceClaim> {
        let ttl = Duration::from_secs(self.config.runtime.device_claim_ttl_secs);
        let now = crate::time::now_eastern();
        let claim = DeviceClaim {
            device_id: device_id.to_string(),
            wg_pubkey: wg_pubkey.to_string(),
            peer_ip: peer_ip.to_string(),
            claimed_at: now.to_rfc3339(),
            expires_at: (now + chrono::Duration::seconds(ttl.as_secs() as i64)).to_rfc3339(),
            expires_instant: Instant::now() + ttl,
        };
        self.device_claims
            .insert(format!("{wg_pubkey}|{peer_ip}"), claim.clone());
        Some(claim)
    }

    pub fn find_claim(
        &self,
        wg_pubkey: Option<&str>,
        peer_ip: Option<&str>,
    ) -> Option<DeviceClaim> {
        let key = format!("{}|{}", wg_pubkey?, peer_ip?);
        let claim = self.device_claims.get(&key)?;
        if claim.active() {
            Some(claim.clone())
        } else {
            drop(claim);
            self.device_claims.remove(&key);
            None
        }
    }

    pub fn refresh_wg_peers(&self, peers: &[WgPeerSnapshot]) {
        let mut inventory = HashMap::with_capacity(peers.len());
        let mut pubkey_by_ip = HashMap::new();

        for peer in peers {
            if let Some(ip) = peer.peer_ip.as_ref() {
                pubkey_by_ip.insert(ip.clone(), peer.wg_pubkey.clone());
            }
            for allowed_ip in &peer.allowed_ips {
                if let Some((ip, _mask)) = allowed_ip.split_once('/') {
                    pubkey_by_ip.insert(ip.to_string(), peer.wg_pubkey.clone());
                }
            }
            inventory.insert(peer.wg_pubkey.clone(), peer.clone());

            let counters = self
                .peer_counters
                .entry(peer.wg_pubkey.clone())
                .or_default();
            counters
                .wg_rx_bytes
                .store(peer.rx_bytes_total, Ordering::Relaxed);
            counters
                .wg_tx_bytes
                .store(peer.tx_bytes_total, Ordering::Relaxed);
            counters.touch();
        }

        self.wg_peers.store(Arc::new(WgPeersSnapshot {
            inventory,
            pubkey_by_ip,
        }));
    }
}
