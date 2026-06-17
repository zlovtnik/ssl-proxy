impl SyncPublisher {
    pub fn new(config: &SyncConfig) -> Self {
        let publisher_config = SyncPublisherConfig {
            redpanda_bootstrap_servers: config.redpanda_bootstrap_servers.clone(),
            connect_timeout: Duration::from_millis(config.connect_timeout_ms),
            publish_timeout: Duration::from_millis(config.publish_timeout_ms),
            queue_capacity: config.publish_queue_capacity,
            enqueue_timeout: Duration::from_millis(config.publish_enqueue_timeout_ms),
            security_protocol: config.security_protocol.clone(),
            sasl_mechanisms: config.sasl_mechanisms.clone(),
            sasl_username: config.sasl_username.clone(),
            sasl_password: config.sasl_password.clone(),
            ssl_ca_location: config.ssl_ca_location.clone(),
            ssl_certificate_location: config.ssl_certificate_location.clone(),
            ssl_key_location: config.ssl_key_location.clone(),
            inline_payload_max_bytes: config.inline_payload_max_bytes,
            outbox_dir: PathBuf::from(&config.outbox_dir),
            publish_spool_dir: PathBuf::from(&config.publish_spool_dir),
        };

        let health = Arc::new(Mutex::new(SyncPublisherHealth::default()));
        let counters = Arc::new(SyncPublisherCounters::default());
        let (publish_tx, publish_task) = if tokio::runtime::Handle::try_current().is_ok() {
            let (publish_tx, mut publish_rx) =
                mpsc::channel::<PublishQueueMessage>(publisher_config.queue_capacity);
            let config_clone = publisher_config.clone();
            let health_clone = Arc::clone(&health);

            let publish_task = tokio::spawn(async move {
                run_publish_worker(config_clone, health_clone, &mut publish_rx).await;
            });

            (Some(publish_tx), Some(publish_task))
        } else {
            (None, None)
        };

        Self {
            config: publisher_config,
            published: Arc::new(Mutex::new(Vec::new())),
            health,
            counters,
            publish_tx: Arc::new(Mutex::new(publish_tx)),
            publish_task: Arc::new(Mutex::new(publish_task)),
        }
    }

    /// Shutdown the publisher gracefully, awaiting all in-flight publishes to complete
    pub async fn shutdown(&self) {
        // Drop the active sender (if present) so the worker recv loop can exit.
        let sender = self
            .publish_tx
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .take();
        drop(sender);

        // Take and await the publisher task
        let handle = {
            self.publish_task
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .take()
        };
        if let Some(handle) = handle {
            let _ = handle.await;
        }
    }

    pub fn publish_scan_request(&self, request: ScanRequest) {
        let payload = match serde_json::to_string(&request) {
            Ok(payload) => payload,
            Err(error) => {
                warn!(%error, "sync publisher failed to serialize scan request");
                return;
            }
        };

        if let Err(error) = self.enqueue_message(SYNC_SCAN_REQUEST_TOPIC, &payload) {
            warn!(
                %error,
                dedupe_key = request.dedupe_key,
                stream_name = request.stream_name,
                "sync publisher failed to enqueue scan request — event may not reach Oracle"
            );
        } else {
            debug!(
                target: "sync",
                dedupe_key = request.dedupe_key,
                stream_name = request.stream_name,
                payload_ref = request.payload_ref,
                "scan request enqueued for Redpanda publish"
            );
        }
    }

    pub fn publish_payload_audit(&self, topic: &str, payload: &str) -> Result<(), String> {
        self.enqueue_message(topic, payload)
    }

    pub fn enqueue_message(&self, topic: &str, payload: &str) -> Result<(), String> {
        self.record(topic, payload);
        self.record_attempt();

        if self.config.redpanda_bootstrap_servers.is_none() {
            let error = "sync publisher disabled".to_string();
            self.record_error(error.clone());
            return Err(error);
        }

        let message = PublishQueueMessage {
            topic: topic.to_string(),
            payload: payload.to_string(),
            response_tx: None,
        };
        let publish_tx = match self.queue_sender() {
            Ok(publish_tx) => publish_tx,
            Err(error) => {
                warn!(%error, %topic, "sync publisher queue unavailable; spooling publish");
                return self.spool_publish(topic, payload);
            }
        };

        match self.enqueue_with_timeout(&publish_tx, message) {
            Ok(()) => Ok(()),
            Err(EnqueueError::Timeout) => {
                self.counters
                    .enqueue_timeouts_total
                    .fetch_add(1, Ordering::Relaxed);
                self.record_error(ENQUEUE_TIMEOUT_ERROR.to_string());
                warn!(
                    %topic,
                    timeout_ms = self.config.enqueue_timeout.as_millis(),
                    "sync publisher enqueue timed out; spooling publish"
                );
                self.spool_publish(topic, payload)
            }
            Err(EnqueueError::Closed) => {
                let error = "sync publisher queue closed".to_string();
                self.record_error(error.clone());
                warn!(%topic, "sync publisher queue closed; spooling publish");
                self.spool_publish(topic, payload)
                    .map_err(|spool_error| format!("{error}; spool failed: {spool_error}"))
            }
        }
    }

    pub fn try_enqueue_message(&self, topic: &str, payload: &str) -> Result<(), String> {
        self.record(topic, payload);
        self.record_attempt();

        if self.config.redpanda_bootstrap_servers.is_none() {
            let error = "sync publisher disabled".to_string();
            self.record_error(error.clone());
            return Err(error);
        }

        let message = PublishQueueMessage {
            topic: topic.to_string(),
            payload: payload.to_string(),
            response_tx: None,
        };
        let publish_tx = self.queue_sender()?;

        match self.enqueue_with_timeout(&publish_tx, message) {
            Ok(()) => Ok(()),
            Err(EnqueueError::Timeout) => {
                self.counters
                    .enqueue_timeouts_total
                    .fetch_add(1, Ordering::Relaxed);
                self.record_error(ENQUEUE_TIMEOUT_ERROR.to_string());
                debug!(
                    %topic,
                    timeout_ms = self.config.enqueue_timeout.as_millis(),
                    "sync publisher enqueue timed out; caller should apply backpressure"
                );
                Err(ENQUEUE_TIMEOUT_ERROR.to_string())
            }
            Err(EnqueueError::Closed) => {
                let error = "sync publisher queue closed".to_string();
                self.record_error(error.clone());
                Err(error)
            }
        }
    }

    pub async fn publish_message(&self, topic: &str, payload: &str) -> Result<(), String> {
        self.record(topic, payload);
        self.record_attempt();

        if self.config.redpanda_bootstrap_servers.is_none() {
            let error = "sync publisher disabled".to_string();
            self.record_error(error.clone());
            return Err(error);
        }

        debug!(
            %topic,
            payload_bytes = payload.len(),
            "sync publisher queueing acknowledged Redpanda publish"
        );
        let publish_tx = self.queue_sender()?;
        let (response_tx, response_rx) = oneshot::channel();
        publish_tx
            .send(PublishQueueMessage {
                topic: topic.to_string(),
                payload: payload.to_string(),
                response_tx: Some(response_tx),
            })
            .await
            .map_err(|_| {
                let error = "sync publisher queue closed".to_string();
                self.record_error(error.clone());
                error
            })?;

        response_rx.await.map_err(|_| {
            let error = "sync publisher response channel closed".to_string();
            self.record_error(error.clone());
            error
        })?
    }

    pub fn payload_ref_for_event(
        &self,
        raw_payload: &str,
        observed_at: &str,
    ) -> Result<String, String> {
        validate_json_payload(raw_payload)?;

        if raw_payload.len() <= self.config.inline_payload_max_bytes {
            return Ok(format!(
                "{INLINE_PAYLOAD_REF_PREFIX}{}",
                URL_SAFE_NO_PAD.encode(raw_payload.as_bytes())
            ));
        }

        std::fs::create_dir_all(&self.config.outbox_dir).map_err(|error| {
            format!(
                "create sync outbox {}: {error}",
                self.config.outbox_dir.display()
            )
        })?;

        let digest = format!("{:x}", Sha256::digest(raw_payload.as_bytes()));
        let observed_token: String = observed_at
            .chars()
            .filter(|ch| ch.is_ascii_alphanumeric())
            .collect();
        let file_name = format!("{observed_token}-{digest}.json");
        let path = self.config.outbox_dir.join(&file_name);
        std::fs::write(&path, raw_payload)
            .map_err(|error| format!("write sync outbox payload {}: {error}", path.display()))?;
        Ok(format!("{OUTBOX_PAYLOAD_REF_PREFIX}{file_name}"))
    }

    pub fn resolve_payload_ref_contents(&self, payload_ref: &str) -> Result<String, String> {
        let parsed = parse_payload_ref(payload_ref)
            .ok_or_else(|| format!("unsupported payload_ref: {payload_ref}"))?;
        let contents = match parsed.kind {
            crate::PayloadRefKind::Inline => URL_SAFE_NO_PAD
                .decode(parsed.locator.as_bytes())
                .map_err(|error| format!("decode inline payload_ref: {error}"))
                .and_then(|bytes| {
                    String::from_utf8(bytes)
                        .map_err(|error| format!("inline payload_ref UTF-8: {error}"))
                }),
            crate::PayloadRefKind::Outbox => {
                let canonical_outbox = std::fs::canonicalize(&self.config.outbox_dir)
                    .map_err(|error| format!("canonicalize outbox directory: {error}"))?;

                let path = self.config.outbox_dir.join(parsed.locator);
                let canonical_path = std::fs::canonicalize(&path).map_err(|error| {
                    format!("canonicalize payload path {}: {error}", path.display())
                })?;

                if !canonical_path.starts_with(&canonical_outbox) {
                    return Err(format!(
                        "payload path traversal attempt blocked: {}",
                        path.display()
                    ));
                }

                std::fs::read_to_string(&canonical_path).map_err(|error| {
                    format!(
                        "read sync outbox payload {}: {error}",
                        canonical_path.display()
                    )
                })
            }
        }?;
        validate_json_payload(&contents)?;
        Ok(contents)
    }

    pub fn health_snapshot(&self) -> SyncPublisherHealthSnapshot {
        let health = self
            .health
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone();
        let (queue_available, queue_capacity) = self
            .publish_tx
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .as_ref()
            .map(|sender| (sender.capacity(), sender.max_capacity()))
            .unwrap_or((0, self.config.queue_capacity));
        let queue_depth = queue_capacity.saturating_sub(queue_available);
        SyncPublisherHealthSnapshot {
            configured: self.config.redpanda_bootstrap_servers.is_some(),
            auth_enabled: self.config.sasl_username.is_some(),
            tls_enabled: self
                .config
                .security_protocol
                .as_deref()
                .map(|protocol| protocol.to_ascii_uppercase().contains("SSL"))
                .unwrap_or(false),
            inline_payload_max_bytes: self.config.inline_payload_max_bytes,
            outbox_dir: self.config.outbox_dir.display().to_string(),
            queue_capacity,
            queue_depth,
            queue_available,
            spool_dir: self.config.publish_spool_dir.display().to_string(),
            spool_pending: count_spool_pending(&self.config.publish_spool_dir),
            spooled_total: self.counters.spooled_total.load(Ordering::Relaxed),
            enqueue_timeouts_total: self.counters.enqueue_timeouts_total.load(Ordering::Relaxed),
            last_attempt_at: health.last_attempt_at,
            last_publish_at: health.last_publish_at,
            last_error: health.last_error,
        }
    }

    pub fn published_messages(&self) -> Vec<PublishedMessage> {
        self.published
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone()
    }

    fn record(&self, topic: &str, payload: &str) {
        self.published
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .push(PublishedMessage {
                topic: topic.to_string(),
                payload: payload.to_string(),
            });
    }

    fn record_attempt(&self) {
        let mut health = self
            .health
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        health.last_attempt_at = Some(crate::time::now_rfc3339());
    }

    fn queue_sender(&self) -> Result<PublishQueueSender, String> {
        self.publish_tx
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone()
            .ok_or_else(|| {
                let error = "sync publisher requires a Tokio runtime".to_string();
                self.record_error(error.clone());
                error
            })
    }

    fn record_error(&self, error: String) {
        let mut health = self
            .health
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        health.last_error = Some(error);
    }

    fn enqueue_with_timeout(
        &self,
        publish_tx: &PublishQueueSender,
        message: PublishQueueMessage,
    ) -> Result<(), EnqueueError> {
        if self.config.enqueue_timeout.is_zero() {
            return publish_tx.try_send(message).map_err(|error| match error {
                mpsc::error::TrySendError::Full(_) => EnqueueError::Timeout,
                mpsc::error::TrySendError::Closed(_) => EnqueueError::Closed,
            });
        }

        match tokio::runtime::Handle::try_current() {
            Ok(handle) if handle.runtime_flavor() == RuntimeFlavor::MultiThread => {
                tokio::task::block_in_place(|| {
                    handle.block_on(async {
                        timeout(self.config.enqueue_timeout, publish_tx.send(message))
                            .await
                            .map_err(|_| EnqueueError::Timeout)?
                            .map_err(|_| EnqueueError::Closed)
                    })
                })
            }
            Ok(_) => publish_tx.try_send(message).map_err(|error| match error {
                mpsc::error::TrySendError::Full(_) => EnqueueError::Timeout,
                mpsc::error::TrySendError::Closed(_) => EnqueueError::Closed,
            }),
            Err(_) => publish_tx.try_send(message).map_err(|error| match error {
                mpsc::error::TrySendError::Full(_) => EnqueueError::Timeout,
                mpsc::error::TrySendError::Closed(_) => EnqueueError::Closed,
            }),
        }
    }

    fn spool_publish(&self, topic: &str, payload: &str) -> Result<(), String> {
        write_spool_envelope(&self.config.publish_spool_dir, topic, payload)?;
        self.counters.spooled_total.fetch_add(1, Ordering::Relaxed);
        Ok(())
    }
}

fn validate_json_payload(raw_payload: &str) -> Result<(), String> {
    serde_json::from_str::<serde_json::Value>(raw_payload)
        .map(|_| ())
        .map_err(|error| format!("sync payload must be valid JSON: {error}"))
}
