fn write_spool_envelope(spool_dir: &Path, topic: &str, payload: &str) -> Result<PathBuf, String> {
    std::fs::create_dir_all(spool_dir)
        .map_err(|error| format!("create sync publish spool {}: {error}", spool_dir.display()))?;
    let created_at = crate::time::now_rfc3339();
    let token = crate::time::file_token_now();
    let id = uuid::Uuid::new_v4().simple();
    let tmp_path = spool_dir.join(format!("{token}-{id}.tmp"));
    let final_path = spool_dir.join(format!("{token}-{id}.json"));
    let envelope = PublishSpoolEnvelope {
        topic: topic.to_string(),
        payload: payload.to_string(),
        created_at,
    };
    let bytes = serde_json::to_vec(&envelope)
        .map_err(|error| format!("serialize sync publish spool envelope: {error}"))?;
    std::fs::write(&tmp_path, bytes).map_err(|error| {
        format!(
            "write sync publish spool envelope {}: {error}",
            tmp_path.display()
        )
    })?;
    std::fs::rename(&tmp_path, &final_path).map_err(|error| {
        let _ = std::fs::remove_file(&tmp_path);
        format!(
            "commit sync publish spool envelope {}: {error}",
            final_path.display()
        )
    })?;
    Ok(final_path)
}

fn count_spool_pending(spool_dir: &Path) -> usize {
    std::fs::read_dir(spool_dir)
        .map(|entries| {
            entries
                .filter_map(Result::ok)
                .filter(|entry| entry.path().extension().is_some_and(|ext| ext == "json"))
                .count()
        })
        .unwrap_or(0)
}

fn list_spool_envelopes(spool_dir: &Path) -> Result<Vec<PathBuf>, String> {
    let entries = match std::fs::read_dir(spool_dir) {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(error) => {
            return Err(format!(
                "read sync publish spool {}: {error}",
                spool_dir.display()
            ));
        }
    };
    let mut paths = entries
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .filter(|path| path.extension().is_some_and(|ext| ext == "json"))
        .collect::<Vec<_>>();
    paths.sort();
    Ok(paths)
}

fn read_spool_envelope(path: &Path) -> Result<PublishSpoolEnvelope, String> {
    let bytes = std::fs::read(path).map_err(|error| {
        format!(
            "read sync publish spool envelope {}: {error}",
            path.display()
        )
    })?;
    serde_json::from_slice(&bytes).map_err(|error| {
        format!(
            "decode sync publish spool envelope {}: {error}",
            path.display()
        )
    })
}

async fn run_publish_worker(
    config: SyncPublisherConfig,
    health: Arc<Mutex<SyncPublisherHealth>>,
    publish_rx: &mut mpsc::Receiver<PublishQueueMessage>,
) {
    let mut producer = build_redpanda_producer(&config)
        .map_err(|error| {
            record_worker_error(&health, error.clone());
            error
        })
        .ok();

    loop {
        let _ = drain_spooled_messages(&config, &health, &mut producer).await;

        let Some(message) = publish_rx.recv().await else {
            let _ = drain_spooled_messages(&config, &health, &mut producer).await;
            break;
        };

        let result = publish_with_producer(
            &config,
            &health,
            &mut producer,
            &message.topic,
            &message.payload,
            "queued",
        )
        .await;

        if let Some(response_tx) = message.response_tx {
            let _ = response_tx.send(result);
        }
    }
}

async fn drain_spooled_messages(
    config: &SyncPublisherConfig,
    health: &Arc<Mutex<SyncPublisherHealth>>,
    producer: &mut Option<FutureProducer>,
) -> Result<(), String> {
    let paths = match list_spool_envelopes(&config.publish_spool_dir) {
        Ok(paths) => paths,
        Err(error) => {
            record_worker_error(health, error.clone());
            return Err(error);
        }
    };

    for path in paths {
        let envelope = match read_spool_envelope(&path) {
            Ok(envelope) => envelope,
            Err(error) => {
                record_worker_error(health, error.clone());
                return Err(error);
            }
        };
        publish_with_producer(
            config,
            health,
            producer,
            &envelope.topic,
            &envelope.payload,
            "spooled",
        )
        .await?;
        std::fs::remove_file(&path).map_err(|error| {
            let message = format!(
                "delete sync publish spool envelope {}: {error}",
                path.display()
            );
            record_worker_error(health, message.clone());
            message
        })?;
    }

    Ok(())
}

async fn publish_with_producer(
    config: &SyncPublisherConfig,
    health: &Arc<Mutex<SyncPublisherHealth>>,
    producer: &mut Option<FutureProducer>,
    topic: &str,
    payload: &str,
    source: &str,
) -> Result<(), String> {
    let span = info_span!(
        "redpanda.publish",
        "messaging.system" = "redpanda",
        "messaging.destination.name" = %topic,
        "messaging.operation" = "publish",
        status = field::Empty
    );
    let result = async {
        if producer.is_none() {
            *producer = Some(build_redpanda_producer(config)?);
        }

        let producer_ref = producer.as_ref().expect("producer is initialized above");
        let mut record = FutureRecord::to(topic).payload(payload).key("");
        if let Some(headers) = current_trace_headers() {
            record = record.headers(headers);
        }
        producer_ref
            .send(record, config.publish_timeout)
            .await
            .map(|_| ())
            .map_err(|(error, _)| format!("publish Redpanda topic {topic}: {error}"))
    }
    .instrument(span.clone())
    .await;
    span.record("status", if result.is_ok() { "ok" } else { "error" });

    match &result {
        Ok(()) => {
            let mut snapshot = health
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            snapshot.last_publish_at = Some(crate::time::now_rfc3339());
            snapshot.last_error = None;
            debug!(
                %topic,
                source,
                payload_bytes = payload.len(),
                "sync publisher Redpanda publish succeeded"
            );
        }
        Err(error) => {
            warn!(
                %error,
                %topic,
                source,
                payload_bytes = payload.len(),
                "sync publisher Redpanda publish failed"
            );
            *producer = None;
            record_worker_error(health, error.clone());
        }
    }

    result
}

struct KafkaHeaderInjector {
    headers: Vec<(String, String)>,
}

impl Injector for KafkaHeaderInjector {
    fn set(&mut self, key: &str, value: String) {
        self.headers.push((key.to_string(), value));
    }
}

fn current_trace_headers() -> Option<OwnedHeaders> {
    let mut injector = KafkaHeaderInjector {
        headers: Vec::new(),
    };
    let context = tracing::Span::current().context();
    global::get_text_map_propagator(|propagator| {
        propagator.inject_context(&context, &mut injector);
    });

    if injector.headers.is_empty() {
        return None;
    }

    let mut headers = OwnedHeaders::new();
    for (key, value) in injector.headers {
        headers = headers.insert(Header {
            key: key.as_str(),
            value: Some(value.as_str()),
        });
    }
    Some(headers)
}

fn build_redpanda_producer(config: &SyncPublisherConfig) -> Result<FutureProducer, String> {
    let bootstrap_servers = config
        .redpanda_bootstrap_servers
        .as_deref()
        .ok_or_else(|| "sync publisher disabled".to_string())?;
    let bootstrap_servers = rdkafka_bootstrap_servers(bootstrap_servers);

    let mut client_config = ClientConfig::new();
    client_config
        .set("bootstrap.servers", &bootstrap_servers)
        .set(
            "message.timeout.ms",
            config.publish_timeout.as_millis().to_string(),
        )
        .set(
            "socket.timeout.ms",
            config.connect_timeout.as_millis().to_string(),
        );

    if let Some(value) = &config.security_protocol {
        client_config.set("security.protocol", value);
    }
    if let Some(value) = &config.sasl_mechanisms {
        client_config.set("sasl.mechanisms", value);
    }
    if let Some(value) = &config.sasl_username {
        client_config.set("sasl.username", value);
    }
    if let Some(value) = &config.sasl_password {
        client_config.set("sasl.password", value);
    }
    if let Some(value) = &config.ssl_ca_location {
        client_config.set("ssl.ca.location", value);
    }
    if let Some(value) = &config.ssl_certificate_location {
        client_config.set("ssl.certificate.location", value);
    }
    if let Some(value) = &config.ssl_key_location {
        client_config.set("ssl.key.location", value);
    }

    client_config
        .create()
        .map_err(|error| format!("create Redpanda producer: {error}"))
}

fn rdkafka_bootstrap_servers(redpanda_bootstrap_servers: &str) -> String {
    let trimmed = redpanda_bootstrap_servers.trim();
    let authority = trimmed
        .strip_prefix("redpanda://")
        .unwrap_or(trimmed)
        .split('/')
        .next()
        .unwrap_or_default();

    authority
        .rsplit('@')
        .next()
        .unwrap_or(authority)
        .to_string()
}

#[cfg(test)]
mod rdkafka_bootstrap_tests {
    use super::rdkafka_bootstrap_servers;

    #[test]
    fn keeps_plain_bootstrap_servers() {
        assert_eq!(
            rdkafka_bootstrap_servers("127.0.0.1:9092"),
            "127.0.0.1:9092"
        );
    }

    #[test]
    fn strips_redpanda_scheme_for_librdkafka() {
        assert_eq!(
            rdkafka_bootstrap_servers("redpanda://127.0.0.1:19092"),
            "127.0.0.1:19092"
        );
    }

    #[test]
    fn strips_url_userinfo_for_librdkafka() {
        assert_eq!(
            rdkafka_bootstrap_servers("redpanda://user:pass@redpanda:9092"),
            "redpanda:9092"
        );
    }
}

fn record_worker_error(health: &Arc<Mutex<SyncPublisherHealth>>, error: String) {
    let mut snapshot = health
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    snapshot.last_error = Some(error);
}

#[cfg(test)]
mod payload_ref_tests {
    use std::path::Path;

    use super::SyncPublisher;
    use crate::{parse_payload_ref, SyncConfig};

    #[test]
    fn inline_payload_ref_decodes_to_valid_json() {
        let publisher = SyncPublisher::new(&SyncConfig::default());
        let payload_ref = publisher
            .payload_ref_for_event("{\"small\":true}", "2026-04-17T00:00:00Z")
            .unwrap();

        let contents = publisher
            .resolve_payload_ref_contents(&payload_ref)
            .unwrap();
        serde_json::from_str::<serde_json::Value>(&contents).unwrap();
        assert_eq!(contents, "{\"small\":true}");
    }

    #[test]
    fn outbox_payload_ref_file_contains_valid_json() {
        let outbox = tempfile::tempdir().unwrap();
        let mut config = SyncConfig::default();
        config.inline_payload_max_bytes = 1;
        config.outbox_dir = outbox.path().display().to_string();
        let publisher = SyncPublisher::new(&config);
        let payload_ref = publisher
            .payload_ref_for_event(
                "{\"large\":true,\"payload\":\"readable\"}",
                "2026-04-17T00:00:00Z",
            )
            .unwrap();

        let parsed = parse_payload_ref(&payload_ref).unwrap();
        let path = Path::new(&config.outbox_dir).join(parsed.locator);
        let file_contents = std::fs::read_to_string(path).unwrap();
        serde_json::from_str::<serde_json::Value>(&file_contents).unwrap();
        assert_eq!(
            publisher
                .resolve_payload_ref_contents(&payload_ref)
                .unwrap(),
            file_contents
        );
    }

    #[test]
    fn payload_ref_for_event_rejects_non_json_payloads() {
        let publisher = SyncPublisher::new(&SyncConfig::default());
        let error = publisher
            .payload_ref_for_event("not json", "2026-04-17T00:00:00Z")
            .unwrap_err();

        assert!(error.contains("valid JSON"));
    }
}
