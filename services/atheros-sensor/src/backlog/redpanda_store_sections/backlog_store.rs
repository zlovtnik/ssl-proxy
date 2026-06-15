impl RedpandaBacklog {
    async fn ping_redpanda(&self) -> Result<(), BacklogError> {
        let redpanda_bootstrap_servers = self
            .sync
            .redpanda_bootstrap_servers
            .as_deref()
            .ok_or_else(|| BacklogError::Disabled {
                operation: "redpanda_health_check",
            })?;
        if let Some(error) =
            request_transport_unsupported("redpanda_health_check", redpanda_bootstrap_servers)
        {
            return Err(error);
        }
        let endpoint = parse_redpanda_endpoint(redpanda_bootstrap_servers).map_err(|source| {
            BacklogError::Redpanda {
                operation: "redpanda_health_check",
                message: source,
            }
        })?;
        let tcp_stream = timeout(self.request_timeout, TcpStream::connect(&endpoint.address))
            .await
            .map_err(|_| BacklogError::Timeout {
                operation: "redpanda_health_check",
            })?
            .map_err(|source| BacklogError::Redpanda {
                operation: "redpanda_health_check",
                message: format!("connect {}: {source}", endpoint.address),
            })?;
        let mut stream: Box<dyn RedpandaStream> = if redpanda_tls_enabled(&self.sync, &endpoint) {
            let connector = self
                .tls_connector
                .as_ref()
                .ok_or_else(|| BacklogError::Redpanda {
                    operation: "redpanda_health_check",
                    message: "Redpanda TLS connector was not initialized".to_string(),
                })?;
            let tls_stream = connect_tls(connector, endpoint.host.as_str(), tcp_stream)
                .await
                .map_err(|message| BacklogError::Redpanda {
                    operation: "redpanda_health_check",
                    message,
                })?;
            Box::new(tls_stream)
        } else {
            Box::new(tcp_stream)
        };
        let mut info_line = String::new();
        {
            let mut reader = BufReader::new(&mut *stream);
            timeout(self.request_timeout, reader.read_line(&mut info_line))
                .await
                .map_err(|_| BacklogError::Timeout {
                    operation: "redpanda_health_check",
                })?
                .map_err(|source| BacklogError::Redpanda {
                    operation: "redpanda_health_check",
                    message: format!("read INFO: {source}"),
                })?;
        }
        if !info_line.starts_with("INFO ") {
            return Err(BacklogError::Redpanda {
                operation: "redpanda_health_check",
                message: format!(
                    "expected Redpanda INFO banner, got: {}",
                    info_line.trim_end()
                ),
            });
        }
        let connect_options = serde_json::json!({
            "lang": "rust",
            "version": env!("CARGO_PKG_VERSION"),
            "verbose": false,
            "pedantic": false,
            "user": self.sync.sasl_username.as_deref(),
            "pass": self.sync.sasl_password.as_deref(),
        });
        let command = format!("CONNECT {connect_options}\r\nPING\r\n");
        timeout(self.request_timeout, stream.write_all(command.as_bytes()))
            .await
            .map_err(|_| BacklogError::Timeout {
                operation: "redpanda_health_check",
            })?
            .map_err(|source| BacklogError::Redpanda {
                operation: "redpanda_health_check",
                message: format!("send CONNECT/PING: {source}"),
            })?;
        timeout(self.request_timeout, stream.flush())
            .await
            .map_err(|_| BacklogError::Timeout {
                operation: "redpanda_health_check",
            })?
            .map_err(|source| BacklogError::Redpanda {
                operation: "redpanda_health_check",
                message: format!("flush CONNECT/PING: {source}"),
            })?;
        let mut reader = BufReader::new(&mut *stream);
        let mut pong_line = String::new();
        timeout(self.request_timeout, reader.read_line(&mut pong_line))
            .await
            .map_err(|_| BacklogError::Timeout {
                operation: "redpanda_health_check",
            })?
            .map_err(|source| BacklogError::Redpanda {
                operation: "redpanda_health_check",
                message: format!("read PONG: {source}"),
            })?;
        if pong_line.trim() != "PONG" {
            return Err(BacklogError::Redpanda {
                operation: "redpanda_health_check",
                message: format!("unexpected health check response: {}", pong_line.trim_end()),
            });
        }
        Ok(())
    }

    async fn request(
        &self,
        operation: &'static str,
        topic: &'static str,
        payload: &str,
    ) -> Result<String, BacklogError> {
        let Some(redpanda_bootstrap_servers) = self.sync.redpanda_bootstrap_servers.as_deref()
        else {
            return Err(BacklogError::Disabled { operation });
        };
        if let Some(error) = request_transport_unsupported(operation, redpanda_bootstrap_servers) {
            return Err(error);
        }
        let reply_topic = next_inbox_topic();
        let payload = payload_with_reply_topic(operation, payload, &reply_topic)?;
        let started = Instant::now();
        let result = self
            .request_with_cached_connection(operation, topic, &payload, &reply_topic)
            .await;
        crate::metrics::record_redpanda_request(result.is_ok(), started.elapsed().as_millis());
        result
    }

    pub async fn lookup_device_by_mac(
        &self,
        mac: &str,
    ) -> Result<Option<(String, Option<String>)>, BacklogError> {
        #[derive(Serialize)]
        struct Request<'a> {
            operation: &'static str,
            mac: &'a str,
        }
        #[derive(Deserialize)]
        struct Response {
            device_id: Option<String>,
            username: Option<String>,
        }

        let payload = serialize(
            "lookup_device_by_mac",
            &Request {
                operation: "lookup_device_by_mac",
                mac,
            },
        )?;
        let response = self
            .request("lookup_device_by_mac", MAC_LOOKUP_TOPIC, &payload)
            .await?;
        if response.trim() == "null" || response.trim().is_empty() {
            return Ok(None);
        }
        let parsed: Response =
            serde_json::from_str(&response).map_err(|source| BacklogError::Deserialize {
                operation: "lookup_device_by_mac",
                source,
            })?;
        Ok(parsed
            .device_id
            .map(|device_id| (device_id, parsed.username)))
    }

    pub async fn list_authorized_wireless_networks(
        &self,
    ) -> Result<Vec<AuthorizedWirelessNetwork>, BacklogError> {
        let response = self
            .request(
                "list_authorized_wireless_networks",
                AUTHORIZED_NETWORKS_TOPIC,
                r#"{"operation":"list_authorized_wireless_networks"}"#,
            )
            .await?;
        parse_authorized_networks_response(&response).map_err(|source| BacklogError::Deserialize {
            operation: "list_authorized_wireless_networks",
            source,
        })
    }

    pub async fn flush_probe_batch(
        &self,
        probes: &[ProbeFlushObservation],
    ) -> Result<(), BacklogError> {
        if probes.is_empty() {
            return Ok(());
        }
        #[derive(Serialize)]
        struct Payload<'a> {
            operation: &'static str,
            observed_at: String,
            probes: &'a [ProbeFlushObservation],
        }
        let observed_at = probes
            .iter()
            .map(|probe| probe.last_seen)
            .max()
            .map(crate::timing::rfc3339_from_utc)
            .unwrap_or_else(crate::timing::now_rfc3339);
        let payload = serialize(
            "flush_probe_batch",
            &Payload {
                operation: "flush_probe_batch",
                observed_at,
                probes,
            },
        )?;
        self.publish(PROBE_FLUSH_TOPIC, &payload).await
    }

    async fn publish(&self, topic: &'static str, payload: &str) -> Result<(), BacklogError> {
        let started = Instant::now();
        let result = self
            .publisher
            .publish_message(topic, payload)
            .await
            .map_err(|source| BacklogError::Redpanda {
                operation: topic,
                message: source,
            });
        crate::metrics::record_redpanda_publish(result.is_ok(), started.elapsed().as_millis());
        result
    }
}

fn request_error_marks_redpanda_unhealthy(error: &BacklogError) -> bool {
    !matches!(
        error,
        BacklogError::Timeout { .. }
            | BacklogError::Serialize { .. }
            | BacklogError::Deserialize { .. }
            | BacklogError::Disabled { .. }
    )
}

#[derive(Clone, Debug, Serialize)]
pub struct ProbeFlushObservation {
    pub ssid: String,
    pub client_mac: String,
    pub known_bssid: Option<String>,
    pub first_seen: chrono::DateTime<chrono::Utc>,
    pub last_seen: chrono::DateTime<chrono::Utc>,
    pub probe_count: u32,
}

#[async_trait]
impl BacklogStore for RedpandaBacklog {
    async fn record_ingest(&self, record: IngestRecord<'_>) -> Result<(), BacklogError> {
        debug!(
            dedupe_key = record.dedupe_key,
            stream_name = record.stream_name,
            observed_at = %record.observed_at,
            payload_ref = record.payload_ref,
            "publishing wireless audit ingest over Redpanda"
        );
        let request = ScanRequest {
            stream_name: record.stream_name.to_string(),
            dedupe_key: record.dedupe_key.to_string(),
            payload_ref: record.payload_ref.to_string(),
            observed_at: crate::timing::rfc3339_from_utc(record.observed_at),
        };
        let payload = serialize("record_ingest", &request)?;
        self.publish(SYNC_SCAN_REQUEST_TOPIC, &payload).await
    }

    async fn save_pending(
        &self,
        dedupe_key: &str,
        stream_name: &str,
        payload: &str,
        error: &str,
    ) -> Result<(), BacklogError> {
        self.save_pending_with_stage(
            dedupe_key,
            stream_name,
            payload,
            error,
            BacklogFailureStage::PrePublish,
        )
        .await
    }

    async fn save_pending_with_stage(
        &self,
        dedupe_key: &str,
        stream_name: &str,
        payload: &str,
        error: &str,
        failure_stage: BacklogFailureStage,
    ) -> Result<(), BacklogError> {
        #[derive(Serialize)]
        struct Message<'a> {
            operation: &'static str,
            dedupe_key: &'a str,
            stream_name: &'a str,
            payload: &'a str,
            error: &'a str,
            failure_stage: &'static str,
        }
        let payload = serialize(
            "save_pending",
            &Message {
                operation: "save_pending",
                dedupe_key,
                stream_name,
                payload,
                error,
                failure_stage: failure_stage.as_str(),
            },
        )?;
        self.publish(BACKLOG_SAVE_TOPIC, &payload).await
    }

    async fn list_pending(&self) -> Result<Vec<BacklogEntry>, BacklogError> {
        let response = self
            .request(
                "list_pending",
                BACKLOG_LIST_TOPIC,
                r#"{"operation":"list_pending"}"#,
            )
            .await?;
        serde_json::from_str(&response).map_err(|source| BacklogError::Deserialize {
            operation: "list_pending",
            source,
        })
    }

    async fn mark_synced(&self, dedupe_key: &str) -> Result<(), BacklogError> {
        #[derive(Serialize)]
        struct Message<'a> {
            operation: &'static str,
            dedupe_key: &'a str,
        }
        let payload = serialize(
            "mark_synced",
            &Message {
                operation: "mark_synced",
                dedupe_key,
            },
        )?;
        self.publish(BACKLOG_SYNCED_TOPIC, &payload).await
    }

    async fn prune_stale(
        &self,
        max_attempts: i32,
        max_age_hours: i64,
    ) -> Result<u64, BacklogError> {
        #[derive(Serialize)]
        struct Message {
            operation: &'static str,
            max_attempts: i32,
            max_age_hours: i64,
        }
        #[derive(Deserialize)]
        struct PruneResult {
            pruned: u64,
        }
        let payload = serialize(
            "prune_stale",
            &Message {
                operation: "prune_stale",
                max_attempts,
                max_age_hours,
            },
        )?;
        let response = self
            .request("prune_stale", BACKLOG_PRUNE_TOPIC, &payload)
            .await?;
        let parsed: PruneResult =
            serde_json::from_str(&response).map_err(|source| BacklogError::Deserialize {
                operation: "prune_stale",
                source,
            })?;
        Ok(parsed.pruned)
    }
}

#[derive(Deserialize)]
#[serde(untagged)]
enum AuthorizedNetworksResponse {
    Wrapped {
        #[serde(default)]
        networks: Option<Vec<AuthorizedWirelessNetwork>>,
    },
    Legacy(Vec<AuthorizedWirelessNetwork>),
}

fn parse_authorized_networks_response(
    response: &str,
) -> Result<Vec<AuthorizedWirelessNetwork>, serde_json::Error> {
    if response.trim().is_empty() || response.trim() == "null" {
        return Ok(Vec::new());
    }

    match serde_json::from_str(response)? {
        AuthorizedNetworksResponse::Wrapped { networks } => Ok(networks.unwrap_or_default()),
        AuthorizedNetworksResponse::Legacy(networks) => Ok(networks),
    }
}

fn serialize<T: Serialize>(operation: &'static str, value: &T) -> Result<String, BacklogError> {
    serde_json::to_string(value).map_err(|source| BacklogError::Serialize { operation, source })
}

fn payload_with_reply_topic(
    operation: &'static str,
    payload: &str,
    reply_topic: &str,
) -> Result<String, BacklogError> {
    let mut object: Map<String, Value> = serde_json::from_str(payload)
        .map_err(|source| BacklogError::Serialize { operation, source })?;

    object.insert(
        "reply_topic".to_string(),
        Value::String(reply_topic.to_string()),
    );

    serde_json::to_string(&object).map_err(|source| BacklogError::Serialize { operation, source })
}

fn next_inbox_topic() -> String {
    let id = NEXT_INBOX_ID.fetch_add(1, Ordering::Relaxed);
    format!("_INBOX.atheros_sensor.{}.{}", std::process::id(), id)
}
