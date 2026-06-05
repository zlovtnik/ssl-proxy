impl RedpandaBacklog {
    pub fn new(
        publisher: Arc<dyn PublishClient>,
        sync: SyncConfig,
        request_timeout: Duration,
    ) -> Result<Self, BacklogError> {
        let tls_client_config =
            build_tls_client_config(&sync).map_err(|message| BacklogError::Redpanda {
                operation: "initialize_redpanda_backlog",
                message,
            })?;
        let tls_connector = tls_client_config
            .as_ref()
            .map(|config| TlsConnector::from(Arc::clone(config)));
        Ok(Self {
            publisher,
            sync,
            request_timeout,
            request_connection_ttl: Duration::from_secs(10),
            tls_connector,
            request_connection: Arc::new(Mutex::new(None)),
            health_status: Arc::new(AtomicBool::new(true)),
            connection_generation: Arc::new(AtomicU64::new(0)),
        })
    }

    pub fn spawn_health_check(self: Arc<Self>) {
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(30));
            interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            loop {
                interval.tick().await;
                self.health_probe().await;
            }
        });
    }

    pub fn is_healthy(&self) -> bool {
        self.health_status.load(Ordering::Relaxed)
    }

    pub fn supports_inline_request_reply(&self) -> bool {
        self.sync
            .redpanda_bootstrap_servers
            .as_deref()
            .is_some_and(inline_request_reply_transport_supported)
    }

    pub fn inline_request_reply_disabled_reason(&self) -> Option<String> {
        let redpanda_bootstrap_servers = self.sync.redpanda_bootstrap_servers.as_deref()?;
        request_transport_unsupported("inline_request_reply", redpanda_bootstrap_servers)
            .map(|error| error.to_string())
    }

    async fn health_probe(&self) {
        let result = self.ping_redpanda().await;
        let healthy = result.is_ok();
        self.health_status.store(healthy, Ordering::Relaxed);
        if healthy {
            self.connection_generation.fetch_add(1, Ordering::Relaxed);
        }
    }

    async fn connect_request_connection(
        &self,
        operation: &'static str,
    ) -> Result<CachedRequestConnection, BacklogError> {
        let redpanda_bootstrap_servers = self
            .sync
            .redpanda_bootstrap_servers
            .as_deref()
            .ok_or_else(|| BacklogError::Disabled { operation })?;
        let endpoint = parse_redpanda_endpoint(redpanda_bootstrap_servers).map_err(|source| {
            BacklogError::Redpanda {
                operation,
                message: source,
            }
        })?;
        let tcp_stream = timeout(self.request_timeout, TcpStream::connect(&endpoint.address))
            .await
            .map_err(|_| BacklogError::Timeout { operation })?
            .map_err(|source| BacklogError::Redpanda {
                operation,
                message: format!("connect {}: {source}", endpoint.address),
            })?;
        let mut stream: Box<dyn RedpandaStream> = if redpanda_tls_enabled(&self.sync, &endpoint) {
            let connector = self
                .tls_connector
                .as_ref()
                .ok_or_else(|| BacklogError::Redpanda {
                    operation,
                    message: "Redpanda TLS connector was not initialized".to_string(),
                })?;
            let tls_stream = connect_tls(connector, endpoint.host.as_str(), tcp_stream)
                .await
                .map_err(|message| BacklogError::Redpanda { operation, message })?;
            Box::new(tls_stream)
        } else {
            Box::new(tcp_stream)
        };
        let mut reader = BufReader::new(&mut *stream);
        let mut info_line = String::new();
        timeout(self.request_timeout, reader.read_line(&mut info_line))
            .await
            .map_err(|_| BacklogError::Timeout { operation })?
            .map_err(|source| BacklogError::Redpanda {
                operation,
                message: format!("read INFO: {source}"),
            })?;
        if !info_line.starts_with("INFO ") {
            return Err(BacklogError::Redpanda {
                operation,
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
        let command = format!("CONNECT {connect_options}\r\n");
        timeout(self.request_timeout, stream.write_all(command.as_bytes()))
            .await
            .map_err(|_| BacklogError::Timeout { operation })?
            .map_err(|source| BacklogError::Redpanda {
                operation,
                message: format!("send CONNECT: {source}"),
            })?;
        timeout(self.request_timeout, stream.flush())
            .await
            .map_err(|_| BacklogError::Timeout { operation })?
            .map_err(|source| BacklogError::Redpanda {
                operation,
                message: format!("flush CONNECT: {source}"),
            })?;
        Ok(CachedRequestConnection {
            reader: BufReader::new(stream),
            last_used: Instant::now(),
            next_sid: 1,
        })
    }

    async fn request_with_cached_connection(
        &self,
        operation: &'static str,
        topic: &'static str,
        payload: &str,
        reply_topic: &str,
    ) -> Result<String, BacklogError> {
        let maybe_connection = self.request_connection.lock().unwrap().take();

        let mut connection = if let Some(conn) = maybe_connection {
            if conn.last_used.elapsed() < self.request_connection_ttl {
                conn
            } else {
                self.connection_generation.fetch_add(1, Ordering::Relaxed);
                match self.connect_request_connection(operation).await {
                    Ok(conn) => conn,
                    Err(err) => {
                        self.health_status.store(false, Ordering::Relaxed);
                        return Err(err);
                    }
                }
            }
        } else {
            match self.connect_request_connection(operation).await {
                Ok(conn) => conn,
                Err(err) => {
                    self.health_status.store(false, Ordering::Relaxed);
                    return Err(err);
                }
            }
        };

        let result = self
            .perform_request_over_connection(
                &mut connection,
                operation,
                topic,
                payload,
                reply_topic,
            )
            .await;
        let mut guard = self.request_connection.lock().unwrap();
        match result {
            Ok(response) => {
                connection.last_used = Instant::now();
                guard.replace(connection);
                self.health_status.store(true, Ordering::Relaxed);
                Ok(response)
            }
            Err(err) => {
                if request_error_marks_redpanda_unhealthy(&err) {
                    self.health_status.store(false, Ordering::Relaxed);
                }
                guard.take();
                Err(err)
            }
        }
    }

    async fn perform_request_over_connection(
        &self,
        connection: &mut CachedRequestConnection,
        operation: &'static str,
        topic: &'static str,
        payload: &str,
        reply_topic: &str,
    ) -> Result<String, BacklogError> {
        let stream = &mut connection.reader;
        let sid = connection.next_sid;
        connection.next_sid = connection.next_sid.saturating_add(1);
        let subscribe = format!("SUB {reply_topic} {sid}\r\n");
        timeout(self.request_timeout, stream.write_all(subscribe.as_bytes()))
            .await
            .map_err(|_| BacklogError::Timeout { operation })?
            .map_err(|source| BacklogError::Redpanda {
                operation,
                message: format!("subscribe reply topic: {source}"),
            })?;

        let publish_command = format!("PUB {topic} {}\r\n", payload.len());
        timeout(
            self.request_timeout,
            stream.write_all(publish_command.as_bytes()),
        )
        .await
        .map_err(|_| BacklogError::Timeout { operation })?
        .map_err(|source| BacklogError::Redpanda {
            operation,
            message: format!("send PUB header: {source}"),
        })?;
        timeout(self.request_timeout, stream.write_all(payload.as_bytes()))
            .await
            .map_err(|_| BacklogError::Timeout { operation })?
            .map_err(|source| BacklogError::Redpanda {
                operation,
                message: format!("send PUB payload: {source}"),
            })?;
        timeout(self.request_timeout, stream.write_all(b"\r\n"))
            .await
            .map_err(|_| BacklogError::Timeout { operation })?
            .map_err(|source| BacklogError::Redpanda {
                operation,
                message: format!("finish PUB payload: {source}"),
            })?;
        timeout(self.request_timeout, stream.flush())
            .await
            .map_err(|_| BacklogError::Timeout { operation })?
            .map_err(|source| BacklogError::Redpanda {
                operation,
                message: format!("flush request: {source}"),
            })?;

        let mut line = String::new();
        loop {
            line.clear();
            let bytes_read = timeout(self.request_timeout, stream.read_line(&mut line))
                .await
                .map_err(|_| BacklogError::Timeout { operation })?
                .map_err(|source| BacklogError::Redpanda {
                    operation,
                    message: format!("read reply: {source}"),
                })?;
            let trimmed = line.trim_end();
            if bytes_read == 0 || trimmed.is_empty() {
                return Err(BacklogError::Redpanda {
                    operation,
                    message: "unexpected EOF while reading reply".to_string(),
                });
            }
            if trimmed == "PING" {
                timeout(
                    self.request_timeout,
                    stream.get_mut().write_all(b"PONG\r\n"),
                )
                .await
                .map_err(|_| BacklogError::Timeout { operation })?
                .map_err(|source| BacklogError::Redpanda {
                    operation,
                    message: format!("send PONG: {source}"),
                })?;
                timeout(self.request_timeout, stream.get_mut().flush())
                    .await
                    .map_err(|_| BacklogError::Timeout { operation })?
                    .map_err(|source| BacklogError::Redpanda {
                        operation,
                        message: format!("flush PONG: {source}"),
                    })?;
                continue;
            }
            if trimmed.starts_with("+OK") || trimmed.starts_with("INFO ") {
                continue;
            }
            if trimmed.starts_with("-ERR") {
                let unsub_command = format!("UNSUB {sid} 1\r\n");
                let _ = timeout(
                    self.request_timeout,
                    stream.write_all(unsub_command.as_bytes()),
                )
                .await;
                let _ = timeout(self.request_timeout, stream.flush()).await;
                return Err(BacklogError::Redpanda {
                    operation,
                    message: trimmed.to_string(),
                });
            }
            if !trimmed.starts_with("MSG ") {
                continue;
            }
            let parts: Vec<_> = trimmed.split_whitespace().collect();
            if parts.len() < 4 {
                continue;
            }
            let msg_topic = parts[1];
            if msg_topic != reply_topic {
                continue;
            }
            let size = parts
                .last()
                .ok_or_else(|| BacklogError::Redpanda {
                    operation,
                    message: format!("missing reply size: {trimmed}"),
                })?
                .parse::<usize>()
                .map_err(|source| BacklogError::Redpanda {
                    operation,
                    message: format!("invalid reply size: {source}"),
                })?;
            let mut payload_buf = vec![0_u8; size];
            timeout(self.request_timeout, stream.read_exact(&mut payload_buf))
                .await
                .map_err(|_| BacklogError::Timeout { operation })?
                .map_err(|source| BacklogError::Redpanda {
                    operation,
                    message: format!("read reply payload: {source}"),
                })?;
            let mut terminator = [0_u8; 2];
            timeout(self.request_timeout, stream.read_exact(&mut terminator))
                .await
                .map_err(|_| BacklogError::Timeout { operation })?
                .map_err(|source| BacklogError::Redpanda {
                    operation,
                    message: format!("read reply terminator: {source}"),
                })?;
            if terminator != *b"\r\n" {
                return Err(BacklogError::Redpanda {
                    operation,
                    message: "invalid reply terminator".to_string(),
                });
            }
            let result = String::from_utf8(payload_buf).map_err(|source| BacklogError::Redpanda {
                operation,
                message: format!("reply is not UTF-8: {source}"),
            });
            let unsub_command = format!("UNSUB {sid} 1\r\n");
            timeout(
                self.request_timeout,
                stream.write_all(unsub_command.as_bytes()),
            )
            .await
            .map_err(|_| BacklogError::Timeout { operation })?
            .map_err(|source| BacklogError::Redpanda {
                operation,
                message: format!("send UNSUB: {source}"),
            })?;
            timeout(self.request_timeout, stream.flush())
                .await
                .map_err(|_| BacklogError::Timeout { operation })?
                .map_err(|source| BacklogError::Redpanda {
                    operation,
                    message: format!("flush UNSUB: {source}"),
                })?;
            return result;
        }
    }

}
