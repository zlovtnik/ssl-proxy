#[cfg(all(test, any()))]
mod tests {
    use std::{
        path::Path,
        sync::{Arc, Mutex},
        time::Duration,
    };

    use tokio::{
        io::{duplex, AsyncReadExt, AsyncWriteExt},
        net::TcpListener,
    };

    use super::{
        count_spool_pending, drain_spooled_messages, parse_redpanda_endpoint, read_spool_envelope,
        write_spool_envelope, RedpandaPublishSession, SyncPublisher, SyncPublisherConfig,
        SyncPublisherHealth, ENQUEUE_TIMEOUT_ERROR,
    };
    use crate::{
        config::Config,
        sync::{
            parse_payload_ref, ScanRequest, INLINE_PAYLOAD_REF_PREFIX, OUTBOX_PAYLOAD_REF_PREFIX,
        },
    };

    #[test]
    fn parse_redpanda_defaults_port() {
        let endpoint = parse_redpanda_endpoint("redpanda://localhost").unwrap();
        assert_eq!(endpoint.address, "localhost:9092");
        assert_eq!(endpoint.host, "localhost");
        assert!(!endpoint.tls_enabled);
    }

    #[test]
    fn parse_redpanda_supports_tls_scheme() {
        let endpoint = parse_redpanda_endpoint("tls://redpanda.example.internal:4443").unwrap();
        assert_eq!(endpoint.address, "redpanda.example.internal:4443");
        assert_eq!(endpoint.host, "redpanda.example.internal");
        assert!(endpoint.tls_enabled);
    }

    #[test]
    fn publisher_records_messages_without_network() {
        let publisher = SyncPublisher::new(&Config::default().sync);
        publisher.publish_scan_request(ScanRequest {
            stream_name: "proxy.events".to_string(),
            dedupe_key: "abc".to_string(),
            payload_ref: "inline://payload".to_string(),
            observed_at: "2026-04-17T00:00:00Z".to_string(),
        });

        let messages = publisher.published_messages();
        assert_eq!(messages.len(), 1);
        assert_eq!(messages[0].topic, crate::sync::SYNC_SCAN_REQUEST_TOPIC);
        assert!(messages[0]
            .payload
            .contains("\"stream_name\":\"proxy.events\""));
    }

    #[test]
    fn enqueue_message_records_disabled_publisher_without_network() {
        let publisher = SyncPublisher::new(&Config::default().sync);

        let error = publisher
            .enqueue_message("wireless.audit", "{}")
            .unwrap_err();

        assert_eq!(error, "sync publisher disabled");
        let messages = publisher.published_messages();
        assert_eq!(messages.len(), 1);
        assert_eq!(messages[0].topic, "wireless.audit");
    }

    #[test]
    fn publish_payload_audit_records_disabled_publisher_without_network() {
        let publisher = SyncPublisher::new(&Config::default().sync);

        let error = publisher
            .publish_payload_audit(crate::sync::PAYLOAD_AUDIT_TOPIC, "{}")
            .unwrap_err();

        assert_eq!(error, "sync publisher disabled");
        let messages = publisher.published_messages();
        assert_eq!(messages.len(), 1);
        assert_eq!(messages[0].topic, crate::sync::PAYLOAD_AUDIT_TOPIC);
        assert_eq!(messages[0].payload, "{}");
    }

    #[tokio::test]
    async fn enqueue_message_spools_when_queue_stays_full() {
        let spool = tempfile::tempdir().unwrap();
        let mut config = Config::default();
        config.sync.redpanda_bootstrap_servers = Some("127.0.0.1:9092".to_string());
        config.sync.publish_enqueue_timeout_ms = 1;
        config.sync.publish_spool_dir = spool.path().display().to_string();
        let publisher = SyncPublisher::new(&config.sync);
        let (tx, _rx) = tokio::sync::mpsc::channel(1);
        *publisher.publish_tx.lock().unwrap() = Some(tx);

        publisher.enqueue_message("wireless.audit", "{}").unwrap();
        publisher.enqueue_message("wireless.audit", "{}").unwrap();

        assert_eq!(count_spool_pending(spool.path()), 1);
        let path = super::list_spool_envelopes(spool.path()).unwrap().remove(0);
        let envelope = read_spool_envelope(&path).unwrap();
        assert_eq!(envelope.topic, "wireless.audit");
        assert_eq!(envelope.payload, "{}");
        let snapshot = publisher.health_snapshot();
        assert_eq!(snapshot.queue_capacity, 1);
        assert_eq!(snapshot.queue_depth, 1);
        assert_eq!(snapshot.spool_pending, 1);
        assert_eq!(snapshot.spooled_total, 1);
        assert_eq!(snapshot.enqueue_timeouts_total, 1);
        publisher.shutdown().await;
    }

    #[tokio::test]
    async fn try_enqueue_message_reports_timeout_without_spooling() {
        let spool = tempfile::tempdir().unwrap();
        let mut config = Config::default();
        config.sync.redpanda_bootstrap_servers = Some("127.0.0.1:9092".to_string());
        config.sync.publish_enqueue_timeout_ms = 1;
        config.sync.publish_spool_dir = spool.path().display().to_string();
        let publisher = SyncPublisher::new(&config.sync);
        let (tx, _rx) = tokio::sync::mpsc::channel(1);
        *publisher.publish_tx.lock().unwrap() = Some(tx);

        publisher
            .try_enqueue_message("wireless.audit", "{}")
            .unwrap();
        let error = publisher
            .try_enqueue_message("wireless.audit", "{}")
            .unwrap_err();

        assert_eq!(error, ENQUEUE_TIMEOUT_ERROR);
        assert_eq!(count_spool_pending(spool.path()), 0);
        let snapshot = publisher.health_snapshot();
        assert_eq!(snapshot.queue_capacity, 1);
        assert_eq!(snapshot.queue_depth, 1);
        assert_eq!(snapshot.spooled_total, 0);
        assert_eq!(snapshot.enqueue_timeouts_total, 1);
        publisher.shutdown().await;
    }

    #[test]
    fn publisher_uses_inline_payload_ref_below_limit() {
        let publisher = SyncPublisher::new(&Config::default().sync);
        let payload_ref = publisher
            .payload_ref_for_event("{\"small\":true}", "2026-04-17T00:00:00Z")
            .unwrap();
        assert!(payload_ref.starts_with(INLINE_PAYLOAD_REF_PREFIX));
        assert_eq!(
            publisher
                .resolve_payload_ref_contents(&payload_ref)
                .unwrap(),
            "{\"small\":true}"
        );
    }

    #[test]
    fn publisher_spools_large_payload_ref_to_outbox() {
        let mut config = Config::default();
        config.sync.inline_payload_max_bytes = 8;
        config.sync.outbox_dir = std::env::temp_dir()
            .join(format!("boringtun-sync-outbox-{}", std::process::id()))
            .display()
            .to_string();
        let publisher = SyncPublisher::new(&config.sync);
        let payload_ref = publisher
            .payload_ref_for_event("{\"large\":true}", "2026-04-17T00:00:00Z")
            .unwrap();
        assert!(payload_ref.starts_with(OUTBOX_PAYLOAD_REF_PREFIX));
        assert_eq!(
            publisher
                .resolve_payload_ref_contents(&payload_ref)
                .unwrap(),
            "{\"large\":true}"
        );
        if let Some(parsed) = parse_payload_ref(&payload_ref) {
            let path = Path::new(&config.sync.outbox_dir).join(parsed.locator);
            let _ = std::fs::remove_file(path);
        }
        let _ = std::fs::remove_dir_all(&config.sync.outbox_dir);
    }

    #[tokio::test]
    async fn persistent_session_publish_uses_ack_inbox_and_unsub() {
        let (client, mut server) = duplex(4096);
        let mut session = RedpandaPublishSession {
            stream: Box::new(client),
        };
        let config = SyncPublisherConfig {
            redpanda_bootstrap_servers: Some("127.0.0.1:9092".to_string()),
            connect_timeout: Duration::from_secs(1),
            publish_timeout: Duration::from_secs(1),
            queue_capacity: 8_192,
            enqueue_timeout: Duration::from_millis(25),
            username: None,
            password: None,
            tls_enabled: false,
            tls_server_name: None,
            tls_ca_cert_path: None,
            tls_client_cert_path: None,
            tls_client_key_path: None,
            inline_payload_max_bytes: 2_048,
            outbox_dir: std::env::temp_dir(),
            publish_spool_dir: std::env::temp_dir().join("ssl-proxy-sync-test-spool"),
        };

        let server_task = tokio::spawn(async move {
            let mut received = Vec::new();
            let mut buffer = [0u8; 256];
            loop {
                let read = server.read(&mut buffer).await.unwrap();
                assert!(read > 0);
                received.extend_from_slice(&buffer[..read]);
                if received
                    .windows(b"\r\nhello\r\n".len())
                    .any(|window| window == b"\r\nhello\r\n")
                {
                    break;
                }
            }
            let text = String::from_utf8(received).unwrap();
            assert!(text.contains("SUB _INBOX."));
            assert!(text.contains("UNSUB "));
            assert!(text.contains("PUB wireless.audit _INBOX."));
            server
                .write_all(b"MSG _INBOX.test 1 2\r\n{}\r\n")
                .await
                .unwrap();
        });

        session
            .publish(&config, "wireless.audit", "hello")
            .await
            .unwrap();
        server_task.await.unwrap();
    }

    #[tokio::test]
    async fn persistent_session_publish_fails_after_too_many_non_msg_responses() {
        let (client, mut server) = duplex(4096);
        let mut session = RedpandaPublishSession {
            stream: Box::new(client),
        };
        let config = SyncPublisherConfig {
            redpanda_bootstrap_servers: Some("127.0.0.1:9092".to_string()),
            connect_timeout: Duration::from_secs(1),
            publish_timeout: Duration::from_secs(1),
            queue_capacity: 8_192,
            enqueue_timeout: Duration::from_millis(25),
            username: None,
            password: None,
            tls_enabled: false,
            tls_server_name: None,
            tls_ca_cert_path: None,
            tls_client_cert_path: None,
            tls_client_key_path: None,
            inline_payload_max_bytes: 2_048,
            outbox_dir: std::env::temp_dir(),
            publish_spool_dir: std::env::temp_dir().join("ssl-proxy-sync-test-spool"),
        };

        let server_task = tokio::spawn(async move {
            let mut received = Vec::new();
            let mut buffer = [0u8; 256];
            loop {
                let read = server.read(&mut buffer).await.unwrap();
                assert!(read > 0);
                received.extend_from_slice(&buffer[..read]);
                if received
                    .windows(b"\r\nhello\r\n".len())
                    .any(|window| window == b"\r\nhello\r\n")
                {
                    break;
                }
            }
            for _ in 0..40 {
                server.write_all(b"+OK\r\n").await.unwrap();
            }
        });

        let error = session
            .publish(&config, "wireless.audit", "hello")
            .await
            .unwrap_err();
        assert!(error.contains("too many non-MSG responses"));
        server_task.await.unwrap();
    }

    #[tokio::test]
    async fn persistent_session_publish_rejects_json_error_ack() {
        let (client, mut server) = duplex(4096);
        let mut session = RedpandaPublishSession {
            stream: Box::new(client),
        };
        let config = SyncPublisherConfig {
            redpanda_bootstrap_servers: Some("127.0.0.1:9092".to_string()),
            connect_timeout: Duration::from_secs(1),
            publish_timeout: Duration::from_secs(1),
            queue_capacity: 8_192,
            enqueue_timeout: Duration::from_millis(25),
            username: None,
            password: None,
            tls_enabled: false,
            tls_server_name: None,
            tls_ca_cert_path: None,
            tls_client_cert_path: None,
            tls_client_key_path: None,
            inline_payload_max_bytes: 2_048,
            outbox_dir: std::env::temp_dir(),
            publish_spool_dir: std::env::temp_dir().join("ssl-proxy-sync-test-spool"),
        };

        let server_task = tokio::spawn(async move {
            let mut received = Vec::new();
            let mut buffer = [0u8; 256];
            loop {
                let read = server.read(&mut buffer).await.unwrap();
                assert!(read > 0);
                received.extend_from_slice(&buffer[..read]);
                if received
                    .windows(b"\r\nhello\r\n".len())
                    .any(|window| window == b"\r\nhello\r\n")
                {
                    break;
                }
            }
            let ack = r#"{"error":{"code":500}}"#;
            let frame = format!("MSG _INBOX.test 1 {}\r\n{}\r\n", ack.len(), ack);
            server.write_all(frame.as_bytes()).await.unwrap();
        });

        let error = session
            .publish(&config, "wireless.audit", "hello")
            .await
            .unwrap_err();
        assert!(error.contains("Redpanda publish failed"));
        server_task.await.unwrap();
    }

    #[tokio::test]
    async fn persistent_session_publish_allows_non_json_ack_with_error_word() {
        let (client, mut server) = duplex(4096);
        let mut session = RedpandaPublishSession {
            stream: Box::new(client),
        };
        let config = SyncPublisherConfig {
            redpanda_bootstrap_servers: Some("127.0.0.1:9092".to_string()),
            connect_timeout: Duration::from_secs(1),
            publish_timeout: Duration::from_secs(1),
            queue_capacity: 8_192,
            enqueue_timeout: Duration::from_millis(25),
            username: None,
            password: None,
            tls_enabled: false,
            tls_server_name: None,
            tls_ca_cert_path: None,
            tls_client_cert_path: None,
            tls_client_key_path: None,
            inline_payload_max_bytes: 2_048,
            outbox_dir: std::env::temp_dir(),
            publish_spool_dir: std::env::temp_dir().join("ssl-proxy-sync-test-spool"),
        };

        let server_task = tokio::spawn(async move {
            let mut received = Vec::new();
            let mut buffer = [0u8; 256];
            loop {
                let read = server.read(&mut buffer).await.unwrap();
                assert!(read > 0);
                received.extend_from_slice(&buffer[..read]);
                if received
                    .windows(b"\r\nhello\r\n".len())
                    .any(|window| window == b"\r\nhello\r\n")
                {
                    break;
                }
            }
            let ack = "error: transient";
            let frame = format!("MSG _INBOX.test 1 {}\r\n{}\r\n", ack.len(), ack);
            server.write_all(frame.as_bytes()).await.unwrap();
        });

        session
            .publish(&config, "wireless.audit", "hello")
            .await
            .unwrap();
        server_task.await.unwrap();
    }

    #[tokio::test]
    async fn worker_publishes_spooled_envelope_and_deletes_file() {
        let spool = tempfile::tempdir().unwrap();
        write_spool_envelope(spool.path(), "wireless.audit", "hello").unwrap();
        let (url, server_task) = spawn_mock_redpanda("hello", r#"{}"#).await;
        let config = test_publisher_config(url, spool.path());
        let health = Arc::new(Mutex::new(SyncPublisherHealth::default()));
        let mut session = None;

        drain_spooled_messages(&config, &health, &mut session)
            .await
            .unwrap();

        assert_eq!(count_spool_pending(spool.path()), 0);
        let received = String::from_utf8(server_task.await.unwrap()).unwrap();
        assert!(received.contains("PUB wireless.audit _INBOX."));
    }

    #[tokio::test]
    async fn worker_leaves_spooled_envelope_when_publish_fails() {
        let spool = tempfile::tempdir().unwrap();
        write_spool_envelope(spool.path(), "wireless.audit", "hello").unwrap();
        let (url, server_task) = spawn_mock_redpanda("hello", r#"{"error":{"code":500}}"#).await;
        let config = test_publisher_config(url, spool.path());
        let health = Arc::new(Mutex::new(SyncPublisherHealth::default()));
        let mut session = None;

        let error = drain_spooled_messages(&config, &health, &mut session)
            .await
            .unwrap_err();

        assert!(error.contains("Redpanda publish failed"));
        assert_eq!(count_spool_pending(spool.path()), 1);
        let _ = server_task.await.unwrap();
    }

    fn test_publisher_config(
        redpanda_bootstrap_servers: String,
        spool_dir: &Path,
    ) -> SyncPublisherConfig {
        SyncPublisherConfig {
            redpanda_bootstrap_servers: Some(redpanda_bootstrap_servers),
            connect_timeout: Duration::from_secs(1),
            publish_timeout: Duration::from_secs(1),
            queue_capacity: 8_192,
            enqueue_timeout: Duration::from_millis(25),
            username: None,
            password: None,
            tls_enabled: false,
            tls_server_name: None,
            tls_ca_cert_path: None,
            tls_client_cert_path: None,
            tls_client_key_path: None,
            inline_payload_max_bytes: 2_048,
            outbox_dir: std::env::temp_dir(),
            publish_spool_dir: spool_dir.to_path_buf(),
        }
    }

    async fn spawn_mock_redpanda(
        expected_payload: &'static str,
        ack_payload: &'static str,
    ) -> (String, tokio::task::JoinHandle<Vec<u8>>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let task = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            stream.write_all(b"INFO {}\r\n").await.unwrap();
            let mut received = Vec::new();
            let mut buffer = [0u8; 256];
            loop {
                let read = stream.read(&mut buffer).await.unwrap();
                assert!(read > 0);
                received.extend_from_slice(&buffer[..read]);
                if received
                    .windows(b"CONNECT ".len())
                    .any(|window| window == b"CONNECT ")
                {
                    break;
                }
            }
            stream.write_all(b"+OK\r\n").await.unwrap();
            let expected_frame = format!("\r\n{expected_payload}\r\n");
            loop {
                let read = stream.read(&mut buffer).await.unwrap();
                assert!(read > 0);
                received.extend_from_slice(&buffer[..read]);
                if received
                    .windows(expected_frame.as_bytes().len())
                    .any(|window| window == expected_frame.as_bytes())
                {
                    break;
                }
            }
            let frame = format!(
                "MSG _INBOX.test 1 {}\r\n{}\r\n",
                ack_payload.len(),
                ack_payload
            );
            stream.write_all(frame.as_bytes()).await.unwrap();
            received
        });

        (format!("redpanda://{address}"), task)
    }
}
