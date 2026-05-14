// Copyright (c) 2026 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

//! Integration test for browser payload audit publishing.

#[cfg(test)]
mod tests {
    use hickory_resolver::TokioAsyncResolver;
    use serde_json::Value;
    use ssl_proxy::{
        config::Config,
        identity::ResolvedIdentity,
        payload_audit::{audit_http_preview, PayloadAuditRecord},
        state::AppState,
    };
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::TcpListener,
        sync::broadcast,
    };

    #[tokio::test]
    #[ignore = "requires a running Redpanda broker"]
    async fn payload_audit_publishes_redacted_record_to_redpanda() {
        let body = r#"{"username":"alice","password":"secret"}"#;
        let preview = format!(
            "POST /login HTTP/1.1\r\nHost: example.com\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{body}",
            body.len()
        );
        let (redpanda_bootstrap_servers, server_task) = spawn_mock_redpanda().await;
        let state = create_state(redpanda_bootstrap_servers).await;
        let identity = ResolvedIdentity {
            peer_ip: Some("10.0.0.2".to_string()),
            wg_pubkey: Some("pubkey".to_string()),
            device_id: Some("device-1".to_string()),
            identity_source: Some("registered".to_string()),
            peer_hostname: Some("phone.local".to_string()),
            client_ua: None,
        };

        assert!(audit_http_preview(
            preview.as_bytes(),
            "example.com",
            &identity,
            &state
        ));

        let published = tokio::time::timeout(std::time::Duration::from_secs(2), server_task)
            .await
            .expect("mock Redpanda should receive publish")
            .expect("mock Redpanda task should complete");
        state.publisher.shutdown().await;

        assert_eq!(published.topic, "proxy.payload_audit");
        let record: PayloadAuditRecord = serde_json::from_str(&published.payload).unwrap();
        assert_eq!(record.body["password"], "[REDACTED]");
        assert_eq!(record.body_bytes_original, body.len());
        let body_value: Value = serde_json::from_str(&published.payload).unwrap();
        assert_eq!(body_value["body"]["username"], "alice");
    }

    async fn create_state(redpanda_bootstrap_servers: String) -> ssl_proxy::state::SharedState {
        let (stats_tx, _) = broadcast::channel(16);
        let (events_tx, _) = broadcast::channel(16);
        let resolver = TokioAsyncResolver::tokio_from_system_conf()
            .expect("system resolver should initialize");
        let mut config = Config::default();
        config.payload_audit.enabled = true;
        config.sync.redpanda_bootstrap_servers = Some(redpanda_bootstrap_servers);

        AppState::new(
            hyper_util::client::legacy::Client::builder(hyper_util::rt::TokioExecutor::new())
                .build(hyper_util::client::legacy::connect::HttpConnector::new()),
            resolver,
            stats_tx,
            events_tx,
            config,
        )
    }

    struct PublishedFrame {
        topic: String,
        payload: String,
    }

    async fn spawn_mock_redpanda() -> (String, tokio::task::JoinHandle<PublishedFrame>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let task = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            stream.write_all(b"INFO {}\r\n").await.unwrap();
            let mut received = Vec::new();
            let mut buffer = [0u8; 1024];
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

            let mut received = Vec::new();
            loop {
                let read = stream.read(&mut buffer).await.unwrap();
                assert!(read > 0);
                received.extend_from_slice(&buffer[..read]);
                if let Some(frame) = parse_pub_frame(&received) {
                    stream
                        .write_all(b"MSG _INBOX.test 1 2\r\n{}\r\n")
                        .await
                        .unwrap();
                    return frame;
                }
            }
        });

        (format!("redpanda://{address}"), task)
    }

    fn parse_pub_frame(bytes: &[u8]) -> Option<PublishedFrame> {
        let start = bytes
            .windows(b"PUB ".len())
            .position(|window| window == b"PUB ")?;
        let bytes = &bytes[start..];
        let header_end = bytes.windows(2).position(|window| window == b"\r\n")?;
        let header = std::str::from_utf8(&bytes[..header_end]).ok()?;
        let mut parts = header.split_whitespace();
        if parts.next()? != "PUB" {
            return None;
        }
        let topic = parts.next()?.to_string();
        let _reply_to = parts.next()?;
        let payload_len = parts.next()?.parse::<usize>().ok()?;
        let payload_start = header_end + 2;
        let payload_end = payload_start + payload_len;
        if bytes.len() < payload_end + 2 {
            return None;
        }
        let payload = std::str::from_utf8(&bytes[payload_start..payload_end])
            .ok()?
            .to_string();
        Some(PublishedFrame { topic, payload })
    }
}
