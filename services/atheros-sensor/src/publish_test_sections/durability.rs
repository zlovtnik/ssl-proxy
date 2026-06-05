    use base64::Engine;
    use chrono::{NaiveTime, TimeZone};
    use std::sync::{Arc, Mutex};

    use super::*;
    use serde_json::json;

    use crate::{
        audit::AuditWindow,
        backlog::{BacklogEntry, BacklogError, IngestRecord},
    };

    struct MemoryPublisher {
        fail: bool,
        published: Arc<Mutex<Vec<(String, String)>>>,
    }

    #[async_trait]
    impl PublishClient for MemoryPublisher {
        fn enqueue_message(&self, topic: &str, payload: &str) -> Result<(), String> {
            if self.fail {
                return Err("redpanda unavailable".to_string());
            }
            self.published
                .lock()
                .unwrap()
                .push((topic.to_string(), payload.to_string()));
            Ok(())
        }

        async fn publish_message(&self, topic: &str, payload: &str) -> Result<(), String> {
            self.enqueue_message(topic, payload)
        }

        fn payload_ref_for_event(
            &self,
            raw_payload: &str,
            _observed_at: &str,
        ) -> Result<String, String> {
            Ok(format!(
                "inline://json/{}",
                base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(raw_payload)
            ))
        }
    }

    #[derive(Default)]
    struct MemoryBacklog {
        rows: Mutex<Vec<BacklogEntry>>,
        ingest_rows: Mutex<Vec<(String, DateTime<Utc>)>>,
    }

    #[async_trait]
    impl BacklogStore for MemoryBacklog {
        async fn record_ingest(&self, record: IngestRecord<'_>) -> Result<(), BacklogError> {
            self.ingest_rows
                .lock()
                .unwrap()
                .push((record.dedupe_key.to_string(), record.observed_at));
            Ok(())
        }

        async fn save_pending(
            &self,
            dedupe_key: &str,
            stream_name: &str,
            payload: &str,
            _error: &str,
        ) -> Result<(), BacklogError> {
            self.rows.lock().unwrap().push(BacklogEntry {
                dedupe_key: dedupe_key.to_string(),
                stream_name: stream_name.to_string(),
                payload: payload.to_string(),
                attempt_count: 1,
            });
            Ok(())
        }

        async fn list_pending(&self) -> Result<Vec<BacklogEntry>, BacklogError> {
            Ok(self.rows.lock().unwrap().clone())
        }

        async fn mark_synced(&self, dedupe_key: &str) -> Result<(), BacklogError> {
            self.rows
                .lock()
                .unwrap()
                .retain(|entry| entry.dedupe_key != dedupe_key);
            Ok(())
        }

        async fn prune_stale(
            &self,
            _max_attempts: i32,
            _max_age_hours: i64,
        ) -> Result<u64, BacklogError> {
            Ok(0)
        }
    }

    struct FailingBacklog;

    #[async_trait]
    impl BacklogStore for FailingBacklog {
        async fn record_ingest(&self, _record: IngestRecord<'_>) -> Result<(), BacklogError> {
            Err(BacklogError::Redpanda {
                operation: "record_ingest",
                message: "unavailable".to_string(),
            })
        }

        async fn save_pending(
            &self,
            _dedupe_key: &str,
            _stream_name: &str,
            _payload: &str,
            _error: &str,
        ) -> Result<(), BacklogError> {
            Err(BacklogError::Redpanda {
                operation: "save_pending",
                message: "unavailable".to_string(),
            })
        }

        async fn list_pending(&self) -> Result<Vec<BacklogEntry>, BacklogError> {
            Ok(Vec::new())
        }

        async fn mark_synced(&self, _dedupe_key: &str) -> Result<(), BacklogError> {
            Ok(())
        }

        async fn prune_stale(
            &self,
            _max_attempts: i32,
            _max_age_hours: i64,
        ) -> Result<u64, BacklogError> {
            Ok(0)
        }
    }

    struct FailingKeyBacklog {
        fail_key: String,
        rows: Mutex<Vec<BacklogEntry>>,
    }

    #[async_trait]
    impl BacklogStore for FailingKeyBacklog {
        async fn record_ingest(&self, _record: IngestRecord<'_>) -> Result<(), BacklogError> {
            Ok(())
        }

        async fn save_pending(
            &self,
            dedupe_key: &str,
            stream_name: &str,
            payload: &str,
            _error: &str,
        ) -> Result<(), BacklogError> {
            if dedupe_key == self.fail_key {
                return Err(BacklogError::Redpanda {
                    operation: "save_pending",
                    message: "selected key unavailable".to_string(),
                });
            }
            self.rows.lock().unwrap().push(BacklogEntry {
                dedupe_key: dedupe_key.to_string(),
                stream_name: stream_name.to_string(),
                payload: payload.to_string(),
                attempt_count: 1,
            });
            Ok(())
        }

        async fn list_pending(&self) -> Result<Vec<BacklogEntry>, BacklogError> {
            Ok(self.rows.lock().unwrap().clone())
        }

        async fn mark_synced(&self, _dedupe_key: &str) -> Result<(), BacklogError> {
            Ok(())
        }

        async fn prune_stale(
            &self,
            _max_attempts: i32,
            _max_age_hours: i64,
        ) -> Result<u64, BacklogError> {
            Ok(0)
        }
    }

    fn test_state() -> SharedPublishState {
        PublishState::shared()
    }

    fn entry() -> AuditEntry {
        serde_json::from_value(json!({
            "event_type": "wifi_management_frame",
            "observed_at": "2026-04-20T12:00:00Z",
            "sensor_id": "00:11:22:33:44:55",
            "location_id": "North-Wing-Entry",
            "interface": "wlan0",
            "channel": 6,
            "bssid": "10:20:30:40:50:60",
            "source_mac": "10:20:30:40:50:60",
            "destination_mac": "ff:ff:ff:ff:ff:ff",
            "ssid": "CorpWiFi",
            "frame_subtype": "beacon",
            "signal_dbm": -42,
            "sequence_number": 1,
            "raw_len": 44,
            "tags": ["wifi", "management"],
            "device_id": null,
            "username": null,
            "identity_source": "unknown"
        }))
        .unwrap()
    }

    #[tokio::test]
    async fn successful_publish_emits_audit_and_records_scan_request() {
        let state = test_state();
        let publisher = MemoryPublisher {
            fail: false,
            published: Arc::new(Mutex::new(Vec::new())),
        };
        let backlog = MemoryBacklog::default();

        publish_entry(&state, &backlog, &publisher, entry())
            .await
            .unwrap();

        let published = publisher.published.lock().unwrap().clone();
        assert_eq!(published.len(), 1);
        assert_eq!(published[0].0, WIRELESS_AUDIT_TOPIC);
        assert!(backlog.rows.lock().unwrap().is_empty());
        let ingest_rows = backlog.ingest_rows.lock().unwrap();
        assert_eq!(ingest_rows.len(), 1);
        assert_eq!(
            ingest_rows[0].1,
            Utc.with_ymd_and_hms(2026, 4, 20, 12, 0, 0).unwrap()
        );
    }

    #[tokio::test]
    async fn publishes_handshake_alert_topic() {
        let publisher = MemoryPublisher {
            fail: false,
            published: Arc::new(Mutex::new(Vec::new())),
        };
        let alert = HandshakeAlert {
            schema_version: 1,
            observed_at: "2026-04-20T12:00:00Z".to_string(),
            sensor_id: "sensor-1".to_string(),
            location_id: "lab".to_string(),
            interface: "wlan0".to_string(),
            bssid: "10:20:30:40:50:60".to_string(),
            client_mac: "aa:bb:cc:dd:ee:01".to_string(),
            signal_dbm: Some(-42),
            pmkid: None,
        };

        publish_handshake_alert(&publisher, &alert).await.unwrap();

        let published = publisher.published.lock().unwrap().clone();
        assert_eq!(published.len(), 1);
        assert_eq!(published[0].0, HANDSHAKE_ALERT_TOPIC);
        assert!(published[0]
            .1
            .contains("\"client_mac\":\"aa:bb:cc:dd:ee:01\""));
    }

    #[tokio::test]
    async fn publishes_bandwidth_event_topic() {
        let state = test_state();
        let backlog = MemoryBacklog::default();
        let publisher = MemoryPublisher {
            fail: false,
            published: Arc::new(Mutex::new(Vec::new())),
        };
        let event = WirelessBandwidthEvent {
            schema_version: 1,
            event_type: "wireless_bandwidth_window".to_string(),
            window_start: "2026-04-20T12:00:00Z".to_string(),
            window_end: "2026-04-20T12:01:00Z".to_string(),
            sensor_id: "sensor-1".to_string(),
            location_id: "lab".to_string(),
            interface: "wlan0".to_string(),
            channel: 6,
            source_mac: "aa:bb:cc:dd:ee:01".to_string(),
            destination_bssid: "10:20:30:40:50:60".to_string(),
            ssid: Some("CorpWiFi".to_string()),
            bytes: 1024,
            frame_count: 2,
            retry_count: 1,
            more_data_count: 1,
            power_save_count: 0,
            strongest_signal_dbm: Some(-42),
            external_bssid: true,
            threshold_exceeded: false,
            frame_size_histogram: Default::default(),
            inter_arrival_p50_ms: Some(500),
            inter_arrival_cv: None,
            wall_clock_delta_ms: None,
            window_is_partial: false,
            max_risk_score: None,
            published_at: None,
        };

        publish_bandwidth_event(&state, &backlog, &publisher, &event)
            .await
            .unwrap();

        let published = publisher.published.lock().unwrap().clone();
        assert_eq!(published.len(), 2);
        assert_eq!(published[0].0, BANDWIDTH_TOPIC);
        assert_eq!(published[1].0, SYNC_SCAN_REQUEST_TOPIC);
        assert!(published[0]
            .1
            .contains("\"event_type\":\"wireless_bandwidth_window\""));
    }

    #[tokio::test]
    async fn durable_oracle_publish_saves_pending_when_live_publish_fails() {
        let state = test_state();
        let publisher = MemoryPublisher {
            fail: true,
            published: Arc::new(Mutex::new(Vec::new())),
        };
        let backlog = MemoryBacklog::default();
        let payload = json!({
            "event_type": "wireless_test_alert",
            "observed_at": "2026-04-20T12:00:00Z",
            "sensor_id": "sensor-1"
        });

        publish_oracle_json_durable(
            &state,
            &backlog,
            &publisher,
            "publish_test_alert",
            "wireless.alert.test",
            &payload,
            "2026-04-20T12:00:00Z",
        )
        .await
        .unwrap();

        let rows = backlog.rows.lock().unwrap().clone();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].stream_name, "wireless.alert.test");
        assert!(rows[0].payload.contains("\"wireless_test_alert\""));
        assert!(publisher.published.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn failed_publish_is_saved_to_backlog_without_pipeline_error() {
        let state = test_state();
        let publisher = MemoryPublisher {
            fail: true,
            published: Arc::new(Mutex::new(Vec::new())),
        };
        let backlog = MemoryBacklog::default();

        publish_entry(&state, &backlog, &publisher, entry())
            .await
            .unwrap();
        assert_eq!(backlog.rows.lock().unwrap().len(), 1);
        assert!(backlog.ingest_rows.lock().unwrap().is_empty());
    }

    struct QueueFullOnEnqueuePublisher {
        published: Arc<Mutex<Vec<(String, String)>>>,
        queue_full_remaining: Mutex<usize>,
    }

    #[async_trait]
    impl PublishClient for QueueFullOnEnqueuePublisher {
        fn enqueue_message(&self, topic: &str, payload: &str) -> Result<(), String> {
            let mut queue_full_remaining = self.queue_full_remaining.lock().unwrap();
            if *queue_full_remaining > 0 {
                *queue_full_remaining -= 1;
                return Err(ENQUEUE_TIMEOUT_ERROR.to_string());
            }
            self.published
                .lock()
                .unwrap()
                .push((topic.to_string(), payload.to_string()));
            Ok(())
        }

        async fn publish_message(&self, topic: &str, payload: &str) -> Result<(), String> {
            self.published
                .lock()
                .unwrap()
                .push((topic.to_string(), payload.to_string()));
            Ok(())
        }

        fn payload_ref_for_event(
            &self,
            raw_payload: &str,
            _observed_at: &str,
        ) -> Result<String, String> {
            Ok(format!(
                "inline://json/{}",
                base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(raw_payload)
            ))
        }
    }

    #[tokio::test]
    async fn queue_full_is_retried_with_backpressure_before_backlog_fallback() {
        let state = test_state();
        let publisher = QueueFullOnEnqueuePublisher {
            published: Arc::new(Mutex::new(Vec::new())),
            queue_full_remaining: Mutex::new(1),
        };
        let backlog = MemoryBacklog::default();

        publish_entry(&state, &backlog, &publisher, entry())
            .await
            .unwrap();

        assert!(backlog.rows.lock().unwrap().is_empty());
        let published = publisher.published.lock().unwrap().clone();
        assert_eq!(published.len(), 1);
        assert_eq!(published[0].0, WIRELESS_AUDIT_TOPIC);
        assert_eq!(backlog.ingest_rows.lock().unwrap().len(), 1);
    }
