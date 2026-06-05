    #[tokio::test]
    async fn invalid_observed_at_is_rejected_before_side_effects() {
        let state = test_state();
        let publisher = MemoryPublisher {
            fail: false,
            published: Arc::new(Mutex::new(Vec::new())),
        };
        let backlog = MemoryBacklog::default();
        let mut event = entry();
        event.observed_at = "not-a-timestamp".to_string();

        let error = publish_entry(&state, &backlog, &publisher, event)
            .await
            .unwrap_err();

        assert!(
            matches!(error, PublishError::Publish(message) if message.contains("invalid observed_at timestamp"))
        );
        assert!(publisher.published.lock().unwrap().is_empty());
        assert!(backlog.rows.lock().unwrap().is_empty());
        assert!(backlog.ingest_rows.lock().unwrap().is_empty());
        assert!(state.lock().unwrap().memory_backlog.is_empty());
    }

    #[tokio::test]
    async fn failed_publish_queued_in_memory_returns_queued() {
        let state = test_state();
        let publisher = MemoryPublisher {
            fail: true,
            published: Arc::new(Mutex::new(Vec::new())),
        };

        let error = publish_entry(&state, &FailingBacklog, &publisher, entry())
            .await
            .unwrap_err();

        assert!(matches!(error, PublishError::Queued(_)));
        assert_eq!(state.lock().unwrap().memory_backlog.len(), 1);
    }

    #[tokio::test]
    async fn flush_memory_backlog_opens_circuit_breaker_when_save_pending_fails() {
        let state = test_state();
        let payload = "{\"event_type\":\"wifi_management_frame\"}".to_string();
        let error = "redpanda unavailable".to_string();

        state.lock().unwrap().put_memory_backlog(
            "dedupe-1".to_string(),
            "wireless.audit".to_string(),
            &payload,
            &error,
        );

        flush_memory_backlog(&state, &FailingBacklog).await;

        assert_eq!(state.lock().unwrap().memory_backlog.len(), 1);
        assert_eq!(
            state.lock().unwrap().circuit_breaker_state,
            CircuitBreakerState::Open
        );
    }

    #[test]
    fn circuit_breaker_uses_configured_timeout_bounds() {
        let state = PublishState::shared_with_config(NonZeroUsize::new(64).unwrap(), None, 5, 20);
        let mut state = state.lock().unwrap();

        state.circuit_breaker_failure_count = 1;
        assert_eq!(state.circuit_breaker_timeout(), Duration::from_millis(5));

        state.circuit_breaker_failure_count = 3;
        assert_eq!(state.circuit_breaker_timeout(), Duration::from_millis(20));
    }

    #[test]
    fn journal_append_skips_when_size_limit_is_exceeded() {
        let temp_dir = tempfile::tempdir().unwrap();
        let journal_path = temp_dir.path().join("publish.jsonl");
        let file = std::fs::File::create(&journal_path).unwrap();
        file.set_len(MAX_JOURNAL_BYTES + 1).unwrap();
        let state = PublishState::shared_with_config(
            NonZeroUsize::new(64).unwrap(),
            Some(journal_path),
            5,
            20,
        );

        {
            let state = state.lock().unwrap();
            state.journal_append("dedupe-1", WIRELESS_AUDIT_TOPIC, "{}", "unavailable");
            assert_eq!(state.journal_bytes(), MAX_JOURNAL_BYTES + 1);
        }
    }

    #[tokio::test]
    async fn replay_journal_retains_entries_that_fail_replay() {
        let temp_dir = tempfile::tempdir().unwrap();
        let journal_path = temp_dir.path().join("publish.jsonl");
        let ok_payload = r#"{"event_type":"ok","observed_at":"2026-04-20T12:00:00Z"}"#;
        let fail_payload = r#"{"event_type":"fail","observed_at":"2026-04-20T12:00:01Z"}"#;
        let ok_key = "ok-key";
        let fail_key = "fail-key";
        let ok_line = serde_json::json!({
            "dedupe_key": ok_key,
            "stream_name": "wireless.audit",
            "payload": ok_payload,
            "error": "unavailable"
        });
        let fail_line = serde_json::json!({
            "dedupe_key": fail_key,
            "stream_name": "wireless.audit",
            "payload": fail_payload,
            "error": "unavailable"
        });
        std::fs::write(&journal_path, format!("{ok_line}\n{fail_line}\n")).unwrap();
        let state = PublishState::shared_with_config(
            NonZeroUsize::new(64).unwrap(),
            Some(journal_path.clone()),
            5,
            20,
        );
        let backlog = FailingKeyBacklog {
            fail_key: fail_key.to_string(),
            rows: Mutex::new(Vec::new()),
        };

        let replayed = replay_journal(&state, &backlog).await.unwrap();

        assert_eq!(replayed, 1);
        assert_eq!(backlog.rows.lock().unwrap().len(), 1);
        let journal = std::fs::read_to_string(&journal_path).unwrap();
        assert!(!journal.contains(ok_key));
        assert!(journal.contains(fail_key));
        assert_eq!(state.lock().unwrap().memory_backlog.len(), 1);
    }

    #[tokio::test]
    async fn reconciliation_retries_and_clears_backlog() {
        let state = test_state();
        let backlog = MemoryBacklog::default();
        let event = entry();
        let payload = serde_json::to_string(&event).unwrap();
        let key = dedupe_key(&payload);
        backlog
            .save_pending(&key, "wireless.audit", &payload, "redpanda unavailable")
            .await
            .unwrap();

        let publisher = MemoryPublisher {
            fail: false,
            published: Arc::new(Mutex::new(Vec::new())),
        };
        reconcile_backlog(
            &state,
            &backlog,
            &publisher,
            &AuditWindow::from_parts(None, None, None, None),
        )
        .await
        .unwrap();

        assert!(backlog.rows.lock().unwrap().is_empty());
        assert_eq!(publisher.published.lock().unwrap().len(), 1);
        assert!(backlog.ingest_rows.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn reconciliation_enqueue_failure_keeps_backlog_entry_pending() {
        let state = test_state();
        let backlog = MemoryBacklog::default();
        let event = entry();
        let payload = serde_json::to_string(&event).unwrap();
        let key = dedupe_key(&payload);
        backlog
            .save_pending(&key, "wireless.audit", &payload, "redpanda unavailable")
            .await
            .unwrap();

        let publisher = MemoryPublisher {
            fail: true,
            published: Arc::new(Mutex::new(Vec::new())),
        };

        reconcile_backlog(
            &state,
            &backlog,
            &publisher,
            &AuditWindow::from_parts(None, None, None, None),
        )
        .await
        .unwrap();

        let rows = backlog.rows.lock().unwrap().clone();
        assert!(!rows.is_empty());
        assert!(rows.iter().any(|row| row.dedupe_key == key));
        assert!(backlog.ingest_rows.lock().unwrap().is_empty());
        assert!(publisher.published.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn reconciliation_continues_across_multiple_entries() {
        let state = test_state();

        let mut first = entry();
        first.sequence_number = Some(1);
        let first_payload = serde_json::to_string(&first).unwrap();
        let first_key = dedupe_key(&first_payload);

        let mut second = entry();
        second.sequence_number = Some(2);
        let second_payload = serde_json::to_string(&second).unwrap();
        let second_key = dedupe_key(&second_payload);

        let backlog = MemoryBacklog::default();
        backlog
            .save_pending(
                &first_key,
                "wireless.audit",
                &first_payload,
                "redpanda unavailable",
            )
            .await
            .unwrap();
        backlog
            .save_pending(
                &second_key,
                "wireless.audit",
                &second_payload,
                "redpanda unavailable",
            )
            .await
            .unwrap();

        let publisher = MemoryPublisher {
            fail: false,
            published: Arc::new(Mutex::new(Vec::new())),
        };

        reconcile_backlog(
            &state,
            &backlog,
            &publisher,
            &AuditWindow::from_parts(None, None, None, None),
        )
        .await
        .unwrap();

        let pending = backlog.rows.lock().unwrap().clone();
        assert!(pending.is_empty());

        let published = publisher.published.lock().unwrap().clone();
        assert_eq!(published.len(), 2);
        assert!(published
            .iter()
            .all(|(topic, _)| topic == SYNC_SCAN_REQUEST_TOPIC));
    }

    #[tokio::test]
    async fn reconciliation_skips_malformed_backlog_payload() {
        let state = test_state();
        let backlog = MemoryBacklog::default();
        backlog
            .save_pending("bad", "wireless.audit", "{}", "redpanda unavailable")
            .await
            .unwrap();
        let publisher = MemoryPublisher {
            fail: false,
            published: Arc::new(Mutex::new(Vec::new())),
        };

        reconcile_backlog(
            &state,
            &backlog,
            &publisher,
            &AuditWindow::from_parts(None, None, None, None),
        )
        .await
        .unwrap();

        assert_eq!(backlog.rows.lock().unwrap().len(), 1);
        assert!(publisher.published.lock().unwrap().is_empty());
        assert!(backlog.ingest_rows.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn reconciliation_skips_entries_outside_audit_window() {
        let state = test_state();
        let backlog = MemoryBacklog::default();
        let event = entry();
        let payload = serde_json::to_string(&event).unwrap();
        let key = dedupe_key(&payload);
        backlog
            .save_pending(&key, "wireless.audit", &payload, "redpanda unavailable")
            .await
            .unwrap();
        let publisher = MemoryPublisher {
            fail: false,
            published: Arc::new(Mutex::new(Vec::new())),
        };

        reconcile_backlog(
            &state,
            &backlog,
            &publisher,
            &AuditWindow::from_parts(
                None,
                None,
                Some(NaiveTime::from_hms_opt(0, 0, 0).unwrap()),
                Some(NaiveTime::from_hms_opt(0, 1, 0).unwrap()),
            ),
        )
        .await
        .unwrap();

        assert_eq!(backlog.rows.lock().unwrap().len(), 1);
        assert!(publisher.published.lock().unwrap().is_empty());
        assert!(backlog.ingest_rows.lock().unwrap().is_empty());
    }
