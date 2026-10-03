use super::*;

fn assert_history_bounded(publisher: &SyncPublisher) {
    let records = publisher.published.lock().unwrap();
    assert!(records.messages.len() <= PUBLISHED_HISTORY_MAX_MESSAGES);
    let bytes: usize = records
        .messages
        .iter()
        .map(|message| message.topic.len() + message.payload.len())
        .sum();
    assert_eq!(records.bytes, bytes);
    assert!(bytes <= PUBLISHED_HISTORY_MAX_BYTES);
}

#[test]
fn disabled_publish_apis_bound_history_and_preserve_attempt_counts() {
    // Construct outside the runtime so no network worker is started.
    let publisher = SyncPublisher::new(&SyncConfig::default());
    let runtime = tokio::runtime::Runtime::new().unwrap();
    for index in 0..1024 {
        let payload = format!("message-{index}");
        let result = match index % 3 {
            0 => publisher.enqueue_message("wireless.audit", &payload),
            1 => publisher.try_enqueue_message("wireless.audit", &payload),
            _ => runtime.block_on(publisher.publish_message("wireless.audit", &payload)),
        };
        assert_eq!(result.unwrap_err(), "sync publisher disabled");
        assert_history_bounded(&publisher);
    }
    let messages = publisher.published_messages();
    assert_eq!(messages.len(), PUBLISHED_HISTORY_MAX_MESSAGES);
    assert_eq!(messages.first().unwrap().payload, "message-768");
    assert_eq!(messages.last().unwrap().payload, "message-1023");
    assert_eq!(publisher.published_topic_counts()["wireless.audit"], 1024);
}

#[test]
fn variable_size_and_oversized_samples_do_not_exceed_byte_limit() {
    let publisher = SyncPublisher::new(&SyncConfig::default());
    let clone = publisher.clone();
    for index in 0..512 {
        let payload = "x".repeat(8192 + index);
        let _ = clone.enqueue_message("wireless.audit", &payload);
        assert_history_bounded(&publisher);
    }
    assert!(publisher.published_messages().len() < PUBLISHED_HISTORY_MAX_MESSAGES);
    let before = publisher.published_messages();
    let oversized = "x".repeat(PUBLISHED_HISTORY_MAX_BYTES);
    let _ = publisher.enqueue_message("wireless.audit", &oversized);
    assert_eq!(publisher.published_messages(), before);
    assert_eq!(publisher.published_topic_counts()["wireless.audit"], 513);
    // Topic bytes count toward the same limit, including oversized topics.
    let _ = publisher.enqueue_message(&oversized, "");
    assert_history_bounded(&publisher);
}

#[test]
fn diagnostic_topic_counts_are_bounded_under_topic_churn() {
    let publisher = SyncPublisher::new(&SyncConfig::default());
    for index in 0..1024 {
        let _ = publisher.enqueue_message(&format!("topic-{index}"), "");
    }
    let oversized_topic = "x".repeat(PUBLISHED_COUNTS_MAX_TOPIC_BYTES + 1);
    let _ = publisher.enqueue_message(&oversized_topic, "");
    let _ = publisher.enqueue_message("topic-0", "");
    let counts = publisher.published_topic_counts();
    assert_eq!(counts.len(), PUBLISHED_COUNTS_MAX_TOPICS);
    assert_eq!(counts["topic-0"], 2);
    assert!(counts
        .keys()
        .all(|topic| topic.len() <= PUBLISHED_COUNTS_MAX_TOPIC_BYTES));
    assert_history_bounded(&publisher);
}

#[test]
fn full_queue_attempts_remain_bounded_and_keep_spool_semantics() {
    let spool = tempfile::tempdir().unwrap();
    let config = SyncConfig {
        redpanda_bootstrap_servers: Some("127.0.0.1:9092".to_string()),
        publish_enqueue_timeout_ms: 0,
        publish_spool_dir: spool.path().display().to_string(),
        ..SyncConfig::default()
    };
    let publisher = SyncPublisher::new(&config);
    let (tx, mut rx) = mpsc::channel(1);
    *publisher.publish_tx.lock().unwrap() = Some(tx);
    publisher
        .enqueue_message("wireless.audit", "first")
        .unwrap();
    for index in 0..512 {
        let payload = "x".repeat(4096 + index);
        assert_eq!(
            publisher
                .try_enqueue_message("wireless.audit", &payload)
                .unwrap_err(),
            ENQUEUE_TIMEOUT_ERROR
        );
        assert_history_bounded(&publisher);
    }
    publisher
        .enqueue_message("wireless.audit", "spooled")
        .unwrap();
    assert_eq!(count_spool_pending(spool.path()), 1);
    let path = list_spool_envelopes(spool.path()).unwrap().remove(0);
    let envelope = read_spool_envelope(&path).unwrap();
    assert_eq!(envelope.payload, "spooled");
    assert_eq!(rx.try_recv().unwrap().payload, "first");
    assert_eq!(publisher.published_topic_counts()["wireless.audit"], 514);
}

#[test]
fn successful_publish_apis_deliver_complete_payloads_despite_history_limits() {
    let config = SyncConfig {
        redpanda_bootstrap_servers: Some("127.0.0.1:9092".to_string()),
        ..SyncConfig::default()
    };
    let publisher = SyncPublisher::new(&config);
    let (tx, mut rx) = mpsc::channel(4);
    *publisher.publish_tx.lock().unwrap() = Some(tx);
    // Oversized for diagnostics, still legal input to all three delivery APIs.
    let payload = "x".repeat(PUBLISHED_HISTORY_MAX_BYTES + 1);
    publisher
        .enqueue_message("wireless.audit", &payload)
        .unwrap();
    publisher
        .try_enqueue_message("wireless.audit", &payload)
        .unwrap();
    let runtime = tokio::runtime::Runtime::new().unwrap();
    runtime.block_on(async {
        let expected = payload.clone();
        let receiver = tokio::spawn(async move {
            for _ in 0..3 {
                let message = rx.recv().await.unwrap();
                assert_eq!(message.topic, "wireless.audit");
                assert_eq!(message.payload, expected);
                if let Some(response) = message.response_tx {
                    response.send(Ok(())).unwrap();
                }
            }
        });
        publisher
            .publish_message("wireless.audit", &payload)
            .await
            .unwrap();
        receiver.await.unwrap();
    });
    assert!(publisher.published_messages().is_empty());
    assert_eq!(publisher.published_topic_counts()["wireless.audit"], 3);
}
