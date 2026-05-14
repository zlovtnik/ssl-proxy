use async_nats::jetstream::{
    self, consumer, consumer::pull::Config as PullConsumerConfig, stream::Stream,
};

use crate::config::RunConfig;

pub(crate) async fn ensure_load_consumer(
    stream: &Stream,
    config: &RunConfig,
) -> Result<jetstream::consumer::PullConsumer, String> {
    let consumer = stream
        .get_or_create_consumer(
            config.load_consumer.as_str(),
            PullConsumerConfig {
                durable_name: Some(config.load_consumer.clone()),
                filter_subject: config.load_subject.clone(),
                ack_policy: consumer::AckPolicy::Explicit,
                ..Default::default()
            },
        )
        .await
        .map_err(|error| {
            format!(
                "get/create pull consumer {} on stream {} (subject {}): {error}",
                config.load_consumer, config.audit_stream_name, config.load_subject
            )
        })?;

    validate_consumer_filter(
        &config.audit_stream_name,
        &config.load_consumer,
        consumer.cached_info().config.filter_subject.as_str(),
        &config.load_subject,
    )?;

    Ok(consumer)
}

pub(crate) fn validate_consumer_filter(
    stream_name: &str,
    consumer_name: &str,
    actual_filter: &str,
    expected_filter: &str,
) -> Result<(), String> {
    if actual_filter == expected_filter {
        return Ok(());
    }

    let actual_filter = if actual_filter.is_empty() {
        "<none>"
    } else {
        actual_filter
    };
    Err(format!(
        "invalid JetStream consumer {consumer_name} on stream {stream_name}: expected filter_subject {expected_filter}, found {actual_filter}; rerun nats-bootstrap or delete and recreate the durable consumer"
    ))
}

#[cfg(test)]
mod tests {
    use super::validate_consumer_filter;

    #[test]
    fn validate_consumer_filter_accepts_expected_filter() {
        assert!(validate_consumer_filter(
            "AUDIT_STREAM",
            "oracle-worker-load",
            "sync.oracle.load",
            "sync.oracle.load"
        )
        .is_ok());
    }

    #[test]
    fn validate_consumer_filter_rejects_stale_filter() {
        let error = validate_consumer_filter(
            "AUDIT_STREAM",
            "oracle-worker-load",
            "wireless.audit",
            "sync.oracle.load",
        )
        .unwrap_err();
        assert!(error.contains("expected filter_subject sync.oracle.load"));
        assert!(error.contains("found wireless.audit"));
    }

    #[test]
    fn validate_consumer_filter_rejects_empty_actual_filter() {
        let error =
            validate_consumer_filter("AUDIT_STREAM", "oracle-worker-load", "", "sync.oracle.load")
                .unwrap_err();
        assert!(error.contains("oracle-worker-load"));
        assert!(error.contains("AUDIT_STREAM"));
        assert!(error.contains("expected filter_subject sync.oracle.load"));
        assert!(error.contains("found <none>"));
    }
}
