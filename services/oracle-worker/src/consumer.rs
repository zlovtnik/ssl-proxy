pub(crate) fn validate_consumer_topic(topic: &str) -> Result<(), String> {
    if topic.trim().is_empty() {
        return Err("Redpanda load topic must not be empty".to_string());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::validate_consumer_topic;

    #[test]
    fn validate_consumer_topic_accepts_topic() {
        assert!(validate_consumer_topic("sync.oracle.load").is_ok());
    }

    #[test]
    fn validate_consumer_topic_rejects_empty_topic() {
        assert!(validate_consumer_topic(" ").is_err());
    }
}
