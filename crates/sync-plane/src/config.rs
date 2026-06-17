/// Sync-plane publisher settings.
///
/// Configures Redpanda connectivity, TLS, authentication, and local spooling
/// for event synchronization producers.
#[derive(Clone)]
pub struct SyncConfig {
    pub redpanda_bootstrap_servers: Option<String>,
    pub connect_timeout_ms: u64,
    pub publish_timeout_ms: u64,
    pub publish_queue_capacity: usize,
    pub publish_enqueue_timeout_ms: u64,
    pub security_protocol: Option<String>,
    pub sasl_mechanisms: Option<String>,
    pub sasl_username: Option<String>,
    pub sasl_password: Option<String>,
    pub ssl_ca_location: Option<String>,
    pub ssl_certificate_location: Option<String>,
    pub ssl_key_location: Option<String>,
    pub inline_payload_max_bytes: usize,
    pub outbox_dir: String,
    pub publish_spool_dir: String,
}

impl Default for SyncConfig {
    fn default() -> Self {
        Self {
            redpanda_bootstrap_servers: None,
            connect_timeout_ms: 2_000,
            publish_timeout_ms: 2_000,
            publish_queue_capacity: 8_192,
            publish_enqueue_timeout_ms: 25,
            security_protocol: None,
            sasl_mechanisms: None,
            sasl_username: None,
            sasl_password: None,
            ssl_ca_location: None,
            ssl_certificate_location: None,
            ssl_key_location: None,
            inline_payload_max_bytes: 2_048,
            outbox_dir: "/tmp/ssl-proxy-sync-outbox".to_string(),
            publish_spool_dir: "/tmp/ssl-proxy-sync-outbox/publish-spool".to_string(),
        }
    }
}

impl std::fmt::Debug for SyncConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SyncConfig")
            .field(
                "redpanda_bootstrap_servers",
                &self.redpanda_bootstrap_servers,
            )
            .field("connect_timeout_ms", &self.connect_timeout_ms)
            .field("publish_timeout_ms", &self.publish_timeout_ms)
            .field("publish_queue_capacity", &self.publish_queue_capacity)
            .field(
                "publish_enqueue_timeout_ms",
                &self.publish_enqueue_timeout_ms,
            )
            .field("security_protocol", &self.security_protocol)
            .field("sasl_mechanisms", &self.sasl_mechanisms)
            .field("sasl_username", &self.sasl_username)
            .field(
                "sasl_password",
                &self
                    .sasl_password
                    .as_ref()
                    .map(|_| "[REDACTED]".to_string()),
            )
            .field("ssl_ca_location", &self.ssl_ca_location)
            .field("ssl_certificate_location", &self.ssl_certificate_location)
            .field("ssl_key_location", &self.ssl_key_location)
            .field("inline_payload_max_bytes", &self.inline_payload_max_bytes)
            .field("outbox_dir", &self.outbox_dir)
            .field("publish_spool_dir", &self.publish_spool_dir)
            .finish()
    }
}
