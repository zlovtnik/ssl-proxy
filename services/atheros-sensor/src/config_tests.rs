use super::*;
use std::sync::{Mutex, MutexGuard, OnceLock};

static ENV_LOCK: OnceLock<Mutex<()>> = OnceLock::new();

struct TestEnv {
    _guard: MutexGuard<'static, ()>,
}

impl Drop for TestEnv {
    fn drop(&mut self) {
        clear_env();
    }
}

fn test_env() -> TestEnv {
    let guard = ENV_LOCK.get_or_init(|| Mutex::new(())).lock().unwrap();
    clear_env();
    TestEnv { _guard: guard }
}

fn clear_env() {
    for name in [
        "ATH_SENSOR_REQUIRE_HOST_ENDPOINTS",
        "SYNC_REDPANDA_BOOTSTRAP_SERVERS",
        "SYNC_REDPANDA_CONNECT_TIMEOUT_MS",
        "SYNC_REDPANDA_PUBLISH_TIMEOUT_MS",
        "SYNC_REDPANDA_SECURITY_PROTOCOL",
        "SYNC_REDPANDA_SASL_MECHANISMS",
        "SYNC_REDPANDA_SASL_USERNAME",
        "SYNC_REDPANDA_SASL_PASSWORD",
        "SYNC_REDPANDA_SASL_PASSWORD_FILE",
        "SYNC_PUBLISH_QUEUE_CAPACITY",
        "SYNC_PUBLISH_ENQUEUE_TIMEOUT_MS",
        "SYNC_REDPANDA_SSL_ENABLED",
        "SYNC_REDPANDA_SSL_ENDPOINT_IDENTIFICATION_ALGORITHM",
        "SYNC_REDPANDA_SSL_CA_LOCATION",
        "SYNC_REDPANDA_SSL_CERTIFICATE_LOCATION",
        "SYNC_REDPANDA_SSL_KEY_LOCATION",
        "SYNC_INLINE_PAYLOAD_MAX_BYTES",
        "SYNC_OUTBOX_DIR",
        "SYNC_PUBLISH_SPOOL_DIR",
        "ATH_SENSOR_DEVICE",
        "ATH_SENSOR_LOCATION_ID",
        "ATH_SENSOR_CHANNEL",
        "ATH_SENSOR_REG_DOMAIN",
        "ATH_SENSOR_BPF",
        "ATH_SENSOR_SNAPLEN",
        "ATH_SENSOR_PCAP_TIMEOUT_MS",
        "ATH_SENSOR_LOG_IDLE_SECS",
        "ATH_SENSOR_CHANNEL_HOP_ENABLED",
        "ATH_SENSOR_CHANNEL_HOP_INTERVAL_MS",
        "ATH_SENSOR_CLIENT_INVENTORY_FLUSH_SECS",
        "ATH_SENSOR_SIGNAL_ANOMALY_DBM_DELTA",
        "ATH_SENSOR_CLOCK_SKEW_ANOMALY_US",
        "ATH_SENSOR_DEAUTH_FLOOD_THRESHOLD",
        "ATH_SENSOR_DEAUTH_FLOOD_WINDOW_SECS",
        "ATH_SENSOR_DEAUTH_FLOOD_COOLDOWN_SECS",
        "ATH_SENSOR_EXPORT_HANDSHAKES",
        "ATH_SENSOR_HANDSHAKE_TTL_SECS",
        "ATH_SENSOR_AUTHORIZED_NETWORK_CACHE_TTL_SECS",
        "ATH_SENSOR_MEMORY_BACKLOG_SIZE",
        "ATH_SENSOR_MEMORY_BACKLOG_FLUSH_INTERVAL_SECS",
        "ATH_SENSOR_PUBLISH_JOURNAL_PATH",
        "ATH_SENSOR_CIRCUIT_BREAKER_INITIAL_TIMEOUT_MS",
        "ATH_SENSOR_CIRCUIT_BREAKER_MAX_TIMEOUT_MS",
        "ATH_SENSOR_AUTHORIZED_NETWORK_CACHE_BACKOFF_MS",
        "ATH_SENSOR_REDPANDA_REQUEST_TIMEOUT_MS",
        "ATH_SENSOR_MAC_DEVICE_LOOKUP_ENABLED",
        "ATH_SENSOR_MAC_LOOKUP_ERROR_TTL_SECS",
        "ATH_SENSOR_MAC_STATE_CAPACITY",
        "ATH_SENSOR_SSID_STATE_CAPACITY",
        "ATH_SENSOR_SESSION_STATE_CAPACITY",
        "ATH_SENSOR_CLIENT_PROBE_SSID_CAPACITY",
        "ATH_SENSOR_PIPELINE_WORKERS",
        "ATH_SENSOR_PIPELINE_QUEUE_CAPACITY",
        "ATH_SENSOR_METRICS_PORT",
        "ATH_SENSOR_SHUTDOWN_GRACE_SECS",
        "ATH_SENSOR_AUDIT_LAYER_STREAM",
        "AUDIT_WINDOW_TZ",
        "AUDIT_WINDOW_DAYS",
        "AUDIT_WINDOW_START",
        "AUDIT_WINDOW_END",
    ] {
        std::env::remove_var(name);
    }
}

#[test]
fn host_endpoint_validation_accepts_loopback_endpoints() {
    let _env = test_env();
    std::env::set_var("ATH_SENSOR_REQUIRE_HOST_ENDPOINTS", "true");
    std::env::set_var(
        "SYNC_REDPANDA_BOOTSTRAP_SERVERS",
        "redpanda://127.0.0.1:19092",
    );

    let config = AppConfig::from_env().unwrap();

    assert_eq!(
        config.sync.redpanda_bootstrap_servers.as_deref(),
        Some("redpanda://127.0.0.1:19092")
    );
    assert_eq!(config.sync.publish_timeout_ms, 2_000);
}

#[test]
fn enrichment_knobs_use_safe_defaults() {
    let _env = test_env();

    let config = AppConfig::from_env().unwrap();

    assert_eq!(config.redpanda_request_timeout_ms, 10_000);
    assert!(config.mac_device_lookup_enabled);
    assert_eq!(config.mac_lookup_error_ttl_secs, 30);
    assert_eq!(config.detector_limits.mac_state_capacity, 100_000);
    assert_eq!(config.detector_limits.ssid_state_capacity, 16_384);
    assert_eq!(config.detector_limits.session_state_capacity, 65_536);
    assert_eq!(config.detector_limits.client_probe_ssid_capacity, 64);
    assert_eq!(config.detector_limits.pipeline_workers, 1);
    assert_eq!(config.detector_limits.pipeline_queue_capacity, 1_024);
    assert_eq!(
        config.publish_journal_path.as_deref(),
        Some(std::path::Path::new(DEFAULT_PUBLISH_JOURNAL_PATH))
    );
}

#[test]
fn enrichment_knobs_accept_overrides() {
    let _env = test_env();
    std::env::set_var("ATH_SENSOR_REDPANDA_REQUEST_TIMEOUT_MS", "15000");
    std::env::set_var("ATH_SENSOR_MAC_DEVICE_LOOKUP_ENABLED", "false");
    std::env::set_var("ATH_SENSOR_MAC_LOOKUP_ERROR_TTL_SECS", "7");
    std::env::set_var("ATH_SENSOR_MAC_STATE_CAPACITY", "12");
    std::env::set_var("ATH_SENSOR_SSID_STATE_CAPACITY", "13");
    std::env::set_var("ATH_SENSOR_SESSION_STATE_CAPACITY", "14");
    std::env::set_var("ATH_SENSOR_CLIENT_PROBE_SSID_CAPACITY", "15");
    std::env::set_var("ATH_SENSOR_PIPELINE_WORKERS", "4");
    std::env::set_var("ATH_SENSOR_PIPELINE_QUEUE_CAPACITY", "256");

    let config = AppConfig::from_env().unwrap();

    assert_eq!(config.redpanda_request_timeout_ms, 15_000);
    assert!(!config.mac_device_lookup_enabled);
    assert_eq!(config.mac_lookup_error_ttl_secs, 7);
    assert_eq!(config.detector_limits.mac_state_capacity, 12);
    assert_eq!(config.detector_limits.ssid_state_capacity, 13);
    assert_eq!(config.detector_limits.session_state_capacity, 14);
    assert_eq!(config.detector_limits.client_probe_ssid_capacity, 15);
    assert_eq!(config.detector_limits.pipeline_workers, 4);
    assert_eq!(config.detector_limits.pipeline_queue_capacity, 256);
}

#[test]
fn enrichment_knobs_invalid_boolean_fallback() {
    let _env = test_env();
    std::env::set_var("ATH_SENSOR_MAC_DEVICE_LOOKUP_ENABLED", "maybe");

    let config = AppConfig::from_env().unwrap();

    assert!(config.mac_device_lookup_enabled);
}

#[test]
fn redpanda_sasl_username_requires_password() {
    let _env = test_env();
    std::env::set_var("SYNC_REDPANDA_SASL_USERNAME", "sensor-user");

    let error = match AppConfig::from_env() {
        Ok(_) => panic!("expected missing SASL password to fail configuration"),
        Err(error) => error,
    };

    assert!(matches!(
        error,
        ConfigError::MissingSyncRedpandaSaslPassword
    ));
}

#[test]
fn redpanda_sasl_password_requires_username() {
    let _env = test_env();
    std::env::set_var("SYNC_REDPANDA_SASL_PASSWORD", "sensor-password");

    let error = match AppConfig::from_env() {
        Ok(_) => panic!("expected missing SASL username to fail configuration"),
        Err(error) => error,
    };

    assert!(matches!(
        error,
        ConfigError::MissingSyncRedpandaSaslUsername
    ));
}

#[test]
fn redpanda_client_certificate_requires_key() {
    let _env = test_env();
    std::env::set_var("SYNC_REDPANDA_SSL_CERTIFICATE_LOCATION", "/tmp/client.pem");

    let error = match AppConfig::from_env() {
        Ok(_) => panic!("expected missing client key to fail configuration"),
        Err(error) => error,
    };

    assert!(matches!(
        error,
        ConfigError::MissingSyncRedpandaSslKeyLocation
    ));
}

#[test]
fn redpanda_client_key_requires_certificate() {
    let _env = test_env();
    std::env::set_var("SYNC_REDPANDA_SSL_KEY_LOCATION", "/tmp/client.key");

    let error = match AppConfig::from_env() {
        Ok(_) => panic!("expected missing client certificate to fail configuration"),
        Err(error) => error,
    };

    assert!(matches!(
        error,
        ConfigError::MissingSyncRedpandaSslCertificateLocation
    ));
}

#[test]
fn log_idle_secs_defaults_to_30() {
    let _env = test_env();

    let config = AppConfig::from_env().unwrap();

    assert_eq!(config.log_idle_secs, 30);
}

#[test]
fn log_idle_secs_accepts_override() {
    let _env = test_env();
    std::env::set_var("ATH_SENSOR_LOG_IDLE_SECS", "5");

    let config = AppConfig::from_env().unwrap();

    assert_eq!(config.log_idle_secs, 5);
}

#[test]
fn log_idle_secs_allows_zero_to_disable() {
    let _env = test_env();
    std::env::set_var("ATH_SENSOR_LOG_IDLE_SECS", "0");

    let config = AppConfig::from_env().unwrap();

    assert_eq!(config.log_idle_secs, 0);
}

#[test]
fn log_idle_secs_rejects_invalid_value() {
    let _env = test_env();
    std::env::set_var("ATH_SENSOR_LOG_IDLE_SECS", "soon");

    let error = match AppConfig::from_env() {
        Ok(_) => panic!("expected invalid idle log interval to fail configuration"),
        Err(error) => error,
    };

    assert!(matches!(
        error,
        ConfigError::InvalidLogIdleSecs(ref value) if value == "soon"
    ));
}

#[test]
fn host_endpoint_validation_rejects_redpanda_service_host() {
    let _env = test_env();
    std::env::set_var("ATH_SENSOR_REQUIRE_HOST_ENDPOINTS", "true");
    std::env::set_var(
        "SYNC_REDPANDA_BOOTSTRAP_SERVERS",
        "redpanda://redpanda:9092",
    );

    let error = match AppConfig::from_env() {
        Ok(_) => panic!("expected host-network endpoint validation to reject Redpanda host"),
        Err(error) => error,
    };

    assert!(matches!(
        error,
        ConfigError::HostNetworkEndpoint {
            variable: "SYNC_REDPANDA_BOOTSTRAP_SERVERS",
            ref host
        } if host == "redpanda"
    ));
}

#[test]
fn host_endpoint_validation_checks_each_bootstrap_server() {
    let _env = test_env();
    std::env::set_var("ATH_SENSOR_REQUIRE_HOST_ENDPOINTS", "true");
    std::env::set_var(
        "SYNC_REDPANDA_BOOTSTRAP_SERVERS",
        "redpanda://127.0.0.1:19092, redpanda://redpanda:9092",
    );

    let error = match AppConfig::from_env() {
        Ok(_) => panic!("expected host-network endpoint validation to reject Redpanda host"),
        Err(error) => error,
    };

    assert!(matches!(
        error,
        ConfigError::HostNetworkEndpoint {
            variable: "SYNC_REDPANDA_BOOTSTRAP_SERVERS",
            ref host
        } if host == "redpanda"
    ));
}

#[test]
fn redpanda_host_extracts_host_with_userinfo() {
    assert_eq!(
        redpanda_host("redpanda://user:pass@redpanda:9092").as_deref(),
        Some("redpanda")
    );
}
