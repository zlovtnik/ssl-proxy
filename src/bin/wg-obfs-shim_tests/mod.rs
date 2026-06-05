use std::{
    io::Write,
    sync::{Mutex, OnceLock},
};

use super::*;

fn env_lock() -> std::sync::MutexGuard<'static, ()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
        .lock()
        .unwrap_or_else(|e| e.into_inner())
}

fn clear_env() {
    for key in [
        "WG_OBFS_SERVER_ADDR",
        "WG_OBFS_SERVER_ADDRS",
        "WG_OBFS_SHIM_LISTEN_ADDR",
        "WG_OBFS_HEALTH_ADDR",
        "WG_OBFUSCATION_KEY",
        "WG_OBFUSCATION_KEY_FILE",
        "WG_OBFUSCATION_MAGIC_BYTE",
        "WG_OBFUSCATION_SESSION_IDLE_SECS",
        "WG_OBFS_SHIM_MAX_SESSIONS",
        "WG_OBFS_SHIM_CLEANUP_INTERVAL_SECS",
        "WG_OBFS_SHIM_DRAIN_TIMEOUT_SECS",
        "WG_OBFS_SHIM_RATE_LIMIT_PPS",
        "WG_OBFS_SHIM_RATE_LIMIT_BURST",
        "WG_OBFS_SHIM_BUFFER_POOL_CAPACITY",
        "WG_OBFS_SHIM_SEND_QUEUE_CAPACITY",
        "WG_OBFS_SHIM_METRICS_ADDR",
        "WG_OBFUSCATION_ENCRYPTION_MODE",
        "WG_OBFUSCATION_PADDING",
        "WG_OBFUSCATION_MAGIC_POSITION",
        "WG_OBFUSCATION_REPLAY_PROTECTION",
        "WG_OBFUSCATION_XOR_REKEY_PACKETS",
        "WG_OBFUSCATION_XOR_REKEY_SECS",
    ] {
        std::env::remove_var(key);
    }
}

#[test]
fn parse_config_supports_cli_overrides() {
    let _guard = env_lock();
    clear_env();
    let process_config = parse_config([
        "--server".to_string(),
        "192.168.1.221:443".to_string(),
        "--server".to_string(),
        "192.168.1.222:443".to_string(),
        "--listen".to_string(),
        "127.0.0.1:51822".to_string(),
        "--health-addr".to_string(),
        "127.0.0.1:51823".to_string(),
        "--key".to_string(),
        "super-secret".to_string(),
        "--magic-byte".to_string(),
        "0xAA".to_string(),
        "--idle-timeout-secs".to_string(),
        "45".to_string(),
        "--max-sessions".to_string(),
        "128".to_string(),
        "--cleanup-interval-secs".to_string(),
        "3".to_string(),
        "--drain-timeout-secs".to_string(),
        "7".to_string(),
        "--rate-limit-pps".to_string(),
        "500".to_string(),
        "--rate-limit-burst".to_string(),
        "50".to_string(),
        "--buffer-pool-capacity".to_string(),
        "16".to_string(),
        "--send-queue-capacity".to_string(),
        "32".to_string(),
        "--metrics-addr".to_string(),
        "127.0.0.1:9900".to_string(),
        "--encryption-mode".to_string(),
        "aead".to_string(),
        "--padding".to_string(),
        "power-of-two".to_string(),
        "--magic-position".to_string(),
        "randomized".to_string(),
        "--xor-rekey-packets".to_string(),
        "64".to_string(),
    ])
    .unwrap();
    let config = &process_config.shims[0];

    assert_eq!(
        process_config.health_addr,
        "127.0.0.1:51823".parse::<SocketAddr>().unwrap()
    );

    assert_eq!(
        config.listen_addr,
        "127.0.0.1:51822".parse::<SocketAddr>().unwrap()
    );
    assert_eq!(
        config.server_addrs,
        vec![
            "192.168.1.221:443".parse::<SocketAddr>().unwrap(),
            "192.168.1.222:443".parse::<SocketAddr>().unwrap(),
        ]
    );
    assert_eq!(config.obfuscation.magic_byte, Some(0xAA));
    assert_eq!(config.obfuscation.key, b"super-secret".to_vec());
    assert_eq!(config.obfuscation.encryption_mode, EncryptionMode::Aead);
    assert_eq!(config.obfuscation.padding, PacketPadding::PowerOfTwo);
    assert_eq!(
        config.obfuscation.magic_position,
        MagicPositionMode::Randomized
    );
    assert!(config.obfuscation.replay_protection);
    assert_eq!(
        config.obfuscation.xor_rekey,
        XorRekeyPolicy::new(Some(64), None)
    );
    assert_eq!(config.idle_timeout, Duration::from_secs(45));
    assert_eq!(config.max_sessions, Some(128));
    assert_eq!(config.cleanup_interval, Some(Duration::from_secs(3)));
    assert_eq!(config.drain_timeout, Duration::from_secs(7));
    assert_eq!(
        config.rate_limit,
        Some(RateLimitConfig {
            packets_per_sec: 500,
            burst_packets: 50
        })
    );
    assert_eq!(config.buffer_pool_capacity, 16);
    assert_eq!(config.send_queue_capacity, 32);
    assert_eq!(
        config.metrics_addr,
        Some("127.0.0.1:9900".parse::<SocketAddr>().unwrap())
    );
}

#[test]
fn parse_config_requires_server_address() {
    let _guard = env_lock();
    clear_env();
    let result = parse_config(["--key".to_string(), "super-secret".to_string()]);

    assert_eq!(
            result,
            Err(ConfigParseOutcome::Error(
                "missing required server address; set --server, WG_OBFS_SERVER_ADDRS, or WG_OBFS_SERVER_ADDR".to_string()
            ))
        );
}

#[test]
fn parse_config_supports_env_server_addr_list_and_default_health() {
    let _guard = env_lock();
    clear_env();
    std::env::set_var("WG_OBFS_SERVER_ADDRS", "127.0.0.1:1111,127.0.0.1:2222");
    std::env::set_var("WG_OBFUSCATION_KEY", "super-secret");

    let process_config = parse_config(std::iter::empty::<String>()).unwrap();
    let config = &process_config.shims[0];

    assert_eq!(
        process_config.health_addr,
        DEFAULT_HEALTH_ADDR.parse::<SocketAddr>().unwrap()
    );
    assert_eq!(
        config.server_addrs,
        vec![
            "127.0.0.1:1111".parse::<SocketAddr>().unwrap(),
            "127.0.0.1:2222".parse::<SocketAddr>().unwrap(),
        ]
    );
}

#[test]
fn parse_config_supports_toml_multi_shim_file() {
    let _guard = env_lock();
    clear_env();
    let mut file = tempfile::NamedTempFile::new().unwrap();
    write!(
        file,
        r#"
health_addr = "127.0.0.1:51824"

[[shim]]
listen_addr = "127.0.0.1:51821"
server_addrs = ["127.0.0.1:443", "127.0.0.1:444"]
key = "first-key"
magic_byte = "0xAA"
idle_timeout_secs = 45
send_queue_capacity = 17

[[shim]]
listen_addr = "127.0.0.1:51822"
server_addr = "127.0.0.1:445"
key = "second-key"
"#
    )
    .unwrap();

    let process_config =
        parse_config(["--config".to_string(), file.path().display().to_string()]).unwrap();

    assert_eq!(
        process_config.health_addr,
        "127.0.0.1:51824".parse::<SocketAddr>().unwrap()
    );
    assert_eq!(process_config.shims.len(), 2);
    assert_eq!(
        process_config.shims[0].server_addrs,
        vec![
            "127.0.0.1:443".parse::<SocketAddr>().unwrap(),
            "127.0.0.1:444".parse::<SocketAddr>().unwrap(),
        ]
    );
    assert_eq!(process_config.shims[0].send_queue_capacity, 17);
    assert_eq!(
        process_config.shims[1].server_addrs,
        vec!["127.0.0.1:445".parse::<SocketAddr>().unwrap()]
    );
}

#[test]
fn parse_config_rejects_empty_toml_server_addrs() {
    let _guard = env_lock();
    clear_env();
    let mut file = tempfile::NamedTempFile::new().unwrap();
    write!(
        file,
        r#"
[[shim]]
listen_addr = "127.0.0.1:51821"
server_addrs = []
key = "first-key"
"#
    )
    .unwrap();

    let result = parse_config(["--config".to_string(), file.path().display().to_string()]);

    assert!(
        matches!(result, Err(ConfigParseOutcome::Error(message)) if message.contains("server address list must contain at least one address"))
    );
}
