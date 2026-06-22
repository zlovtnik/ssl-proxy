    use super::*;
    use std::sync::{Mutex, OnceLock};

    fn env_lock() -> std::sync::MutexGuard<'static, ()> {
        static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        LOCK.get_or_init(|| Mutex::new(()))
            .lock()
            .unwrap_or_else(|e| e.into_inner())
    }

    /// Removes a fixed set of configuration-related environment variables used by tests.
    ///
    /// This clears any of the known config environment variables so tests can start from a clean environment.
    ///
    /// # Examples
    ///
    /// ```
    /// use std::env;
    /// env::set_var("ADMIN_API_KEY", "secret");
    /// assert!(env::var_os("ADMIN_API_KEY").is_some());
    /// clear_env();
    /// assert!(env::var_os("ADMIN_API_KEY").is_none());
    /// ```
    fn clear_env() {
        for key in [
            "PROXY_PORT",
            "TPROXY_PORT",
            "WG_PORT",
            "WG_INTERNAL_PORT",
            "ADMIN_PORT",
            "EXPLICIT_PROXY_ENABLED",
            "WG_INTERFACE",
            "MAX_CONNECTIONS",
            "TARPIT_MAX_CONNECTIONS",
            "ADMIN_API_KEY",
            "ADMIN_API_KEY_FILE",
            "CORS_ALLOWED_ORIGINS",
            "LOG_FORMAT",
            "DNS_RESOLVE_TIMEOUT_MS",
            "OBFUSCATION_ENABLED",
            "OBFUSCATION_PROFILE",
            "FOX_UA_OVERRIDE",
            "TLS_CERT_PATH",
            "TLS_KEY_PATH",
            "PROXY_USERNAME",
            "PROXY_PASSWORD",
            "PROXY_PASSWORD_FILE",
            "TUNNEL_ENDPOINT",
            "UPSTREAM_PROXY",
            "ENABLE_DNS_LOOKUPS",
            "TPROXY_FAIL_CLOSED_NO_SNI",
            "CAPTURE_PLAINTEXT_PAYLOADS",
            "FORENSIC_SENTRY_ENABLED",
            "FORENSIC_MONITOR_INTERFACE",
            "WG_DROP_UDP_443",
            "WG_OBFUSCATION_ENABLED",
            "WG_OBFUSCATION_KEY",
            "WG_OBFUSCATION_KEY_FILE",
            "WG_OBFUSCATION_MAGIC_BYTE",
            "WG_OBFUSCATION_SESSION_IDLE_SECS",
            "WG_OBFUSCATION_ENCRYPTION_MODE",
            "WG_OBFUSCATION_PADDING",
            "WG_OBFUSCATION_MAGIC_POSITION",
            "WG_OBFUSCATION_REPLAY_PROTECTION",
            "WG_OBFUSCATION_XOR_REKEY_PACKETS",
            "WG_OBFUSCATION_XOR_REKEY_SECS",
            "SYNC_REDPANDA_BOOTSTRAP_SERVERS",
            "SYNC_REDPANDA_CONNECT_TIMEOUT_MS",
            "SYNC_REDPANDA_PUBLISH_TIMEOUT_MS",
            "SYNC_REDPANDA_SASL_USERNAME",
            "SYNC_REDPANDA_SASL_PASSWORD",
            "SYNC_REDPANDA_SASL_PASSWORD_FILE",
            "SYNC_REDPANDA_SECURITY_PROTOCOL",
            "SYNC_REDPANDA_SASL_MECHANISMS",
            "SYNC_REDPANDA_SSL_CA_LOCATION",
            "SYNC_REDPANDA_SSL_CERTIFICATE_LOCATION",
            "SYNC_REDPANDA_SSL_KEY_LOCATION",
            "SYNC_INLINE_PAYLOAD_MAX_BYTES",
            "SYNC_OUTBOX_DIR",
            "SYNC_PUBLISH_QUEUE_CAPACITY",
            "SYNC_PUBLISH_ENQUEUE_TIMEOUT_MS",
            "SYNC_PUBLISH_SPOOL_DIR",
            "PAYLOAD_AUDIT_ENABLED",
            "PAYLOAD_AUDIT_REDPANDA_TOPIC",
            "PAYLOAD_AUDIT_MAX_BODY_BYTES",
            "PAYLOAD_AUDIT_ALLOWED_METHODS",
            "PAYLOAD_AUDIT_ALLOWED_CONTENT_TYPES",
        ] {
            std::env::remove_var(key);
        }
    }

    /// Sets test defaults for the shared config tests.
    fn set_test_env_defaults() {
        std::env::set_var("WG_OBFUSCATION_KEY", "test-obfuscation-key");
    }

    #[cfg(unix)]
    #[test]
    fn wireguard_obfuscation_key_file_requires_strict_permissions() {
        use std::os::unix::fs::PermissionsExt;

        let _guard = env_lock();
        clear_env();
        std::env::set_var("ADMIN_API_KEY", "test-admin-api-key-0000000000000");
        let file = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(file.path(), "file-key").unwrap();
        std::fs::set_permissions(file.path(), std::fs::Permissions::from_mode(0o600)).unwrap();
        std::env::set_var("WG_OBFUSCATION_KEY_FILE", file.path());

        let err = Config::from_env().unwrap_err();

        assert!(matches!(
            err,
            ConfigError::InvalidSecretFile {
                file_var: "WG_OBFUSCATION_KEY_FILE",
                ..
            }
        ));
    }

    #[cfg(unix)]
    #[test]
    fn wireguard_obfuscation_key_file_loads_with_strict_permissions() {
        use std::os::unix::fs::PermissionsExt;

        let _guard = env_lock();
        clear_env();
        std::env::set_var("ADMIN_API_KEY", "test-admin-api-key-0000000000000");
        let file = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(file.path(), "file-key").unwrap();
        std::fs::set_permissions(file.path(), std::fs::Permissions::from_mode(0o400)).unwrap();
        std::env::set_var("WG_OBFUSCATION_KEY_FILE", file.path());

        let config = Config::from_env().unwrap();

        assert_eq!(config.wireguard.obfuscation_key.as_slice(), b"file-key");
    }

    #[test]
    fn admin_api_key_must_be_at_least_32_bytes() {
        let _guard = env_lock();
        clear_env();
        set_test_env_defaults();
        std::env::set_var("ADMIN_API_KEY", "short-key");

        assert!(matches!(
            Config::from_env(),
            Err(ConfigError::AdminApiKeyTooShort {
                min_len: MIN_ADMIN_API_KEY_LEN,
                actual_len: 9
            })
        ));
    }

    #[test]
    fn config_port_conflict_error() {
        let _guard = env_lock();
        clear_env();
        set_test_env_defaults();
        std::env::set_var("PROXY_PORT", "51820");
        std::env::set_var("WG_PORT", "51820");
        std::env::set_var("ADMIN_API_KEY", "test-admin-api-key-0000000000000");

        let result = Config::from_env();
        assert!(matches!(
            result,
            Err(ConfigError::PortConflict(51820, 51820))
        ));
    }

    #[test]
    fn explicit_proxy_disabled_by_default() {
        let _guard = env_lock();
        clear_env();
        set_test_env_defaults();
        std::env::set_var("ADMIN_API_KEY", "test-admin-api-key-0000000000000");

        let result = Config::from_env().unwrap();

        assert!(!result.proxy.explicit_enabled);
    }

    #[test]
    fn explicit_proxy_enabled_when_requested() {
        let _guard = env_lock();
        clear_env();
        set_test_env_defaults();
        std::env::set_var("ADMIN_API_KEY", "test-admin-api-key-0000000000000");
        std::env::set_var("EXPLICIT_PROXY_ENABLED", "true");

        let result = Config::from_env().unwrap();

        assert!(result.proxy.explicit_enabled);
    }

    #[test]
    fn capture_plaintext_payloads_defaults_to_false_and_reads_env() {
        let _guard = env_lock();
        clear_env();
        set_test_env_defaults();
        std::env::set_var("ADMIN_API_KEY", "test-admin-api-key-0000000000000");

        let result = Config::from_env().unwrap();
        assert!(!result.proxy.capture_plaintext_payloads);

        std::env::set_var("CAPTURE_PLAINTEXT_PAYLOADS", "true");
        let result = Config::from_env().unwrap();
        assert!(result.proxy.capture_plaintext_payloads);
    }

    #[test]
    fn forensic_sentry_defaults_to_false_and_reads_env() {
        let _guard = env_lock();
        clear_env();
        set_test_env_defaults();
        std::env::set_var("ADMIN_API_KEY", "test-admin-api-key-0000000000000");

        let result = Config::from_env().unwrap();
        assert!(!result.proxy.forensic_sentry_enabled);
        assert!(result.proxy.forensic_monitor_interface.is_none());

        std::env::set_var("FORENSIC_SENTRY_ENABLED", "true");
        std::env::set_var("FORENSIC_MONITOR_INTERFACE", "mon0");
        let result = Config::from_env().unwrap();
        assert!(result.proxy.forensic_sentry_enabled);
        assert_eq!(
            result.proxy.forensic_monitor_interface.as_deref(),
            Some("mon0")
        );
    }

    #[test]
    fn tproxy_fail_closed_no_sni_defaults_to_true_and_reads_env() {
        let _guard = env_lock();
        clear_env();
        set_test_env_defaults();
        std::env::set_var("ADMIN_API_KEY", "test-admin-api-key-0000000000000");

        let result = Config::from_env().unwrap();
        assert!(result.proxy.fail_closed_no_sni);

        std::env::set_var("TPROXY_FAIL_CLOSED_NO_SNI", "false");
        let result = Config::from_env().unwrap();
        assert!(!result.proxy.fail_closed_no_sni);
    }

    #[test]
    fn wg_drop_udp_443_defaults_to_true_and_reads_env() {
        let _guard = env_lock();
        clear_env();
        set_test_env_defaults();
        std::env::set_var("ADMIN_API_KEY", "test-admin-api-key-0000000000000");

        let result = Config::from_env().unwrap();
        assert!(result.wireguard.drop_udp_443);

        std::env::set_var("WG_DROP_UDP_443", "false");
        let result = Config::from_env().unwrap();
        assert!(!result.wireguard.drop_udp_443);
    }

    #[test]
    fn wireguard_obfuscation_defaults_are_loaded() {
        let _guard = env_lock();
        clear_env();
        set_test_env_defaults();
        std::env::set_var("ADMIN_API_KEY", "test-admin-api-key-0000000000000");

        let result = Config::from_env().unwrap();
        assert_eq!(result.wireguard.port, 443);
        assert_eq!(result.wireguard.internal_port, 51820);
        assert!(result.wireguard.obfuscation_enabled);
        assert_eq!(result.wireguard.obfuscation_magic_byte, None);
        assert_eq!(result.wireguard.obfuscation_session_idle_secs, 300);
        assert_eq!(
            result.wireguard.obfuscation_encryption_mode,
            EncryptionMode::Xor
        );
        assert_eq!(result.wireguard.obfuscation_padding, PacketPadding::None);
        assert_eq!(
            result.wireguard.obfuscation_magic_position,
            MagicPositionMode::Fixed
        );
        assert!(!result.wireguard.obfuscation_replay_protection);
        assert_eq!(result.wireguard.obfuscation_xor_rekey_packets, None);
        assert_eq!(result.wireguard.obfuscation_xor_rekey_secs, None);
        assert_eq!(
            result.wireguard.obfuscation_key,
            b"test-obfuscation-key".to_vec()
        );
    }

    #[test]
    fn wireguard_framed_obfuscation_options_are_loaded() {
        let _guard = env_lock();
        clear_env();
        set_test_env_defaults();
        std::env::set_var("ADMIN_API_KEY", "test-admin-api-key-0000000000000");
        std::env::set_var("WG_OBFUSCATION_ENCRYPTION_MODE", "aead");
        std::env::set_var("WG_OBFUSCATION_PADDING", "fixed-mtu:1200");
        std::env::set_var("WG_OBFUSCATION_MAGIC_POSITION", "randomized");
        std::env::set_var("WG_OBFUSCATION_XOR_REKEY_PACKETS", "128");
        std::env::set_var("WG_OBFUSCATION_XOR_REKEY_SECS", "60");

        let result = Config::from_env().unwrap();

        assert_eq!(
            result.wireguard.obfuscation_encryption_mode,
            EncryptionMode::Aead
        );
        assert_eq!(
            result.wireguard.obfuscation_padding,
            PacketPadding::FixedMtu(1200)
        );
        assert_eq!(
            result.wireguard.obfuscation_magic_position,
            MagicPositionMode::Randomized
        );
        assert!(result.wireguard.obfuscation_replay_protection);
        assert_eq!(result.wireguard.obfuscation_xor_rekey_packets, Some(128));
        assert_eq!(result.wireguard.obfuscation_xor_rekey_secs, Some(60));
    }

    #[test]
    fn wireguard_random_bucket_padding_is_loaded() {
        let _guard = env_lock();
        clear_env();
        set_test_env_defaults();
        std::env::set_var("ADMIN_API_KEY", "test-admin-api-key-0000000000000");
        std::env::set_var("WG_OBFUSCATION_PADDING", "random-bucket:1200,1280,1400");

        let result = Config::from_env().unwrap();

        assert_eq!(
            result.wireguard.obfuscation_padding,
            PacketPadding::RandomBucket(vec![1200, 1280, 1400])
        );
    }

    #[test]
    fn wireguard_xor_rekey_values_must_be_positive_integers() {
        let _guard = env_lock();
        clear_env();
        set_test_env_defaults();
        std::env::set_var("ADMIN_API_KEY", "test-admin-api-key-0000000000000");
        std::env::set_var("WG_OBFUSCATION_XOR_REKEY_PACKETS", "0");

        assert!(matches!(
            Config::from_env(),
            Err(ConfigError::InvalidWireGuardObfuscationXorRekeyValue {
                var: "WG_OBFUSCATION_XOR_REKEY_PACKETS",
                ..
            })
        ));

        std::env::set_var("WG_OBFUSCATION_XOR_REKEY_PACKETS", "not-a-number");
        assert!(matches!(
            Config::from_env(),
            Err(ConfigError::InvalidWireGuardObfuscationXorRekeyValue {
                var: "WG_OBFUSCATION_XOR_REKEY_PACKETS",
                ..
            })
        ));
    }

    #[test]
    fn missing_wireguard_obfuscation_key_errors_when_enabled() {
        let _guard = env_lock();
        clear_env();
        set_test_env_defaults();
        std::env::remove_var("WG_OBFUSCATION_KEY");
        std::env::set_var("ADMIN_API_KEY", "test-admin-api-key-0000000000000");

        let result = Config::from_env();
        assert!(matches!(
            result,
            Err(ConfigError::MissingWireGuardObfuscationKey)
        ));
    }

    #[test]
    fn wireguard_obfuscation_can_be_disabled_without_key() {
        let _guard = env_lock();
        clear_env();
        set_test_env_defaults();
        std::env::remove_var("WG_OBFUSCATION_KEY");
        std::env::set_var("WG_OBFUSCATION_ENABLED", "false");
        std::env::set_var("ADMIN_API_KEY", "test-admin-api-key-0000000000000");

        let result = Config::from_env().unwrap();
        assert!(!result.wireguard.obfuscation_enabled);
        assert!(result.wireguard.obfuscation_key.is_empty());
    }

    #[test]
    fn wireguard_magic_byte_accepts_hex_and_decimal() {
        let _guard = env_lock();
        clear_env();
        set_test_env_defaults();
        std::env::set_var("ADMIN_API_KEY", "test-admin-api-key-0000000000000");

        std::env::set_var("WG_OBFUSCATION_MAGIC_BYTE", "0xAA");
        let result = Config::from_env().unwrap();
        assert_eq!(result.wireguard.obfuscation_magic_byte, Some(0xAA));

        std::env::set_var("WG_OBFUSCATION_MAGIC_BYTE", "170");
        let result = Config::from_env().unwrap();
        assert_eq!(result.wireguard.obfuscation_magic_byte, Some(170));
    }

    #[test]
    fn invalid_wireguard_magic_byte_errors() {
        let _guard = env_lock();
        clear_env();
        set_test_env_defaults();
        std::env::set_var("ADMIN_API_KEY", "test-admin-api-key-0000000000000");
        std::env::set_var("WG_OBFUSCATION_MAGIC_BYTE", "0xGG");

        let result = Config::from_env();
        assert!(matches!(
            result,
            Err(ConfigError::InvalidWireGuardObfuscationMagicByte(_))
        ));
    }

    #[test]
    fn wireguard_public_and_internal_ports_must_differ_when_obfuscated() {
        let _guard = env_lock();
        clear_env();
        set_test_env_defaults();
        std::env::set_var("ADMIN_API_KEY", "test-admin-api-key-0000000000000");
        std::env::set_var("WG_PORT", "51820");
        std::env::set_var("WG_INTERNAL_PORT", "51820");

        let result = Config::from_env();
        assert!(matches!(
            result,
            Err(ConfigError::WireGuardObfuscationPortConflict {
                public_port: 51820,
                internal_port: 51820,
            })
        ));
    }

    #[test]
    fn read_secret_trims_direct_env_and_file_values() {
        let _guard = env_lock();
        clear_env();

        let unique = format!(
            "boringtun-read-secret-{}-{}.txt",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        );
        let path = std::env::temp_dir().join(unique);

        std::env::set_var("MY_SECRET", "  direct secret  ");
        assert_eq!(
            read_secret("MY_SECRET", "MY_SECRET_FILE"),
            Some("direct secret".to_string())
        );

        std::env::set_var("MY_SECRET", "   ");
        assert_eq!(read_secret("MY_SECRET", "MY_SECRET_FILE"), None);

        std::env::remove_var("MY_SECRET");
        std::fs::write(&path, "  file secret  \n").unwrap();
        std::env::set_var("MY_SECRET_FILE", &path);
        assert_eq!(
            read_secret("MY_SECRET", "MY_SECRET_FILE"),
            Some("file secret".to_string())
        );

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn admin_config_debug_redacts_api_key() {
        let config = AdminConfig {
            port: 3002,
            bind_addr: "127.0.0.1".to_string(),
            api_key: "super-secret".to_string(),
            require_mfa_claim: false,
            mfa_header_names: vec![],
            cors_allowed_origins: vec!["https://example.com".to_string()],
            patch_cadence_report_path: None,
            recovery_drill_report_path: None,
        };

        let rendered = format!("{config:?}");
        assert!(rendered.contains("[REDACTED]"));
        assert!(!rendered.contains("super-secret"));
    }

    #[test]
    fn proxy_config_debug_redacts_schemeless_userinfo() {
        let config = ProxyConfig {
            port: 8080,
            transparent_port: 8081,
            explicit_enabled: true,
            max_connections: 100,
            tarpit_max_connections: 10,
            credentials: None,
            upstream_proxy: Some("alice@proxy.internal:8080".to_string()),
            tunnel_endpoint: Some("bob@example.internal:443".to_string()),
            enable_dns_lookups: true,
            fail_closed_no_sni: false,
            capture_plaintext_payloads: false,
            forensic_sentry_enabled: false,
            forensic_monitor_interface: None,
        };

        let rendered = format!("{config:?}");
        assert!(rendered.contains("[REDACTED]@proxy.internal:8080"));
        assert!(rendered.contains("[REDACTED]@example.internal:443"));
        assert!(!rendered.contains("alice@"));
        assert!(!rendered.contains("bob@"));
    }
