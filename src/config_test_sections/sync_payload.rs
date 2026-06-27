    #[test]
    fn sync_config_defaults_and_auth_pair_validation() {
        let _guard = env_lock();
        clear_env();
        set_test_env_defaults();
        std::env::set_var("ADMIN_API_KEY", "test-admin-api-key-0000000000000");

        let result = Config::from_env().unwrap();
        assert_eq!(result.sync.connect_timeout_ms, 2_000);
        assert_eq!(result.sync.publish_timeout_ms, 2_000);
        assert_eq!(result.sync.inline_payload_max_bytes, 2_048);
        assert_eq!(result.sync.outbox_dir, "/tmp/ssl-proxy-sync-outbox");
        assert_eq!(result.sync.publish_queue_capacity, 8_192);
        assert_eq!(result.sync.publish_enqueue_timeout_ms, 25);
        assert_eq!(
            result.sync.publish_spool_dir,
            "/tmp/ssl-proxy-sync-outbox/publish-spool"
        );
        assert!(result.sync.redpanda_bootstrap_servers.is_none());

        std::env::set_var("SYNC_REDPANDA_SASL_USERNAME", "proxy-user");
        let result = Config::from_env();
        assert!(matches!(
            result,
            Err(ConfigError::MissingSyncRedpandaSaslPassword)
        ));

        std::env::set_var("SYNC_REDPANDA_SASL_PASSWORD", "proxy-pass");
        let result = Config::from_env().unwrap();
        assert_eq!(result.sync.sasl_username.as_deref(), Some("proxy-user"));
        assert_eq!(result.sync.sasl_password.as_deref(), Some("proxy-pass"));
    }

    #[test]
    fn sync_publish_backpressure_config_parses_env() {
        let _guard = env_lock();
        clear_env();
        set_test_env_defaults();
        std::env::set_var("ADMIN_API_KEY", "test-admin-api-key-0000000000000");
        std::env::set_var("SYNC_OUTBOX_DIR", "/tmp/custom-sync-outbox");
        std::env::set_var("SYNC_PUBLISH_QUEUE_CAPACITY", "4096");
        std::env::set_var("SYNC_PUBLISH_ENQUEUE_TIMEOUT_MS", "50");

        let result = Config::from_env().unwrap();

        assert_eq!(result.sync.publish_queue_capacity, 4_096);
        assert_eq!(result.sync.publish_enqueue_timeout_ms, 50);
        assert_eq!(
            result.sync.publish_spool_dir,
            "/tmp/custom-sync-outbox/publish-spool"
        );

        std::env::set_var("SYNC_PUBLISH_SPOOL_DIR", "/tmp/custom-spool");
        let result = Config::from_env().unwrap();
        assert_eq!(result.sync.publish_spool_dir, "/tmp/custom-spool");
    }

    #[test]
    fn sync_ssl_validates_client_cert_pair() {
        let _guard = env_lock();
        clear_env();
        set_test_env_defaults();
        std::env::set_var("ADMIN_API_KEY", "test-admin-api-key-0000000000000");

        std::env::set_var("SYNC_REDPANDA_SSL_CERTIFICATE_LOCATION", "/tmp/client.pem");
        let result = Config::from_env();
        assert!(matches!(
            result,
            Err(ConfigError::MissingSyncRedpandaSslKeyLocation)
        ));
    }

    #[test]
    fn payload_audit_defaults_and_env_are_loaded() {
        let _guard = env_lock();
        clear_env();
        set_test_env_defaults();
        std::env::set_var("ADMIN_API_KEY", "test-admin-api-key-0000000000000");

        let result = Config::from_env().unwrap();
        assert!(!result.payload_audit.enabled);
        assert_eq!(result.payload_audit.redpanda_topic, "proxy.payload_audit");
        assert_eq!(result.payload_audit.max_body_bytes, 65_536);
        assert_eq!(
            result.payload_audit.allowed_methods,
            vec!["POST", "PUT", "PATCH"]
        );
        assert_eq!(
            result.payload_audit.allowed_content_types,
            vec!["application/json"]
        );

        std::env::set_var("PAYLOAD_AUDIT_ENABLED", "true");
        std::env::set_var("PAYLOAD_AUDIT_REDPANDA_TOPIC", "audit.payloads");
        std::env::set_var("PAYLOAD_AUDIT_MAX_BODY_BYTES", "1024");
        std::env::set_var("PAYLOAD_AUDIT_ALLOWED_METHODS", "POST,DELETE");
        std::env::set_var(
            "PAYLOAD_AUDIT_ALLOWED_CONTENT_TYPES",
            "application/json,text/json",
        );

        let result = Config::from_env().unwrap();
        assert!(result.payload_audit.enabled);
        assert_eq!(result.payload_audit.redpanda_topic, "audit.payloads");
        assert_eq!(result.payload_audit.max_body_bytes, 1_024);
        assert_eq!(result.payload_audit.allowed_methods, vec!["POST", "DELETE"]);
        assert_eq!(
            result.payload_audit.allowed_content_types,
            vec!["application/json", "text/json"]
        );
    }

    #[test]
    fn wireguard_config_debug_redacts_obfuscation_key() {
        let config = WireGuardConfig {
            port: 443,
            internal_port: 51820,
            interface: Some("wg0".to_string()),
            drop_udp_443: true,
            obfuscation_enabled: true,
            obfuscation_key: b"super-secret".to_vec(),
            obfuscation_magic_byte: Some(0xAA),
            obfuscation_session_idle_secs: 300,
            obfuscation_encryption_mode: EncryptionMode::Xor,
            obfuscation_padding: PacketPadding::None,
            obfuscation_magic_position: MagicPositionMode::Fixed,
            obfuscation_replay_protection: false,
            obfuscation_xor_rekey_packets: None,
            obfuscation_xor_rekey_secs: None,
            obfuscation_max_datagram_bytes: DEFAULT_WIREGUARD_PATH_MTU_BYTES + 1,
            udp_socket_buffer_bytes: DEFAULT_WIREGUARD_UDP_SOCKET_BUFFER_BYTES,
        };

        let rendered = format!("{config:?}");
        assert!(rendered.contains("[REDACTED]"));
        assert!(!rendered.contains("super-secret"));
    }

    #[test]
    fn config_default_uses_empty_admin_api_key() {
        assert!(Config::default().admin.api_key.is_empty());
    }

    #[test]
    fn config_for_tests_uses_test_admin_api_key() {
        assert_eq!(Config::for_tests().admin.api_key, "test-admin-api-key-0000000000000");
    }
