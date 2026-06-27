use std::collections::HashMap;

use super::{parsing::*, sync_tls::*, types::*};
use crate::wg_packet_obfuscation::{EncryptionMode, MagicPositionMode, PacketPadding};
use sync_plane::SyncConfig;

impl Config {
    /// Load and validate the application's configuration from environment variables.
    ///
    /// This constructs each subsystem configuration from the environment, checks for
    /// port conflicts between proxy, admin, and WireGuard, and returns a fully
    /// populated `Config` on success.
    ///
    /// # Returns
    ///
    /// `Ok(Self)` with all subsystem configurations populated on success;
    /// `Err(ConfigError::PortConflict(_, _))` when any proxy/admin/wireguard port conflicts are detected;
    /// or another `ConfigError` for other validation or loading failures.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// let cfg = crate::config::Config::from_env().expect("failed to load config");
    /// println!("{:?}", cfg);
    /// ```
    pub fn from_env() -> Result<Self, ConfigError> {
        let proxy = ProxyConfig::from_env()?;
        let admin = AdminConfig::from_env()?;
        let sync = sync_config_from_env()?;
        let payload_audit = PayloadAuditConfig::from_env();
        let obfuscation = ObfuscationConfig::from_env();
        let tls = TlsConfig::from_env();
        let wireguard = WireGuardConfig::from_env()?;
        let runtime = RuntimeConfig::from_env();

        if proxy.port == proxy.transparent_port {
            return Err(ConfigError::PortConflict(
                proxy.port,
                proxy.transparent_port,
            ));
        }
        if proxy.transparent_port == wireguard.port {
            return Err(ConfigError::PortConflict(
                proxy.transparent_port,
                wireguard.port,
            ));
        }
        if proxy.transparent_port == wireguard.internal_port {
            return Err(ConfigError::PortConflict(
                proxy.transparent_port,
                wireguard.internal_port,
            ));
        }
        if proxy.port == wireguard.port {
            return Err(ConfigError::PortConflict(proxy.port, wireguard.port));
        }
        if proxy.port == wireguard.internal_port {
            return Err(ConfigError::PortConflict(
                proxy.port,
                wireguard.internal_port,
            ));
        }
        if admin.port == proxy.port {
            return Err(ConfigError::PortConflict(admin.port, proxy.port));
        }
        if admin.port == proxy.transparent_port {
            return Err(ConfigError::PortConflict(
                admin.port,
                proxy.transparent_port,
            ));
        }
        if admin.port == wireguard.port {
            return Err(ConfigError::PortConflict(admin.port, wireguard.port));
        }
        if admin.port == wireguard.internal_port {
            return Err(ConfigError::PortConflict(
                admin.port,
                wireguard.internal_port,
            ));
        }
        if wireguard.obfuscation_enabled && wireguard.port == wireguard.internal_port {
            return Err(ConfigError::WireGuardObfuscationPortConflict {
                public_port: wireguard.port,
                internal_port: wireguard.internal_port,
            });
        }

        Ok(Self {
            proxy,
            admin,
            sync,
            payload_audit,
            obfuscation,
            tls,
            wireguard,
            runtime,
        })
    }

    /// Load configuration from the environment, panicking if any validation or parsing error occurs.
    ///
    /// On failure this function will panic with a message prefixed by `"Configuration error:"`.
    ///
    /// # Examples
    ///
    /// ```
    /// let cfg = Config::from_env_or_panic();
    /// assert_eq!(cfg.runtime.log_format, "human"); // example assertion using the default
    /// ```
    pub fn from_env_or_panic() -> Self {
        match Config::from_env() {
            Ok(cfg) => cfg,
            Err(e) => panic!("Configuration error: {e}"),
        }
    }

    /// Creates a configuration prefilled for use in tests.
    ///
    /// The returned Config is `Default` with a valid test admin API key.
    ///
    /// # Examples
    ///
    /// ```
    /// let cfg = crate::config::Config::for_tests();
    /// assert_eq!(cfg.admin.api_key, "test-admin-api-key-0000000000000");
    /// ```
    #[cfg(test)]
    pub(crate) fn for_tests() -> Self {
        let mut config = Self::default();
        config.admin.api_key = "test-admin-api-key-0000000000000".to_string();
        config
    }
}

impl Default for Config {
    /// Constructs a `Config` populated with sensible defaults for all subsystems.
    ///
    /// # Examples
    ///
    /// ```
    /// let cfg = Config::default();
    /// assert_eq!(cfg.proxy.port, 3000);
    /// assert_eq!(cfg.proxy.transparent_port, 3001);
    /// assert_eq!(cfg.admin.port, 3002);
    /// assert_eq!(cfg.wireguard.port, 443);
    /// assert_eq!(cfg.wireguard.internal_port, 51820);
    /// assert!(cfg.obfuscation.enabled);
    /// assert!(!cfg.obfuscation.domain_map.is_empty());
    /// ```
    fn default() -> Self {
        let mut config = Self {
            proxy: ProxyConfig {
                port: 3000,
                transparent_port: 3001,
                explicit_enabled: false,
                max_connections: 4096,
                tarpit_max_connections: 64,
                credentials: None,
                upstream_proxy: None,
                tunnel_endpoint: None,
                enable_dns_lookups: false,
                fail_closed_no_sni: true,
                capture_plaintext_payloads: false,
                forensic_sentry_enabled: false,
                forensic_monitor_interface: None,
            },
            admin: AdminConfig {
                port: 3002,
                bind_addr: "127.0.0.1".to_string(),
                api_key: String::new(),
                require_mfa_claim: true,
                mfa_header_names: vec![
                    "x-auth-amr".to_string(),
                    "x-auth-acr".to_string(),
                    "x-mfa-claim".to_string(),
                ],
                cors_allowed_origins: vec![],
                patch_cadence_report_path: None,
                recovery_drill_report_path: None,
            },
            sync: SyncConfig::default(),
            payload_audit: PayloadAuditConfig {
                enabled: false,
                redpanda_topic: "proxy.payload_audit".to_string(),
                max_body_bytes: 65_536,
                allowed_methods: vec!["POST".to_string(), "PUT".to_string(), "PATCH".to_string()],
                allowed_content_types: vec!["application/json".to_string()],
            },
            obfuscation: ObfuscationConfig {
                enabled: true,
                enabled_profiles: vec![
                    "fox-news".to_string(),
                    "fox-sports".to_string(),
                    "fox-general".to_string(),
                    "fox-cdn".to_string(),
                    "fx-network".to_string(),
                ],
                fox_ua_override: "Mozilla/5.0 (Test UA)".to_string(),
                domain_map: HashMap::new(),
            },
            tls: TlsConfig {
                cert_path: None,
                key_path: None,
            },
            wireguard: WireGuardConfig {
                port: 443,
                internal_port: 51820,
                interface: None,
                drop_udp_443: true,
                obfuscation_enabled: true,
                obfuscation_key: b"test-obfuscation-key".to_vec(),
                obfuscation_magic_byte: Some(0xAA),
                obfuscation_session_idle_secs: 300,
                obfuscation_encryption_mode: EncryptionMode::Xor,
                obfuscation_padding: PacketPadding::None,
                obfuscation_magic_position: MagicPositionMode::Fixed,
                obfuscation_replay_protection: false,
                obfuscation_xor_rekey_packets: None,
                obfuscation_xor_rekey_secs: None,
                obfuscation_max_datagram_bytes: DEFAULT_WIREGUARD_PATH_MTU_BYTES,
                udp_socket_buffer_bytes: DEFAULT_WIREGUARD_UDP_SOCKET_BUFFER_BYTES,
            },
            runtime: RuntimeConfig {
                log_format: "human".to_string(),
                bandwidth_sample_interval_secs: 60,
                device_claim_ttl_secs: 300,
                dns_resolve_timeout_ms: 2_000,
            },
        };
        config.obfuscation.domain_map = build_domain_map(&config.obfuscation.enabled_profiles);
        config
    }
}

impl ProxyConfig {
    /// Builds a `ProxyConfig` from environment variables.
    ///
    /// Reads proxy-related environment variables and constructs a `ProxyConfig`.
    /// If both `PROXY_USERNAME` and a password (from `PROXY_PASSWORD` or `PROXY_PASSWORD_FILE`)
    /// are provided, they are combined into `credentials`. If only one of username or password
    /// is present, the function returns a `ConfigError` indicating the missing counterpart.
    ///
    /// Env variables read (with defaults where applicable):
    /// - `PROXY_PORT` (default 3000)
    /// - `TPROXY_PORT` (default 3001)
    /// - `EXPLICIT_PROXY_ENABLED` (default false)
    /// - `MAX_CONNECTIONS` (default 4096)
    /// - `TARPIT_MAX_CONNECTIONS` (default 64)
    /// - `PROXY_USERNAME`
    /// - `PROXY_PASSWORD` or `PROXY_PASSWORD_FILE`
    /// - `UPSTREAM_PROXY`
    /// - `TUNNEL_ENDPOINT`
    /// - `ENABLE_DNS_LOOKUPS` (default false)
    /// - `TPROXY_FAIL_CLOSED_NO_SNI` (default true)
    /// - `CAPTURE_PLAINTEXT_PAYLOADS` (default false)
    /// - `FORENSIC_SENTRY_ENABLED` (default false)
    /// - `FORENSIC_MONITOR_INTERFACE` (optional)
    ///
    /// # Returns
    ///
    /// `Ok(ProxyConfig)` containing the parsed settings and optional credentials,
    /// or a `ConfigError::MissingProxyPassword` / `ConfigError::MissingProxyUsername` when
    /// credentials are provided incompletely.
    ///
    /// # Examples
    ///
    /// ```
    /// use std::env;
    /// // Arrange environment for example
    /// env::set_var("PROXY_PORT", "4000");
    /// env::remove_var("PROXY_USERNAME");
    /// let cfg = ProxyConfig::from_env().unwrap();
    /// assert_eq!(cfg.port, 4000);
    /// ```
    fn from_env() -> Result<Self, ConfigError> {
        let username = std::env::var("PROXY_USERNAME")
            .ok()
            .filter(|s| !s.is_empty());
        let password = read_secret("PROXY_PASSWORD", "PROXY_PASSWORD_FILE");

        let credentials = match (username, password) {
            (Some(username), Some(password)) => Some(ProxyCredentials { username, password }),
            (Some(_), None) => return Err(ConfigError::MissingProxyPassword),
            (None, Some(_)) => return Err(ConfigError::MissingProxyUsername),
            (None, None) => None,
        };

        Ok(Self {
            port: read_port("PROXY_PORT", 3000),
            transparent_port: read_port("TPROXY_PORT", 3001),
            explicit_enabled: read_bool("EXPLICIT_PROXY_ENABLED", false),
            max_connections: read_usize("MAX_CONNECTIONS", 4096),
            tarpit_max_connections: read_usize("TARPIT_MAX_CONNECTIONS", 64),
            credentials,
            upstream_proxy: std::env::var("UPSTREAM_PROXY")
                .ok()
                .filter(|s| !s.is_empty()),
            tunnel_endpoint: std::env::var("TUNNEL_ENDPOINT")
                .ok()
                .filter(|s| !s.is_empty()),
            enable_dns_lookups: read_bool("ENABLE_DNS_LOOKUPS", false),
            fail_closed_no_sni: read_bool("TPROXY_FAIL_CLOSED_NO_SNI", true),
            capture_plaintext_payloads: read_bool("CAPTURE_PLAINTEXT_PAYLOADS", false),
            forensic_sentry_enabled: read_bool("FORENSIC_SENTRY_ENABLED", false),
            forensic_monitor_interface: std::env::var("FORENSIC_MONITOR_INTERFACE")
                .ok()
                .filter(|s| !s.is_empty()),
        })
    }
}

impl AdminConfig {
    /// Loads `AdminConfig` from environment variables.
    ///
    /// Reads `ADMIN_API_KEY` (or `ADMIN_API_KEY_FILE`) and fails if no API key is provided. Also reads `ADMIN_PORT` (default 3002) and `CORS_ALLOWED_ORIGINS` as a comma-separated list of origins (empty entries are ignored).
    ///
    /// # Errors
    ///
    /// Returns `ConfigError::MissingAdminApiKey` if no admin API key is found in the environment or in the configured file.
    ///
    /// # Examples
    ///
    /// ```
    /// use std::env;
    /// env::set_var("ADMIN_API_KEY", "example-admin-api-key-0000000000");
    /// env::set_var("ADMIN_PORT", "4000");
    /// env::set_var("CORS_ALLOWED_ORIGINS", "https://a.example, https://b.example");
    ///
    /// let cfg = crate::AdminConfig::from_env().unwrap();
    /// assert_eq!(cfg.port, 4000);
    /// assert_eq!(cfg.api_key, "example-admin-api-key-0000000000");
    /// assert_eq!(cfg.cors_allowed_origins, vec!["https://a.example".to_string(), "https://b.example".to_string()]);
    /// ```
    fn from_env() -> Result<Self, ConfigError> {
        let api_key = read_secret("ADMIN_API_KEY", "ADMIN_API_KEY_FILE")
            .ok_or(ConfigError::MissingAdminApiKey)?;
        if api_key.len() < MIN_ADMIN_API_KEY_LEN {
            return Err(ConfigError::AdminApiKeyTooShort {
                min_len: MIN_ADMIN_API_KEY_LEN,
                actual_len: api_key.len(),
            });
        }
        Ok(Self {
            port: read_port("ADMIN_PORT", 3002),
            bind_addr: std::env::var("ADMIN_BIND_ADDR")
                .ok()
                .filter(|s| !s.is_empty())
                .unwrap_or_else(|| "127.0.0.1".to_string()),
            api_key,
            require_mfa_claim: read_bool("ADMIN_REQUIRE_MFA_CLAIM", true),
            mfa_header_names: std::env::var("ADMIN_MFA_HEADER_NAMES")
                .unwrap_or_else(|_| "x-auth-amr,x-auth-acr,x-mfa-claim".to_string())
                .split(',')
                .map(|s| s.trim().to_ascii_lowercase())
                .filter(|s| !s.is_empty())
                .collect(),
            cors_allowed_origins: std::env::var("CORS_ALLOWED_ORIGINS")
                .unwrap_or_default()
                .split(',')
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect(),
            patch_cadence_report_path: std::env::var("PATCH_CADENCE_REPORT_PATH")
                .ok()
                .filter(|s| !s.is_empty()),
            recovery_drill_report_path: std::env::var("RECOVERY_DRILL_REPORT_PATH")
                .ok()
                .filter(|s| !s.is_empty()),
        })
    }
}
