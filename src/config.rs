//! Runtime configuration loaded from environment variables.
//!
//! Call `Config::from_env()` once at startup. All fields are validated before
//! `Ok` is returned; invalid configurations produce `ConfigError` instead of
//! panicking. Sensitive fields remain redacted in `Debug`.

use std::collections::HashMap;

use thiserror::Error;

use crate::{
    obfuscation::{Profile, FOX_DOMAINS},
    wg_packet_obfuscation::parse_magic_byte,
};

/// Runtime configuration grouped by subsystem.
#[derive(Clone)]
pub struct Config {
    pub proxy: ProxyConfig,
    pub admin: AdminConfig,
    pub sync: SyncConfig,
    pub obfuscation: ObfuscationConfig,
    pub tls: TlsConfig,
    pub wireguard: WireGuardConfig,
    pub runtime: RuntimeConfig,
}

/// Explicit proxy credentials loaded from environment or files.
#[derive(Clone)]
pub struct ProxyCredentials {
    pub username: String,
    pub password: String,
}

/// Proxy listener and tunnel runtime settings.
#[derive(Clone)]
pub struct ProxyConfig {
    pub port: u16,
    pub transparent_port: u16,
    pub explicit_enabled: bool,
    pub max_connections: usize,
    pub tarpit_max_connections: usize,
    pub credentials: Option<ProxyCredentials>,
    pub upstream_proxy: Option<String>,
    pub tunnel_endpoint: Option<String>,
    pub enable_dns_lookups: bool,
    pub fail_closed_no_sni: bool,
    pub capture_plaintext_payloads: bool,
    pub forensic_sentry_enabled: bool,
    pub forensic_monitor_interface: Option<String>,
}

/// Admin API settings.
#[derive(Clone)]
pub struct AdminConfig {
    pub port: u16,
    pub bind_addr: String,
    pub api_key: String,
    pub require_mfa_claim: bool,
    pub mfa_header_names: Vec<String>,
    pub cors_allowed_origins: Vec<String>,
    pub patch_cadence_report_path: Option<String>,
    pub recovery_drill_report_path: Option<String>,
}

/// Sync-plane publisher settings.
#[derive(Clone)]
pub struct SyncConfig {
    pub nats_url: Option<String>,
    pub connect_timeout_ms: u64,
    pub username: Option<String>,
    pub password: Option<String>,
    pub tls_enabled: bool,
    pub tls_server_name: Option<String>,
    pub tls_ca_cert_path: Option<String>,
    pub tls_client_cert_path: Option<String>,
    pub tls_client_key_path: Option<String>,
    pub inline_payload_max_bytes: usize,
    pub outbox_dir: String,
}

/// Traffic obfuscation settings and prebuilt domain map.
#[derive(Clone, Debug)]
pub struct ObfuscationConfig {
    pub enabled: bool,
    pub enabled_profiles: Vec<String>,
    pub fox_ua_override: String,
    pub domain_map: HashMap<String, Profile>,
}

/// TLS listener certificate settings.
#[derive(Clone, Debug)]
pub struct TlsConfig {
    pub cert_path: Option<String>,
    pub key_path: Option<String>,
}

/// WireGuard ingress settings.
#[derive(Clone)]
pub struct WireGuardConfig {
    pub port: u16,
    pub internal_port: u16,
    pub interface: Option<String>,
    pub drop_udp_443: bool,
    pub obfuscation_enabled: bool,
    pub obfuscation_key: Vec<u8>,
    pub obfuscation_magic_byte: Option<u8>,
    pub obfuscation_session_idle_secs: u64,
}

/// Runtime-only logging settings.
#[derive(Clone, Debug)]
pub struct RuntimeConfig {
    pub log_format: String,
    pub bandwidth_sample_interval_secs: u64,
    pub device_claim_ttl_secs: u64,
    pub dns_resolve_timeout_ms: u64,
}

/// Typed configuration loading errors returned by `Config::from_env()`.
#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("Conflicting ports: {0} and {1}")]
    PortConflict(u16, u16),
    #[error("ADMIN_API_KEY is required and must not be empty")]
    MissingAdminApiKey,
    #[error(
        "PROXY_USERNAME is set but PROXY_PASSWORD is missing (both are required for proxy auth)"
    )]
    MissingProxyPassword,
    #[error(
        "PROXY_PASSWORD is set but PROXY_USERNAME is missing (both are required for proxy auth)"
    )]
    MissingProxyUsername,
    #[error("WG_OBFUSCATION_ENABLED=true requires non-empty WG_OBFUSCATION_KEY")]
    MissingWireGuardObfuscationKey,
    #[error("WG_OBFUSCATION_MAGIC_BYTE must be a single byte in decimal or 0xNN form; got {0:?}")]
    InvalidWireGuardObfuscationMagicByte(String),
    #[error(
        "WG_PORT ({public_port}) and WG_INTERNAL_PORT ({internal_port}) must differ when WG_OBFUSCATION_ENABLED=true"
    )]
    WireGuardObfuscationPortConflict {
        public_port: u16,
        internal_port: u16,
    },
    #[error(
        "SYNC_NATS_USERNAME is set but SYNC_NATS_PASSWORD is missing (both are required for NATS auth)"
    )]
    MissingSyncNatsPassword,
    #[error(
        "SYNC_NATS_PASSWORD is set but SYNC_NATS_USERNAME is missing (both are required for NATS auth)"
    )]
    MissingSyncNatsUsername,
    #[error(
        "SYNC_NATS_TLS_ENABLED=true requires SYNC_NATS_TLS_CA_CERT_PATH because this runtime does not load system roots automatically"
    )]
    MissingSyncNatsTlsCaCertPath,
    #[error("SYNC_NATS_TLS_CLIENT_CERT_PATH is set but SYNC_NATS_TLS_CLIENT_KEY_PATH is missing")]
    MissingSyncNatsTlsClientKeyPath,
    #[error("SYNC_NATS_TLS_CLIENT_KEY_PATH is set but SYNC_NATS_TLS_CLIENT_CERT_PATH is missing")]
    MissingSyncNatsTlsClientCertPath,
}

impl std::fmt::Debug for Config {
    /// Formats the `Config` for debug output by emitting a debug struct with each subsystem field.
    ///
    /// # Examples
    ///
    /// ```
    /// let cfg = Config::default();
    /// let s = format!("{:?}", cfg);
    /// assert!(s.contains("proxy"));
    /// assert!(s.contains("admin"));
    /// ```
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Config")
            .field("proxy", &self.proxy)
            .field("admin", &self.admin)
            .field("sync", &self.sync)
            .field("obfuscation", &self.obfuscation)
            .field("tls", &self.tls)
            .field("wireguard", &self.wireguard)
            .field("runtime", &self.runtime)
            .finish()
    }
}

impl std::fmt::Debug for ProxyCredentials {
    /// Formats `ProxyCredentials` for debug output while redacting the `password` field.
    ///
    /// # Examples
    ///
    /// ```
    /// let creds = ProxyCredentials { username: "alice".into(), password: "hunter2".into() };
    /// let s = format!("{:?}", creds);
    /// assert!(s.contains("username: \"alice\""));
    /// assert!(s.contains("password: \"[REDACTED]\""));
    /// assert!(!s.contains("hunter2"));
    /// ```
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ProxyCredentials")
            .field("username", &self.username)
            .field("password", &"[REDACTED]")
            .finish()
    }
}

impl std::fmt::Debug for ProxyConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ProxyConfig")
            .field("port", &self.port)
            .field("transparent_port", &self.transparent_port)
            .field("explicit_enabled", &self.explicit_enabled)
            .field("max_connections", &self.max_connections)
            .field("tarpit_max_connections", &self.tarpit_max_connections)
            .field("credentials", &self.credentials)
            .field(
                "upstream_proxy",
                &redact_url_userinfo(self.upstream_proxy.as_deref()),
            )
            .field(
                "tunnel_endpoint",
                &redact_url_userinfo(self.tunnel_endpoint.as_deref()),
            )
            .field("enable_dns_lookups", &self.enable_dns_lookups)
            .field("fail_closed_no_sni", &self.fail_closed_no_sni)
            .field(
                "capture_plaintext_payloads",
                &self.capture_plaintext_payloads,
            )
            .field("forensic_sentry_enabled", &self.forensic_sentry_enabled)
            .field(
                "forensic_monitor_interface",
                &self.forensic_monitor_interface,
            )
            .finish()
    }
}

impl std::fmt::Debug for AdminConfig {
    /// Formats `AdminConfig` for debug output, redacting the `api_key` field.
    ///
    /// This implementation prints the struct with `api_key` replaced by `"[REDACTED]"`
    /// to avoid leaking sensitive information in logs or debug output.
    ///
    /// # Examples
    ///
    /// ```
    /// let cfg = AdminConfig {
    ///     port: 3002,
    ///     api_key: "secret".to_string(),
    ///     cors_allowed_origins: vec!["https://example.com".to_string()],
    /// };
    /// let s = format!("{:?}", cfg);
    /// assert!(s.contains("\"api_key\": \"[REDACTED]\""));
    /// assert!(!s.contains("secret"));
    /// ```
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AdminConfig")
            .field("port", &self.port)
            .field("bind_addr", &self.bind_addr)
            .field("api_key", &"[REDACTED]")
            .field("require_mfa_claim", &self.require_mfa_claim)
            .field("mfa_header_names", &self.mfa_header_names)
            .field("cors_allowed_origins", &self.cors_allowed_origins)
            .field("patch_cadence_report_path", &self.patch_cadence_report_path)
            .field(
                "recovery_drill_report_path",
                &self.recovery_drill_report_path,
            )
            .finish()
    }
}

impl std::fmt::Debug for SyncConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SyncConfig")
            .field("nats_url", &redact_url_userinfo(self.nats_url.as_deref()))
            .field("connect_timeout_ms", &self.connect_timeout_ms)
            .field("username", &self.username)
            .field(
                "password",
                &self.password.as_ref().map(|_| "[REDACTED]".to_string()),
            )
            .field("tls_enabled", &self.tls_enabled)
            .field("tls_server_name", &self.tls_server_name)
            .field("tls_ca_cert_path", &self.tls_ca_cert_path)
            .field("tls_client_cert_path", &self.tls_client_cert_path)
            .field("tls_client_key_path", &self.tls_client_key_path)
            .field("inline_payload_max_bytes", &self.inline_payload_max_bytes)
            .field("outbox_dir", &self.outbox_dir)
            .finish()
    }
}

impl std::fmt::Debug for WireGuardConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WireGuardConfig")
            .field("port", &self.port)
            .field("internal_port", &self.internal_port)
            .field("interface", &self.interface)
            .field("drop_udp_443", &self.drop_udp_443)
            .field("obfuscation_enabled", &self.obfuscation_enabled)
            .field("obfuscation_key", &"[REDACTED]")
            .field("obfuscation_magic_byte", &self.obfuscation_magic_byte)
            .field(
                "obfuscation_session_idle_secs",
                &self.obfuscation_session_idle_secs,
            )
            .finish()
    }
}

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
        let sync = SyncConfig::from_env()?;
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
    /// The returned Config is `Default` with `admin.api_key` set to `"test-key"`.
    ///
    /// # Examples
    ///
    /// ```
    /// let cfg = crate::config::Config::for_tests();
    /// assert_eq!(cfg.admin.api_key, "test-key");
    /// ```
    #[cfg(test)]
    pub(crate) fn for_tests() -> Self {
        let mut config = Self::default();
        config.admin.api_key = "test-key".to_string();
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
            sync: SyncConfig {
                nats_url: None,
                connect_timeout_ms: 2_000,
                username: None,
                password: None,
                tls_enabled: false,
                tls_server_name: None,
                tls_ca_cert_path: None,
                tls_client_cert_path: None,
                tls_client_key_path: None,
                inline_payload_max_bytes: 2_048,
                outbox_dir: "/tmp/ssl-proxy-sync-outbox".to_string(),
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
    /// env::set_var("ADMIN_API_KEY", "secret-key");
    /// env::set_var("ADMIN_PORT", "4000");
    /// env::set_var("CORS_ALLOWED_ORIGINS", "https://a.example, https://b.example");
    ///
    /// let cfg = crate::AdminConfig::from_env().unwrap();
    /// assert_eq!(cfg.port, 4000);
    /// assert_eq!(cfg.api_key, "secret-key");
    /// assert_eq!(cfg.cors_allowed_origins, vec!["https://a.example".to_string(), "https://b.example".to_string()]);
    /// ```
    fn from_env() -> Result<Self, ConfigError> {
        let api_key = read_secret("ADMIN_API_KEY", "ADMIN_API_KEY_FILE")
            .ok_or(ConfigError::MissingAdminApiKey)?;
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

impl SyncConfig {
    fn from_env() -> Result<Self, ConfigError> {
        let nats_url = std::env::var("SYNC_NATS_URL")
            .ok()
            .map(|value| value.trim().to_string())
            .filter(|value| !value.is_empty());
        let username = std::env::var("SYNC_NATS_USERNAME")
            .ok()
            .map(|value| value.trim().to_string())
            .filter(|value| !value.is_empty());
        let password = read_secret("SYNC_NATS_PASSWORD", "SYNC_NATS_PASSWORD_FILE");
        let (username, password) = match (username, password) {
            (Some(username), Some(password)) => (Some(username), Some(password)),
            (Some(_), None) => return Err(ConfigError::MissingSyncNatsPassword),
            (None, Some(_)) => return Err(ConfigError::MissingSyncNatsUsername),
            (None, None) => (None, None),
        };

        let inferred_tls = nats_url
            .as_deref()
            .map(|url| url.starts_with("tls://"))
            .unwrap_or(false);
        let tls_enabled = read_bool("SYNC_NATS_TLS_ENABLED", inferred_tls);
        let tls_ca_cert_path = std::env::var("SYNC_NATS_TLS_CA_CERT_PATH")
            .ok()
            .map(|value| value.trim().to_string())
            .filter(|value| !value.is_empty());
        let tls_client_cert_path = std::env::var("SYNC_NATS_TLS_CLIENT_CERT_PATH")
            .ok()
            .map(|value| value.trim().to_string())
            .filter(|value| !value.is_empty());
        let tls_client_key_path = std::env::var("SYNC_NATS_TLS_CLIENT_KEY_PATH")
            .ok()
            .map(|value| value.trim().to_string())
            .filter(|value| !value.is_empty());
        match (&tls_client_cert_path, &tls_client_key_path) {
            (Some(_), None) => return Err(ConfigError::MissingSyncNatsTlsClientKeyPath),
            (None, Some(_)) => return Err(ConfigError::MissingSyncNatsTlsClientCertPath),
            _ => {}
        }
        if tls_enabled && nats_url.is_some() && tls_ca_cert_path.is_none() {
            return Err(ConfigError::MissingSyncNatsTlsCaCertPath);
        }

        Ok(Self {
            nats_url,
            connect_timeout_ms: read_u64("SYNC_NATS_CONNECT_TIMEOUT_MS", 2_000),
            username,
            password,
            tls_enabled,
            tls_server_name: std::env::var("SYNC_NATS_TLS_SERVER_NAME")
                .ok()
                .map(|value| value.trim().to_string())
                .filter(|value| !value.is_empty()),
            tls_ca_cert_path,
            tls_client_cert_path,
            tls_client_key_path,
            inline_payload_max_bytes: read_usize("SYNC_INLINE_PAYLOAD_MAX_BYTES", 2_048),
            outbox_dir: std::env::var("SYNC_OUTBOX_DIR")
                .ok()
                .map(|value| value.trim().to_string())
                .filter(|value| !value.is_empty())
                .unwrap_or_else(|| "/tmp/ssl-proxy-sync-outbox".to_string()),
        })
    }
}

impl ObfuscationConfig {
    /// Constructs an `ObfuscationConfig` from environment variables.
    ///
    /// The resulting configuration:
    // - `enabled` is taken from `OBFUSCATION_ENABLED` (defaults to `true`).
    // - `enabled_profiles` is parsed from `OBFUSCATION_PROFILE` as a comma-separated list (defaults to `"fox-news,fox-sports"`).
    // - `fox_ua_override` is taken from `FOX_UA_OVERRIDE` (defaults to a built-in mobile Safari user agent).
    // - `domain_map` contains mappings for the enabled profiles.
    ///
    /// # Examples
    ///
    /// ```
    /// std::env::set_var("OBFUSCATION_PROFILE", "fox-news");
    /// std::env::set_var("OBFUSCATION_ENABLED", "false");
    /// std::env::remove_var("FOX_UA_OVERRIDE");
    ///
    /// let cfg = ObfuscationConfig::from_env();
    /// assert_eq!(cfg.enabled, false);
    /// assert_eq!(cfg.enabled_profiles, vec!["fox-news".to_string()]);
    /// assert!(cfg.fox_ua_override.contains("Mozilla/5.0"));
    /// assert!(cfg.domain_map.len() > 0);
    /// ```
    fn from_env() -> Self {
        let enabled_profiles: Vec<String> = std::env::var("OBFUSCATION_PROFILE")
            .unwrap_or_else(|_| "fox-news,fox-sports".to_string())
            .split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect();

        Self {
            enabled: read_bool("OBFUSCATION_ENABLED", true),
            fox_ua_override: std::env::var("FOX_UA_OVERRIDE").unwrap_or_else(|_| {
                "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15"
                    .to_string()
            }),
            domain_map: build_domain_map(&enabled_profiles),
            enabled_profiles,
        }
    }
}

impl TlsConfig {
    /// Loads TLS certificate and key file paths from environment variables.
    ///
    /// Each field is populated with the corresponding environment variable value
    /// (`TLS_CERT_PATH` and `TLS_KEY_PATH`) if the variable is present and not empty;
    /// otherwise the field is `None`.
    ///
    /// # Examples
    ///
    /// ```
    /// // Ensure a controlled environment for the example
    /// std::env::remove_var("TLS_CERT_PATH");
    /// std::env::set_var("TLS_KEY_PATH", "/tmp/key.pem");
    ///
    /// let cfg = crate::TlsConfig::from_env();
    /// assert_eq!(cfg.cert_path, None);
    /// assert_eq!(cfg.key_path.as_deref(), Some("/tmp/key.pem"));
    /// ```
    fn from_env() -> Self {
        Self {
            cert_path: std::env::var("TLS_CERT_PATH")
                .ok()
                .filter(|s| !s.is_empty()),
            key_path: std::env::var("TLS_KEY_PATH").ok().filter(|s| !s.is_empty()),
        }
    }
}

impl WireGuardConfig {
    /// Constructs a `WireGuardConfig` from environment variables.
    ///
    /// Reads `WG_PORT` (defaults to `443`), `WG_INTERNAL_PORT` (defaults to `51820`),
    /// `WG_INTERFACE` (optional; treated as `None` when missing or empty),
    /// `WG_DROP_UDP_443` (defaults to `true`), `WG_OBFUSCATION_ENABLED`
    /// (defaults to `true`), `WG_OBFUSCATION_KEY` (required when obfuscation
    /// is enabled), `WG_OBFUSCATION_MAGIC_BYTE` (optional decimal or `0xNN` form),
    /// and `WG_OBFUSCATION_SESSION_IDLE_SECS` (defaults to `300`).
    ///
    /// # Examples
    ///
    /// ```
    /// std::env::remove_var("WG_PORT");
    /// std::env::remove_var("WG_INTERNAL_PORT");
    /// std::env::remove_var("WG_INTERFACE");
    /// std::env::set_var("WG_OBFUSCATION_KEY", "test-key");
    /// let cfg = WireGuardConfig::from_env().unwrap();
    /// assert_eq!(cfg.port, 443);
    /// assert_eq!(cfg.internal_port, 51820);
    /// assert!(cfg.interface.is_none());
    ///
    /// std::env::set_var("WG_PORT", "443");
    /// std::env::set_var("WG_INTERNAL_PORT", "51821");
    /// std::env::set_var("WG_INTERFACE", "wg0");
    /// std::env::set_var("WG_DROP_UDP_443", "false");
    /// std::env::set_var("WG_OBFUSCATION_MAGIC_BYTE", "0xAA");
    /// let cfg = WireGuardConfig::from_env().unwrap();
    /// assert_eq!(cfg.port, 443);
    /// assert_eq!(cfg.internal_port, 51821);
    /// assert_eq!(cfg.interface.as_deref(), Some("wg0"));
    /// assert!(!cfg.drop_udp_443);
    /// assert_eq!(cfg.obfuscation_magic_byte, Some(0xAA));
    /// ```
    fn from_env() -> Result<Self, ConfigError> {
        let obfuscation_enabled = read_bool("WG_OBFUSCATION_ENABLED", true);
        let obfuscation_key =
            read_secret("WG_OBFUSCATION_KEY", "WG_OBFUSCATION_KEY_FILE").unwrap_or_default();
        if obfuscation_enabled && obfuscation_key.is_empty() {
            return Err(ConfigError::MissingWireGuardObfuscationKey);
        }

        Ok(Self {
            port: read_port("WG_PORT", 443),
            internal_port: read_port("WG_INTERNAL_PORT", 51820),
            interface: std::env::var("WG_INTERFACE").ok().filter(|s| !s.is_empty()),
            drop_udp_443: read_bool("WG_DROP_UDP_443", true),
            obfuscation_enabled,
            obfuscation_key: obfuscation_key.into_bytes(),
            obfuscation_magic_byte: read_magic_byte("WG_OBFUSCATION_MAGIC_BYTE")?,
            obfuscation_session_idle_secs: read_u64("WG_OBFUSCATION_SESSION_IDLE_SECS", 300).max(1),
        })
    }
}

impl RuntimeConfig {
    /// Load runtime configuration from environment variables.
    ///
    /// Reads the `LOG_FORMAT` environment variable and sets `log_format` to its value; if the
    /// variable is not set or empty, `"human"` is used as the default.
    ///
    /// # Examples
    ///
    /// ```
    /// // Ensure environment is predictable in examples/tests.
    /// std::env::remove_var("LOG_FORMAT");
    /// let cfg = crate::RuntimeConfig::from_env();
    /// assert_eq!(cfg.log_format, "human");
    ///
    /// std::env::set_var("LOG_FORMAT", "json");
    /// let cfg = crate::RuntimeConfig::from_env();
    /// assert_eq!(cfg.log_format, "json");
    /// ```
    fn from_env() -> Self {
        Self {
            log_format: std::env::var("LOG_FORMAT").unwrap_or_else(|_| "human".to_string()),
            bandwidth_sample_interval_secs: read_u64("BANDWIDTH_SAMPLE_INTERVAL_SECS", 60),
            device_claim_ttl_secs: read_u64("DEVICE_CLAIM_TTL_SECS", 300),
            dns_resolve_timeout_ms: read_u64("DNS_RESOLVE_TIMEOUT_MS", 2_000),
        }
    }
}

/// Builds a mapping from domain patterns to `Profile` values using the static `FOX_DOMAINS`,
/// including only entries whose profile name appears in `enabled_profiles`.
///
/// Wildcard patterns that start with `"*."` are normalized by removing the `*` and
/// inserting the key with a leading dot (e.g., `"*.example.com"` becomes `".example.com"`).
///
/// # Parameters
///
/// - `enabled_profiles`: list of profile names to include in the resulting map.
///
/// # Returns
///
/// A `HashMap` where keys are domain patterns (with wildcard patterns normalized as described)
/// and values are the corresponding `Profile`.
///
/// # Examples
///
/// ```
/// # use std::collections::HashMap;
/// # // assume build_domain_map and Profile are in scope
/// let map = build_domain_map(&[]);
/// assert!(map.is_empty());
/// ```
fn build_domain_map(enabled_profiles: &[String]) -> HashMap<String, Profile> {
    let mut map = HashMap::new();
    for (pattern, profile_name) in FOX_DOMAINS {
        let Some(profile) = Profile::from_name(profile_name) else {
            continue;
        };
        if !enabled_profiles
            .iter()
            .any(|enabled| enabled == profile.as_str())
        {
            continue;
        }
        if let Some(stripped) = pattern.strip_prefix("*.") {
            map.insert(format!(".{}", stripped), profile);
        } else {
            map.insert((*pattern).to_string(), profile);
        }
    }
    map
}

fn redact_url_userinfo(value: Option<&str>) -> Option<String> {
    value.map(|raw| {
        if let Some((scheme, rest)) = raw.split_once("://") {
            if let Some((userinfo, suffix)) = rest.split_once('@') {
                if !userinfo.is_empty() {
                    return format!("{scheme}://[REDACTED]@{suffix}");
                }
            }
        }
        if let Some((userinfo, suffix)) = raw.split_once('@') {
            if userinfo.contains(':') {
                return format!("[REDACTED]@{suffix}");
            }
        }
        raw.to_string()
    })
}

/// Read an environment variable as a port number, falling back to a provided default when the
/// variable is missing or cannot be parsed as a valid port.
///
/// # Examples
///
/// ```
/// use std::env;
/// env::set_var("TEST_PORT", "12345");
/// assert_eq!(read_port("TEST_PORT", 3000), 12345);
/// env::remove_var("TEST_PORT");
/// assert_eq!(read_port("TEST_PORT", 3000), 3000);
/// ```
fn read_port(var: &str, default: u16) -> u16 {
    std::env::var(var)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
}

/// Read an environment variable as `u64`, falling back to `default` on absence or parse failure.
fn read_u64(var: &str, default: u64) -> u64 {
    std::env::var(var)
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
        .unwrap_or(default)
}

/// Reads an environment variable, parses it as an unsigned integer, and returns the parsed value or a fallback when missing or invalid.
///
/// `var` is the environment variable name to read. `default` is returned when the variable is not set or cannot be parsed as a usize.
///
/// # Examples
///
/// ```
/// use std::env;
/// env::set_var("MY_TEST_USIZE", "42");
/// assert_eq!(read_usize("MY_TEST_USIZE", 7), 42);
/// env::remove_var("MY_TEST_USIZE");
/// ```
fn read_usize(var: &str, default: usize) -> usize {
    std::env::var(var)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
}

/// Interpret an environment variable as a boolean with a fallback.
///
/// The environment variable named `var` is read and compared case-insensitively against
/// accepted truthy values (`"true"`, `"1"`, `"yes"`, `"on"`) and falsy values
/// (`"false"`, `"0"`, `"no"`, `"off"`). If the variable is missing or contains any other
/// value, `default` is returned.
///
/// # Examples
///
/// ```
/// // If MY_FLAG is unset, returns the provided default
/// std::env::remove_var("MY_FLAG");
/// assert_eq!(read_bool("MY_FLAG", true), true);
///
/// // Recognizes common truthy/falsy strings
/// std::env::set_var("MY_FLAG", "yes");
/// assert_eq!(read_bool("MY_FLAG", false), true);
///
/// std::env::set_var("MY_FLAG", "0");
/// assert_eq!(read_bool("MY_FLAG", true), false);
/// ```
fn read_bool(var: &str, default: bool) -> bool {
    std::env::var(var)
        .map(|v| match v.to_ascii_lowercase().as_str() {
            "true" | "1" | "yes" | "on" => true,
            "false" | "0" | "no" | "off" => false,
            _ => default,
        })
        .unwrap_or(default)
}

/// Returns a secret value taken from an environment variable or, if that is empty/missing,
/// from a file whose path is specified by a second environment variable.
///
/// If `var` is set and non-empty, its trimmed contents are returned. Otherwise, if `file_var`
/// is set to a non-empty file path and that file can be read, the file's trimmed contents are
/// returned. Empty or unreadable values yield `None`.
///
/// # Arguments
///
/// * `var` - Environment variable name that may contain the secret value.
/// * `file_var` - Environment variable name that may contain a path to a file holding the secret.
///
/// # Examples
///
/// ```
/// # // run inside a test to avoid leaking environment changes
/// std::env::remove_var("MY_SECRET");
/// std::env::remove_var("MY_SECRET_FILE");
/// std::env::set_var("MY_SECRET", "  s3cr3t  ");
/// assert_eq!(read_secret("MY_SECRET", "MY_SECRET_FILE"), Some("s3cr3t".to_string()));
/// ```
fn read_secret(var: &str, file_var: &str) -> Option<String> {
    std::env::var(var)
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .or_else(|| {
            let file = std::env::var(file_var).unwrap_or_default();
            if file.is_empty() {
                return None;
            }
            std::fs::read_to_string(file)
                .ok()
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
        })
}

fn read_magic_byte(var: &str) -> Result<Option<u8>, ConfigError> {
    let Some(raw) = std::env::var(var)
        .ok()
        .map(|value| value.trim().to_string())
    else {
        return Ok(None);
    };
    if raw.is_empty() {
        return Ok(None);
    }

    parse_magic_byte(&raw)
        .map(Some)
        .ok_or(ConfigError::InvalidWireGuardObfuscationMagicByte(raw))
}

#[cfg(test)]
mod tests {
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
            "SYNC_NATS_URL",
            "SYNC_NATS_CONNECT_TIMEOUT_MS",
            "SYNC_NATS_USERNAME",
            "SYNC_NATS_PASSWORD",
            "SYNC_NATS_PASSWORD_FILE",
            "SYNC_NATS_TLS_ENABLED",
            "SYNC_NATS_TLS_SERVER_NAME",
            "SYNC_NATS_TLS_CA_CERT_PATH",
            "SYNC_NATS_TLS_CLIENT_CERT_PATH",
            "SYNC_NATS_TLS_CLIENT_KEY_PATH",
            "SYNC_INLINE_PAYLOAD_MAX_BYTES",
            "SYNC_OUTBOX_DIR",
        ] {
            std::env::remove_var(key);
        }
    }

    /// Sets test defaults for the shared config tests.
    fn set_test_env_defaults() {
        std::env::set_var("WG_OBFUSCATION_KEY", "test-obfuscation-key");
    }

    #[test]
    fn config_port_conflict_error() {
        let _guard = env_lock();
        clear_env();
        set_test_env_defaults();
        std::env::set_var("PROXY_PORT", "51820");
        std::env::set_var("WG_PORT", "51820");
        std::env::set_var("ADMIN_API_KEY", "test-key");

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
        std::env::set_var("ADMIN_API_KEY", "test-key");

        let result = Config::from_env().unwrap();

        assert!(!result.proxy.explicit_enabled);
    }

    #[test]
    fn explicit_proxy_enabled_when_requested() {
        let _guard = env_lock();
        clear_env();
        set_test_env_defaults();
        std::env::set_var("ADMIN_API_KEY", "test-key");
        std::env::set_var("EXPLICIT_PROXY_ENABLED", "true");

        let result = Config::from_env().unwrap();

        assert!(result.proxy.explicit_enabled);
    }

    #[test]
    fn capture_plaintext_payloads_defaults_to_false_and_reads_env() {
        let _guard = env_lock();
        clear_env();
        set_test_env_defaults();
        std::env::set_var("ADMIN_API_KEY", "test-key");

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
        std::env::set_var("ADMIN_API_KEY", "test-key");

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
        std::env::set_var("ADMIN_API_KEY", "test-key");

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
        std::env::set_var("ADMIN_API_KEY", "test-key");

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
        std::env::set_var("ADMIN_API_KEY", "test-key");

        let result = Config::from_env().unwrap();
        assert_eq!(result.wireguard.port, 443);
        assert_eq!(result.wireguard.internal_port, 51820);
        assert!(result.wireguard.obfuscation_enabled);
        assert_eq!(result.wireguard.obfuscation_magic_byte, None);
        assert_eq!(result.wireguard.obfuscation_session_idle_secs, 300);
        assert_eq!(
            result.wireguard.obfuscation_key,
            b"test-obfuscation-key".to_vec()
        );
    }

    #[test]
    fn missing_wireguard_obfuscation_key_errors_when_enabled() {
        let _guard = env_lock();
        clear_env();
        set_test_env_defaults();
        std::env::remove_var("WG_OBFUSCATION_KEY");
        std::env::set_var("ADMIN_API_KEY", "test-key");

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
        std::env::set_var("ADMIN_API_KEY", "test-key");

        let result = Config::from_env().unwrap();
        assert!(!result.wireguard.obfuscation_enabled);
        assert!(result.wireguard.obfuscation_key.is_empty());
    }

    #[test]
    fn wireguard_magic_byte_accepts_hex_and_decimal() {
        let _guard = env_lock();
        clear_env();
        set_test_env_defaults();
        std::env::set_var("ADMIN_API_KEY", "test-key");

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
        std::env::set_var("ADMIN_API_KEY", "test-key");
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
        std::env::set_var("ADMIN_API_KEY", "test-key");
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
    fn sync_config_defaults_and_auth_pair_validation() {
        let _guard = env_lock();
        clear_env();
        set_test_env_defaults();
        std::env::set_var("ADMIN_API_KEY", "test-key");

        let result = Config::from_env().unwrap();
        assert_eq!(result.sync.connect_timeout_ms, 2_000);
        assert_eq!(result.sync.inline_payload_max_bytes, 2_048);
        assert_eq!(result.sync.outbox_dir, "/tmp/ssl-proxy-sync-outbox");
        assert!(result.sync.nats_url.is_none());

        std::env::set_var("SYNC_NATS_USERNAME", "proxy-user");
        let result = Config::from_env();
        assert!(matches!(result, Err(ConfigError::MissingSyncNatsPassword)));

        std::env::set_var("SYNC_NATS_PASSWORD", "proxy-pass");
        let result = Config::from_env().unwrap();
        assert_eq!(result.sync.username.as_deref(), Some("proxy-user"));
        assert_eq!(result.sync.password.as_deref(), Some("proxy-pass"));
    }

    #[test]
    fn sync_tls_requires_ca_and_validates_client_cert_pair() {
        let _guard = env_lock();
        clear_env();
        set_test_env_defaults();
        std::env::set_var("ADMIN_API_KEY", "test-key");
        std::env::set_var("SYNC_NATS_URL", "tls://nats.internal:4443");

        let result = Config::from_env();
        assert!(matches!(
            result,
            Err(ConfigError::MissingSyncNatsTlsCaCertPath)
        ));

        std::env::set_var("SYNC_NATS_TLS_CA_CERT_PATH", "/tmp/ca.pem");
        std::env::set_var("SYNC_NATS_TLS_CLIENT_CERT_PATH", "/tmp/client.pem");
        let result = Config::from_env();
        assert!(matches!(
            result,
            Err(ConfigError::MissingSyncNatsTlsClientKeyPath)
        ));
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
        assert_eq!(Config::for_tests().admin.api_key, "test-key");
    }
}
