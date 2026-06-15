use std::collections::HashMap;

use sync_plane::SyncConfig;
use thiserror::Error;

use crate::{
    obfuscation::Profile,
    wg_packet_obfuscation::{EncryptionMode, MagicPositionMode, PacketPadding},
};

pub const MIN_ADMIN_API_KEY_LEN: usize = 32;

/// Runtime configuration grouped by subsystem.
#[derive(Clone)]
pub struct Config {
    pub proxy: ProxyConfig,
    pub admin: AdminConfig,
    pub sync: SyncConfig,
    pub payload_audit: PayloadAuditConfig,
    pub obfuscation: ObfuscationConfig,
    pub tls: TlsConfig,
    pub wireguard: WireGuardConfig,
    pub runtime: RuntimeConfig,
}

/// Explicit proxy credentials loaded from environment or files.
///
/// Both username and password must be provided together; partial credentials
/// will cause `Config::from_env()` to return a `ConfigError`.
#[derive(Clone)]
pub struct ProxyCredentials {
    /// Username for proxy authentication.
    pub username: String,
    /// Password for proxy authentication (redacted in Debug output).
    pub password: String,
}

/// Proxy listener and tunnel runtime settings.
///
/// Controls both transparent proxy (TPROXY) and explicit proxy modes,
/// connection limits, upstream proxy chaining, and forensic capture features.
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
    /// Capture bounded payload previews only for flows that do not look like TLS.
    pub capture_plaintext_payloads: bool,
    pub forensic_sentry_enabled: bool,
    pub forensic_monitor_interface: Option<String>,
}

/// Admin API settings.
///
/// Configures the administrative HTTP API including authentication,
/// CORS policies, and MFA requirements.
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

/// Browser payload audit publishing settings.
#[derive(Clone, Debug)]
pub struct PayloadAuditConfig {
    pub enabled: bool,
    pub redpanda_topic: String,
    pub max_body_bytes: usize,
    pub allowed_methods: Vec<String>,
    pub allowed_content_types: Vec<String>,
}

/// Traffic obfuscation settings and prebuilt domain map.
///
/// Controls which obfuscation profiles are active and maintains a mapping
/// from domain patterns to their corresponding obfuscation profiles.
#[derive(Clone, Debug)]
pub struct ObfuscationConfig {
    pub enabled: bool,
    pub enabled_profiles: Vec<String>,
    pub fox_ua_override: String,
    pub domain_map: HashMap<String, Profile>,
}

/// TLS listener certificate settings.
///
/// Specifies paths to certificate and private key files for TLS termination.
#[derive(Clone, Debug)]
pub struct TlsConfig {
    pub cert_path: Option<String>,
    pub key_path: Option<String>,
}

/// WireGuard ingress settings.
///
/// Configures WireGuard listener ports, packet obfuscation, and session management.
/// When obfuscation is enabled, the public port receives obfuscated packets which
/// are deobfuscated and forwarded to the internal port.
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
    pub obfuscation_encryption_mode: EncryptionMode,
    pub obfuscation_padding: PacketPadding,
    pub obfuscation_magic_position: MagicPositionMode,
    pub obfuscation_replay_protection: bool,
    pub obfuscation_xor_rekey_packets: Option<u64>,
    pub obfuscation_xor_rekey_secs: Option<u64>,
}

/// Runtime-only logging and operational settings.
///
/// Controls log formatting, sampling intervals, and timeout values that
/// don't fit into other subsystem configurations.
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
    #[error("ADMIN_API_KEY must be at least {min_len} bytes; got {actual_len}")]
    AdminApiKeyTooShort { min_len: usize, actual_len: usize },
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
    #[error("WG_OBFUSCATION_ENCRYPTION_MODE must be xor or aead; got {0:?}")]
    InvalidWireGuardObfuscationEncryptionMode(String),
    #[error("WG_OBFUSCATION_PADDING must be none, power-of-two, or fixed-mtu:<bytes>; got {0:?}")]
    InvalidWireGuardObfuscationPadding(String),
    #[error("WG_OBFUSCATION_MAGIC_POSITION must be fixed or randomized; got {0:?}")]
    InvalidWireGuardObfuscationMagicPosition(String),
    #[error("{var} must be a positive integer; got {value:?}")]
    InvalidWireGuardObfuscationXorRekeyValue { var: &'static str, value: String },
    #[error(
        "WG_PORT ({public_port}) and WG_INTERNAL_PORT ({internal_port}) must differ when WG_OBFUSCATION_ENABLED=true"
    )]
    WireGuardObfuscationPortConflict {
        public_port: u16,
        internal_port: u16,
    },
    #[error("SYNC_REDPANDA_SASL_USERNAME is set but SYNC_REDPANDA_SASL_PASSWORD is missing")]
    MissingSyncRedpandaSaslPassword,
    #[error("SYNC_REDPANDA_SASL_PASSWORD is set but SYNC_REDPANDA_SASL_USERNAME is missing")]
    MissingSyncRedpandaSaslUsername,
    #[error("SYNC_REDPANDA_SSL_CERTIFICATE_LOCATION is set but SYNC_REDPANDA_SSL_KEY_LOCATION is missing")]
    MissingSyncRedpandaSslKeyLocation,
    #[error("SYNC_REDPANDA_SSL_KEY_LOCATION is set but SYNC_REDPANDA_SSL_CERTIFICATE_LOCATION is missing")]
    MissingSyncRedpandaSslCertificateLocation,
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
            .field("payload_audit", &self.payload_audit)
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
            .field(
                "obfuscation_encryption_mode",
                &self.obfuscation_encryption_mode,
            )
            .field("obfuscation_padding", &self.obfuscation_padding)
            .field(
                "obfuscation_magic_position",
                &self.obfuscation_magic_position,
            )
            .field(
                "obfuscation_replay_protection",
                &self.obfuscation_replay_protection,
            )
            .field(
                "obfuscation_xor_rekey_packets",
                &self.obfuscation_xor_rekey_packets,
            )
            .field(
                "obfuscation_xor_rekey_secs",
                &self.obfuscation_xor_rekey_secs,
            )
            .finish()
    }
}
