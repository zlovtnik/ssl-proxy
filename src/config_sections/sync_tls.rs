use std::collections::HashMap;

use super::{parsing::*, types::*};
use crate::{
    obfuscation::{Profile, FOX_DOMAINS},
    wg_packet_obfuscation::{
        encoded_packet_len_bounds, EncryptionMode, PacketPadding, WgPacketObfuscation,
        WgPacketObfuscationError, XorRekeyPolicy,
    },
};
use sync_plane::SyncConfig;

pub(super) fn sync_config_from_env() -> Result<SyncConfig, ConfigError> {
    let redpanda_bootstrap_servers = std::env::var("SYNC_REDPANDA_BOOTSTRAP_SERVERS")
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty());
    let sasl_username = std::env::var("SYNC_REDPANDA_SASL_USERNAME")
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty());
    let sasl_password = read_secret(
        "SYNC_REDPANDA_SASL_PASSWORD",
        "SYNC_REDPANDA_SASL_PASSWORD_FILE",
    );
    let (sasl_username, sasl_password) = match (sasl_username, sasl_password) {
        (Some(username), Some(password)) => (Some(username), Some(password)),
        (Some(_), None) => return Err(ConfigError::MissingSyncRedpandaSaslPassword),
        (None, Some(_)) => return Err(ConfigError::MissingSyncRedpandaSaslUsername),
        (None, None) => (None, None),
    };
    let security_protocol = std::env::var("SYNC_REDPANDA_SECURITY_PROTOCOL")
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty());
    let sasl_mechanisms = std::env::var("SYNC_REDPANDA_SASL_MECHANISMS")
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty());
    let ssl_ca_location = std::env::var("SYNC_REDPANDA_SSL_CA_LOCATION")
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty());
    let ssl_certificate_location = std::env::var("SYNC_REDPANDA_SSL_CERTIFICATE_LOCATION")
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty());
    let ssl_key_location = std::env::var("SYNC_REDPANDA_SSL_KEY_LOCATION")
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty());
    match (&ssl_certificate_location, &ssl_key_location) {
        (Some(_), None) => return Err(ConfigError::MissingSyncRedpandaSslKeyLocation),
        (None, Some(_)) => return Err(ConfigError::MissingSyncRedpandaSslCertificateLocation),
        _ => {}
    }

    let outbox_dir = std::env::var("SYNC_OUTBOX_DIR")
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| "/tmp/ssl-proxy-sync-outbox".to_string());
    let publish_spool_dir = std::env::var("SYNC_PUBLISH_SPOOL_DIR")
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| {
            std::path::Path::new(&outbox_dir)
                .join("publish-spool")
                .display()
                .to_string()
        });

    Ok(SyncConfig {
        redpanda_bootstrap_servers,
        connect_timeout_ms: read_u64("SYNC_REDPANDA_CONNECT_TIMEOUT_MS", 2_000),
        publish_timeout_ms: read_u64("SYNC_REDPANDA_PUBLISH_TIMEOUT_MS", 2_000),
        publish_queue_capacity: read_usize("SYNC_PUBLISH_QUEUE_CAPACITY", 8_192),
        publish_enqueue_timeout_ms: read_u64("SYNC_PUBLISH_ENQUEUE_TIMEOUT_MS", 25),
        security_protocol,
        sasl_mechanisms,
        sasl_username,
        sasl_password,
        ssl_ca_location,
        ssl_certificate_location,
        ssl_key_location,
        inline_payload_max_bytes: read_usize("SYNC_INLINE_PAYLOAD_MAX_BYTES", 2_048),
        outbox_dir,
        publish_spool_dir,
    })
}

impl PayloadAuditConfig {
    pub(super) fn from_env() -> Self {
        Self {
            enabled: read_bool("PAYLOAD_AUDIT_ENABLED", false),
            redpanda_topic: std::env::var("PAYLOAD_AUDIT_REDPANDA_TOPIC")
                .ok()
                .map(|value| value.trim().to_string())
                .filter(|value| !value.is_empty())
                .unwrap_or_else(|| "proxy.payload_audit".to_string()),
            max_body_bytes: read_usize("PAYLOAD_AUDIT_MAX_BODY_BYTES", 65_536),
            allowed_methods: read_csv_list(
                "PAYLOAD_AUDIT_ALLOWED_METHODS",
                &["POST", "PUT", "PATCH"],
            ),
            allowed_content_types: read_csv_list(
                "PAYLOAD_AUDIT_ALLOWED_CONTENT_TYPES",
                &["application/json"],
            ),
        }
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
    pub(super) fn from_env() -> Self {
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
    pub(super) fn from_env() -> Self {
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
    /// `WG_OBFUSCATION_SESSION_IDLE_SECS` (defaults to `300`), optional
    /// framed-mode controls for encryption, padding, marker position, replay
    /// protection, and XOR re-keying, plus `WG_OBFUSCATION_MAX_DATAGRAM_BYTES`
    /// and `WG_UDP_SOCKET_BUFFER_BYTES` for UDP hot-path sizing.
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
    pub(super) fn from_env() -> Result<Self, ConfigError> {
        let obfuscation_enabled = read_bool("WG_OBFUSCATION_ENABLED", true);
        let (
            obfuscation_key,
            obfuscation_encryption_mode,
            obfuscation_replay_protection,
            obfuscation_magic_byte,
            obfuscation_padding,
            obfuscation_magic_position,
            obfuscation_xor_rekey_packets,
            obfuscation_xor_rekey_secs,
            sizing_settings,
        ) = if obfuscation_enabled {
            let obfuscation_key =
                read_secret_strict_file("WG_OBFUSCATION_KEY", "WG_OBFUSCATION_KEY_FILE")?
                    .unwrap_or_default();
            if obfuscation_key.is_empty() {
                return Err(ConfigError::MissingWireGuardObfuscationKey);
            }
            let obfuscation_encryption_mode =
                read_wireguard_obfuscation_encryption_mode("WG_OBFUSCATION_ENCRYPTION_MODE")?;
            let obfuscation_replay_protection = read_bool(
                "WG_OBFUSCATION_REPLAY_PROTECTION",
                matches!(obfuscation_encryption_mode, EncryptionMode::Aead),
            );
            let obfuscation_magic_byte = read_magic_byte("WG_OBFUSCATION_MAGIC_BYTE")?;
            let obfuscation_padding = read_wireguard_obfuscation_padding("WG_OBFUSCATION_PADDING")?;
            let obfuscation_magic_position =
                read_wireguard_obfuscation_magic_position("WG_OBFUSCATION_MAGIC_POSITION")?;
            let obfuscation_xor_rekey_packets =
                read_optional_u64("WG_OBFUSCATION_XOR_REKEY_PACKETS")?;
            let obfuscation_xor_rekey_secs = read_optional_u64("WG_OBFUSCATION_XOR_REKEY_SECS")?;
            let sizing_settings = WgPacketObfuscation::new(
                obfuscation_key.clone().into_bytes(),
                obfuscation_magic_byte,
            )
            .map_err(|e| ConfigError::InvalidWireGuardObfuscationSizing {
                var: "WG_OBFUSCATION_KEY",
                message: e.to_string(),
            })?
            .with_encryption_mode(obfuscation_encryption_mode)
            .with_padding(obfuscation_padding.clone())
            .with_magic_position(obfuscation_magic_position)
            .with_xor_rekey(XorRekeyPolicy::new(
                obfuscation_xor_rekey_packets,
                obfuscation_xor_rekey_secs,
            ))
            .with_replay_protection(obfuscation_replay_protection);
            (
                obfuscation_key,
                obfuscation_encryption_mode,
                obfuscation_replay_protection,
                obfuscation_magic_byte,
                obfuscation_padding,
                obfuscation_magic_position,
                obfuscation_xor_rekey_packets,
                obfuscation_xor_rekey_secs,
                Some(sizing_settings),
            )
        } else {
            (
                String::new(),
                EncryptionMode::Xor,
                false,
                None,
                PacketPadding::None,
                crate::wg_packet_obfuscation::MagicPositionMode::Fixed,
                None,
                None,
                None,
            )
        };
        let default_max_datagram_bytes =
            default_obfuscation_max_datagram_bytes(sizing_settings.as_ref())?;
        let obfuscation_max_datagram_bytes = read_optional_bounded_usize(
            "WG_OBFUSCATION_MAX_DATAGRAM_BYTES",
            1,
            MAX_WIREGUARD_DATAGRAM_BYTES,
        )?
        .unwrap_or(default_max_datagram_bytes);

        Ok(Self {
            port: read_port("WG_PORT", 443),
            internal_port: read_port("WG_INTERNAL_PORT", 51820),
            interface: std::env::var("WG_INTERFACE").ok().filter(|s| !s.is_empty()),
            drop_udp_443: read_bool("WG_DROP_UDP_443", true),
            obfuscation_enabled,
            obfuscation_key: obfuscation_key.into_bytes(),
            obfuscation_magic_byte,
            obfuscation_session_idle_secs: read_u64("WG_OBFUSCATION_SESSION_IDLE_SECS", 300).max(1),
            obfuscation_encryption_mode,
            obfuscation_padding,
            obfuscation_magic_position,
            obfuscation_replay_protection,
            obfuscation_xor_rekey_packets,
            obfuscation_xor_rekey_secs,
            obfuscation_max_datagram_bytes,
            udp_socket_buffer_bytes: read_bounded_usize(
                "WG_UDP_SOCKET_BUFFER_BYTES",
                DEFAULT_WIREGUARD_UDP_SOCKET_BUFFER_BYTES,
                1,
                usize::MAX,
            )?,
        })
    }

    pub fn packet_obfuscation(&self) -> Result<WgPacketObfuscation, WgPacketObfuscationError> {
        let result = WgPacketObfuscation::new(self.obfuscation_key.clone(), self.obfuscation_magic_byte)?
            .with_encryption_mode(self.obfuscation_encryption_mode)
            .with_padding(self.obfuscation_padding.clone())
            .with_magic_position(self.obfuscation_magic_position)
            .with_xor_rekey(XorRekeyPolicy::new(
                self.obfuscation_xor_rekey_packets,
                self.obfuscation_xor_rekey_secs,
            ))
            .with_replay_protection(self.obfuscation_replay_protection);
        Ok(result)
    }
}

pub(super) fn default_obfuscation_max_datagram_bytes(
    settings: Option<&WgPacketObfuscation>,
) -> Result<usize, ConfigError> {
    let wg_mtu = read_optional_usize("WG_MTU")
        .unwrap_or(DEFAULT_WIREGUARD_PATH_MTU_BYTES)
        .clamp(1, MAX_WIREGUARD_DATAGRAM_BYTES);
    default_obfuscation_max_datagram_bytes_for_mtu(wg_mtu, settings)
}

pub(super) fn default_obfuscation_max_datagram_bytes_for_mtu(
    wg_mtu: usize,
    settings: Option<&WgPacketObfuscation>,
) -> Result<usize, ConfigError> {
    let Some(settings) = settings else {
        return Ok(max_wireguard_transport_packet_bytes(wg_mtu));
    };
    let plaintext_datagram_len = max_wireguard_transport_packet_bytes(wg_mtu);

    let bytes = match encoded_packet_len_bounds(plaintext_datagram_len, settings) {
        Ok(bounds) => bounds.max_encoded_len,
        Err(err) => match &settings.padding {
            PacketPadding::FixedMtu(mtu) => *mtu,
            PacketPadding::RandomBucket(mtus) => mtus.iter().copied().max().unwrap_or(wg_mtu),
            PacketPadding::None | PacketPadding::PowerOfTwo => {
                return Err(ConfigError::InvalidWireGuardObfuscationSizing {
                    var: "WG_OBFUSCATION_MAX_DATAGRAM_BYTES",
                    message: format!(
                        "cannot derive default for WG_MTU={wg_mtu} (WireGuard transport packet bytes {plaintext_datagram_len}) and padding {:?}: {err}",
                        settings.padding
                    ),
                });
            }
        },
    };
    Ok(bytes.clamp(1, MAX_WIREGUARD_DATAGRAM_BYTES))
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
    pub(super) fn from_env() -> Self {
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
pub(super) fn build_domain_map(enabled_profiles: &[String]) -> HashMap<String, Profile> {
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
pub(super) fn read_port(var: &str, default: u16) -> u16 {
    std::env::var(var)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
}

/// Read an environment variable as `u64`, falling back to `default` on absence or parse failure.
pub(super) fn read_u64(var: &str, default: u64) -> u64 {
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
pub(super) fn read_usize(var: &str, default: usize) -> usize {
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
pub(super) fn read_bool(var: &str, default: bool) -> bool {
    std::env::var(var)
        .map(|v| match v.to_ascii_lowercase().as_str() {
            "true" | "1" | "yes" | "on" => true,
            "false" | "0" | "no" | "off" => false,
            _ => default,
        })
        .unwrap_or(default)
}

pub(super) fn read_csv_list(var: &str, default: &[&str]) -> Vec<String> {
    std::env::var(var)
        .ok()
        .map(|value| {
            value
                .split(',')
                .map(|part| part.trim().to_string())
                .filter(|part| !part.is_empty())
                .collect::<Vec<_>>()
        })
        .filter(|values| !values.is_empty())
        .unwrap_or_else(|| default.iter().map(|value| (*value).to_string()).collect())
}
