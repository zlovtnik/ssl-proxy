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

fn read_optional_u64(var: &'static str) -> Result<Option<u64>, ConfigError> {
    let Some(raw) = std::env::var(var).ok() else {
        return Ok(None);
    };
    let value = raw.trim();
    if value.is_empty() {
        return Ok(None);
    }

    let parsed = value.parse::<u64>().map_err(|_| {
        ConfigError::InvalidWireGuardObfuscationXorRekeyValue {
            var,
            value: raw.clone(),
        }
    })?;
    if parsed == 0 {
        return Err(ConfigError::InvalidWireGuardObfuscationXorRekeyValue { var, value: raw });
    }

    Ok(Some(parsed))
}

fn read_wireguard_obfuscation_encryption_mode(var: &str) -> Result<EncryptionMode, ConfigError> {
    let Some(raw) = std::env::var(var)
        .ok()
        .map(|value| value.trim().to_ascii_lowercase())
        .filter(|value| !value.is_empty())
    else {
        return Ok(EncryptionMode::Xor);
    };

    match raw.as_str() {
        "xor" => Ok(EncryptionMode::Xor),
        "aead" | "xchacha20-poly1305" | "xchacha20poly1305" => Ok(EncryptionMode::Aead),
        _ => Err(ConfigError::InvalidWireGuardObfuscationEncryptionMode(raw)),
    }
}

fn read_wireguard_obfuscation_padding(var: &str) -> Result<PacketPadding, ConfigError> {
    let Some(raw) = std::env::var(var)
        .ok()
        .map(|value| value.trim().to_ascii_lowercase())
        .filter(|value| !value.is_empty())
    else {
        return Ok(PacketPadding::None);
    };

    match raw.as_str() {
        "none" | "off" | "false" => Ok(PacketPadding::None),
        "power-of-two" | "power_of_two" | "pow2" => Ok(PacketPadding::PowerOfTwo),
        _ => raw
            .strip_prefix("fixed-mtu:")
            .or_else(|| raw.strip_prefix("fixed_mtu:"))
            .or_else(|| raw.strip_prefix("fixed:"))
            .and_then(|value| value.parse::<usize>().ok())
            .filter(|value| *value > 0)
            .map(PacketPadding::FixedMtu)
            .ok_or(ConfigError::InvalidWireGuardObfuscationPadding(raw)),
    }
}

fn read_wireguard_obfuscation_magic_position(var: &str) -> Result<MagicPositionMode, ConfigError> {
    let Some(raw) = std::env::var(var)
        .ok()
        .map(|value| value.trim().to_ascii_lowercase())
        .filter(|value| !value.is_empty())
    else {
        return Ok(MagicPositionMode::Fixed);
    };

    match raw.as_str() {
        "fixed" => Ok(MagicPositionMode::Fixed),
        "randomized" | "randomised" | "random" => Ok(MagicPositionMode::Randomized),
        _ => Err(ConfigError::InvalidWireGuardObfuscationMagicPosition(raw)),
    }
}
