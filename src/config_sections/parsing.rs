use super::types::ConfigError;
use crate::wg_packet_obfuscation::{
    parse_magic_byte, EncryptionMode, MagicPositionMode, PacketPadding,
};
use std::path::Path;

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
pub(crate) fn read_secret(var: &str, file_var: &str) -> Option<String> {
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

pub(super) fn read_secret_strict_file(
    var: &str,
    file_var: &'static str,
) -> Result<Option<String>, ConfigError> {
    if let Some(secret) = std::env::var(var)
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
    {
        return Ok(Some(secret));
    }

    let file = std::env::var(file_var)
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty());
    let Some(file) = file else {
        return Ok(None);
    };

    let path = Path::new(&file);
    validate_secret_file(path, file_var)?;
    std::fs::read_to_string(path)
        .map(|s| s.trim().to_string())
        .map(|s| (!s.is_empty()).then_some(s))
        .map_err(|error| ConfigError::InvalidSecretFile {
            file_var,
            message: format!("failed to read {:?}: {error}", path.display()),
        })
}

#[cfg(unix)]
fn validate_secret_file(path: &Path, file_var: &'static str) -> Result<(), ConfigError> {
    use std::os::unix::fs::MetadataExt;

    let metadata = std::fs::metadata(path).map_err(|error| ConfigError::InvalidSecretFile {
        file_var,
        message: format!("failed to inspect {:?}: {error}", path.display()),
    })?;
    if !metadata.is_file() {
        return Err(ConfigError::InvalidSecretFile {
            file_var,
            message: format!("{:?} must be a regular file", path.display()),
        });
    }
    let mode = metadata.mode() & 0o777;
    if mode != 0o400 {
        return Err(ConfigError::InvalidSecretFile {
            file_var,
            message: format!("{:?} must have mode 0400; got {:04o}", path.display(), mode),
        });
    }

    // SAFETY: `geteuid` has no preconditions and only returns the current
    // process effective uid.
    let uid = unsafe { libc::geteuid() };
    if metadata.uid() != uid {
        return Err(ConfigError::InvalidSecretFile {
            file_var,
            message: format!(
                "{:?} must be owned by uid {}; got uid {}",
                path.display(),
                uid,
                metadata.uid()
            ),
        });
    }
    Ok(())
}

#[cfg(not(unix))]
fn validate_secret_file(_path: &Path, _file_var: &'static str) -> Result<(), ConfigError> {
    Ok(())
}

pub(super) fn read_magic_byte(var: &str) -> Result<Option<u8>, ConfigError> {
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

pub(super) fn read_optional_u64(var: &'static str) -> Result<Option<u64>, ConfigError> {
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

pub(super) fn read_wireguard_obfuscation_encryption_mode(
    var: &str,
) -> Result<EncryptionMode, ConfigError> {
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

pub(super) fn read_wireguard_obfuscation_padding(var: &str) -> Result<PacketPadding, ConfigError> {
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
            .or_else(|| {
                raw.strip_prefix("random-bucket:")
                    .or_else(|| raw.strip_prefix("random_bucket:"))
                    .or_else(|| raw.strip_prefix("bucket:"))
                    .and_then(parse_padding_bucket)
                    .map(PacketPadding::RandomBucket)
            })
            .ok_or(ConfigError::InvalidWireGuardObfuscationPadding(raw)),
    }
}

fn parse_padding_bucket(raw: &str) -> Option<Vec<usize>> {
    let values = raw
        .split(',')
        .map(str::trim)
        .map(str::parse::<usize>)
        .collect::<Result<Vec<_>, _>>()
        .ok()?;
    (!values.is_empty() && values.iter().all(|value| *value > 0)).then_some(values)
}

pub(super) fn read_wireguard_obfuscation_magic_position(
    var: &str,
) -> Result<MagicPositionMode, ConfigError> {
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
