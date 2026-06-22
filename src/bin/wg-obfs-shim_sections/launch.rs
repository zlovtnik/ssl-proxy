fn parse_optional_positive_u64(
    raw: Option<String>,
    label: &str,
) -> Result<Option<u64>, ConfigParseOutcome> {
    raw.map(|raw| {
        raw.parse::<u64>()
            .ok()
            .filter(|value| *value > 0)
            .ok_or_else(|| {
                ConfigParseOutcome::Error(format!(
                    "invalid {label} {raw:?}; expected positive integer"
                ))
            })
    })
    .transpose()
}

fn parse_optional_nonnegative_u64(
    raw: Option<String>,
    label: &str,
) -> Result<Option<u64>, ConfigParseOutcome> {
    raw.map(|raw| {
        raw.parse::<u64>().map_err(|_| {
            ConfigParseOutcome::Error(format!(
                "invalid {label} {raw:?}; expected non-negative integer"
            ))
        })
    })
    .transpose()
}

fn parse_optional_usize(
    raw: Option<String>,
    label: &str,
) -> Result<Option<usize>, ConfigParseOutcome> {
    raw.map(|raw| {
        raw.parse::<usize>()
            .ok()
            .filter(|value| *value > 0)
            .ok_or_else(|| {
                ConfigParseOutcome::Error(format!(
                    "invalid {label} {raw:?}; expected positive integer"
                ))
            })
    })
    .transpose()
}

fn parse_optional_duration_secs(
    raw: Option<String>,
    label: &str,
) -> Result<Option<Duration>, ConfigParseOutcome> {
    parse_optional_positive_u64(raw, label).map(|value| value.map(Duration::from_secs))
}

fn parse_optional_bool(
    raw: Option<String>,
    label: &str,
) -> Result<Option<bool>, ConfigParseOutcome> {
    raw.map(|raw| match raw.to_ascii_lowercase().as_str() {
        "true" | "1" | "yes" | "on" => Ok(true),
        "false" | "0" | "no" | "off" => Ok(false),
        _ => Err(ConfigParseOutcome::Error(format!(
            "invalid {label} {raw:?}; expected boolean"
        ))),
    })
    .transpose()
}

fn parse_encryption_mode(raw: Option<String>) -> Result<EncryptionMode, ConfigParseOutcome> {
    let Some(raw) = raw else {
        return Ok(EncryptionMode::Xor);
    };
    match raw.to_ascii_lowercase().as_str() {
        "xor" => Ok(EncryptionMode::Xor),
        "aead" | "xchacha20-poly1305" | "xchacha20poly1305" => Ok(EncryptionMode::Aead),
        _ => Err(ConfigParseOutcome::Error(format!(
            "invalid encryption mode {raw:?}; expected xor or aead"
        ))),
    }
}

fn parse_padding(raw: Option<String>) -> Result<PacketPadding, ConfigParseOutcome> {
    let Some(raw) = raw else {
        return Ok(PacketPadding::None);
    };
    let normalized = raw.to_ascii_lowercase();
    match normalized.as_str() {
        "none" | "off" | "false" => Ok(PacketPadding::None),
        "power-of-two" | "power_of_two" | "pow2" => Ok(PacketPadding::PowerOfTwo),
        _ => normalized
            .strip_prefix("fixed-mtu:")
            .or_else(|| normalized.strip_prefix("fixed_mtu:"))
            .or_else(|| normalized.strip_prefix("fixed:"))
            .and_then(|value| value.parse::<usize>().ok())
            .filter(|value| *value > 0)
            .map(PacketPadding::FixedMtu)
            .or_else(|| {
                normalized
                    .strip_prefix("random-bucket:")
                    .or_else(|| normalized.strip_prefix("random_bucket:"))
                    .or_else(|| normalized.strip_prefix("bucket:"))
                    .and_then(parse_padding_bucket)
                    .map(PacketPadding::RandomBucket)
            })
            .ok_or_else(|| {
                ConfigParseOutcome::Error(format!(
                    "invalid padding {raw:?}; expected none, power-of-two, fixed-mtu:N, or random-bucket:N,N"
                ))
            }),
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

fn parse_magic_position(raw: Option<String>) -> Result<MagicPositionMode, ConfigParseOutcome> {
    let Some(raw) = raw else {
        return Ok(MagicPositionMode::Fixed);
    };
    match raw.to_ascii_lowercase().as_str() {
        "fixed" => Ok(MagicPositionMode::Fixed),
        "randomized" | "randomised" | "random" => Ok(MagicPositionMode::Randomized),
        _ => Err(ConfigParseOutcome::Error(format!(
            "invalid magic position {raw:?}; expected fixed or randomized"
        ))),
    }
}

fn parse_rate_limit(options: &CliOptions) -> Result<Option<RateLimitConfig>, ConfigParseOutcome> {
    let pps = parse_optional_positive_u64(
        optional_value(&options.rate_limit_pps, "WG_OBFS_SHIM_RATE_LIMIT_PPS"),
        "rate limit pps",
    )?;
    let burst = parse_optional_positive_u64(
        optional_value(&options.rate_limit_burst, "WG_OBFS_SHIM_RATE_LIMIT_BURST"),
        "rate limit burst",
    )?;

    match (pps, burst) {
        (None, None) => Ok(None),
        (Some(pps), Some(burst)) => Ok(RateLimitConfig::new(pps, burst)),
        _ => Err(ConfigParseOutcome::Error(
            "rate limiting requires both packets per second and burst values".to_string(),
        )),
    }
}

fn load_key_from_values(
    key: Option<String>,
    key_file: Option<String>,
) -> Result<Option<String>, ConfigParseOutcome> {
    if let Some(key) = key.map(|value| value.trim().to_string()) {
        return Ok((!key.is_empty()).then_some(key));
    }

    if let Some(path) = key_file {
        return read_key_file(&path);
    }

    Ok(None)
}

fn load_key(options: &CliOptions) -> Result<Option<String>, ConfigParseOutcome> {
    if let Some(key) = options.key.as_ref().map(|value| value.trim().to_string()) {
        return Ok((!key.is_empty()).then_some(key));
    }

    if let Some(path) = options.key_file.as_ref() {
        return read_key_file(path);
    }

    if let Some(key) = std::env::var("WG_OBFUSCATION_KEY")
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
    {
        return Ok(Some(key));
    }

    if let Some(path) = std::env::var("WG_OBFUSCATION_KEY_FILE")
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
    {
        return read_key_file(&path);
    }

    Ok(None)
}

fn read_key_file(path: &str) -> Result<Option<String>, ConfigParseOutcome> {
    let path = Path::new(path);
    validate_key_file_permissions(path)?;
    std::fs::read_to_string(path)
        .map(|contents| contents.trim().to_string())
        .map(|contents| (!contents.is_empty()).then_some(contents))
        .map_err(|err| {
            ConfigParseOutcome::Error(format!(
                "failed to read obfuscation key file {:?}: {err}",
                path.display()
            ))
        })
}

#[cfg(unix)]
fn validate_key_file_permissions(path: &Path) -> Result<(), ConfigParseOutcome> {
    use std::os::unix::fs::MetadataExt;

    let metadata = std::fs::metadata(path).map_err(|err| {
        ConfigParseOutcome::Error(format!(
            "failed to inspect obfuscation key file {:?}: {err}",
            path.display()
        ))
    })?;
    let mode = metadata.mode() & 0o777;
    if mode != 0o400 {
        return Err(ConfigParseOutcome::Error(format!(
            "obfuscation key file {:?} must have mode 0400; got {:04o}",
            path.display(),
            mode
        )));
    }

    // SAFETY: `geteuid` takes no pointers and has no preconditions; it only
    // returns the effective uid for the current process.
    let uid = unsafe { libc::geteuid() };
    if metadata.uid() != uid {
        return Err(ConfigParseOutcome::Error(format!(
            "obfuscation key file {:?} must be owned by uid {}; got uid {}",
            path.display(),
            uid,
            metadata.uid()
        )));
    }
    Ok(())
}

#[cfg(not(unix))]
fn validate_key_file_permissions(_path: &Path) -> Result<(), ConfigParseOutcome> {
    Ok(())
}
