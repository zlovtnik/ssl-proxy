fn parse_config(path: &Path) -> Result<DeviceConfig, ControlError> {
    let contents = fs::read_to_string(path).map_err(|source| ControlError::ReadConfig {
        path: path.to_path_buf(),
        source,
    })?;
    let mut device = DeviceConfig::default();
    let mut section = String::new();
    let mut current_peer: Option<PeerConfig> = None;

    for raw_line in contents.lines() {
        let line = raw_line
            .split_once('#')
            .map(|(before, _)| before)
            .unwrap_or(raw_line)
            .trim();
        if line.is_empty() {
            continue;
        }
        if line.starts_with('[') && line.ends_with(']') {
            if line.eq_ignore_ascii_case("[Peer]") {
                if let Some(peer) = current_peer.take() {
                    device.peers.push(peer);
                }
                current_peer = Some(PeerConfig::default());
                section.clear();
                section.push_str("peer");
            } else if line.eq_ignore_ascii_case("[Interface]") {
                if let Some(peer) = current_peer.take() {
                    device.peers.push(peer);
                }
                section.clear();
                section.push_str("interface");
            } else {
                section.clear();
            }
            continue;
        }
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        let key = key.trim();
        let value = value.trim();
        match section.as_str() {
            "interface" => match key {
                "PrivateKey" => device.interface.private_key = value.to_string(),
                "ListenPort" => {
                    device.interface.listen_port =
                        Some(parse_u16_config_field("Interface.ListenPort", value)?)
                }
                "FwMark" => device.interface.fwmark = Some(value.to_string()),
                "Address" => device
                    .interface
                    .addresses
                    .extend(split_csv(value).map(ToString::to_string)),
                "MTU" => {
                    device.interface.mtu = Some(parse_u16_config_field("Interface.MTU", value)?)
                }
                _ => {}
            },
            "peer" => {
                let peer = current_peer.as_mut().ok_or_else(|| {
                    ControlError::InvalidConfig("peer section state lost while parsing".to_string())
                })?;
                match key {
                    "PublicKey" => peer.public_key = value.to_string(),
                    "PresharedKey" => peer.preshared_key = Some(value.to_string()),
                    "Endpoint" => peer.endpoint = Some(value.to_string()),
                    "AllowedIPs" => {
                        peer.allowed_ips
                            .extend(split_csv(value).map(ToString::to_string));
                    }
                    "PersistentKeepalive" => {
                        peer.persistent_keepalive =
                            Some(parse_u16_config_field("Peer.PersistentKeepalive", value)?)
                    }
                    _ => {}
                }
            }
            _ => {}
        }
    }
    if let Some(peer) = current_peer.take() {
        device.peers.push(peer);
    }

    if device.interface.private_key.is_empty() {
        return Err(ControlError::InvalidConfig(
            "missing Interface.PrivateKey".to_string(),
        ));
    }
    for (idx, peer) in device.peers.iter().enumerate() {
        if peer.public_key.is_empty() {
            return Err(ControlError::InvalidConfig(format!(
                "peer {} is missing PublicKey",
                idx + 1
            )));
        }
    }

    Ok(device)
}

fn parse_u16_config_field(field_name: &str, value: &str) -> Result<u16, ControlError> {
    value.parse::<u16>().map_err(|error| {
        ControlError::InvalidConfig(format!("invalid {field_name} value {value:?}: {error}"))
    })
}

fn split_csv(value: &str) -> impl Iterator<Item = &str> {
    value
        .split(',')
        .map(str::trim)
        .filter(|entry| !entry.is_empty())
}

fn send_uapi_request(interface: &str, request: &str) -> Result<String, ControlError> {
    let path = uapi_socket_path(interface);
    validate_uapi_socket_dir(&path)?;
    let mut stream = UnixStream::connect(&path).map_err(|source| ControlError::ConnectSocket {
        path: path.clone(),
        source,
    })?;
    stream
        .set_read_timeout(Some(Duration::from_secs(3)))
        .map_err(|source| ControlError::SocketIo {
            path: path.clone(),
            source,
        })?;
    stream
        .set_write_timeout(Some(Duration::from_secs(3)))
        .map_err(|source| ControlError::SocketIo {
            path: path.clone(),
            source,
        })?;
    stream
        .write_all(request.as_bytes())
        .map_err(|source| ControlError::SocketIo {
            path: path.clone(),
            source,
        })?;
    stream.flush().map_err(|source| ControlError::SocketIo {
        path: path.clone(),
        source,
    })?;
    stream
        .shutdown(std::net::Shutdown::Write)
        .map_err(|source| ControlError::SocketIo {
            path: path.clone(),
            source,
        })?;
    read_uapi_response(&mut stream, &path)
}

fn validate_uapi_socket_dir(path: &Path) -> Result<(), ControlError> {
    let Some(parent) = path.parent() else {
        return Err(ControlError::SocketPathHasNoParent {
            path: path.to_path_buf(),
        });
    };

    validate_uapi_socket_parent(parent)?;
    let canonical_path =
        fs::canonicalize(path).map_err(|source| ControlError::UapiSocketPathCanonicalize {
            path: path.to_path_buf(),
            source,
        })?;
    let Some(canonical_parent) = canonical_path.parent() else {
        return Err(ControlError::SocketPathHasNoParent {
            path: canonical_path,
        });
    };
    validate_uapi_socket_parent(canonical_parent)
}

fn validate_uapi_socket_parent(parent: &Path) -> Result<(), ControlError> {
    let metadata = fs::metadata(parent).map_err(|source| ControlError::UapiSocketDirStat {
        path: parent.to_path_buf(),
        source,
    })?;
    let uid = metadata.uid();
    let mode = metadata.mode() & 0o777;
    if uid != 0 || mode != 0o700 {
        return Err(ControlError::InsecureUapiSocketDir {
            path: parent.to_path_buf(),
            uid,
            mode,
        });
    }
    Ok(())
}

fn read_uapi_response<R: Read>(reader: &mut R, path: &Path) -> Result<String, ControlError> {
    let mut response = Vec::new();
    let mut buffer = [0u8; 4096];

    loop {
        match reader.read(&mut buffer) {
            Ok(0) => break,
            Ok(read) => response.extend_from_slice(&buffer[..read]),
            Err(source) if source.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(source) => {
                return Err(ControlError::SocketIo {
                    path: path.to_path_buf(),
                    source,
                })
            }
        }
    }

    String::from_utf8(response).map_err(|source| ControlError::SocketIo {
        path: path.to_path_buf(),
        source: std::io::Error::new(std::io::ErrorKind::InvalidData, source),
    })
}

fn ensure_uapi_success(response: &str) -> Result<(), ControlError> {
    let errno = response
        .lines()
        .find_map(|line| line.strip_prefix("errno="))
        .unwrap_or("0");
    match errno.trim().parse::<i32>() {
        Ok(0) => Ok(()),
        Ok(code) => Err(ControlError::Uapi(format!("errno={code}"))),
        Err(_) => Err(ControlError::Uapi(response.trim().to_string())),
    }
}

fn uapi_socket_path(interface: &str) -> PathBuf {
    let socket_dir =
        std::env::var("WG_UAPI_SOCKET_DIR").unwrap_or_else(|_| DEFAULT_UAPI_DIR.to_string());
    Path::new(&socket_dir).join(format!("{interface}.sock"))
}

fn base64_key_to_hex(input: &str) -> Result<String, ControlError> {
    Ok(encode_hex(&decode_base64_32(input)?))
}

fn hex_key_to_base64(input: &str) -> Result<String, ControlError> {
    Ok(encode_base64(&decode_hex_32(input)?))
}

fn decode_base64_32(input: &str) -> Result<[u8; 32], ControlError> {
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(input.trim())
        .map_err(|err| ControlError::InvalidKey(err.to_string()))?;
    decoded
        .as_slice()
        .try_into()
        .map_err(|_| ControlError::InvalidKey("expected a 32-byte key".to_string()))
}

fn decode_hex_32(input: &str) -> Result<[u8; 32], ControlError> {
    let value = input.trim();
    if value.len() != 64 {
        return Err(ControlError::InvalidKey(format!(
            "expected 64 hex characters, got {}",
            value.len()
        )));
    }
    let mut bytes = [0u8; 32];
    for (idx, chunk) in value.as_bytes().chunks(2).enumerate() {
        let high = decode_hex_nibble(chunk[0])?;
        let low = decode_hex_nibble(chunk[1])?;
        bytes[idx] = (high << 4) | low;
    }
    Ok(bytes)
}

fn decode_hex_nibble(byte: u8) -> Result<u8, ControlError> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        b'A'..=b'F' => Ok(byte - b'A' + 10),
        _ => Err(ControlError::InvalidKey(format!(
            "invalid hex digit {:?}",
            byte as char
        ))),
    }
}

fn encode_base64(bytes: &[u8; 32]) -> String {
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

fn encode_hex(bytes: &[u8; 32]) -> String {
    let mut output = String::with_capacity(64);
    for byte in bytes {
        use fmt::Write as _;
        let _ = write!(&mut output, "{byte:02x}");
    }
    output
}
