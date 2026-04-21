//! Native BoringTun userspace control helpers and CLI plumbing.

use std::{
    fmt, fs,
    io::{Read, Write},
    os::unix::{fs::MetadataExt, net::UnixStream},
    path::{Path, PathBuf},
    time::{Duration, UNIX_EPOCH},
};

use base64::Engine;
use rand_core::OsRng;
use thiserror::Error;
use x25519_dalek::{PublicKey, StaticSecret};

const DEFAULT_UAPI_DIR: &str = "/var/run/wireguard";

#[derive(Debug, Error)]
pub enum ControlError {
    #[error("{0}")]
    Usage(String),
    #[error("failed to read config {path}: {source}")]
    ReadConfig {
        path: PathBuf,
        source: std::io::Error,
    },
    #[error("invalid config: {0}")]
    InvalidConfig(String),
    #[error("invalid base64 key: {0}")]
    InvalidKey(String),
    #[error("failed to connect to BoringTun UAPI socket {path}: {source}")]
    ConnectSocket {
        path: PathBuf,
        source: std::io::Error,
    },
    #[error("failed to inspect BoringTun UAPI socket directory {path}: {source}")]
    UapiSocketDirStat {
        path: PathBuf,
        source: std::io::Error,
    },
    #[error(
        "insecure BoringTun UAPI socket directory {path}: owner must be root and permissions must be 0700 (uid={uid}, mode={mode:o})"
    )]
    InsecureUapiSocketDir { path: PathBuf, uid: u32, mode: u32 },
    #[error("BoringTun UAPI socket path has no parent directory: {path}")]
    SocketPathHasNoParent { path: PathBuf },
    #[error("failed to communicate with BoringTun UAPI socket {path}: {source}")]
    SocketIo {
        path: PathBuf,
        source: std::io::Error,
    },
    #[error("BoringTun UAPI request failed: {0}")]
    Uapi(String),
}

#[derive(Clone, Debug, Default)]
struct InterfaceConfig {
    private_key: String,
    listen_port: Option<u16>,
    fwmark: Option<String>,
    mtu: Option<u16>,
    addresses: Vec<String>,
}

#[derive(Clone, Debug, Default)]
struct PeerConfig {
    public_key: String,
    preshared_key: Option<String>,
    endpoint: Option<String>,
    allowed_ips: Vec<String>,
    persistent_keepalive: Option<u16>,
}

#[derive(Clone, Debug, Default)]
struct DeviceConfig {
    interface: InterfaceConfig,
    peers: Vec<PeerConfig>,
}

#[derive(Clone, Debug, Default)]
struct RuntimePeer {
    public_key: String,
    preshared_key: Option<String>,
    endpoint: Option<String>,
    allowed_ips: Vec<String>,
    latest_handshake_sec: Option<u64>,
    rx_bytes: u64,
    tx_bytes: u64,
    persistent_keepalive: Option<u16>,
}

#[derive(Clone, Debug, Default)]
struct RuntimeDevice {
    private_key: Option<String>,
    public_key: Option<String>,
    listen_port: Option<u16>,
    fwmark: Option<String>,
    peers: Vec<RuntimePeer>,
}

pub fn generate_private_key_base64() -> Result<String, ControlError> {
    let secret = StaticSecret::random_from_rng(OsRng);
    Ok(encode_base64(&secret.to_bytes()))
}

pub fn public_key_from_private_base64(private_key: &str) -> Result<String, ControlError> {
    let secret = StaticSecret::from(decode_base64_32(private_key)?);
    Ok(encode_base64(PublicKey::from(&secret).as_bytes()))
}

pub fn apply_config(interface: &str, config_path: &Path) -> Result<(), ControlError> {
    let config = parse_config(config_path)?;
    let request = build_set_request(&config)?;
    let response = send_uapi_request(interface, &request)?;
    ensure_uapi_success(&response)
}

pub fn show_interface(interface: &str) -> Result<String, ControlError> {
    let device = get_device(interface)?;
    Ok(render_show(interface, &device))
}

pub fn dump_interface(interface: &str) -> Result<String, ControlError> {
    let device = get_device(interface)?;
    Ok(render_dump(&device))
}

fn get_device(interface: &str) -> Result<RuntimeDevice, ControlError> {
    let response = send_uapi_request(interface, "get=1\n\n")?;
    ensure_uapi_success(&response)?;
    parse_get_response(&response)
}

fn render_show(interface: &str, device: &RuntimeDevice) -> String {
    let mut output = String::new();
    output.push_str(&format!("interface: {interface}\n"));
    if let Some(public_key) = device.public_key.as_ref().cloned().or_else(|| {
        device
            .private_key
            .as_ref()
            .and_then(|key| public_key_from_private_base64(key).ok())
    }) {
        output.push_str(&format!("  public key: {public_key}\n"));
    }
    if let Some(listen_port) = device.listen_port {
        output.push_str(&format!("  listening port: {listen_port}\n"));
    }
    if let Some(fwmark) = &device.fwmark {
        output.push_str(&format!("  fwmark: {fwmark}\n"));
    }
    if !device.peers.is_empty() {
        output.push('\n');
    }
    for (idx, peer) in device.peers.iter().enumerate() {
        output.push_str(&format!("peer: {}\n", peer.public_key));
        if let Some(endpoint) = &peer.endpoint {
            output.push_str(&format!("  endpoint: {endpoint}\n"));
        }
        if !peer.allowed_ips.is_empty() {
            output.push_str(&format!("  allowed ips: {}\n", peer.allowed_ips.join(", ")));
        }
        output.push_str(&format!(
            "  latest handshake: {}\n",
            peer.latest_handshake_sec
                .and_then(format_unix_timestamp)
                .unwrap_or_else(|| "never".to_string())
        ));
        output.push_str(&format!(
            "  transfer: {} received, {} sent\n",
            format_bytes(peer.rx_bytes),
            format_bytes(peer.tx_bytes)
        ));
        if let Some(interval) = peer.persistent_keepalive {
            output.push_str(&format!(
                "  persistent keepalive: every {interval} seconds\n"
            ));
        }
        if idx + 1 != device.peers.len() {
            output.push('\n');
        }
    }
    output
}

fn render_dump(device: &RuntimeDevice) -> String {
    let private_key = device.private_key.clone().unwrap_or_default();
    let public_key = device
        .public_key
        .clone()
        .or_else(|| {
            device
                .private_key
                .as_ref()
                .and_then(|key| public_key_from_private_base64(key).ok())
        })
        .unwrap_or_default();
    let listen_port = device
        .listen_port
        .map(|port| port.to_string())
        .unwrap_or_else(|| "0".to_string());
    let fwmark = device.fwmark.clone().unwrap_or_else(|| "off".to_string());
    let mut output = format!("{private_key}\t{public_key}\t{listen_port}\t{fwmark}\n");
    for peer in &device.peers {
        output.push_str(&format!(
            "{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\n",
            peer.public_key,
            peer.preshared_key.clone().unwrap_or_default(),
            peer.endpoint.clone().unwrap_or_default(),
            peer.allowed_ips.join(","),
            peer.latest_handshake_sec.unwrap_or(0),
            peer.rx_bytes,
            peer.tx_bytes,
            peer.persistent_keepalive.unwrap_or(0)
        ));
    }
    output
}

fn format_bytes(bytes: u64) -> String {
    const UNITS: [&str; 5] = ["B", "KiB", "MiB", "GiB", "TiB"];
    let mut value = bytes as f64;
    let mut unit = UNITS[0];
    for candidate in UNITS {
        unit = candidate;
        if value < 1024.0 || candidate == UNITS[UNITS.len() - 1] {
            break;
        }
        value /= 1024.0;
    }
    if unit == "B" {
        format!("{bytes} B")
    } else {
        format!("{value:.2} {unit}")
    }
}

fn format_unix_timestamp(epoch: u64) -> Option<String> {
    let timestamp = UNIX_EPOCH.checked_add(Duration::from_secs(epoch))?;
    let datetime: chrono::DateTime<chrono::Utc> = timestamp.into();
    Some(datetime.to_rfc3339())
}

fn parse_get_response(response: &str) -> Result<RuntimeDevice, ControlError> {
    let mut device = RuntimeDevice::default();
    let mut current_peer: Option<RuntimePeer> = None;
    for line in response.lines() {
        if line.is_empty() {
            continue;
        }
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        match key {
            "errno" => {}
            "private_key" => {
                device.private_key = Some(hex_key_to_base64(value)?);
            }
            "listen_port" => {
                device.listen_port = value.parse::<u16>().ok();
            }
            "fwmark" => {
                if value != "0" && !value.eq_ignore_ascii_case("off") {
                    device.fwmark = Some(value.to_string());
                }
            }
            "public_key" => {
                let decoded = hex_key_to_base64(value)?;
                if let Some(finished) = current_peer.replace(RuntimePeer {
                    public_key: decoded,
                    ..RuntimePeer::default()
                }) {
                    if !finished.public_key.is_empty() {
                        device.peers.push(finished);
                    }
                }
            }
            "preshared_key" => {
                if !value.is_empty() && !value.chars().all(|ch| ch == '0') {
                    if let Some(peer) = current_peer.as_mut() {
                        peer.preshared_key = Some(hex_key_to_base64(value)?);
                    }
                }
            }
            "endpoint" => {
                if let Some(peer) = current_peer.as_mut() {
                    if !value.is_empty() {
                        peer.endpoint = Some(value.to_string());
                    }
                }
            }
            "allowed_ip" => {
                if let Some(peer) = current_peer.as_mut() {
                    peer.allowed_ips.push(value.to_string());
                }
            }
            "last_handshake_time_sec" => {
                if let Some(peer) = current_peer.as_mut() {
                    peer.latest_handshake_sec = value.parse::<u64>().ok().filter(|v| *v > 0);
                }
            }
            "rx_bytes" => {
                if let Some(peer) = current_peer.as_mut() {
                    peer.rx_bytes = value.parse::<u64>().unwrap_or(0);
                }
            }
            "tx_bytes" => {
                if let Some(peer) = current_peer.as_mut() {
                    peer.tx_bytes = value.parse::<u64>().unwrap_or(0);
                }
            }
            "persistent_keepalive_interval" => {
                if let Some(peer) = current_peer.as_mut() {
                    peer.persistent_keepalive = value.parse::<u16>().ok().filter(|v| *v > 0);
                }
            }
            _ => {}
        }
    }
    if let Some(peer) = current_peer.take() {
        if !peer.public_key.is_empty() {
            device.peers.push(peer);
        }
    }
    Ok(device)
}

fn build_set_request(config: &DeviceConfig) -> Result<String, ControlError> {
    let mut request = String::from("set=1\n");
    request.push_str(&format!(
        "private_key={}\n",
        base64_key_to_hex(&config.interface.private_key)?
    ));
    if let Some(listen_port) = config.interface.listen_port {
        request.push_str(&format!("listen_port={listen_port}\n"));
    }
    if let Some(fwmark) = &config.interface.fwmark {
        request.push_str(&format!("fwmark={fwmark}\n"));
    }
    request.push_str("replace_peers=true\n");
    for peer in &config.peers {
        request.push_str(&format!(
            "public_key={}\n",
            base64_key_to_hex(&peer.public_key)?
        ));
        request.push_str("replace_allowed_ips=true\n");
        if let Some(preshared_key) = &peer.preshared_key {
            request.push_str(&format!(
                "preshared_key={}\n",
                base64_key_to_hex(preshared_key)?
            ));
        }
        if let Some(endpoint) = &peer.endpoint {
            request.push_str(&format!("endpoint={endpoint}\n"));
        }
        if let Some(keepalive) = peer.persistent_keepalive {
            request.push_str(&format!("persistent_keepalive_interval={keepalive}\n"));
        }
        for allowed_ip in &peer.allowed_ips {
            request.push_str(&format!("allowed_ip={allowed_ip}\n"));
        }
    }
    request.push('\n');
    Ok(request)
}

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
                "ListenPort" => device.interface.listen_port = value.parse::<u16>().ok(),
                "FwMark" => device.interface.fwmark = Some(value.to_string()),
                "Address" => device
                    .interface
                    .addresses
                    .extend(split_csv(value).map(ToString::to_string)),
                "MTU" => device.interface.mtu = value.parse::<u16>().ok(),
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
                    "PersistentKeepalive" => peer.persistent_keepalive = value.parse::<u16>().ok(),
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::{io, path::Path};

    #[test]
    fn private_key_generation_round_trips_to_public_key() {
        let private_key = generate_private_key_base64().expect("private key should generate");
        let public_key =
            public_key_from_private_base64(&private_key).expect("public key should derive");

        assert_eq!(decode_base64_32(&private_key).unwrap().len(), 32);
        assert_eq!(decode_base64_32(&public_key).unwrap().len(), 32);
    }

    #[test]
    fn parses_wireguard_style_config_for_boringtun_control() {
        let tempdir = tempfile::tempdir().unwrap();
        let config_path = tempdir.path().join("wg0.conf");
        fs::write(
            &config_path,
            "[Interface]\nAddress = 10.13.13.1/24\nListenPort = 51820\nPrivateKey = eHz8Gu9Uhp8Zqc+nEDp98kVxKlznPAouR4VLr5J6jGs=\nMTU = 1280\nPostUp = ignored\n\n[Peer]\nPublicKey = RMG56qSaFhNYkZVoizYm9g4pqSRZ+EQYkLhxGUtCeQw=\nPresharedKey = JiSXAaw54GnEjuwO9RUCbumIJI/Jb7oBCEibn3KTHo0=\nEndpoint = 192.0.2.10:443\nAllowedIPs = 10.13.13.2/32, 10.13.13.3/32\nPersistentKeepalive = 25\n",
        )
        .unwrap();

        let parsed = parse_config(&config_path).expect("config should parse");
        assert_eq!(parsed.interface.listen_port, Some(51820));
        assert_eq!(parsed.interface.addresses, vec!["10.13.13.1/24"]);
        assert_eq!(parsed.peers.len(), 1);
        assert_eq!(
            parsed.peers[0].allowed_ips,
            vec!["10.13.13.2/32", "10.13.13.3/32"]
        );
    }

    #[test]
    fn render_dump_matches_wg_dump_shape() {
        let dump = render_dump(&RuntimeDevice {
            private_key: Some("private".to_string()),
            public_key: Some("public".to_string()),
            listen_port: Some(51820),
            fwmark: None,
            peers: vec![RuntimePeer {
                public_key: "peer".to_string(),
                preshared_key: Some("psk".to_string()),
                endpoint: Some("198.51.100.10:443".to_string()),
                allowed_ips: vec!["10.13.13.2/32".to_string()],
                latest_handshake_sec: Some(1713225600),
                rx_bytes: 10,
                tx_bytes: 20,
                persistent_keepalive: Some(25),
            }],
        });

        let lines: Vec<_> = dump.lines().collect();
        assert_eq!(lines.len(), 2);
        assert_eq!(lines[0], "private\tpublic\t51820\toff");
        assert_eq!(
            lines[1],
            "peer\tpsk\t198.51.100.10:443\t10.13.13.2/32\t1713225600\t10\t20\t25"
        );
    }

    #[test]
    fn uapi_socket_directory_validation_rejects_non_root_owner() {
        let tempdir = tempfile::tempdir().unwrap();
        let socket_path = tempdir.path().join("wg0.sock");

        let err = validate_uapi_socket_dir(&socket_path).unwrap_err();

        assert!(matches!(err, ControlError::InsecureUapiSocketDir { .. }));
    }

    #[test]
    fn read_uapi_response_accumulates_partial_chunks() {
        struct ChunkedReader<'a> {
            data: &'a [u8],
            offset: usize,
            chunk_size: usize,
        }

        impl Read for ChunkedReader<'_> {
            fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
                if self.offset >= self.data.len() {
                    return Ok(0);
                }

                let len = self
                    .chunk_size
                    .min(buf.len())
                    .min(self.data.len() - self.offset);
                let end = self.offset + len;
                buf[..len].copy_from_slice(&self.data[self.offset..end]);
                self.offset = end;
                Ok(len)
            }
        }

        let mut reader = ChunkedReader {
            data: b"errno=0\ninterface=wg0\n\n",
            offset: 0,
            chunk_size: 3,
        };

        let response = read_uapi_response(&mut reader, Path::new("/tmp/wg0.sock"))
            .expect("chunked response should be preserved");

        assert_eq!(response, "errno=0\ninterface=wg0\n\n");
    }
}
