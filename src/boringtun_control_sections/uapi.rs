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
    #[error("failed to canonicalize BoringTun UAPI socket path {path}: {source}")]
    UapiSocketPathCanonicalize {
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
    Some(crate::time::rfc3339_from_system_time(timestamp))
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
                device.listen_port = Some(parse_u16_config_field("uapi.listen_port", value)?);
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
                    let keepalive =
                        parse_u16_config_field("uapi.persistent_keepalive_interval", value)?;
                    peer.persistent_keepalive = (keepalive > 0).then_some(keepalive);
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
