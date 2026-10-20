//! Device-token hashing and runtime identity resolution.

use axum::http::HeaderMap;
use sha2::{Digest, Sha256};

use crate::state::{DeviceInfo, SharedState};

pub const DEVICE_TOKEN_HEADER: &str = "x-device-token";

#[derive(Clone, Debug, Default)]
pub struct ResolvedIdentity {
    pub peer_ip: Option<String>,
    pub wg_pubkey: Option<String>,
    pub device_id: Option<String>,
    pub identity_source: Option<String>,
    pub peer_hostname: Option<String>,
    pub client_ua: Option<String>,
    pub attribution_method: Option<String>,
    pub valid_from: Option<String>,
    pub valid_until: Option<String>,
}

impl ResolvedIdentity {
    pub(crate) fn evidence(&self) -> serde_json::Value {
        static SCOPE: std::sync::OnceLock<String> = std::sync::OnceLock::new();
        let scope = SCOPE.get_or_init(|| uuid::Uuid::new_v4().to_string());
        let peer_reference = self.wg_pubkey.as_ref().map(|key| {
            let encoded = serde_json::to_vec(&(scope, key)).unwrap_or_default();
            format!("{:x}", Sha256::digest(encoded))
        });
        serde_json::json!({"version": "proxy-attribution-v1", "method": self.attribution_method.as_deref().unwrap_or("unknown"),
            "valid_from": self.valid_from, "valid_until": self.valid_until,
            "mapping_revision": self.valid_from, "peer_reference": peer_reference,
            "reference_scope": "process_wireguard_peer", "reference_rotation": "process_restart_or_key_change",
            "reference_expiry": "process_lifetime",
            "ownership": "registration_claim_only"})
    }
}

pub fn mint_device_token() -> String {
    format!(
        "{}{}",
        uuid::Uuid::new_v4().simple(),
        uuid::Uuid::new_v4().simple()
    )
}

pub fn hash_device_token(token: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(token.as_bytes());
    let digest = hasher.finalize();
    digest.iter().map(|byte| format!("{byte:02x}")).collect()
}

pub fn extract_device_token(headers: &HeaderMap) -> Option<String> {
    headers
        .get(DEVICE_TOKEN_HEADER)
        .and_then(|value| value.to_str().ok())
        .map(str::trim)
        .filter(|value| value.len() == 64)
        .map(|value| value.to_string())
}

pub fn extract_user_agent(headers: &HeaderMap) -> Option<String> {
    headers
        .get("user-agent")
        .and_then(|value| value.to_str().ok())
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(|value| truncate(value, 512))
}

pub fn resolve_identity(
    state: &SharedState,
    peer_ip: Option<String>,
    device_token: Option<String>,
    client_ua: Option<String>,
) -> ResolvedIdentity {
    let wg_pubkey = state.resolve_wg_pubkey(peer_ip.as_deref());
    let peer_hostname = peer_ip
        .as_deref()
        .and_then(|ip| state.ptr_cache.get(ip))
        .and_then(|entry| entry.ptr_hostname.clone());
    let mut resolved = ResolvedIdentity {
        peer_ip: peer_ip.clone(),
        wg_pubkey: wg_pubkey.clone(),
        device_id: None,
        identity_source: None,
        peer_hostname,
        client_ua: client_ua.map(|value| truncate(&value, 512)),
        attribution_method: None,
        valid_from: None,
        valid_until: None,
    };

    if let Some(token) = device_token {
        let hash = hash_device_token(&token);
        if let Some(device) =
            state.resolve_device_claim_token(&hash, wg_pubkey.as_deref(), peer_ip.as_deref())
        {
            resolved.device_id = Some(device.device_id.clone());
            resolved.identity_source = Some("registered".to_string());
            resolved.attribution_method = Some("device_token".into());
            if let Some(claim) = state.find_claim(wg_pubkey.as_deref(), peer_ip.as_deref()) {
                resolved.valid_from = Some(claim.claimed_at);
                resolved.valid_until = Some(claim.expires_at);
            }
            return resolved;
        }
    }

    if let Some(claim) = state.find_claim(wg_pubkey.as_deref(), peer_ip.as_deref()) {
        resolved.device_id = Some(claim.device_id);
        resolved.identity_source = Some("registered".to_string());
        resolved.attribution_method = Some("peer_claim".into());
        resolved.valid_from = Some(claim.claimed_at);
        resolved.valid_until = Some(claim.expires_at);
        return resolved;
    }

    resolved.identity_source =
        Some(
            if wg_pubkey.is_some()
                || resolved.peer_hostname.is_some()
                || resolved.client_ua.is_some()
            {
                "derived"
            } else {
                "unknown"
            }
            .to_string(),
        );
    resolved
}

pub fn truncate(value: &str, max_chars: usize) -> String {
    value.chars().take(max_chars).collect()
}

pub fn update_device_metadata(
    mut device: DeviceInfo,
    wg_pubkey: Option<&str>,
    client_ua: Option<&str>,
    peer_hostname: Option<&str>,
) -> DeviceInfo {
    if device.wg_pubkey.is_none() {
        device.wg_pubkey = wg_pubkey.map(|value| value.to_string());
    }
    if device.os_hint.is_none() {
        device.os_hint = client_ua.map(os_hint_from_user_agent);
    }
    if device.hostname.is_none() {
        device.hostname = peer_hostname.map(|value| value.to_string());
    }
    device.last_seen = crate::time::now_rfc3339();
    device
}

pub fn os_hint_from_user_agent(user_agent: &str) -> String {
    let ua = user_agent.to_ascii_lowercase();
    if ua.contains("iphone") || ua.contains("ipad") || ua.contains("ios") {
        "iOS".to_string()
    } else if ua.contains("android") {
        "Android".to_string()
    } else if ua.contains("windows") {
        "Windows".to_string()
    } else if ua.contains("mac os") || ua.contains("macintosh") {
        "macOS".to_string()
    } else if ua.contains("linux") {
        "Linux".to_string()
    } else {
        "Unknown".to_string()
    }
}
