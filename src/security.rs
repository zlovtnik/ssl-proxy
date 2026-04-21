//! Security hardening helpers for control-plane protections.

use axum::http::HeaderMap;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{collections::HashMap, fs, io::Read, path::Path};

/// Status payload for patch-cadence checks consumed by admin endpoints.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PatchCadenceReport {
    pub generated_at: String,
    pub overdue_critical: u64,
    pub overdue_high: u64,
    pub overdue_medium: u64,
    pub sla_critical_hours: u64,
    pub sla_high_days: u64,
    pub sla_medium_days: u64,
}

/// Status payload for recovery-drill evidence consumed by admin endpoints.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecoveryDrillReport {
    pub generated_at: String,
    pub last_restore_drill_at: String,
    pub last_failover_drill_at: String,
    pub pass_rate_percent: f64,
    pub rto_met: bool,
    pub rpo_met: bool,
}

/// Returns true when any configured claim header indicates MFA.
pub fn has_required_mfa_claim(headers: &HeaderMap, claim_headers: &[String]) -> bool {
    claim_headers.iter().any(|name| {
        headers
            .get(name)
            .and_then(|v| v.to_str().ok())
            .map(|v| {
                let val = v.trim().to_ascii_lowercase();
                if val.is_empty() {
                    return false;
                }
                if val == "true" {
                    return true;
                }
                val.split(|c: char| c == ',' || c.is_ascii_whitespace())
                    .map(str::trim)
                    .any(|token| matches!(token, "mfa" | "otp" | "totp" | "hwk"))
            })
            .unwrap_or(false)
    })
}

/// Validate startup binary and config hashes against allowlisted SHA-256 values.
pub fn verify_startup_integrity() -> Result<(), String> {
    let expected_bin_hash = std::env::var("ALLOWED_BINARY_SHA256")
        .ok()
        .filter(|v| !v.trim().is_empty());
    let config_hashes_raw = std::env::var("ALLOWED_CONFIG_SHA256").unwrap_or_default();

    if let Some(expected) = expected_bin_hash {
        let exe = std::env::current_exe().map_err(|e| format!("resolve binary path: {e}"))?;
        let actual = sha256_file(&exe).map_err(|e| format!("hash binary: {e}"))?;
        if actual != expected.to_ascii_lowercase() {
            return Err(format!(
                "binary integrity mismatch: expected {expected}, got {actual}"
            ));
        }
    }

    let expected_cfg_hashes = parse_expected_config_hashes(&config_hashes_raw)?;
    if !expected_cfg_hashes.is_empty() {
        let paths = std::env::var("INTEGRITY_CONFIG_PATHS")
            .unwrap_or_else(|_| "config/templates/server.conf,config/templates/peer.conf".into());
        let config_paths: Vec<&str> = paths
            .split(',')
            .map(|s| s.trim())
            .filter(|s| !s.is_empty())
            .collect();

        for path in config_paths {
            let filename = Path::new(path)
                .file_name()
                .and_then(|name| name.to_str())
                .ok_or_else(|| format!("unable to derive config filename for {path}"))?;
            let expected = expected_cfg_hashes.get(filename).ok_or_else(|| {
                format!("missing expected config hash for {path} (key {filename})")
            })?;
            let actual =
                sha256_file(Path::new(path)).map_err(|e| format!("hash config {path}: {e}"))?;
            if actual != *expected {
                return Err(format!(
                    "config integrity mismatch for {path}: expected {expected}, got {actual}"
                ));
            }
        }
    }

    Ok(())
}

fn parse_expected_config_hashes(raw: &str) -> Result<HashMap<String, String>, String> {
    let mut parsed = HashMap::new();
    for entry in raw
        .split(',')
        .map(str::trim)
        .filter(|entry| !entry.is_empty())
    {
        let (name, hash) = entry.split_once('=').ok_or_else(|| {
            format!("invalid ALLOWED_CONFIG_SHA256 entry {entry:?}; expected filename=sha256")
        })?;
        let filename = Path::new(name.trim())
            .file_name()
            .and_then(|value| value.to_str())
            .filter(|value| !value.is_empty())
            .ok_or_else(|| format!("invalid config hash key {name:?}"))?;
        let hash = hash.trim().to_ascii_lowercase();
        if hash.is_empty() {
            return Err(format!(
                "invalid ALLOWED_CONFIG_SHA256 entry {entry:?}; missing hash value"
            ));
        }
        parsed.insert(filename.to_string(), hash);
    }
    Ok(parsed)
}

/// Load a patch-cadence report from disk.
pub fn load_patch_cadence_report(path: &str) -> Result<PatchCadenceReport, String> {
    let content = fs::read_to_string(path).map_err(|e| format!("read patch report {path}: {e}"))?;
    serde_json::from_str(&content).map_err(|e| format!("parse patch report {path}: {e}"))
}

/// Load a recovery-drill report from disk.
pub fn load_recovery_drill_report(path: &str) -> Result<RecoveryDrillReport, String> {
    let content =
        fs::read_to_string(path).map_err(|e| format!("read recovery report {path}: {e}"))?;
    serde_json::from_str(&content).map_err(|e| format!("parse recovery report {path}: {e}"))
}

fn sha256_file(path: &Path) -> std::io::Result<String> {
    let mut file = fs::File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buffer = [0u8; 16 * 1024];

    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }

    Ok(format!("{:x}", hasher.finalize()))
}

#[cfg(test)]
mod tests {
    use super::{has_required_mfa_claim, parse_expected_config_hashes};
    use axum::http::HeaderMap;
    use std::{
        fs,
        sync::{Mutex, OnceLock},
        time::{SystemTime, UNIX_EPOCH},
    };

    fn env_lock() -> std::sync::MutexGuard<'static, ()> {
        static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        LOCK.get_or_init(|| Mutex::new(())).lock().unwrap()
    }

    #[test]
    fn mfa_claim_detected_from_amr() {
        let mut headers = HeaderMap::new();
        headers.insert("x-auth-amr", "pwd,mfa".parse().unwrap());
        assert!(has_required_mfa_claim(
            &headers,
            &["x-auth-amr".to_string()]
        ));
    }

    #[test]
    fn mfa_claim_missing_returns_false() {
        let headers = HeaderMap::new();
        assert!(!has_required_mfa_claim(
            &headers,
            &["x-auth-amr".to_string(), "x-auth-acr".to_string()]
        ));
    }

    #[test]
    fn mfa_claim_requires_exact_tokens() {
        let mut headers = HeaderMap::new();
        headers.insert("x-auth-amr", "mfa_disabled otp_expired".parse().unwrap());
        assert!(!has_required_mfa_claim(
            &headers,
            &["x-auth-amr".to_string()]
        ));
    }

    #[test]
    fn mfa_claim_accepts_exact_tokens_and_true() {
        let mut headers = HeaderMap::new();
        headers.insert("x-auth-amr", "pwd otp".parse().unwrap());
        headers.insert("x-auth-acr", "true".parse().unwrap());
        assert!(has_required_mfa_claim(
            &headers,
            &["x-auth-amr".to_string()]
        ));
        assert!(has_required_mfa_claim(
            &headers,
            &["x-auth-acr".to_string()]
        ));
    }

    #[test]
    fn parse_expected_config_hashes_requires_filename_pairs() {
        let parsed = parse_expected_config_hashes("server.conf=abc123,peer.conf=def456").unwrap();
        assert_eq!(
            parsed.get("server.conf").map(String::as_str),
            Some("abc123")
        );
        assert_eq!(parsed.get("peer.conf").map(String::as_str), Some("def456"));
        assert!(parse_expected_config_hashes("abc123").is_err());
    }

    #[test]
    fn startup_integrity_matches_hash_by_filename() {
        let _guard = env_lock();
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!(
            "boringtun-security-test-{}-{}",
            std::process::id(),
            unique
        ));
        fs::create_dir_all(&dir).unwrap();

        let server = dir.join("server.conf");
        let peer = dir.join("peer.conf");
        fs::write(&server, "server").unwrap();
        fs::write(&peer, "peer").unwrap();

        let server_hash = super::sha256_file(&server).unwrap();
        let peer_hash = super::sha256_file(&peer).unwrap();

        std::env::set_var(
            "ALLOWED_CONFIG_SHA256",
            format!("server.conf={server_hash},peer.conf={peer_hash}"),
        );
        std::env::set_var(
            "INTEGRITY_CONFIG_PATHS",
            format!("{},{}", server.display(), peer.display()),
        );
        assert!(super::verify_startup_integrity().is_ok());

        std::env::set_var(
            "ALLOWED_CONFIG_SHA256",
            format!("server.conf={peer_hash},peer.conf={server_hash}"),
        );
        let err = super::verify_startup_integrity().unwrap_err();
        assert!(err.contains("server.conf"));

        std::env::remove_var("ALLOWED_CONFIG_SHA256");
        std::env::remove_var("INTEGRITY_CONFIG_PATHS");
        let _ = fs::remove_dir_all(dir);
    }
}
