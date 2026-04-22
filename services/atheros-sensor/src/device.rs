use std::{
    fs,
    path::{Path, PathBuf},
};

use thiserror::Error;

#[derive(Debug, Error)]
pub enum DeviceError {
    #[error("failed to read sysfs device inventory: {0}")]
    Io(#[from] std::io::Error),
    #[error("no wireless interface found under /sys/class/net (ath9k_htc preferred)")]
    NotFound,
    #[error("configured interface {0} exists but is not a wireless interface")]
    OverrideNotWireless(String),
    #[error("configured interface {0} was not found under /sys/class/net")]
    OverrideNotFound(String),
    #[error("missing interface MAC address for {0}")]
    MissingMac(String),
}

pub fn detect(override_name: Option<&str>) -> Result<String, DeviceError> {
    if let Some(name) = override_name {
        return detect_interface_at(name, Path::new("/sys/class/net"));
    }
    detect_in(Path::new("/sys/class/net"))
}

fn detect_interface_at(name: &str, root: &Path) -> Result<String, DeviceError> {
    let path = root.join(name);
    if !path.exists() {
        return Err(DeviceError::OverrideNotFound(name.to_string()));
    }
    if !is_wireless_interface(&path) {
        return Err(DeviceError::OverrideNotWireless(name.to_string()));
    }
    Ok(name.to_string())
}

pub fn detect_in(root: &Path) -> Result<String, DeviceError> {
    let mut wireless_interfaces = Vec::new();

    for entry in fs::read_dir(root)? {
        let entry = entry?;
        let interface = entry.file_name().to_string_lossy().to_string();
        let interface_path = entry.path();
        if !is_wireless_interface(&interface_path) {
            continue;
        }

        wireless_interfaces.push((interface, interface_path));
    }

    if wireless_interfaces.is_empty() {
        return Err(DeviceError::NotFound);
    }

    wireless_interfaces.sort_by(|left, right| left.0.cmp(&right.0));

    for (interface, interface_path) in &wireless_interfaces {
        if driver_name(interface_path).as_deref() == Some("ath9k_htc") {
            return Ok(interface.clone());
        }
    }

    Ok(wireless_interfaces[0].0.clone())
}

fn is_wireless_interface(interface_path: &Path) -> bool {
    interface_path.join("wireless").exists() || interface_path.join("phy80211").exists()
}

fn driver_name(interface_path: &Path) -> Option<String> {
    let canonical = fs::canonicalize(interface_path.join("device/driver")).ok()?;
    canonical
        .file_name()
        .map(|name| name.to_string_lossy().to_string())
}

pub fn read_mac_address(interface: &str) -> Result<String, DeviceError> {
    let path = PathBuf::from("/sys/class/net")
        .join(interface)
        .join("address");
    let mac = fs::read_to_string(&path)?;
    let trimmed = mac.trim().to_ascii_lowercase();
    if trimmed.is_empty() {
        return Err(DeviceError::MissingMac(interface.to_string()));
    }
    Ok(trimmed)
}

#[cfg(test)]
mod tests {
    use std::{fs, path::Path};

    use tempfile::tempdir;

    use super::{detect_in, DeviceError};

    #[cfg(unix)]
    #[test]
    fn detects_ath9k_htc_interface() {
        let dir = tempdir().unwrap();
        let wlan0 = dir.path().join("wlan0/device");
        let driver_dir = dir.path().join("drivers/ath9k_htc");
        fs::create_dir_all(&wlan0).unwrap();
        fs::create_dir_all(dir.path().join("wlan0/wireless")).unwrap();
        fs::create_dir_all(&driver_dir).unwrap();
        std::os::unix::fs::symlink(&driver_dir, wlan0.join("driver")).unwrap();

        assert_eq!(detect_in(dir.path()).unwrap(), "wlan0");
    }

    #[cfg(unix)]
    #[test]
    fn falls_back_to_non_ath_wireless_interface() {
        let dir = tempdir().unwrap();
        let wlan0 = dir.path().join("wlan0/device");
        let driver_dir = dir.path().join("drivers/iwlwifi");
        fs::create_dir_all(&wlan0).unwrap();
        fs::create_dir_all(dir.path().join("wlan0/wireless")).unwrap();
        fs::create_dir_all(&driver_dir).unwrap();
        std::os::unix::fs::symlink(&driver_dir, wlan0.join("driver")).unwrap();

        assert_eq!(detect_in(Path::new(dir.path())).unwrap(), "wlan0");
    }

    #[test]
    fn configured_missing_interface_reports_override_not_found() {
        let dir = tempdir().unwrap();
        let error = super::detect_interface_at("missing0", dir.path()).unwrap_err();
        assert!(
            matches!(error, DeviceError::OverrideNotFound(interface) if interface == "missing0")
        );
    }

    #[cfg(unix)]
    #[test]
    fn configured_non_wireless_interface_reports_error() {
        let dir = tempdir().unwrap();
        fs::create_dir_all(dir.path().join("eth0/device")).unwrap();

        let error = super::detect_interface_at("eth0", dir.path()).unwrap_err();
        assert!(
            matches!(error, DeviceError::OverrideNotWireless(interface) if interface == "eth0")
        );
    }

    #[cfg(unix)]
    #[test]
    fn prefers_ath9k_over_other_wireless_interfaces() {
        let dir = tempdir().unwrap();

        let wlan0 = dir.path().join("wlan0/device");
        let wlan1 = dir.path().join("wlan1/device");
        let iwl_driver = dir.path().join("drivers/iwlwifi");
        let ath_driver = dir.path().join("drivers/ath9k_htc");

        fs::create_dir_all(&wlan0).unwrap();
        fs::create_dir_all(dir.path().join("wlan0/wireless")).unwrap();
        fs::create_dir_all(&wlan1).unwrap();
        fs::create_dir_all(dir.path().join("wlan1/wireless")).unwrap();
        fs::create_dir_all(&iwl_driver).unwrap();
        fs::create_dir_all(&ath_driver).unwrap();
        std::os::unix::fs::symlink(&iwl_driver, wlan0.join("driver")).unwrap();
        std::os::unix::fs::symlink(&ath_driver, wlan1.join("driver")).unwrap();

        assert_eq!(detect_in(dir.path()).unwrap(), "wlan1");
    }

    #[cfg(unix)]
    #[test]
    fn deterministic_fallback_uses_sorted_wireless_interface_name() {
        let dir = tempdir().unwrap();

        let wlan2 = dir.path().join("wlan2/device");
        let wlan0 = dir.path().join("wlan0/device");
        let iwl_driver = dir.path().join("drivers/iwlwifi");
        let rtl_driver = dir.path().join("drivers/rtl8xxxu");

        fs::create_dir_all(&wlan2).unwrap();
        fs::create_dir_all(dir.path().join("wlan2/wireless")).unwrap();
        fs::create_dir_all(&wlan0).unwrap();
        fs::create_dir_all(dir.path().join("wlan0/wireless")).unwrap();
        fs::create_dir_all(&iwl_driver).unwrap();
        fs::create_dir_all(&rtl_driver).unwrap();
        std::os::unix::fs::symlink(&iwl_driver, wlan2.join("driver")).unwrap();
        std::os::unix::fs::symlink(&rtl_driver, wlan0.join("driver")).unwrap();

        assert_eq!(detect_in(dir.path()).unwrap(), "wlan0");
    }
}
