use std::{
    fs,
    path::{Path, PathBuf},
};

use thiserror::Error;

#[derive(Debug, Error)]
pub enum DeviceError {
    #[error("failed to read sysfs device inventory: {0}")]
    Io(#[from] std::io::Error),
    #[error("no ath9k_htc interface found under /sys/class/net")]
    NotFound,
    #[error("missing interface MAC address for {0}")]
    MissingMac(String),
}

pub fn detect(override_name: Option<&str>) -> Result<String, DeviceError> {
    if let Some(name) = override_name {
        let path = Path::new("/sys/class/net").join(name);
        if path.exists() {
            // Verify it's actually the correct driver
            let driver_path = path.join("device/driver");
            if let Ok(canonical) = fs::canonicalize(&driver_path) {
                if canonical
                    .file_name()
                    .map(|n| n.to_string_lossy() == "ath9k_htc")
                    .unwrap_or(false)
                {
                    return Ok(name.to_string());
                }
            }
        }

        // Explicit device not found - fall back to auto-detect
        let auto = detect_in(Path::new("/sys/class/net"));
        if auto.is_ok() {
            return auto;
        }
    }
    detect_in(Path::new("/sys/class/net"))
}

pub fn detect_in(root: &Path) -> Result<String, DeviceError> {
    for entry in fs::read_dir(root)? {
        let entry = entry?;
        let interface = entry.file_name().to_string_lossy().to_string();
        let driver_path = entry.path().join("device/driver");
        let canonical = match fs::canonicalize(&driver_path) {
            Ok(path) => path,
            Err(_) => continue,
        };
        if canonical
            .file_name()
            .map(|name| name.to_string_lossy() == "ath9k_htc")
            .unwrap_or(false)
        {
            return Ok(interface);
        }
    }
    Err(DeviceError::NotFound)
}

pub fn read_mac_address(interface: &str) -> Result<String, DeviceError> {
    let path = PathBuf::from("/sys/class/net").join(interface).join("address");
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

    use super::detect_in;

    #[test]
    fn detects_ath9k_htc_interface() {
        let dir = tempdir().unwrap();
        let wlan0 = dir.path().join("wlan0/device");
        let driver_dir = dir.path().join("drivers/ath9k_htc");
        fs::create_dir_all(&wlan0).unwrap();
        fs::create_dir_all(&driver_dir).unwrap();
        #[cfg(unix)]
        std::os::unix::fs::symlink(&driver_dir, wlan0.join("driver")).unwrap();

        assert_eq!(detect_in(dir.path()).unwrap(), "wlan0");
    }

    #[test]
    fn ignores_non_matching_driver() {
        let dir = tempdir().unwrap();
        let wlan0 = dir.path().join("wlan0/device");
        let driver_dir = dir.path().join("drivers/iwlwifi");
        fs::create_dir_all(&wlan0).unwrap();
        fs::create_dir_all(&driver_dir).unwrap();
        #[cfg(unix)]
        std::os::unix::fs::symlink(&driver_dir, wlan0.join("driver")).unwrap();

        assert!(detect_in(Path::new(dir.path())).is_err());
    }
}
