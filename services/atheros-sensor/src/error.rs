//! Top-level error enum for the sensor process.
//!
//! Wraps subsystem errors (ConfigError, DeviceError, CaptureError, BacklogError, PublishError)
//! into a single SensorError returned from main, with a freeform Step variant for ad-hoc
//! labeled failures during startup sequencing.

use std::{fmt::Display, io};

use thiserror::Error;

use crate::{
    backlog::BacklogError, capture::CaptureError, config::ConfigError, device::DeviceError,
    publish::PublishError,
};

#[derive(Debug, Error)]
pub enum SensorError {
    /// Fired when `AppConfig::from_env` fails to parse or validate environment variables.
    #[error("configuration failed: {0}")]
    Config(#[from] ConfigError),
    /// Fired when the wireless interface cannot be detected or its MAC address cannot be read.
    #[error("device setup failed: {0}")]
    Device(#[from] DeviceError),
    /// Fired when the pcap handle cannot be opened or the datalink type is not radiotap.
    #[error("capture setup failed: {0}")]
    Capture(#[from] CaptureError),
    /// Fired when the Redpanda-backed backlog boundary fails.
    #[error("backlog failed: {0}")]
    Backlog(#[from] BacklogError),
    /// Fired when a publish fails with no fallback path and the pipeline cannot continue.
    #[error("publish failed: {0}")]
    Publish(#[from] PublishError),
    /// Fired by the `step` / `step_async` helpers for any labeled startup failure not covered
    /// by the typed variants above.
    #[error("{0}")]
    Step(String),
}

/// Constructs a SensorError::Step variant with a formatted label and error message.
impl SensorError {
    /// Creates a Step error by formatting the label and error into a single string.
    /// Used during startup sequencing for ad-hoc failures not covered by typed variants.
    pub fn step(label: impl Display, error: impl Display) -> Self {
        Self::Step(format!("{label}: {error}"))
    }
}

/// Converts io::Error into SensorError::Step for generic I/O failures during startup.
impl From<io::Error> for SensorError {
    fn from(error: io::Error) -> Self {
        Self::Step(error.to_string())
    }
}
