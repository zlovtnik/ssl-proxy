use std::{fmt::Display, io};

use thiserror::Error;

use crate::{
    backlog::BacklogError, capture::CaptureError, config::ConfigError, device::DeviceError,
    publish::PublishError,
};

#[derive(Debug, Error)]
pub enum SensorError {
    #[error("configuration failed: {0}")]
    Config(#[from] ConfigError),
    #[error("device setup failed: {0}")]
    Device(#[from] DeviceError),
    #[error("capture setup failed: {0}")]
    Capture(#[from] CaptureError),
    #[error("backlog failed: {0}")]
    Backlog(#[from] BacklogError),
    #[error("publish failed: {0}")]
    Publish(#[from] PublishError),
    #[error("{0}")]
    Step(String),
}

impl SensorError {
    pub fn step(label: impl Display, error: impl Display) -> Self {
        Self::Step(format!("{label}: {error}"))
    }
}

impl From<io::Error> for SensorError {
    fn from(error: io::Error) -> Self {
        Self::Step(error.to_string())
    }
}
