//! Thin wrapper around `iw dev <iface> set channel <n>`, called by the channel hopper and the
//! Redpanda sensor config subscriber to switch the monitor-mode interface to a new 802.11 channel.

use std::process::Command;

use thiserror::Error;

#[derive(Debug, Error)]
pub enum ChannelControlError {
    /// Wraps std::io::Error when the iw binary cannot be executed (not found, permission denied).
    #[error("failed to run iw: {0}")]
    Io(#[from] std::io::Error),
    /// Carries stderr output when iw returns a non-zero exit code.
    #[error("iw set channel failed for {interface} channel {channel}: {stderr}")]
    Command {
        interface: String,
        channel: u8,
        stderr: String,
    },
}

/// Shells out to `iw dev <iface> set channel <n>` synchronously, blocking briefly until
/// the command completes. Fails fast on non-zero exit, returning stderr in the error.
pub fn set_channel(interface: &str, channel: u8) -> Result<(), ChannelControlError> {
    let output = Command::new("iw")
        .arg("dev")
        .arg(interface)
        .arg("set")
        .arg("channel")
        .arg(channel.to_string())
        .output()?;
    if output.status.success() {
        return Ok(());
    }
    Err(ChannelControlError::Command {
        interface: interface.to_string(),
        channel,
        stderr: String::from_utf8_lossy(&output.stderr).trim().to_string(),
    })
}
