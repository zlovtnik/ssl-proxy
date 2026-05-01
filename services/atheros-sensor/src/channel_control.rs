use std::process::Command;

use thiserror::Error;

#[derive(Debug, Error)]
pub enum ChannelControlError {
    #[error("failed to run iw: {0}")]
    Io(#[from] std::io::Error),
    #[error("iw set channel failed for {interface} channel {channel}: {stderr}")]
    Command {
        interface: String,
        channel: u8,
        stderr: String,
    },
}

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
