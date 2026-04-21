use std::{thread, time::Duration};

use chrono::Utc;
use pcap::{Capture, Error as PcapError};
use thiserror::Error;
use tokio::sync::mpsc;
use tokio_stream::wrappers::ReceiverStream;

use crate::model::RawPacket;

#[derive(Debug, Error)]
pub enum CaptureError {
    #[error("pcap error: {0}")]
    Pcap(#[from] PcapError),
}

pub fn stream_packets(
    device: &str,
    snaplen: i32,
    timeout_ms: i32,
    filter: &str,
) -> Result<ReceiverStream<Result<RawPacket, CaptureError>>, CaptureError> {
    let mut capture = Capture::from_device(device)?
        .immediate_mode(true)
        .rfmon(true)
        .promisc(true)
        .snaplen(snaplen)
        .timeout(timeout_ms)
        .open()?
        .setnonblock()?;
    capture.filter(filter, true)?;

    let (tx, rx) = mpsc::channel(64);
    thread::spawn(move || loop {
        match capture.next_packet() {
            Ok(packet) => {
                if tx
                    .blocking_send(Ok(RawPacket {
                        observed_at: Utc::now(),
                        data: packet.data.to_vec(),
                    }))
                    .is_err()
                {
                    break;
                }
            }
            Err(PcapError::NoMorePackets) | Err(PcapError::TimeoutExpired) => {
                thread::sleep(Duration::from_millis(10));
            }
            Err(error) => {
                let _ = tx.blocking_send(Err(CaptureError::Pcap(error)));
                break;
            }
        }
    });

    Ok(ReceiverStream::new(rx))
}

#[cfg(test)]
mod tests {
    use std::{fs, path::Path};

    use pcap::Capture;
    use tempfile::tempdir;

    #[test]
    fn offline_pcap_fixture_contains_expected_packets() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("mgmt-fixtures.pcap");
        write_test_pcap(
            &path,
            &[
                super::super::parse::tests::beacon_radiotap_frame(),
                super::super::parse::tests::probe_request_radiotap_frame(),
                super::super::parse::tests::probe_response_radiotap_frame(),
            ],
        );

        let mut capture = Capture::from_file(&path).unwrap();
        let mut count = 0usize;
        while let Ok(packet) = capture.next_packet() {
            assert!(!packet.data.is_empty());
            count += 1;
        }

        assert_eq!(count, 3);
    }

    fn write_test_pcap(path: &Path, frames: &[Vec<u8>]) {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&0xa1b2c3d4u32.to_le_bytes());
        bytes.extend_from_slice(&2u16.to_le_bytes());
        bytes.extend_from_slice(&4u16.to_le_bytes());
        bytes.extend_from_slice(&0i32.to_le_bytes());
        bytes.extend_from_slice(&0u32.to_le_bytes());
        bytes.extend_from_slice(&65535u32.to_le_bytes());
        bytes.extend_from_slice(&127u32.to_le_bytes());

        for frame in frames {
            bytes.extend_from_slice(&1u32.to_le_bytes());
            bytes.extend_from_slice(&0u32.to_le_bytes());
            bytes.extend_from_slice(&(frame.len() as u32).to_le_bytes());
            bytes.extend_from_slice(&(frame.len() as u32).to_le_bytes());
            bytes.extend_from_slice(frame);
        }

        fs::write(path, bytes).unwrap();
    }
}
