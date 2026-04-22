use std::{thread, time::Duration};

use chrono::Utc;
use pcap::{Capture, Error as PcapError, Linktype};
use thiserror::Error;
use tokio::sync::mpsc;
use tokio_stream::wrappers::ReceiverStream;

use crate::model::RawPacket;

#[derive(Debug, Error)]
pub enum CaptureError {
    #[error("pcap error: {0}")]
    Pcap(#[from] PcapError),
    #[error(
        "unsupported pcap datalink {actual}; expected DLT_IEEE802_11_RADIO (127). Enable monitor mode with radiotap headers for this interface"
    )]
    UnsupportedDatalink { actual: i32 },
}

pub fn stream_packets(
    device: &str,
    snaplen: i32,
    timeout_ms: i32,
    filter: &str,
) -> Result<ReceiverStream<Result<RawPacket, CaptureError>>, CaptureError> {
    let builder = Capture::from_device(device)?
        .immediate_mode(true)
        .promisc(true)
        .snaplen(snaplen)
        .timeout(timeout_ms);

    let capture = match builder.open() {
        Ok(cap) => cap,
        Err(e) => {
            if e.to_string().contains("monitor mode")
                || e.to_string().contains("rfmon")
                || e.to_string().contains("not supported")
            {
                eprintln!(
                    "ERROR: Interface {} does not have monitor mode enabled.",
                    device
                );
                eprintln!("       This is required for 802.11 frame capture.");
                eprintln!(
                    "       Run on the HOST first: sudo ./scripts/prep_ath.sh {}",
                    device
                );
                eprintln!("       The container cannot configure monitor mode from inside.");
            }
            return Err(CaptureError::Pcap(e));
        }
    };

    validate_radiotap_datalink(capture.get_datalink())?;

    let mut capture = capture.setnonblock()?;

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

fn validate_radiotap_datalink(linktype: Linktype) -> Result<(), CaptureError> {
    if linktype == Linktype::IEEE802_11_RADIOTAP {
        return Ok(());
    }

    eprintln!(
        "ERROR: Interface returned datalink {} instead of DLT_IEEE802_11_RADIO (127).",
        linktype.0
    );
    eprintln!("       Monitor mode or radiotap capture is not configured correctly.");
    Err(CaptureError::UnsupportedDatalink { actual: linktype.0 })
}

#[cfg(test)]
mod tests {
    use std::{fs, path::Path};

    use super::{validate_radiotap_datalink, CaptureError};
    use pcap::Capture;
    use pcap::Linktype;
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

    #[test]
    fn accepts_radiotap_datalink() {
        assert!(validate_radiotap_datalink(Linktype::IEEE802_11_RADIOTAP).is_ok());
    }

    #[test]
    fn rejects_non_radiotap_datalink() {
        assert!(matches!(
            validate_radiotap_datalink(Linktype::ETHERNET),
            Err(CaptureError::UnsupportedDatalink { actual: 1 })
        ));
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
