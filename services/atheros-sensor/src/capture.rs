//! Dedicated capture thread and non-blocking pcap packet stream.
//!
//! Spawns a single OS thread (not a Tokio task) to drive the pcap loop, since libpcap is
//! synchronous and blocking it inside the async runtime would stall the executor. The thread
//! polls in non-blocking mode, sleeping 10 ms on NoMorePackets/TimeoutExpired to avoid busy-spin.
//! A CaptureControl channel allows the async runtime to push live BPF filter reloads into the
//! thread without restarting capture. Radiotap headers (DLT_IEEE802_11_RADIO, linktype 127) are
//! required and validated at startup; plain 802.11 or Ethernet linktypes are rejected immediately.

use std::{thread, time::Duration};

use chrono::Utc;
use pcap::{Capture, Error as PcapError, Linktype};
use thiserror::Error;
use tokio::sync::mpsc;
use tokio_stream::wrappers::ReceiverStream;

use crate::model::RawPacket;

#[derive(Debug, Error)]
pub enum CaptureError {
    /// Fired by libpcap for any I/O or filter compilation failure during capture setup or runtime.
    /// Also emitted when `blocking_send` on the packet channel fails (e.g. the receiver has been
    /// dropped), which causes the capture thread to terminate.
    #[error("pcap error: {0}")]
    Pcap(#[from] PcapError),
    /// Fired at startup when the interface's datalink type is not DLT_IEEE802_11_RADIO (127),
    /// meaning monitor mode with radiotap headers is not enabled on the interface.
    #[error(
        "unsupported pcap datalink {actual}; expected DLT_IEEE802_11_RADIO (127). Enable monitor mode with radiotap headers for this interface"
    )]
    UnsupportedDatalink { actual: i32 },
}

#[derive(Clone)]
pub struct CaptureControl {
    tx: mpsc::UnboundedSender<CaptureCommand>,
}

impl CaptureControl {
    pub fn apply_filter(&self, filter: String) {
        let _ = self.tx.send(CaptureCommand::ApplyFilter(filter));
    }
}

enum CaptureCommand {
    ApplyFilter(String),
}
/// A bounded channel of captured 802.11 frames and a control handle for live BPF filter reloads.
///
/// The `packets` receiver is backed by an `mpsc::channel(64)` — a 64-slot capacity that serves as
/// the effective backpressure limit before the pcap capture thread blocks. When all 64 slots are
/// full, the capture thread's `blocking_send` call blocks, pausing the pcap loop until the async
/// receiver drains. This prevents unbounded memory growth during processing backlogs and ensures
/// the capture thread does not outrun the consumer.
pub struct PacketStream {
    pub packets: ReceiverStream<Result<RawPacket, CaptureError>>,
    pub control: CaptureControl,
}

/// Spawns a dedicated OS thread to drive the pcap loop since libpcap is synchronous and
/// blocking it inside the async runtime would stall the executor. The thread polls in
/// non-blocking mode, sleeping 10 ms on NoMorePackets/TimeoutExpired to avoid busy-spin.
/// CaptureControl channel allows the async runtime to push live BPF filter reloads without
/// restarting capture.
pub fn stream_packets(
    device: &str,
    snaplen: i32,
    timeout_ms: i32,
    filter: &str,
) -> Result<PacketStream, CaptureError> {
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
    let (control_tx, mut control_rx) = mpsc::unbounded_channel();
    thread::spawn(move || loop {
        while let Ok(command) = control_rx.try_recv() {
            match command {
                CaptureCommand::ApplyFilter(filter) => {
                    if let Err(error) = capture.filter(&filter, true) {
                        let _ = tx.blocking_send(Err(CaptureError::Pcap(error)));
                    }
                }
            }
        }
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

    Ok(PacketStream {
        packets: ReceiverStream::new(rx),
        control: CaptureControl { tx: control_tx },
    })
}

/// Validates that the interface datalink is DLT_IEEE802_11_RADIO (127); rejects all others.
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
    fn repeated_handshake_observations_preserve_baseline_capture() {
        use crate::{
            model::{AuditContext, RawPacket},
            parse::{decode_frame, HandshakeMonitor},
            testutil::{
                beacon_radiotap_frame, data_from_distribution_radiotap_frame,
                data_to_distribution_radiotap_frame, eapol_key_payload,
                qos_data_to_distribution_radiotap_frame,
            },
        };

        let baseline = "type mgt or type data";
        let dead_capture = Capture::dead(Linktype::IEEE802_11_RADIOTAP).unwrap();
        let mut active_filter = dead_capture.compile(baseline, true).unwrap();
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
        let control = super::CaptureControl { tx };
        let context = AuditContext {
            sensor_id: "sensor-1".into(),
            location_id: "lab".into(),
            interface: "wlan0".into(),
            channel: 6,
            reg_domain: "US".into(),
        };
        let mut monitor = HandshakeMonitor::default();
        let mut protected = data_to_distribution_radiotap_frame(vec![0; 32]);
        protected[11] |= 0x40;
        let required_frames = [
            beacon_radiotap_frame(),
            protected,
            data_from_distribution_radiotap_frame(eapol_key_payload(1)),
            qos_data_to_distribution_radiotap_frame(0, eapol_key_payload(2)),
        ];

        for attempt in 0..256 {
            // Alternate ordinary/QoS M1 and changing replay counters; each is
            // attacker-controlled and must remain a passive observation.
            let mut payload = eapol_key_payload(1);
            payload[10..12].copy_from_slice(&95u16.to_be_bytes());
            payload.resize(8 + 4 + 95, 0);
            payload[15..23].copy_from_slice(&(attempt as u64).to_be_bytes());
            let data = if attempt % 2 == 0 {
                data_from_distribution_radiotap_frame(payload)
            } else {
                let mut data = qos_data_to_distribution_radiotap_frame(0, payload);
                // QoS AP -> client, matching the ordinary M1's pair.
                data[11] = 0x02;
                data[14..20].copy_from_slice(&crate::testutil::CLIENT);
                data[20..26].copy_from_slice(&crate::testutil::AP);
                data
            };
            let mut frame = decode_frame(&RawPacket {
                observed_at: chrono::Utc::now(),
                data,
            })
            .unwrap();
            frame.channel_number = Some(6);
            assert_eq!(frame.eapol_key_message, Some(1));
            assert!(monitor
                .observe(
                    &mut frame,
                    &context,
                    None,
                    std::time::Duration::from_secs(60)
                )
                .is_none());
            monitor.cleanup_expired(std::time::Duration::from_secs(60));
            assert!(matches!(
                rx.try_recv(),
                Err(tokio::sync::mpsc::error::TryRecvError::Empty)
            ));
            for required in &required_frames {
                assert!(
                    active_filter.filter(required),
                    "baseline frame remains visible after M1"
                );
            }
        }

        // Explicit configuration still owns and can reload the filter.
        control.apply_filter("type mgt".into());
        let super::CaptureCommand::ApplyFilter(filter) = rx.try_recv().unwrap();
        active_filter = dead_capture.compile(&filter, true).unwrap();
        assert!(active_filter.filter(&required_frames[0]));
        assert!(!active_filter.filter(&required_frames[1]));

        // Already queued handshake frames can complete without restoring a stale
        // baseline over a newer operator-selected filter.
        let mut alerts = 0;
        for message in [2, 3, 4, 4] {
            let data = if message == 3 {
                data_from_distribution_radiotap_frame(eapol_key_payload(message))
            } else {
                data_to_distribution_radiotap_frame(eapol_key_payload(message))
            };
            let mut frame = decode_frame(&RawPacket {
                observed_at: chrono::Utc::now(),
                data,
            })
            .unwrap();
            if monitor
                .observe(
                    &mut frame,
                    &context,
                    None,
                    std::time::Duration::from_secs(60),
                )
                .is_some()
            {
                assert!(frame.handshake_captured);
                alerts += 1;
            }
            assert!(matches!(
                rx.try_recv(),
                Err(tokio::sync::mpsc::error::TryRecvError::Empty)
            ));
        }
        assert_eq!(alerts, 1, "completion and retransmission dedup still work");
        assert!(active_filter.filter(&required_frames[0]));
        assert!(!active_filter.filter(&required_frames[1]));
    }

    #[test]
    fn offline_pcap_fixture_contains_expected_packets() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("mgmt-fixtures.pcap");
        write_test_pcap(
            &path,
            &[
                crate::testutil::beacon_radiotap_frame(),
                crate::testutil::probe_request_radiotap_frame(),
                crate::testutil::probe_response_radiotap_frame(),
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
