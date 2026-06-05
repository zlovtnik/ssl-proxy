use super::*;
use std::{io, path::Path};

#[test]
fn private_key_generation_round_trips_to_public_key() {
    let private_key = generate_private_key_base64().expect("private key should generate");
    let public_key =
        public_key_from_private_base64(&private_key).expect("public key should derive");

    assert_eq!(decode_base64_32(&private_key).unwrap().len(), 32);
    assert_eq!(decode_base64_32(&public_key).unwrap().len(), 32);
}

#[test]
fn parses_wireguard_style_config_for_boringtun_control() {
    let tempdir = tempfile::tempdir().unwrap();
    let config_path = tempdir.path().join("wg0.conf");
    fs::write(
            &config_path,
            "[Interface]\nAddress = 10.13.13.1/24\nListenPort = 51820\nPrivateKey = eHz8Gu9Uhp8Zqc+nEDp98kVxKlznPAouR4VLr5J6jGs=\nMTU = 1280\nPostUp = ignored\n\n[Peer]\nPublicKey = RMG56qSaFhNYkZVoizYm9g4pqSRZ+EQYkLhxGUtCeQw=\nPresharedKey = JiSXAaw54GnEjuwO9RUCbumIJI/Jb7oBCEibn3KTHo0=\nEndpoint = 192.0.2.10:443\nAllowedIPs = 10.13.13.2/32, 10.13.13.3/32\nPersistentKeepalive = 25\n",
        )
        .unwrap();

    let parsed = parse_config(&config_path).expect("config should parse");
    assert_eq!(parsed.interface.listen_port, Some(51820));
    assert_eq!(parsed.interface.addresses, vec!["10.13.13.1/24"]);
    assert_eq!(parsed.peers.len(), 1);
    assert_eq!(
        parsed.peers[0].allowed_ips,
        vec!["10.13.13.2/32", "10.13.13.3/32"]
    );
}

#[test]
fn render_dump_matches_wg_dump_shape() {
    let dump = render_dump(&RuntimeDevice {
        private_key: Some("private".to_string()),
        public_key: Some("public".to_string()),
        listen_port: Some(51820),
        fwmark: None,
        peers: vec![RuntimePeer {
            public_key: "peer".to_string(),
            preshared_key: Some("psk".to_string()),
            endpoint: Some("198.51.100.10:443".to_string()),
            allowed_ips: vec!["10.13.13.2/32".to_string()],
            latest_handshake_sec: Some(1713225600),
            rx_bytes: 10,
            tx_bytes: 20,
            persistent_keepalive: Some(25),
        }],
    });

    let lines: Vec<_> = dump.lines().collect();
    assert_eq!(lines.len(), 2);
    assert_eq!(lines[0], "private\tpublic\t51820\toff");
    assert_eq!(
        lines[1],
        "peer\tpsk\t198.51.100.10:443\t10.13.13.2/32\t1713225600\t10\t20\t25"
    );
}

#[test]
fn uapi_socket_directory_validation_rejects_non_root_owner() {
    let tempdir = tempfile::tempdir().unwrap();
    let socket_path = tempdir.path().join("wg0.sock");

    let err = validate_uapi_socket_dir(&socket_path).unwrap_err();

    assert!(matches!(err, ControlError::InsecureUapiSocketDir { .. }));
}

#[test]
fn read_uapi_response_accumulates_partial_chunks() {
    struct ChunkedReader<'a> {
        data: &'a [u8],
        offset: usize,
        chunk_size: usize,
    }

    impl Read for ChunkedReader<'_> {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            if self.offset >= self.data.len() {
                return Ok(0);
            }

            let len = self
                .chunk_size
                .min(buf.len())
                .min(self.data.len() - self.offset);
            let end = self.offset + len;
            buf[..len].copy_from_slice(&self.data[self.offset..end]);
            self.offset = end;
            Ok(len)
        }
    }

    let mut reader = ChunkedReader {
        data: b"errno=0\ninterface=wg0\n\n",
        offset: 0,
        chunk_size: 3,
    };

    let response = read_uapi_response(&mut reader, Path::new("/tmp/wg0.sock"))
        .expect("chunked response should be preserved");

    assert_eq!(response, "errno=0\ninterface=wg0\n\n");
}
