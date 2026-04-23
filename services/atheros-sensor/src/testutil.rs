const LLC_SNAP_EAPOL_PREFIX: [u8; 8] = [0xaa, 0xaa, 0x03, 0x00, 0x00, 0x00, 0x88, 0x8e];
const WPS_ATTR_DEVICE_NAME: u16 = 0x1011;
const WPS_ATTR_MANUFACTURER: u16 = 0x1021;
const WPS_ATTR_MODEL_NAME: u16 = 0x1023;

pub(crate) const BROADCAST: [u8; 6] = [0xff; 6];
pub(crate) const AP: [u8; 6] = [0x10, 0x20, 0x30, 0x40, 0x50, 0x60];
pub(crate) const AP2: [u8; 6] = [0x10, 0x20, 0x30, 0x40, 0x50, 0x61];
pub(crate) const CLIENT: [u8; 6] = [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x01];
pub(crate) const DISTRIBUTION_DST: [u8; 6] = [0x22, 0x33, 0x44, 0x55, 0x66, 0x77];

pub(crate) fn beacon_radiotap_frame() -> Vec<u8> {
    build_frame(0x80, 0x00, BROADCAST, AP, AP, None, beacon_body())
}

pub(crate) fn detailed_radiotap_beacon_frame() -> Vec<u8> {
    let frame = build_frame(0x80, 0x00, BROADCAST, AP, AP, None, beacon_body());
    let mut bytes = detailed_radiotap_header();
    bytes.extend_from_slice(&frame[10..]);
    bytes
}

pub(crate) fn tsft_antenna_radiotap_beacon_frame() -> Vec<u8> {
    let frame = build_frame(0x80, 0x00, BROADCAST, AP, AP, None, beacon_body());
    let mut bytes = tsft_antenna_radiotap_header();
    bytes.extend_from_slice(&frame[10..]);
    bytes
}

pub(crate) fn extended_mask_radiotap_beacon_frame() -> Vec<u8> {
    let frame = build_frame(0x80, 0x00, BROADCAST, AP, AP, None, beacon_body());
    let mut bytes = extended_mask_radiotap_header();
    bytes.extend_from_slice(&frame[10..]);
    bytes
}

pub(crate) fn namespace_radiotap_beacon_frame() -> Vec<u8> {
    let frame = build_frame(0x80, 0x00, BROADCAST, AP, AP, None, beacon_body());
    let mut bytes = namespace_radiotap_header();
    bytes.extend_from_slice(&frame[10..]);
    bytes
}

pub(crate) fn probe_request_radiotap_frame() -> Vec<u8> {
    build_frame(0x40, 0x00, BROADCAST, CLIENT, BROADCAST, None, ssid_ie())
}

pub(crate) fn probe_response_radiotap_frame() -> Vec<u8> {
    build_frame(0x50, 0x00, CLIENT, AP, AP, None, beacon_body())
}

pub(crate) fn data_to_distribution_radiotap_frame(payload: Vec<u8>) -> Vec<u8> {
    build_frame(0x08, 0x01, AP, CLIENT, DISTRIBUTION_DST, None, payload)
}

pub(crate) fn data_from_distribution_radiotap_frame(payload: Vec<u8>) -> Vec<u8> {
    build_frame(0x08, 0x02, CLIENT, AP, DISTRIBUTION_DST, None, payload)
}

pub(crate) fn build_frame(
    frame_control_first: u8,
    frame_control_second: u8,
    addr1: [u8; 6],
    addr2: [u8; 6],
    addr3: [u8; 6],
    addr4: Option<[u8; 6]>,
    body: Vec<u8>,
) -> Vec<u8> {
    let mut bytes = vec![
        0x00,
        0x00,
        0x0a,
        0x00,
        0x20,
        0x00,
        0x00,
        0x00,
        0xd6,
        0x00,
        frame_control_first,
        frame_control_second,
        0x00,
        0x00,
    ];
    bytes.extend_from_slice(&addr1);
    bytes.extend_from_slice(&addr2);
    bytes.extend_from_slice(&addr3);
    bytes.extend_from_slice(&[0x10, 0x00]);
    if let Some(addr4) = addr4 {
        bytes.extend_from_slice(&addr4);
    }
    bytes.extend_from_slice(&body);
    bytes
}

pub(crate) fn detailed_radiotap_header() -> Vec<u8> {
    vec![
        0x00, 0x00, 0x10, 0x00, 0x6c, 0x00, 0x00, 0x00, 0x0c, 0x00, 0x85, 0x09, 0xa0, 0x00, 0xd6,
        0xa1,
    ]
}

pub(crate) fn tsft_antenna_radiotap_header() -> Vec<u8> {
    vec![
        0x00, 0x00, 0x19, 0x00, 0x6d, 0x08, 0x00, 0x00, 0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02,
        0x01, 0x0c, 0x00, 0x85, 0x09, 0xa0, 0x00, 0xd6, 0xa1, 0x03,
    ]
}

pub(crate) fn extended_mask_radiotap_header() -> Vec<u8> {
    vec![
        0x00, 0x00, 0x0d, 0x00, 0x20, 0x00, 0x00, 0x80, 0x00, 0x00, 0x00, 0x00, 0xd6,
    ]
}

pub(crate) fn namespace_radiotap_header() -> Vec<u8> {
    vec![0x00, 0x00, 0x09, 0x00, 0x20, 0x00, 0x00, 0x20, 0xd6]
}

pub(crate) fn beacon_body() -> Vec<u8> {
    let mut body = vec![0; 8];
    body.extend_from_slice(&100u16.to_le_bytes());
    body.extend_from_slice(&0x0431u16.to_le_bytes());
    body.extend_from_slice(&ssid_ie());
    body
}

pub(crate) fn ssid_ie() -> Vec<u8> {
    let mut ie = vec![0x00, 0x08];
    ie.extend_from_slice(b"CorpWiFi");
    ie
}

pub(crate) fn rsn_ie(wpa3: bool, pmf_required: bool) -> Vec<u8> {
    let akm = if wpa3 { 8 } else { 2 };
    let capabilities = if pmf_required { 0x0040u16 } else { 0 };
    let mut rsn = vec![
        0x30, 0x14, 0x01, 0x00, 0x00, 0x0f, 0xac, 0x04, 0x01, 0x00, 0x00, 0x0f, 0xac, 0x04, 0x01,
        0x00, 0x00, 0x0f, 0xac, akm,
    ];
    rsn.extend_from_slice(&capabilities.to_le_bytes());
    rsn
}

pub(crate) fn wpa_vendor_ie() -> Vec<u8> {
    vec![0xdd, 0x04, 0x00, 0x50, 0xf2, 0x01]
}

pub(crate) fn wps_vendor_ie() -> Vec<u8> {
    let mut body = vec![0x00, 0x50, 0xf2, 0x04];
    append_wps_attr(&mut body, WPS_ATTR_DEVICE_NAME, b"Lobby AP");
    append_wps_attr(&mut body, WPS_ATTR_MANUFACTURER, b"Acme");
    append_wps_attr(&mut body, WPS_ATTR_MODEL_NAME, b"Model 7");
    let mut ie = vec![0xdd, body.len() as u8];
    ie.extend_from_slice(&body);
    ie
}

pub(crate) fn append_wps_attr(body: &mut Vec<u8>, attr: u16, value: &[u8]) {
    body.extend_from_slice(&attr.to_be_bytes());
    body.extend_from_slice(&(value.len() as u16).to_be_bytes());
    body.extend_from_slice(value);
}

pub(crate) fn eap_identity_payload(identity: &str) -> Vec<u8> {
    let identity_bytes = identity.as_bytes();
    let eap_len = 5 + identity_bytes.len();
    let mut eap = vec![0x02, 0x01];
    eap.extend_from_slice(&(eap_len as u16).to_be_bytes());
    eap.push(0x01);
    eap.extend_from_slice(identity_bytes);

    let mut payload = LLC_SNAP_EAPOL_PREFIX.to_vec();
    payload.push(0x02);
    payload.push(0x00);
    payload.extend_from_slice(&(eap.len() as u16).to_be_bytes());
    payload.extend_from_slice(&eap);
    payload
}

pub(crate) fn eapol_key_payload(message: u8) -> Vec<u8> {
    let key_info = match message {
        1 => 0x0080u16,
        2 => 0x0100u16,
        3 => 0x01c0u16,
        4 => 0x0300u16,
        _ => 0,
    };
    let mut payload = LLC_SNAP_EAPOL_PREFIX.to_vec();
    payload.push(0x02);
    payload.push(0x03);
    payload.extend_from_slice(&3u16.to_be_bytes());
    payload.push(0x02);
    payload.extend_from_slice(&key_info.to_be_bytes());
    payload
}

pub(crate) fn dynamic_channel_radiotap_header() -> Vec<u8> {
    vec![
        0x00, 0x00, 0x19, 0x00, 0x6d, 0x08, 0x00, 0x00, 0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02,
        0x01, 0x0c, 0x00, 0x85, 0x09, 0x80, 0x04, 0xd6, 0xa1, 0x03,
    ]
}

pub(crate) fn dynamic_channel_beacon_frame() -> Vec<u8> {
    let frame = build_frame(0x80, 0x00, BROADCAST, AP, AP, None, beacon_body());
    let mut bytes = dynamic_channel_radiotap_header();
    bytes.extend_from_slice(&frame[10..]);
    bytes
}

pub(crate) fn qos_data_to_distribution_radiotap_frame(qos_control: u16, payload: Vec<u8>) -> Vec<u8> {
    let mut body = qos_control.to_le_bytes().to_vec();
    body.extend_from_slice(&payload);
    build_frame(0x88, 0x01, AP, CLIENT, DISTRIBUTION_DST, None, body)
}

pub(crate) fn llc_snap_ipv4_udp_payload(
    src_ip: [u8; 4],
    dst_ip: [u8; 4],
    src_port: u16,
    dst_port: u16,
    udp_payload: &[u8],
) -> Vec<u8> {
    let udp_len = (8 + udp_payload.len()) as u16;
    let total_len = 20 + udp_len;
    let mut bytes = vec![0xaa, 0xaa, 0x03, 0x00, 0x00, 0x00, 0x08, 0x00];
    bytes.extend_from_slice(&[
        0x45,
        0x00,
        (total_len >> 8) as u8,
        total_len as u8,
        0x12,
        0x34,
        0x00,
        0x00,
        64,
        17,
        0x00,
        0x00,
    ]);
    bytes.extend_from_slice(&src_ip);
    bytes.extend_from_slice(&dst_ip);
    bytes.extend_from_slice(&src_port.to_be_bytes());
    bytes.extend_from_slice(&dst_port.to_be_bytes());
    bytes.extend_from_slice(&udp_len.to_be_bytes());
    bytes.extend_from_slice(&0u16.to_be_bytes());
    bytes.extend_from_slice(udp_payload);
    bytes
}

pub(crate) fn llc_snap_ipv4_tcp_payload(
    src_ip: [u8; 4],
    dst_ip: [u8; 4],
    src_port: u16,
    dst_port: u16,
    tcp_flags: u8,
    tcp_payload: &[u8],
) -> Vec<u8> {
    let tcp_len = 20 + tcp_payload.len();
    let total_len = 20 + tcp_len;
    let mut bytes = vec![0xaa, 0xaa, 0x03, 0x00, 0x00, 0x00, 0x08, 0x00];
    bytes.extend_from_slice(&[
        0x45,
        0x00,
        (total_len >> 8) as u8,
        total_len as u8,
        0xab,
        0xcd,
        0x00,
        0x00,
        64,
        6,
        0x00,
        0x00,
    ]);
    bytes.extend_from_slice(&src_ip);
    bytes.extend_from_slice(&dst_ip);
    bytes.extend_from_slice(&src_port.to_be_bytes());
    bytes.extend_from_slice(&dst_port.to_be_bytes());
    bytes.extend_from_slice(&0x0102_0304u32.to_be_bytes());
    bytes.extend_from_slice(&0x0000_0000u32.to_be_bytes());
    bytes.push(0x50);
    bytes.push(tcp_flags);
    bytes.extend_from_slice(&0x4000u16.to_be_bytes());
    bytes.extend_from_slice(&0u16.to_be_bytes());
    bytes.extend_from_slice(&0u16.to_be_bytes());
    bytes.extend_from_slice(tcp_payload);
    bytes
}

pub(crate) fn ssdp_udp_payload() -> Vec<u8> {
    b"M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nST: urn:schemas-upnp-org:device:MediaRenderer:1\r\nMX: 3\r\nMAN: \"ssdp:discover\"\r\nUSN: uuid:device-1::upnp:rootdevice\r\n\r\n".to_vec()
}

pub(crate) fn dns_query_payload(name: &str) -> Vec<u8> {
    let mut bytes = vec![
        0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ];
    append_dns_name(&mut bytes, name);
    bytes.extend_from_slice(&[0x00, 0x01, 0x00, 0x01]);
    bytes
}

pub(crate) fn mdns_response_payload(name: &str) -> Vec<u8> {
    let mut bytes = vec![
        0x00, 0x00, 0x84, 0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
    ];
    append_dns_name(&mut bytes, name);
    bytes.extend_from_slice(&[0x00, 0x0c, 0x00, 0x01]);
    append_dns_name(&mut bytes, name);
    bytes.extend_from_slice(&[0x00, 0x0c, 0x00, 0x01, 0x00, 0x00, 0x00, 0x78]);
    let mut rdata = Vec::new();
    append_dns_name(&mut rdata, "speaker.local");
    bytes.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
    bytes.extend_from_slice(&rdata);
    bytes
}

pub(crate) fn dhcp_discover_payload() -> Vec<u8> {
    let mut bytes = vec![0u8; 240];
    bytes[0] = 1;
    bytes[1] = 1;
    bytes[2] = 6;
    bytes[236..240].copy_from_slice(&[99, 130, 83, 99]);
    bytes.extend_from_slice(&[53, 1, 1]);
    bytes.extend_from_slice(&[50, 4, 192, 168, 1, 44]);
    bytes.extend_from_slice(&[12, 6]);
    bytes.extend_from_slice(b"sensor");
    bytes.extend_from_slice(&[60, 11]);
    bytes.extend_from_slice(b"AcmeClient1");
    bytes.push(255);
    bytes
}

fn append_dns_name(bytes: &mut Vec<u8>, name: &str) {
    for label in name.split('.') {
        bytes.push(label.len() as u8);
        bytes.extend_from_slice(label.as_bytes());
    }
    bytes.push(0);
}
