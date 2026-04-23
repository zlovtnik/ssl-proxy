use std::net::Ipv4Addr;

use crate::model::{
    ApplicationLayer, DhcpLayer, DnsLayer, Ipv4Layer, LlcSnapLayer, SsdpLayer, TransportLayer,
};

use super::eapol::data_payload_offset;

#[derive(Clone, Debug, Default)]
pub(super) struct PayloadAnalysis {
    pub llc_snap: Option<LlcSnapLayer>,
    pub network: Option<Ipv4Layer>,
    pub transport: Option<TransportLayer>,
    pub application: Option<ApplicationLayer>,
    pub llc_oui: Option<String>,
    pub ethertype: Option<u16>,
    pub ethertype_name: Option<String>,
    pub src_ip: Option<String>,
    pub dst_ip: Option<String>,
    pub ip_ttl: Option<u8>,
    pub ip_protocol: Option<u8>,
    pub ip_protocol_name: Option<String>,
    pub src_port: Option<u16>,
    pub dst_port: Option<u16>,
    pub transport_protocol: Option<String>,
    pub transport_length: Option<u16>,
    pub transport_checksum: Option<u16>,
    pub app_protocol: Option<String>,
    pub ssdp_message_type: Option<String>,
    pub ssdp_st: Option<String>,
    pub ssdp_mx: Option<String>,
    pub ssdp_usn: Option<String>,
    pub dhcp_requested_ip: Option<String>,
    pub dhcp_hostname: Option<String>,
    pub dhcp_vendor_class: Option<String>,
    pub dns_query_name: Option<String>,
    pub mdns_name: Option<String>,
}

pub(super) fn analyze_payload(
    frame_type: u8,
    frame_control: u16,
    subtype: u8,
    protected: bool,
    frame_bytes: &[u8],
) -> PayloadAnalysis {
    if frame_type != 2 || protected {
        return PayloadAnalysis::default();
    }

    let Some(payload_offset) = data_payload_offset(frame_control, subtype, frame_bytes) else {
        return PayloadAnalysis::default();
    };
    let Some(llc) = frame_bytes.get(payload_offset..payload_offset + 8) else {
        return PayloadAnalysis::default();
    };
    if llc[0] != 0xaa || llc[1] != 0xaa || llc[2] != 0x03 {
        return PayloadAnalysis::default();
    }

    let oui = format!("{:02x}:{:02x}:{:02x}", llc[3], llc[4], llc[5]);
    let ethertype = u16::from_be_bytes([llc[6], llc[7]]);
    let ethertype_name = ethertype_name(ethertype).to_string();
    let payload = frame_bytes.get(payload_offset + 8..).unwrap_or_default();

    let mut analysis = PayloadAnalysis {
        llc_snap: Some(LlcSnapLayer {
            dsap: llc[0],
            ssap: llc[1],
            control: llc[2],
            oui: oui.clone(),
            ethertype,
            ethertype_name: ethertype_name.clone(),
        }),
        llc_oui: Some(oui),
        ethertype: Some(ethertype),
        ethertype_name: Some(ethertype_name),
        ..PayloadAnalysis::default()
    };

    if ethertype != 0x0800 {
        return analysis;
    }

    let Some(ipv4) = parse_ipv4(payload) else {
        return analysis;
    };
    analysis.src_ip = Some(ipv4.src_ip.clone());
    analysis.dst_ip = Some(ipv4.dst_ip.clone());
    analysis.ip_ttl = Some(ipv4.ttl);
    analysis.ip_protocol = Some(ipv4.protocol);
    analysis.ip_protocol_name = Some(ipv4.protocol_name.clone());
    analysis.network = Some(ipv4.clone());

    let header_len = ipv4.header_len as usize;
    let total_len = usize::from(ipv4.total_len).min(payload.len());
    if total_len <= header_len {
        return analysis;
    }
    let ip_payload = &payload[header_len..total_len];

    match ipv4.protocol {
        17 => parse_udp(ip_payload, &mut analysis),
        6 => parse_tcp(ip_payload, &mut analysis),
        _ => {}
    }

    analysis
}

fn parse_ipv4(bytes: &[u8]) -> Option<Ipv4Layer> {
    let version_ihl = *bytes.first()?;
    if version_ihl >> 4 != 4 {
        return None;
    }
    let header_len = (version_ihl & 0x0f) * 4;
    if header_len < 20 || bytes.len() < header_len as usize {
        return None;
    }
    let total_len = u16::from_be_bytes([*bytes.get(2)?, *bytes.get(3)?]);
    Some(Ipv4Layer {
        src_ip: Ipv4Addr::new(*bytes.get(12)?, *bytes.get(13)?, *bytes.get(14)?, *bytes.get(15)?)
            .to_string(),
        dst_ip: Ipv4Addr::new(*bytes.get(16)?, *bytes.get(17)?, *bytes.get(18)?, *bytes.get(19)?)
            .to_string(),
        ttl: *bytes.get(8)?,
        protocol: *bytes.get(9)?,
        protocol_name: ip_protocol_name(*bytes.get(9)?).to_string(),
        header_len,
        total_len,
    })
}

fn parse_udp(bytes: &[u8], analysis: &mut PayloadAnalysis) {
    let Some(header) = bytes.get(..8) else {
        return;
    };
    let src_port = u16::from_be_bytes([header[0], header[1]]);
    let dst_port = u16::from_be_bytes([header[2], header[3]]);
    let length = u16::from_be_bytes([header[4], header[5]]);
    let checksum = u16::from_be_bytes([header[6], header[7]]);
    let payload = bytes.get(8..).unwrap_or_default();

    analysis.src_port = Some(src_port);
    analysis.dst_port = Some(dst_port);
    analysis.transport_protocol = Some("udp".to_string());
    analysis.transport_length = Some(length);
    analysis.transport_checksum = Some(checksum);
    analysis.transport = Some(TransportLayer {
        protocol: "udp".to_string(),
        src_port,
        dst_port,
        length: Some(length),
        checksum: Some(checksum),
        tcp_flags: Vec::new(),
    });

    if src_port == 1900 || dst_port == 1900 {
        if let Some(ssdp) = parse_ssdp(payload) {
            analysis.app_protocol = Some("ssdp".to_string());
            analysis.ssdp_message_type = Some(ssdp.message_type.clone());
            analysis.ssdp_st = ssdp.st.clone();
            analysis.ssdp_mx = ssdp.mx.clone();
            analysis.ssdp_usn = ssdp.usn.clone();
            analysis.application = Some(ApplicationLayer {
                protocol: Some("ssdp".to_string()),
                ssdp: Some(ssdp),
                mdns: None,
                dhcp: None,
                dns: None,
            });
        }
        return;
    }

    if src_port == 5353 || dst_port == 5353 {
        if let Some(dns) = parse_dns(payload) {
            analysis.app_protocol = Some("mdns".to_string());
            analysis.mdns_name = dns
                .query_names
                .first()
                .cloned()
                .or_else(|| dns.answer_names.first().cloned());
            analysis.application = Some(ApplicationLayer {
                protocol: Some("mdns".to_string()),
                ssdp: None,
                mdns: Some(dns),
                dhcp: None,
                dns: None,
            });
        }
        return;
    }

    if matches!(src_port, 67 | 68) || matches!(dst_port, 67 | 68) {
        if let Some(dhcp) = parse_dhcp(payload) {
            analysis.app_protocol = Some("dhcp".to_string());
            analysis.dhcp_requested_ip = dhcp.requested_ip.clone();
            analysis.dhcp_hostname = dhcp.hostname.clone();
            analysis.dhcp_vendor_class = dhcp.vendor_class.clone();
            analysis.application = Some(ApplicationLayer {
                protocol: Some("dhcp".to_string()),
                ssdp: None,
                mdns: None,
                dhcp: Some(dhcp),
                dns: None,
            });
        }
        return;
    }

    if src_port == 53 || dst_port == 53 {
        if let Some(dns) = parse_dns(payload) {
            analysis.app_protocol = Some("dns".to_string());
            analysis.dns_query_name = dns.query_names.first().cloned();
            analysis.application = Some(ApplicationLayer {
                protocol: Some("dns".to_string()),
                ssdp: None,
                mdns: None,
                dhcp: None,
                dns: Some(dns),
            });
        }
    }
}

fn parse_tcp(bytes: &[u8], analysis: &mut PayloadAnalysis) {
    let Some(header) = bytes.get(..20) else {
        return;
    };
    let src_port = u16::from_be_bytes([header[0], header[1]]);
    let dst_port = u16::from_be_bytes([header[2], header[3]]);
    let data_offset = (header[12] >> 4) * 4;
    if data_offset < 20 || bytes.len() < data_offset as usize {
        return;
    }
    let checksum = u16::from_be_bytes([header[16], header[17]]);
    analysis.src_port = Some(src_port);
    analysis.dst_port = Some(dst_port);
    analysis.transport_protocol = Some("tcp".to_string());
    analysis.transport_length = Some(bytes.len() as u16);
    analysis.transport_checksum = Some(checksum);
    analysis.transport = Some(TransportLayer {
        protocol: "tcp".to_string(),
        src_port,
        dst_port,
        length: Some(bytes.len() as u16),
        checksum: Some(checksum),
        tcp_flags: tcp_flags(header[13]),
    });
}

fn parse_ssdp(bytes: &[u8]) -> Option<SsdpLayer> {
    let text = std::str::from_utf8(bytes).ok()?;
    let mut lines = text.lines();
    let first_line = lines.next()?.trim();
    let message_type = if first_line.starts_with("M-SEARCH") {
        "M-SEARCH"
    } else if first_line.starts_with("NOTIFY") {
        "NOTIFY"
    } else if first_line.starts_with("HTTP/1.1 200") {
        "RESPONSE"
    } else {
        return None;
    };
    let mut st = None;
    let mut mx = None;
    let mut usn = None;
    for line in lines {
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        let name = name.trim().to_ascii_uppercase();
        let value = value.trim().to_string();
        match name.as_str() {
            "ST" | "NT" => st = Some(value),
            "MX" => mx = Some(value),
            "USN" => usn = Some(value),
            _ => {}
        }
    }
    Some(SsdpLayer {
        message_type: message_type.to_string(),
        st,
        mx,
        usn,
    })
}

fn parse_dhcp(bytes: &[u8]) -> Option<DhcpLayer> {
    if bytes.len() < 240 || bytes.get(236..240)? != [99, 130, 83, 99] {
        return None;
    }
    let mut message_type = None;
    let mut requested_ip = None;
    let mut hostname = None;
    let mut vendor_class = None;
    let mut cursor = 240usize;
    while cursor < bytes.len() {
        let option = *bytes.get(cursor)?;
        cursor += 1;
        match option {
            0 => continue,
            255 => break,
            _ => {}
        }
        let len = *bytes.get(cursor)? as usize;
        cursor += 1;
        let value = bytes.get(cursor..cursor + len)?;
        cursor += len;
        match option {
            53 => message_type = value.first().copied(),
            50 if value.len() == 4 => {
                requested_ip = Some(Ipv4Addr::new(value[0], value[1], value[2], value[3]).to_string())
            }
            12 => hostname = text_option(value),
            60 => vendor_class = text_option(value),
            _ => {}
        }
    }
    Some(DhcpLayer {
        message_type,
        requested_ip,
        hostname,
        vendor_class,
    })
}

fn parse_dns(bytes: &[u8]) -> Option<DnsLayer> {
    if bytes.len() < 12 {
        return None;
    }
    let qdcount = u16::from_be_bytes([bytes[4], bytes[5]]) as usize;
    let ancount = u16::from_be_bytes([bytes[6], bytes[7]]) as usize;
    let mut offset = 12usize;
    let mut query_names = Vec::new();
    let mut answer_names = Vec::new();
    for _ in 0..qdcount {
        let (name, next) = decode_dns_name(bytes, offset)?;
        query_names.push(name);
        offset = next.checked_add(4)?;
        if offset > bytes.len() {
            return None;
        }
    }
    for _ in 0..ancount {
        let (name, next) = decode_dns_name(bytes, offset)?;
        answer_names.push(name);
        offset = next.checked_add(10)?;
        if offset > bytes.len() {
            return None;
        }
        let rdlen = u16::from_be_bytes([*bytes.get(offset - 2)?, *bytes.get(offset - 1)?]) as usize;
        offset = offset.checked_add(rdlen)?;
        if offset > bytes.len() {
            return None;
        }
    }
    Some(DnsLayer {
        query_names,
        answer_names,
    })
}

fn decode_dns_name(bytes: &[u8], offset: usize) -> Option<(String, usize)> {
    let mut labels = Vec::new();
    let mut cursor = offset;
    let mut end_offset = None;
    let mut jumps = 0usize;
    loop {
        let len = *bytes.get(cursor)? as usize;
        if len & 0xc0 == 0xc0 {
            let next = *bytes.get(cursor + 1)? as usize;
            let pointer = ((len & 0x3f) << 8) | next;
            end_offset.get_or_insert(cursor + 2);
            cursor = pointer;
            jumps += 1;
            if jumps > 8 {
                return None;
            }
            continue;
        }
        cursor += 1;
        if len == 0 {
            break;
        }
        let label = bytes.get(cursor..cursor + len)?;
        labels.push(std::str::from_utf8(label).ok()?.to_string());
        cursor += len;
    }
    Some((labels.join("."), end_offset.unwrap_or(cursor)))
}

fn tcp_flags(value: u8) -> Vec<String> {
    let mut flags = Vec::new();
    if value & 0x01 != 0 {
        flags.push("fin".to_string());
    }
    if value & 0x02 != 0 {
        flags.push("syn".to_string());
    }
    if value & 0x04 != 0 {
        flags.push("rst".to_string());
    }
    if value & 0x08 != 0 {
        flags.push("psh".to_string());
    }
    if value & 0x10 != 0 {
        flags.push("ack".to_string());
    }
    if value & 0x20 != 0 {
        flags.push("urg".to_string());
    }
    if value & 0x40 != 0 {
        flags.push("ece".to_string());
    }
    if value & 0x80 != 0 {
        flags.push("cwr".to_string());
    }
    flags
}

fn ip_protocol_name(protocol: u8) -> &'static str {
    match protocol {
        1 => "icmp",
        6 => "tcp",
        17 => "udp",
        _ => "other",
    }
}

fn ethertype_name(ethertype: u16) -> &'static str {
    match ethertype {
        0x0800 => "ipv4",
        0x0806 => "arp",
        0x86dd => "ipv6",
        0x888e => "eapol",
        _ => "other",
    }
}

fn text_option(bytes: &[u8]) -> Option<String> {
    let value = std::str::from_utf8(bytes).ok()?.trim_matches(char::from(0)).trim();
    if value.is_empty() {
        None
    } else {
        Some(value.to_string())
    }
}
