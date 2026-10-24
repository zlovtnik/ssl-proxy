use std::fs;

#[test]
fn wireguard_template_redirects_tcp_and_drops_udp_443_when_enabled() {
    let path = format!(
        "{}/config/templates/server.conf",
        env!("CARGO_MANIFEST_DIR")
    );
    let template = fs::read_to_string(path).expect("wireguard template should exist");
    let rendered = template.replace("__WG_PUBLIC_PORT__", "443");

    assert!(template.contains("ListenPort = __WG_INTERNAL_PORT__"));
    assert!(template.contains(
        "iptables -A INPUT -i __WG_WAN_INTERFACE__ -p udp --dport __WG_PUBLIC_PORT__ -j ACCEPT"
    ));
    assert!(rendered.lines().any(|line| line.trim()
        == "PostUp = iptables -A INPUT -i __WG_WAN_INTERFACE__ -p udp --dport 443 -j ACCEPT"));
    assert!(template.contains(
        "if [ \"__WG_PUBLIC_PORT__\" != \"443\" ]; then iptables -A INPUT -i __WG_WAN_INTERFACE__ -p udp --dport 443 -j ACCEPT; fi"
    ));
    assert!(template.contains(
        "iptables -t nat -A PREROUTING -i %i -p tcp --dport 443 -j REDIRECT --to-port 3001"
    ));
    assert!(template.contains(
        "iptables -t nat -A PREROUTING -i %i -p tcp --dport 80 -j REDIRECT --to-port 3001"
    ));
    assert!(template.contains("WG_DROP_UDP_443:-1"));
    assert!(template.contains("iptables -A FORWARD -i %i -p udp --dport 443 -j DROP"));
    assert!(template.contains("iptables -D FORWARD -i %i -p udp --dport 443 -j DROP"));
    assert!(template.contains(
        "iptables -D INPUT -i __WG_WAN_INTERFACE__ -p udp --dport __WG_PUBLIC_PORT__ -j ACCEPT"
    ));
    assert!(template.contains(
        "if [ \"__WG_PUBLIC_PORT__\" != \"443\" ]; then iptables -D INPUT -i __WG_WAN_INTERFACE__ -p udp --dport 443 -j ACCEPT; fi"
    ));
    assert!(template.contains("__WG_PEERS__"));
    assert!(!template.contains("__WG_PEER1_PUBLIC_KEY__"));
    assert!(!template.contains("__WG_PEER2_PUBLIC_KEY__"));
}

#[test]
fn direct_peer_template_uses_normal_wireguard_mtu() {
    let path = format!("{}/config/templates/peer.conf", env!("CARGO_MANIFEST_DIR"));
    let template = fs::read_to_string(path).expect("peer template should exist");

    assert!(template.contains("MTU = ${WG_MTU:-1420}"));
    assert!(!template.contains("ListenPort ="));
}

#[test]
fn obfuscated_peer_examples_use_framed_aead_mtu() {
    for peer in ["peer1", "peer2"] {
        let path = format!(
            "{}/config/{peer}/{peer}-obfuscated.conf.example",
            env!("CARGO_MANIFEST_DIR")
        );
        let template = fs::read_to_string(&path).expect("obfuscated peer template should exist");

        // The v2 framed format replaces the legacy magic byte with a keyed
        // header tag; the MTU leaves headroom for the 30-byte header, 2-byte
        // length field, and 16-byte AEAD tag.
        assert!(template.contains("MTU = 1419"));
        assert!(template.contains("framed AEAD overhead"));
        assert!(!template.contains("WG_OBFUSCATION_MAGIC_BYTE"));
    }
}

#[test]
fn linux_containment_limits_physical_egress_to_owned_expiring_tuples() {
    let template = fs::read_to_string(format!(
        "{}/config/client/leak-containment-linux.nft.example",
        env!("CARGO_MANIFEST_DIR")
    ))
    .expect("Linux containment reference should exist");
    let rules: Vec<_> = template
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .collect();

    assert!(rules.contains(&"table inet wg_containment {"));
    assert!(rules.contains(&"type filter hook output priority filter; policy drop;"));
    assert!(rules.contains(&"type filter hook forward priority filter; policy drop;"));
    assert!(rules.contains(&"oifname \"lo\" counter accept"));
    assert!(rules.contains(&"oifname $wireguard counter accept"));
    assert!(rules.contains(&"type ipv4_addr . inet_service"));
    assert!(rules.contains(&"type ipv6_addr . inet_service"));
    assert_eq!(
        rules.iter().filter(|line| **line == "timeout 1h").count(),
        2
    );
    assert!(rules.contains(&"elements = { __RELAY_IPV4__ . __RELAY_PORT__ timeout 1h }"));
    assert!(rules.contains(&"elements = { __RELAY_IPV6__ . __RELAY_PORT__ timeout 1h }"));

    // Every physical accept must be an exact owned tuple or scoped IPv6 ND.
    // In particular, established application sockets get no physical bypass.
    for line in rules.iter().filter(|line| line.ends_with("accept")) {
        if *line == "oifname \"lo\" counter accept" || *line == "oifname $wireguard counter accept"
        {
            continue;
        }
        assert!(line.starts_with("oifname $physical "), "{line}");
        assert!(
            *line == "oifname $physical meta skuid $shim_uid ip daddr . udp dport @relay4 counter accept"
                || *line == "oifname $physical meta skuid $shim_uid ip6 daddr . udp dport @relay6 counter accept"
                || (line.contains("ip6 hoplimit 255 ip6 daddr")
                    && line.contains("icmpv6 type")
                    && line.contains("icmpv6 code 0")
                    && !line.contains("router")),
            "physical exception must be reviewed: {line}"
        );
    }
    assert!(!rules.iter().any(|line| line.contains("ct state")));
    assert!(!rules.iter().any(|line| line.contains("flush ruleset")));
}

#[test]
fn shim_unit_requires_separate_containment_without_network_admin() {
    let unit = fs::read_to_string(format!(
        "{}/config/client/wg-obfs-shim.service",
        env!("CARGO_MANIFEST_DIR")
    ))
    .expect("shim unit should exist");
    assert!(unit.contains("Requires=wg-client-containment.service"));
    assert!(unit.contains("After=network-online.target wg-client-containment.service"));
    assert!(unit.contains("EnvironmentFile=/etc/wireguard/wg-obfs-shim.env"));
    assert!(unit.lines().any(|line| line == "CapabilityBoundingSet="));
    assert!(unit.lines().any(|line| line == "AmbientCapabilities="));
    assert!(unit.contains("User=wg-obfs-shim"));
    assert!(!unit.contains("ExecStop="));
    assert!(!unit.contains("CAP_NET_ADMIN"));
    for peer in ["peer1", "peer2"] {
        let template = fs::read_to_string(format!(
            "{}/config/{peer}/{peer}-obfuscated.conf.example",
            env!("CARGO_MANIFEST_DIR")
        ))
        .expect("obfuscated peer should exist");
        assert!(template.contains("Endpoint = 127.0.0.1:51821"));
        assert!(template.contains("AllowedIPs = 0.0.0.0/0, ::/0"));
        assert!(template.contains("wg-client-containment.service"));
        assert!(template.contains("after WG/shim shutdown"));
        assert!(!template.lines().any(|line| line.starts_with("PostDown =")));
    }
}
