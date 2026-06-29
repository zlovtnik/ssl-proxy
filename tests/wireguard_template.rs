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
}

#[test]
fn obfuscated_peer_examples_use_legacy_magic_mtu() {
    for peer in ["peer1", "peer2"] {
        let path = format!(
            "{}/config/{peer}/{peer}-obfuscated.conf.example",
            env!("CARGO_MANIFEST_DIR")
        );
        let template = fs::read_to_string(path).expect("obfuscated peer template should exist");

        assert!(template.contains("MTU = 1419"));
        assert!(template.contains("legacy XOR plus a 1-byte magic marker"));
    }
}
