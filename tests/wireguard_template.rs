use std::fs;

#[test]
fn wireguard_template_redirects_tcp_and_drops_udp_443_when_enabled() {
    let path = format!(
        "{}/config/templates/server.conf",
        env!("CARGO_MANIFEST_DIR")
    );
    let template = fs::read_to_string(path).expect("wireguard template should exist");

    assert!(template.contains("ListenPort = __WG_INTERNAL_PORT__"));
    assert!(template.contains(
        "iptables -A INPUT -i __WG_WAN_INTERFACE__ -p udp --dport __WG_PUBLIC_PORT__ -j ACCEPT"
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
}
