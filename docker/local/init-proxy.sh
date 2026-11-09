#!/usr/bin/env bash
set -euo pipefail
umask 077

mkdir -p /config/templates /config/coredns /config/server /run/local-secrets
cp /bootstrap/server.conf /config/templates/server.conf
if [ "${LOCAL_MAC_EGRESS_ENABLED:-false}" = "true" ]; then
    dns_port="${LOCAL_MAC_DNS_PORT:-1853}"
    case "$dns_port" in
        ''|*[!0-9]*) echo "LOCAL_MAC_DNS_PORT must be a TCP port" >&2; exit 1 ;;
    esac
    if [ "$dns_port" -lt 1 ] || [ "$dns_port" -gt 65535 ]; then
        echo "LOCAL_MAC_DNS_PORT must be between 1 and 65535" >&2
        exit 1
    fi
    if ! host_ip=$(getent ahostsv4 host.docker.internal | awk 'NR == 1 {print $1}') || [ -z "$host_ip" ]; then
        echo "Failed to resolve an IPv4 address for host.docker.internal; refusing DNS relay setup" >&2
        exit 1
    fi
    if ! grep -Fxq '    forward . tls://1.1.1.1 tls://1.0.0.1 {' /bootstrap/Corefile; then
        echo "Corefile is missing the expected DNS upstream line; refusing relay bypass" >&2
        exit 1
    fi
    sed "s|tls://1\\.1\\.1\\.1 tls://1\\.0\\.0\\.1|tls://${host_ip}:${dns_port}|" \
        /bootstrap/Corefile > /config/coredns/Corefile
    if ! grep -Fxq "    forward . tls://${host_ip}:${dns_port} {" /config/coredns/Corefile; then
        echo "Corefile DNS relay substitution failed; refusing relay bypass" >&2
        exit 1
    fi
else
    cp /bootstrap/Corefile /config/coredns/Corefile
fi

if [ ! -s /run/local-secrets/admin_api_key ]; then
    admin_key_tmp=$(mktemp /run/local-secrets/.admin_api_key.XXXXXX)
    if ! openssl rand -hex 32 > "$admin_key_tmp"; then
        rm -f "$admin_key_tmp"
        echo "Failed to generate the local admin API key" >&2
        exit 1
    fi
    mv "$admin_key_tmp" /run/local-secrets/admin_api_key
fi
if [ ! -s /config/server/privatekey-server ]; then
    /app/ssl-proxy boringtun genkey > /config/server/privatekey-server
fi
/app/ssl-proxy boringtun pubkey < /config/server/privatekey-server > /config/server/publickey-server

for peer in peer1 peer2; do
    mkdir -p "/config/$peer"
    if [ ! -s "/config/$peer/privatekey-$peer" ]; then
        /app/ssl-proxy boringtun genkey > "/config/$peer/privatekey-$peer"
    fi
    if [ ! -s "/config/$peer/presharedkey-$peer" ]; then
        openssl rand -base64 32 > "/config/$peer/presharedkey-$peer"
    fi
    /app/ssl-proxy boringtun pubkey < "/config/$peer/privatekey-$peer" > "/config/$peer/publickey-$peer"
    case "$peer" in
        peer1) address=10.13.13.2/32 ;;
        peer2) address=10.13.13.3/32 ;;
    esac
    cat > "/config/$peer/$peer.conf" <<EOF
[Interface]
Address = $address
PrivateKey = $(cat "/config/$peer/privatekey-$peer")
DNS = 10.13.13.1
MTU = 1420

[Peer]
PublicKey = $(cat /config/server/publickey-server)
PresharedKey = $(cat "/config/$peer/presharedkey-$peer")
Endpoint = ${LOCAL_VPN_ENDPOINT}:${LOCAL_VPN_PORT}
AllowedIPs = 0.0.0.0/0
PersistentKeepalive = 25
EOF
done
echo "Local VPN keys and peer profiles ready in the wireguard-config volume."
