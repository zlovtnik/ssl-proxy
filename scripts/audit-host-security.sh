#!/usr/bin/env bash
set -Eeuo pipefail

# Read-only evidence collection. Run with sudo for firewall/process details.
# Socket bindings alone cannot establish Internet reachability.
section() { printf '\n=== %s ===\n' "$1"; }
inspect() {
  if ! command -v "$1" >/dev/null 2>&1; then
    printf 'UNVERIFIED: %s is not installed\n' "$1"
  elif ! "$@"; then
    printf 'UNVERIFIED: command failed: %s\n' "$*"
  fi
}

section 'Host interfaces and routes (IPv4 and IPv6)'
inspect ip -brief address
inspect ip -4 route
inspect ip -6 route

section 'All TCP listeners, including private and wildcard bindings'
inspect ss -H -lntp

section 'UDP listeners (WireGuard may run in a pod network namespace)'
inspect ss -H -lnup
inspect wg show interfaces

section 'SSH socket activation and effective daemon bindings'
inspect systemctl show ssh.socket -p ActiveState -p Listen
inspect systemctl show ssh.service -p ActiveState
if command -v sshd >/dev/null 2>&1; then
  if ssh_config="$(sshd -T)"; then
    printf '%s\n' "$ssh_config" | awk '$1 == "listenaddress" || $1 == "port"'
  else
    printf 'UNVERIFIED: sshd -T failed (root may be required)\n'
  fi
else
  printf 'UNVERIFIED: sshd is not installed or is outside PATH\n'
fi

section 'Firewall evidence (review INPUT and FORWARD, NAT and IPv6)'
inspect ufw status verbose
inspect nft list ruleset
inspect iptables-save
inspect ip6tables-save

section 'Host tunnel process (absence does not check Kubernetes pods)'
if command -v pgrep >/dev/null 2>&1; then
  if ! pgrep -l -x cloudflared; then
    printf 'UNVERIFIED: no host cloudflared process; inspect tunnel pods separately\n'
  fi
else
  printf 'UNVERIFIED: pgrep is not installed\n'
fi

section 'Verification boundary'
printf '%s\n' \
  'This report is evidence collection, not a firewall compliance verdict.' \
  'Verify router forwarding/UPnP and scan the origin public IPv4 and IPv6 from outside the LAN.' \
  'Scan all TCP ports; Docker/Kubernetes published ports can bypass host INPUT rules.' \
  'Only UDP 51820 is permitted as a new inbound WAN service; preserve tunnel reply traffic.'
