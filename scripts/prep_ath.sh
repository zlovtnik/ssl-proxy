#!/usr/bin/env bash
set -euo pipefail

if [[ $# -gt 1 ]]; then
  echo "usage: $0 [interface]" >&2
  exit 2
fi

IFACE="${1:-${ATH_SENSOR_DEVICE:-wlan0}}"
REG_DOMAIN="${ATH_SENSOR_REG_DOMAIN:-US}"
CHANNEL="${ATH_SENSOR_CHANNEL:-6}"

set_channel() {
  local iface="$1"
  local channel="$2"
  iw dev "${iface}" set channel "${channel}"
}

iw reg set "${REG_DOMAIN}"
ip link set "${IFACE}" down
iw "${IFACE}" set monitor control
ip link set "${IFACE}" up
set_channel "${IFACE}" "${CHANNEL}"
