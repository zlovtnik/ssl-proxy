#!/usr/bin/env bash
set -euo pipefail

usage() {
    cat <<'EOF'
Usage: prep_ath.sh [--reg-domain DOMAIN] [--channel CHANNEL] [interface]

Prepare a wireless interface for monitor-mode capture.

Defaults:
  interface    ATH_SENSOR_DEVICE or wlan0
  DOMAIN       ATH_SENSOR_REG_DOMAIN or US
  CHANNEL      ATH_SENSOR_CHANNEL or 6
EOF
}

fail() {
    printf 'prep_ath.sh: %s\n' "$*" >&2
    exit 1
}

require_command() {
    command -v "$1" >/dev/null 2>&1 || fail "required command not found: $1"
}

require_root() {
    if (( EUID != 0 )); then
        fail "must be run as root (try: sudo $0)"
    fi
}

main() {
    local iface="${ATH_SENSOR_DEVICE:-wlan0}"
    local reg_domain="${ATH_SENSOR_REG_DOMAIN:-US}"
    local channel="${ATH_SENSOR_CHANNEL:-6}"
    local interface_seen=0

    while (( $# > 0 )); do
        case "$1" in
            --reg-domain)
                (( $# >= 2 )) || fail "--reg-domain requires a value"
                reg_domain="$2"
                shift 2
                ;;
            --reg-domain=*)
                reg_domain="${1#*=}"
                shift
                ;;
            --channel)
                (( $# >= 2 )) || fail "--channel requires a value"
                channel="$2"
                shift 2
                ;;
            --channel=*)
                channel="${1#*=}"
                shift
                ;;
            -h|--help)
                usage
                return 0
                ;;
            --)
                shift
                if (( $# > 1 )); then
                    fail "expected at most one interface"
                fi
                if (( $# == 1 )); then
                    iface="$1"
                    interface_seen=1
                fi
                break
                ;;
            -*)
                fail "unknown option: $1"
                ;;
            *)
                (( interface_seen == 0 )) || fail "expected at most one interface"
                iface="$1"
                interface_seen=1
                shift
                ;;
        esac
    done

    [[ -n "$iface" ]] || fail "interface must not be empty"
    [[ "$reg_domain" =~ ^([[:alpha:]]{2}|00)$ ]] || \
        fail "regulatory domain must be a two-letter country code or 00"
    [[ "$channel" =~ ^[0-9]+$ ]] || fail "channel must be a positive integer"
    (( 10#$channel > 0 )) || fail "channel must be a positive integer"

    reg_domain="${reg_domain^^}"

    require_root
    require_command ip
    require_command iw

    ip link show dev "$iface" >/dev/null 2>&1 || fail "wireless interface not found: $iface"

    iw reg set "$reg_domain"
    ip link set "$iface" down
    if ! iw "$iface" set monitor control; then
        ip link set "$iface" up || true
        fail "could not enable monitor mode on $iface"
    fi
    ip link set "$iface" up
    iw dev "$iface" set channel "$channel"

    printf 'Prepared %s for monitor mode (regulatory domain %s, channel %s).\n' \
        "$iface" "$reg_domain" "$channel"
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
    main "$@"
fi
