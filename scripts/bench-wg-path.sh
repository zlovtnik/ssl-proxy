#!/usr/bin/env bash
set -euo pipefail

DURATION="${DURATION:-20}"
PARALLEL="${PARALLEL:-4}"
UDP_BW="${UDP_BW:-1G}"
OUT_DIR="${OUT_DIR:-bench-results/wg-path-$(date +%Y%m%d-%H%M%S)}"
BYPASS_TARGET="${BYPASS_TARGET:-${IPERF_SERVER:-}}"
PLAIN_TARGET="${PLAIN_TARGET:-${IPERF_SERVER:-}}"
OBFS_TARGET="${OBFS_TARGET:-${IPERF_SERVER:-}}"
PERF_PID="${PERF_PID:-}"

usage() {
    cat <<EOF
Usage:
  BYPASS_TARGET=<host> PLAIN_TARGET=<host> OBFS_TARGET=<host> [PERF_PID=<pid>] $0

Environment:
  DURATION   iperf duration in seconds (default: 20)
  PARALLEL   TCP parallel streams (default: 4)
  UDP_BW     UDP target bandwidth (default: 1G)
  OUT_DIR    output directory (default: bench-results/wg-path-<timestamp>)
  PERF_PID   optional ssl-proxy or wg-obfs-shim PID for perf stat during obfs TCP

Set IPERF_SERVER to reuse the same target for all three paths.
EOF
}

require_tool() {
    if ! command -v "$1" >/dev/null 2>&1; then
        echo "missing required tool: $1" >&2
        exit 2
    fi
}

snapshot_fragments() {
    local output="$1"
    if command -v netstat >/dev/null 2>&1; then
        netstat -s | grep -i 'frag\|reassembl' >"$output" || true
    else
        printf 'netstat unavailable\n' >"$output"
    fi
}

snapshot_ss() {
    local output="$1"
    if command -v ss >/dev/null 2>&1; then
        ss -s >"$output" || true
    else
        printf 'ss unavailable\n' >"$output"
    fi
}

run_iperf_case() {
    local label="$1"
    local target="$2"
    shift 2

    if [ -z "$target" ]; then
        echo "skip $label: target not set"
        return
    fi

    echo "run $label -> $target"
    snapshot_ss "$OUT_DIR/${label}.ss.before.txt"
    snapshot_fragments "$OUT_DIR/${label}.fragments.before.txt"

    local perf_job=""
    if [ "$label" = "obfs-tcp" ] && [ -n "$PERF_PID" ] && command -v perf >/dev/null 2>&1; then
        perf stat \
            -e cycles,cache-misses,context-switches \
            -p "$PERF_PID" \
            -o "$OUT_DIR/${label}.perf.txt" \
            -- sleep "$DURATION" &
        perf_job="$!"
    fi

    if iperf3 -c "$target" "$@" -J >"$OUT_DIR/${label}.iperf.json"; then
        echo "pass $label"
    else
        echo "fail $label" >&2
    fi

    if [ -n "$perf_job" ]; then
        wait "$perf_job" || true
    fi
    snapshot_ss "$OUT_DIR/${label}.ss.after.txt"
    snapshot_fragments "$OUT_DIR/${label}.fragments.after.txt"
}

main() {
    if [ "${1:-}" = "--help" ] || [ "${1:-}" = "-h" ]; then
        usage
        exit 0
    fi

    require_tool iperf3
    mkdir -p "$OUT_DIR"

    run_iperf_case bypass-tcp "$BYPASS_TARGET" -t "$DURATION" -P "$PARALLEL"
    run_iperf_case bypass-udp "$BYPASS_TARGET" -u -b "$UDP_BW" -t "$DURATION"
    run_iperf_case plain-tcp "$PLAIN_TARGET" -t "$DURATION" -P "$PARALLEL"
    run_iperf_case plain-udp "$PLAIN_TARGET" -u -b "$UDP_BW" -t "$DURATION"
    run_iperf_case obfs-tcp "$OBFS_TARGET" -t "$DURATION" -P "$PARALLEL"
    run_iperf_case obfs-udp "$OBFS_TARGET" -u -b "$UDP_BW" -t "$DURATION"

    echo "results: $OUT_DIR"
}

main "$@"
