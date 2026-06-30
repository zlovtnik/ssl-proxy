#!/usr/bin/env bash
set -euo pipefail

SCRIPT_PATH="${BASH_SOURCE[0]:-$0}"
ROOT_DIR="$(cd "$(dirname "$SCRIPT_PATH")/.." && pwd -P)"
source "$ROOT_DIR/scripts/lib/ops-python.sh"

if [ "$#" -eq 0 ] || [ "${1#-}" != "$1" ]; then
    sslproxy_exec_ops "$ROOT_DIR" db check-connections "$@"
fi

TARGET="$1"
PORT="${2:-8081}"
sslproxy_exec_ops "$ROOT_DIR" db check-connections --target "$TARGET" --port "$PORT"
