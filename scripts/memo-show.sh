#!/usr/bin/env bash
set -euo pipefail

SCRIPT_PATH="${BASH_SOURCE[0]:-$0}"
ROOT_DIR="$(cd "$(dirname "$SCRIPT_PATH")/.." && pwd -P)"

source "$ROOT_DIR/scripts/lib/ops-python.sh"
sslproxy_exec_ops "$ROOT_DIR" memo show "$@"
