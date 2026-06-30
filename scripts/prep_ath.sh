#!/usr/bin/env bash
set -euo pipefail

SCRIPT_PATH="${BASH_SOURCE[0]:-$0}"
ROOT_DIR="$(python3 -c 'from pathlib import Path; import sys; print(Path(sys.argv[1]).resolve().parents[1])' "$SCRIPT_PATH")"

exec env PYTHONPATH="$ROOT_DIR/ops/src${PYTHONPATH:+:$PYTHONPATH}" python3 -m sslproxy_ops host prep-ath "$@"
