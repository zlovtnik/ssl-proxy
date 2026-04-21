#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
MEMORY_FILE="${UP_READY_MEMORY_FILE:-$ROOT_DIR/ops-memory.md}"

if [ ! -f "$MEMORY_FILE" ]; then
    echo "[memo-show][ERROR] missing memory file: $MEMORY_FILE" >&2
    exit 1
fi

cat "$MEMORY_FILE"
