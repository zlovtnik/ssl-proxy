#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

echo "[deploy-ready][WARN] scripts/deploy-and-verify.sh is deprecated. Use scripts/up-ready.sh instead."
exec ./scripts/up-ready.sh "$@"
