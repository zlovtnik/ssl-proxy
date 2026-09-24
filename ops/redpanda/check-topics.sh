#!/usr/bin/env bash
set -euo pipefail

# Static contract check for the tracked Redpanda topic manifest plus an
# optional read-only drift check against a live cluster.
#
# Usage:
#   ops/redpanda/check-topics.sh           # static only (CI)
#   ops/redpanda/check-topics.sh --live    # static + live drift (read-only)

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
live=0

for argument in "$@"; do
  case "$argument" in
    --live) live=1 ;;
    -h|--help)
      sed -n '2,10p' "$0"
      exit 0
      ;;
    *)
      printf 'check-topics: unknown argument: %s\n' "$argument" >&2
      exit 1
      ;;
  esac
done

python3 "$repo_root/scripts/check_redpanda_maintenance.py"
printf 'check-topics: static manifest contract holds\n'

if (( live )); then
  python3 "$repo_root/ops/redpanda/reconcile_topics.py" check
fi
