#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
MEMORY_FILE="${UP_READY_MEMORY_FILE:-$ROOT_DIR/ops-memory.md}"
EVENT="${EVENT:-}"
CONTEXT="${CONTEXT:-}"
RESULT="${RESULT:-}"
PROFILE_MODE="${PROFILE_MODE:-unknown}"
SIGNATURE="${SIGNATURE:-none}"
ACTION="${ACTION:-manual-note}"

case "$RESULT" in
    pass|fail) ;;
    *)
        echo "[memo-log][ERROR] RESULT must be pass or fail" >&2
        exit 1
        ;;
esac

if [ -z "$EVENT" ] || [ -z "$CONTEXT" ]; then
    cat >&2 <<'EOF_USAGE'
[memo-log][ERROR] EVENT and CONTEXT are required.
Example:
  make memo-log EVENT="iphone tunnel validated" CONTEXT="server 192.168.1.221 amd64; client 192.168.1.68 iPhone" RESULT=pass PROFILE_MODE=iphone
EOF_USAGE
    exit 1
fi

if [ ! -f "$MEMORY_FILE" ]; then
    echo "[memo-log][ERROR] missing memory file: $MEMORY_FILE" >&2
    exit 1
fi

grep -q '^## Incident Timeline' "$MEMORY_FILE" || {
    echo "[memo-log][ERROR] memory schema invalid: missing Incident Timeline section" >&2
    exit 1
}

TS="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
entry="- ${TS} | result=${RESULT} | mode=${PROFILE_MODE} | signature=${SIGNATURE} | action=${ACTION} | context=${CONTEXT} | event=${EVENT}"
tmp_file="$(mktemp)"
awk -v entry="$entry" '
    { print }
    !inserted && $0 ~ /^## Incident Timeline/ {
        print entry
        inserted = 1
    }
    END {
        if (!inserted) {
            print entry
        }
    }
' "$MEMORY_FILE" >"$tmp_file"
mv "$tmp_file" "$MEMORY_FILE"

echo "[memo-log] inserted incident entry"
