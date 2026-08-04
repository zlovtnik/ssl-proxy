#!/usr/bin/env bash
# Check that every global.shared key overridden in values-k8s.yaml has a
# corresponding default in values.yaml.  values-k8s.yaml is an overlay so it
# may omit keys; values.yaml is the canonical source and must define every key.
set -euo pipefail

CHART="${1:-helm/ssl-proxy}"
VALUES="$CHART/values.yaml"
K8S="$CHART/values-k8s.yaml"

if [ ! -f "$VALUES" ] || [ ! -f "$K8S" ]; then
    echo "SKIP: values files not found"
    exit 0
fi

extract_shared_keys() {
    local file="$1"
    if command -v yq &>/dev/null; then
        yq eval '.global.shared | keys | .[]' "$file" 2>/dev/null | sort -u || true
    elif command -v python3 &>/dev/null; then
        python3 -c "
import sys, yaml
with open('$file') as f:
    data = yaml.safe_load(f)
    shared = data.get('global', {}).get('shared', {})
    for k in shared:
        print(k)
" 2>/dev/null | sort -u || true
    else
        echo "ERR: need yq or python3" >&2
        exit 1
    fi
}

echo "Checking global.shared overlay keys have matching defaults..."

default_keys=$(extract_shared_keys "$VALUES")
k8s_keys=$(extract_shared_keys "$K8S")

missing_in_default=$(comm -23 <(echo "$k8s_keys") <(echo "$default_keys"))

exit_code=0
if [ -n "$missing_in_default" ]; then
    echo "ERROR: global.shared keys in values-k8s.yaml without matching default in values.yaml:"
    echo "$missing_in_default"
    echo "Every key overridden in values-k8s.yaml must first be defined in values.yaml."
    exit_code=1
fi

if [ "$exit_code" -eq 0 ]; then
    echo "OK: all global.shared overlay keys have defaults in values.yaml"
fi

exit "$exit_code"
