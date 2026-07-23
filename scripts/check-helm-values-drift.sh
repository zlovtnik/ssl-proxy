#!/usr/bin/env bash
# Check that global.shared.* keys in values.yaml and values-k8s.yaml are in sync.
# Compares the set of top-level keys under global.shared in both files
# using structural YAML parsing.
set -euo pipefail

CHART="${1:-helm/ssl-proxy}"
VALUES="$CHART/values.yaml"
K8S="$CHART/values-k8s.yaml"

if [ ! -f "$VALUES" ] || [ ! -f "$K8S" ]; then
    echo "SKIP: values files not found"
    exit 0
fi

# Extract top-level global.shared keys from each file.
# Uses yq or python3 to parse YAML.
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

echo "Checking global.shared key alignment between values.yaml and values-k8s.yaml..."

default_keys=$(extract_shared_keys "$VALUES")
k8s_keys=$(extract_shared_keys "$K8S")

missing_in_k8s=$(comm -23 <(echo "$default_keys") <(echo "$k8s_keys"))
missing_in_default=$(comm -23 <(echo "$k8s_keys") <(echo "$default_keys"))

exit_code=0

if [ -n "$missing_in_k8s" ]; then
    echo "ERROR: global.shared keys in values.yaml missing from values-k8s.yaml:"
    echo "$missing_in_k8s"
    echo "Add overlay entries for these keys in values-k8s.yaml."
    exit_code=1
fi

if [ -n "$missing_in_default" ]; then
    echo "ERROR: global.shared keys in values-k8s.yaml missing from values.yaml:"
    echo "$missing_in_default"
    echo "Add default entries for these keys in values.yaml."
    exit_code=1
fi

if [ "$exit_code" -eq 0 ]; then
    echo "OK: global.shared keys are in sync"
fi

exit "$exit_code"
