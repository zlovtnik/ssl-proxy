#!/usr/bin/env bash
# Bootstrap Vault for platform-sync: create policy and K8s auth role
# Run this once by a human with Vault admin capability
# Idempotent: safe to re-run

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

POLICY_NAME="platform-sync-ro"
ROLE_NAME="platform-sync"
SA_NAME="ssl-proxy-platform-sync"
SA_NAMESPACE="prod-ssl-proxy"
POLICY_FILE="$REPO_ROOT/vault/policies/platform-sync-ro.hcl"

echo "=== Vault Platform Sync Bootstrap ==="

# Check Vault connectivity
if ! vault status -format=json >/dev/null 2>&1; then
    echo "ERROR: Cannot connect to Vault. Check VAULT_ADDR and VAULT_TOKEN." >&2
    exit 1
fi

echo "Vault connected: $(vault status -format=json | python3 -c 'import sys,json; print(json.load(sys.stdin)["initialized"])')"

# Write policy
echo "Writing policy: $POLICY_NAME"
vault policy write "$POLICY_NAME" "$POLICY_FILE"

# Enable K8s auth if not already enabled
if ! vault auth list -format=json | python3 -c 'import sys,json; exit(0 if "kubernetes/" in json.load(sys.stdin) else 1)' 2>/dev/null; then
    echo "Enabling Kubernetes auth method"
    vault auth enable kubernetes
fi

# Configure K8s auth
echo "Configuring Kubernetes auth"
vault write auth/kubernetes/config \
    kubernetes_host="https://kubernetes.default.svc" \
    disable_local_ca_jwt=true

# Create role
echo "Creating role: $ROLE_NAME"
vault write "auth/kubernetes/role/$ROLE_NAME" \
    bound_service_account_names="$SA_NAME" \
    bound_service_account_namespaces="$SA_NAMESPACE" \
    policies="$POLICY_NAME" \
    ttl="1h" \
    max_ttl="1h"

echo "=== Bootstrap complete ==="
echo "Policy: $POLICY_NAME"
echo "Role: $ROLE_NAME"
echo "ServiceAccount: $SA_NAMESPACE/$SA_NAME"
echo ""
echo "Next steps:"
echo "1. Install platform-sync on the Ubuntu server"
echo "2. Start the credential generator timer"
echo "3. Verify the sync completes successfully"
