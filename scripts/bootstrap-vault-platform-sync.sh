#!/usr/bin/env bash
# Provision the renewable read-only Vault token consumed by platform-sync.
# Run once with a Vault administrator token. The service token is written to
# PLATFORM_SYNC_TOKEN_FILE and is never printed.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
POLICY_NAME="platform-sync-ro"
POLICY_FILE="$REPO_ROOT/vault/policies/platform-sync-ro.hcl"
TOKEN_FILE="${PLATFORM_SYNC_TOKEN_FILE:-}"
TOKEN_PERIOD="${PLATFORM_SYNC_TOKEN_PERIOD:-24h}"

if [ -z "$TOKEN_FILE" ]; then
    echo "ERROR: Set PLATFORM_SYNC_TOKEN_FILE to a path outside the repository." >&2
    exit 1
fi

if [ -e "$TOKEN_FILE" ]; then
    echo "ERROR: Refusing to replace existing token file: $TOKEN_FILE" >&2
    exit 1
fi

if ! vault status -format=json >/dev/null 2>&1; then
    echo "ERROR: Cannot connect to Vault. Check VAULT_ADDR, VAULT_CACERT and VAULT_TOKEN." >&2
    exit 1
fi

echo "Writing Vault policy: $POLICY_NAME"
vault policy write "$POLICY_NAME" "$POLICY_FILE" >/dev/null

token_dir="$(dirname "$TOKEN_FILE")"
mkdir -p "$token_dir"
chmod 700 "$token_dir"
umask 077
temporary_token="$(mktemp "$token_dir/.platform-sync-token.XXXXXX")"
trap 'rm -f "$temporary_token"' EXIT

vault token create \
    -policy="$POLICY_NAME" \
    -period="$TOKEN_PERIOD" \
    -orphan \
    -no-default-policy \
    -renewable=true \
    -display-name=ssl-proxy-platform-sync \
    -format=json \
    | jq -er '.auth.client_token' > "$temporary_token"

chmod 600 "$temporary_token"
mv "$temporary_token" "$TOKEN_FILE"
trap - EXIT
echo "Created renewable read-only token at $TOKEN_FILE"
