#!/usr/bin/env bash
# Create a short-lived, narrow Vault token for one PostgreSQL rotation window.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
POLICY_NAME="postgres-rotation"
POLICY_FILE="$REPO_ROOT/vault/policies/postgres-rotation.hcl"
TOKEN_FILE="${POSTGRES_ROTATION_TOKEN_FILE:-}"
TOKEN_TTL="${POSTGRES_ROTATION_TOKEN_TTL:-30m}"
TOKEN_MAX_TTL="${POSTGRES_ROTATION_TOKEN_MAX_TTL:-2h}"

if [ -z "$TOKEN_FILE" ]; then
    echo "ERROR: Set POSTGRES_ROTATION_TOKEN_FILE to a path outside the repository." >&2
    exit 1
fi
case "$TOKEN_FILE" in
    "$REPO_ROOT"/*|"")
        echo "ERROR: Token file must be outside the repository: $TOKEN_FILE" >&2
        exit 1
        ;;
esac
if [ -e "$TOKEN_FILE" ]; then
    echo "ERROR: Refusing to replace existing token file: $TOKEN_FILE" >&2
    exit 1
fi
if ! vault status -format=json >/dev/null 2>&1; then
    echo "ERROR: Cannot connect to Vault. Check VAULT_ADDR, VAULT_CACERT and VAULT_TOKEN." >&2
    exit 1
fi

require_admin_capability() {
    local path="$1"
    local capabilities
    capabilities="$(vault token capabilities "$path" | tr -d '[:space:]')" || {
        echo "ERROR: Cannot inspect Vault capabilities for $path." >&2
        exit 1
    }
    case ",$capabilities," in
        *,root,*|*,sudo,*|*,create,*|*,update,*) return 0 ;;
        *)
            echo "ERROR: The active Vault token cannot administer $path." >&2
            exit 1
            ;;
    esac
}

require_admin_capability "sys/policies/acl/$POLICY_NAME"
require_admin_capability "auth/token/create-orphan"
vault policy write "$POLICY_NAME" "$POLICY_FILE" >/dev/null

token_dir="$(dirname "$TOKEN_FILE")"
if [ ! -d "$token_dir" ]; then
    mkdir -p "$token_dir"
    chmod 700 "$token_dir"
else
    current_mode="$(stat -f '%Lp' "$token_dir" 2>/dev/null || stat -c '%a' "$token_dir" 2>/dev/null)"
    if [ "$current_mode" != "700" ]; then
        echo "ERROR: Existing token directory $token_dir has mode $current_mode, expected 700" >&2
        exit 1
    fi
fi
umask 077
temporary_token="$(mktemp "$token_dir/.postgres-rotation-token.XXXXXX")"
trap 'rm -f "$temporary_token"' EXIT

vault token create \
    -policy="$POLICY_NAME" \
    -ttl="$TOKEN_TTL" \
    -explicit-max-ttl="$TOKEN_MAX_TTL" \
    -orphan \
    -no-default-policy \
    -renewable=false \
    -display-name=ssl-proxy-postgres-rotation \
    -format=json \
    | jq -er '.auth.client_token' > "$temporary_token"

chmod 600 "$temporary_token"
mv "$temporary_token" "$TOKEN_FILE"
trap - EXIT
echo "Created short-lived PostgreSQL rotation token at $TOKEN_FILE"
echo "Revoke it after validation with: VAULT_TOKEN=... vault token revoke -self"
