#!/usr/bin/env bash
set -euo pipefail
set +x

PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
export PATH
umask 077

readonly CONFIRMATION="REPAIR-PGBOUNCER-USERLIST"
readonly PLATFORM_CONFIG="/etc/platform-sync/platform-sync.conf"
readonly VAULT_TOKEN_PATH="/etc/platform-sync/vault-token"
readonly VAULT_CA_PATH="/etc/platform-sync/vault-ca.crt"
readonly PLATFORM_BINARY="/opt/platform-sync/bin/platform-sync"
readonly POSTGRES_CONTAINER="ssl-proxy-platform-postgres"
readonly SYNC_SERVICE="vault-k8s-sync.service"
readonly SYNC_TIMER="vault-k8s-sync.timer"
readonly NAMESPACE="prod-ssl-proxy"

fail() {
    printf 'recover-platform-sync-pgbouncer: %s\n' "$*" >&2
    exit 1
}

require_command() {
    command -v "$1" >/dev/null 2>&1 || fail "required command not found: $1"
}

usage() {
    cat <<EOF
Usage: sudo $0 --confirm $CONFIRMATION

Installs the current platform-sync binary, replaces the three PgBouncer
runtime entries in Vault with their corresponding plaintext Vault passwords,
and runs platform-sync. Secret values are never printed.
EOF
}

if [[ ${1:-} != "--confirm" || ${2:-} != "$CONFIRMATION" || $# -ne 2 ]]; then
    usage >&2
    exit 2
fi

(( EUID == 0 )) || fail "must run as root"

readonly SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
readonly INSTALLER="$REPO_ROOT/scripts/install-platform-sync.sh"

[[ -x "$INSTALLER" ]] || fail "installer is missing or not executable: $INSTALLER"
[[ -r "$PLATFORM_CONFIG" ]] || fail "platform config is not readable: $PLATFORM_CONFIG"
[[ -r "$VAULT_TOKEN_PATH" ]] || fail "Vault token is not readable: $VAULT_TOKEN_PATH"
[[ -r "$VAULT_CA_PATH" ]] || fail "Vault CA is not readable: $VAULT_CA_PATH"

require_command docker
require_command kubectl
require_command strings
require_command systemctl
require_command vault

if systemctl is-active --quiet "$SYNC_SERVICE"; then
    fail "$SYNC_SERVICE is currently running; wait for it to finish and retry"
fi

timer_was_active=false
work_dir=""
strings_file=""

cleanup() {
    unset VAULT_TOKEN octopus_password atheros_password migrator_password
    if [[ -n ${strings_file:-} && -f $strings_file ]]; then
        rm -f -- "$strings_file"
    fi
    if [[ -n ${work_dir:-} && -d $work_dir ]]; then
        rmdir -- "$work_dir" 2>/dev/null || true
    fi
    if [[ $timer_was_active == true ]]; then
        systemctl start "$SYNC_TIMER" || true
    fi
}
trap cleanup EXIT

if systemctl is-active --quiet "$SYNC_TIMER"; then
    timer_was_active=true
    systemctl stop "$SYNC_TIMER"
fi

work_dir="$(mktemp -d /tmp/platform-pgbouncer-recovery.XXXXXX)"
strings_file="$work_dir/platform-sync.strings"

set -a
# shellcheck disable=SC1090 -- this is the installed, root-owned platform config.
source "$PLATFORM_CONFIG"
set +a

export VAULT_TOKEN="$(<"$VAULT_TOKEN_PATH")"
export VAULT_CACERT="$VAULT_CA_PATH"
readonly VAULT_KV_MOUNT="${VAULT_KV_MOUNT:-secret}"
readonly VAULT_KV_PREFIX="${VAULT_KV_PREFIX:-ssl-proxy/prod}"

vault status >/dev/null || fail "Vault is unavailable or the installed token is invalid"
docker inspect "$POSTGRES_CONTAINER" >/dev/null 2>&1 || \
    fail "PostgreSQL container is unavailable: $POSTGRES_CONTAINER"

printf '%s\n' 'Installing current platform-sync binaries and systemd units...'
"$INSTALLER"

strings "$PLATFORM_BINARY" >"$strings_file"
grep -Fq 'userlist password does not match account' "$strings_file" || \
    fail "installed platform-sync binary lacks strict PgBouncer validation"
grep -Fq 'last-success-unix' "$strings_file" || \
    fail "installed platform-sync binary lacks readiness publication"
rm -f -- "$strings_file"

read_password() {
    local secret_name="$1"
    local value
    value="$(vault kv get \
        -mount="$VAULT_KV_MOUNT" \
        -field=password \
        "$VAULT_KV_PREFIX/$secret_name")" || \
        fail "could not read Vault password for $secret_name"
    [[ -n $value ]] || fail "Vault password for $secret_name is empty"
    [[ $value != *$'\n'* && $value != *$'\r'* && $value != *'"'* && $value != *'\\'* ]] || \
        fail "Vault password for $secret_name cannot be represented safely in userlist.txt"
    printf '%s' "$value"
}

validate_direct_login() {
    local role="$1"
    local password="$2"
    local actual
    actual="$(printf '%s\n' "$password" | docker exec -i "$POSTGRES_CONTAINER" \
        sh -ceu 'IFS= read -r PGPASSWORD; export PGPASSWORD; exec psql \
            --no-psqlrc --host=127.0.0.1 --username="$1" --dbname=sync \
            --tuples-only --no-align --set=ON_ERROR_STOP=1 \
            --command="select current_user"' sh "$role")" || \
        fail "Vault password does not authenticate directly as $role"
    [[ $actual == "$role" ]] || fail "direct login returned an unexpected identity for $role"
    printf 'Validated direct PostgreSQL login for %s.\n' "$role"
}

octopus_password="$(read_password postgres-octopus)"
atheros_password="$(read_password postgres-atheros-search)"
migrator_password="$(read_password postgres-schema-migrator)"

validate_direct_login octopus_runtime "$octopus_password"
validate_direct_login atheros_search_runtime "$atheros_password"
validate_direct_login schema_migrator_runtime "$migrator_password"

printf '%s\n' 'Writing a new Vault version for pgbouncer-runtime-users/userlist.txt...'
vault kv patch \
    -mount="$VAULT_KV_MOUNT" \
    "$VAULT_KV_PREFIX/pgbouncer-runtime-users" \
    'userlist.txt=-' < <(
        printf '"octopus_runtime" "%s"\n' "$octopus_password"
        printf '"atheros_search_runtime" "%s"\n' "$atheros_password"
        printf '"schema_migrator_runtime" "%s"\n' "$migrator_password"
    ) >/dev/null

unset octopus_password atheros_password migrator_password

printf '%s\n' 'Running platform-sync...'
systemctl start "$SYNC_SERVICE"
systemctl --quiet is-failed "$SYNC_SERVICE" && \
    fail "$SYNC_SERVICE failed; inspect journalctl -u $SYNC_SERVICE"

export KUBECONFIG=/run/platform-sync/kubeconfig
ready="$(kubectl get configmap platform-ready -n "$NAMESPACE" -o jsonpath='{.data.ready}')"
contract_sha="$(kubectl get configmap platform-ready -n "$NAMESPACE" -o jsonpath='{.data.contract-sha256}')"
last_success="$(kubectl get configmap platform-ready -n "$NAMESPACE" -o jsonpath='{.data.last-success-unix}')"

[[ $ready == true ]] || fail "platform-ready/ready is not true"
[[ $contract_sha =~ ^[0-9a-f]{64}$ ]] || fail "platform-ready/contract-sha256 is invalid"
[[ $last_success =~ ^[0-9]+$ ]] || fail "platform-ready/last-success-unix is invalid"

printf '%s\n' 'Recovery complete: platform-ready is published and the sync timer is restored.'
