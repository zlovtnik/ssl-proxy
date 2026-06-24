#!/usr/bin/env bash
set -euo pipefail

TARGET=${1:-java-coordinator}
PORT=${2:-8081}

resolve_container() {
    local target=$1
    local container_id

    if docker inspect "${target}" >/dev/null 2>&1; then
        printf '%s\n' "${target}"
        return
    fi

    container_id=$(docker compose ps -q "${target}" 2>/dev/null || true)
    if [ -n "${container_id}" ]; then
        printf '%s\n' "${container_id}"
        return
    fi

    printf '%s\n' "${target}"
}

CONTAINER=$(resolve_container "${TARGET}")
FAILED=0

print_postgres_password_fingerprints() {
    local postgres_container
    local coordinator_fp
    local postgres_fp

    postgres_container=$(resolve_container postgres)

    echo "=== POSTGRES_PASSWORD Fingerprints ==="
    coordinator_fp=$(docker exec "${CONTAINER}" sh -lc 'printf "%s" "${POSTGRES_PASSWORD:-}" | sha256sum | awk "{print \$1}"' 2>/dev/null || true)
    postgres_fp=$(docker exec "${postgres_container}" sh -lc 'printf "%s" "${POSTGRES_PASSWORD:-}" | sha256sum | awk "{print \$1}"' 2>/dev/null || true)

    echo "coordinator=${coordinator_fp:-unavailable}"
    echo "postgres=${postgres_fp:-unavailable}"
    if [ -n "${coordinator_fp}" ] && [ -n "${postgres_fp}" ] && [ "${coordinator_fp}" = "${postgres_fp}" ]; then
        echo "password_env_match=true"
    else
        echo "password_env_match=false"
        FAILED=1
    fi
}

print_json_endpoint() {
    local label=$1
    local path=$2
    local body
    local status

    body=$(mktemp "${TMPDIR:-/tmp}/check-db-connections.XXXXXX")
    status=$(curl -sS -o "${body}" -w "%{http_code}" "http://localhost:${PORT}${path}" || true)

    echo "=== ${label} ==="
    if [ "${status}" -ge 200 ] && [ "${status}" -lt 300 ] && python3 -m json.tool < "${body}"; then
        rm -f "${body}"
        return 0
    fi

    echo "request_failed http_status=${status}"
    if [ -s "${body}" ]; then
        sed -n '1,80p' "${body}"
    else
        echo "<empty body>"
    fi
    rm -f "${body}"
    return 1
}

print_json_endpoint "Actuator Health" "/actuator/health" || FAILED=1

echo ""
print_json_endpoint "HikariCP Active Connections" "/actuator/metrics/hikaricp.connections.active" || FAILED=1

echo ""
print_json_endpoint "HikariCP Pending" "/actuator/metrics/hikaricp.connections.pending" || FAILED=1

echo ""
print_postgres_password_fingerprints

echo ""
echo "=== Recent connection errors in logs ==="
docker inspect "${CONTAINER}" >/dev/null
docker logs "${CONTAINER}" 2>&1 | grep -E 'FATAL|CannotGetJdbc|PSQLException|ORA-|HikariPool' | tail -20 || true

exit "${FAILED}"
