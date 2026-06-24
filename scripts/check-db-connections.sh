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
echo "=== Recent connection errors in logs ==="
docker inspect "${CONTAINER}" >/dev/null
docker logs "${CONTAINER}" 2>&1 | grep -E 'FATAL|CannotGetJdbc|PSQLException|ORA-|HikariPool' | tail -20 || true

exit "${FAILED}"
