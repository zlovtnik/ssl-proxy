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

echo "=== Actuator Health ==="
curl -sf "http://localhost:${PORT}/actuator/health" | python3 -m json.tool

echo ""
echo "=== HikariCP Active Connections ==="
curl -sf "http://localhost:${PORT}/actuator/metrics/hikaricp.connections.active" | python3 -m json.tool

echo ""
echo "=== HikariCP Pending ==="
curl -sf "http://localhost:${PORT}/actuator/metrics/hikaricp.connections.pending" | python3 -m json.tool

echo ""
echo "=== Recent connection errors in logs ==="
docker inspect "${CONTAINER}" >/dev/null
docker logs "${CONTAINER}" 2>&1 | grep -E 'FATAL|CannotGetJdbc|PSQLException|ORA-|HikariPool' | tail -20 || true
