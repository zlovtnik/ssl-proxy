#!/usr/bin/env bash
set -euo pipefail

CONTAINER=${1:-ssl-proxy-java-coordinator-1}
PORT=${2:-8081}

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
