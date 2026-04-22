#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

SERVICE_NAME="${UP_READY_SERVICE_NAME:-ssl-proxy}"
STACK_HEALTH_SERVICES="${UP_READY_STACK_HEALTH_SERVICES:-nats postgres zig-coordinator oracle-worker ssl-proxy}"
PROFILE_MODE="${PROFILE_MODE:-}"
SERVER_IP="${SERVER_IP:-192.168.1.221}"
CLIENT_IP="${CLIENT_IP:-192.168.1.68}"
LOG_TAIL_LINES="${UP_READY_LOG_TAIL_LINES:-200}"

LAST_FAILURE_CLASS="none"
LAST_FAILURE_CAUSE="No known signature matched"
LAST_FAILURE_FIX="Inspect diagnostics output"
LAST_FAILURE_RETRY="manual"

compose() {
    docker compose "$@"
}

require_profile_mode() {
    case "$PROFILE_MODE" in
        iphone|linux-shim|linux-direct) ;;
        *)
            cat >&2 <<'EOF_MODE'
[diagnose][ERROR] PROFILE_MODE is required.
Allowed values: iphone | linux-shim | linux-direct
Example: make diagnose PROFILE_MODE=iphone SERVER_IP=192.168.1.221 CLIENT_IP=192.168.1.68
EOF_MODE
            exit 1
            ;;
    esac
}

signature_table() {
    cat <<'SIGEOF'
profile_obfuscation_mismatch::magic_byte_mismatch::Mode/runtime mismatch: direct client sent raw packets to obfuscated endpoint::Set runtime obfuscation to match PROFILE_MODE and recreate container::auto
docker_registry_dns_timeout::lookup registry-1\\.docker\\.io .* i/o timeout::Host resolver cannot resolve Docker registry::Recover host DNS; rerun with --no-build if local image exists::auto
dns_upstream_timeout::plugin/errors: .* i/o timeout::CoreDNS upstream reachability failure::Adjust upstream DNS or host egress firewall::manual
admin_loopback_false_negative::host-local 127\\.0\\.0\\.1:3002 check failed, but in-container admin health is OK::Admin bind is container-local loopback::Use in-container health probe for truth::auto
coordinator_unhealthy::zig-coordinator unhealthy::Coordinator failed health or dependency checks::Inspect zig-coordinator logs and DATABASE_URL/SYNC_NATS_URL/schema access::manual
worker_unhealthy::oracle-worker unhealthy::Worker failed Oracle or NATS preflight::Inspect oracle-worker logs and wallet/lib/secret mounts::manual
postgres_unavailable::postgres unhealthy|Postgres unavailable::Postgres dependency unavailable::Ensure postgres is healthy and DATABASE_URL points to postgres:5432::manual
nats_unavailable::nats unhealthy|NATS unavailable::NATS dependency unavailable::Ensure nats is healthy and SYNC_NATS_URL points to nats:4222::manual
worker_wallet_missing::missing Oracle wallet artifact|wallet directory missing|no libclntsh|missing Oracle password file::Worker Oracle assets are missing::Mount wallet lib and secrets into oracle-worker only::manual
rust_toolchain_mismatch::rustc [0-9]+\.[0-9]+\.[0-9]+ is not supported by the following packages::Builder Rust toolchain too old for locked dependencies::Bump the builder Rust image (or pin compatible crate versions) and rebuild::manual
schema_apply_failed::psql failed::Coordinator could not apply or validate the sync schema::Check DATABASE_URL and Postgres readiness::manual
wg_client_listenport_conflict::RTNETLINK answers: Address already in use::Client ListenPort conflict::Remove/adjust ListenPort in client config::manual
wg_client_ipv6_route_failure::RTNETLINK answers: No such device::Client IPv6 default route setup failed::Temporarily remove the IPv6 default route from AllowedIPs on that client::manual
qr_permission_denied::Permission denied::Peer config unreadable on host filesystem::Read profile from /config bind mount inside container::auto
SIGEOF
}

set_failure_from_text() {
    local text="$1"
    local line class rest pattern cause fix retry
    LAST_FAILURE_CLASS="none"
    LAST_FAILURE_CAUSE="No known signature matched"
    LAST_FAILURE_FIX="Inspect diagnostics output"
    LAST_FAILURE_RETRY="manual"

    while IFS= read -r line; do
        [ -n "$line" ] || continue
        class="${line%%::*}"
        rest="${line#*::}"
        pattern="${rest%%::*}"
        rest="${rest#*::}"
        cause="${rest%%::*}"
        rest="${rest#*::}"
        fix="${rest%%::*}"
        retry="${rest#*::}"
        if printf '%s\n' "$text" | grep -Eiq "$pattern"; then
            LAST_FAILURE_CLASS="$class"
            LAST_FAILURE_CAUSE="$cause"
            LAST_FAILURE_FIX="$fix"
            LAST_FAILURE_RETRY="$retry"
            return 0
        fi
    done <<EOF_TABLE
$(signature_table)
EOF_TABLE
}

runtime_obfuscation_value() {
    compose logs --tail 200 "$SERVICE_NAME" 2>/dev/null \
        | sed -n 's/.*wg_obfuscation_enabled=\(true\|false\).*/\1/p' \
        | tail -n 1
}

desired_obfuscation_value() {
    case "$PROFILE_MODE" in
        linux-shim) printf 'true' ;;
        iphone|linux-direct) printf 'false' ;;
    esac
}

main() {
    require_profile_mode

    echo "[diagnose] mode=${PROFILE_MODE} server=${SERVER_IP} client=${CLIENT_IP}"
    echo "--- compose ps ---"
    compose ps || true
    echo "--- service health ---"
    local service cid status health
    for service in $STACK_HEALTH_SERVICES; do
        cid="$(compose ps -q "$service" 2>/dev/null || true)"
        status="$(docker inspect -f '{{.State.Status}}' "$cid" 2>/dev/null || echo unknown)"
        health="$(docker inspect -f '{{if .State.Health}}{{.State.Health.Status}}{{else}}none{{end}}' "$cid" 2>/dev/null || echo unknown)"
        echo "$service status=$status health=$health"
    done

    echo "--- runtime obfuscation ---"
    echo "desired=$(desired_obfuscation_value)"
    echo "actual=$(runtime_obfuscation_value || echo unknown)"

    echo "--- admin health ---"
    if curl -fsS --max-time 2 http://127.0.0.1:3002/health >/dev/null 2>&1; then
        echo "host=ok"
    else
        echo "host=fail"
    fi
    if compose exec -T "$SERVICE_NAME" curl -fsS --max-time 2 http://127.0.0.1:3002/health >/dev/null 2>&1; then
        echo "container=ok"
    else
        echo "container=fail"
    fi

    echo "--- boringtun show ---"
    compose exec -T "$SERVICE_NAME" /app/ssl-proxy boringtun show wg0 || true

    echo "--- listeners ---"
    compose exec -T "$SERVICE_NAME" sh -lc 'ss -lunt; ss -lun' || true

    for service in $STACK_HEALTH_SERVICES; do
        echo "--- logs tail (${LOG_TAIL_LINES}) ${service} ---"
        compose logs --tail "$LOG_TAIL_LINES" "$service" || true
    done

    local log_text
    log_text="$(compose logs --tail "$LOG_TAIL_LINES" 2>&1 || true)"
    set_failure_from_text "$log_text"

    echo "--- classification ---"
    echo "class=${LAST_FAILURE_CLASS}"
    echo "cause=${LAST_FAILURE_CAUSE}"
    echo "fix=${LAST_FAILURE_FIX}"
    echo "retry=${LAST_FAILURE_RETRY}"
}

main "$@"
