#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

SERVICE_NAME="${UP_READY_SERVICE_NAME:-ssl-proxy}"
STACK_HEALTH_SERVICES="${UP_READY_STACK_HEALTH_SERVICES:-nats postgres zig-coordinator oracle-worker ssl-proxy}"
MEMORY_FILE="${UP_READY_MEMORY_FILE:-$ROOT_DIR/ops-memory.md}"
PROFILE_MODE="${PROFILE_MODE:-}"
SERVER_IP="${SERVER_IP:-192.168.1.221}"
CLIENT_IP="${CLIENT_IP:-192.168.1.68}"
HEALTH_TIMEOUT_SECS="${UP_READY_HEALTH_TIMEOUT_SECS:-120}"
CHECK_RETRY_SECS="${UP_READY_CHECK_RETRY_SECS:-15}"
LOG_TAIL_LINES="${UP_READY_LOG_TAIL_LINES:-200}"
QR_TYPE="${UP_READY_QR_TYPE:-ansiutf8}"
QR_MARGIN="${UP_READY_QR_MARGIN:-0}"

RUN_TS="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
HOST_ARCH="$(uname -m 2>/dev/null || echo unknown)"
LAST_FAILED_CHECK=""
LAST_FAILURE_CLASS=""
LAST_FAILURE_CAUSE=""
LAST_FAILURE_FIX=""
LAST_FAILURE_RETRY=""
LAST_FAILURE_TEXT=""

# bash 3.x compatible indexed arrays
AUTO_FIXED_CLASSES="|"
PEER_KEYS="|"
PEER_CONFIGS="|"

compose() {
    docker compose "$@"
}

step() {
    local id="$1"
    shift
    printf '[up-ready][%s] %s\n' "$id" "$*"
}

warn() {
    printf '[up-ready][WARN] %s\n' "$*" >&2
}

fail() {
    printf '[up-ready][ERROR] %s\n' "$*" >&2
    exit 1
}

signature_table() {
    cat <<'SIGEOF'
profile_obfuscation_mismatch::magic_byte_mismatch::Mode/runtime mismatch: direct client sent raw packets to obfuscated endpoint::Set runtime obfuscation to match PROFILE_MODE and recreate container::auto
profile_obfuscation_mismatch::wg_obfuscation_enabled=true::iPhone/linux-direct mode cannot use obfuscated ingress::Use WG_OBFUSCATION_ENABLED=false and recreate::auto
docker_registry_dns_timeout::lookup registry-1\.docker\.io .* i/o timeout::Host resolver cannot resolve Docker registry::Recover host DNS; fallback to --no-build if local image exists::auto
dns_upstream_timeout::plugin/errors: .* i/o timeout::CoreDNS upstream reachability failure::Adjust upstream DNS or host egress firewall::manual
admin_loopback_false_negative::host-local 127\\.0\\.0\\.1:3002 check failed, but in-container admin health is OK::Admin bind is container-local loopback::Treat in-container health as authoritative::auto
coordinator_unhealthy::zig-coordinator unhealthy::Coordinator failed health or dependency checks::Inspect zig-coordinator logs and DATABASE_URL/SYNC_NATS_URL/schema access::manual
worker_unhealthy::oracle-worker unhealthy::Worker failed Oracle or NATS preflight::Inspect oracle-worker logs and wallet/lib/secret mounts::manual
postgres_unavailable::postgres unhealthy|Postgres unavailable::Postgres dependency unavailable::Ensure postgres is healthy and DATABASE_URL points to postgres:5432::manual
nats_unavailable::nats unhealthy|NATS unavailable::NATS dependency unavailable::Ensure nats is healthy and SYNC_NATS_URL points to nats:4222::manual
worker_wallet_missing::missing Oracle wallet artifact|wallet directory missing|no libclntsh|missing Oracle password file::Worker Oracle assets are missing::Mount wallet lib and secrets into oracle-worker only::manual
rust_toolchain_mismatch::rustc [0-9]+\.[0-9]+\.[0-9]+ is not supported by the following packages::Builder Rust toolchain too old for locked dependencies::Bump the builder Rust image (or pin compatible crate versions) and rebuild::manual
schema_apply_failed::psql failed::Coordinator could not apply or validate the sync schema::Check DATABASE_URL and Postgres readiness::manual
wg_client_listenport_conflict::RTNETLINK answers: Address already in use::Client ListenPort conflict (often 443 in local tests)::Remove/adjust ListenPort in client config::manual
wg_client_ipv6_route_failure::RTNETLINK answers: No such device::Client IPv6 default route setup failed::Temporarily remove the IPv6 default route from AllowedIPs on that client::manual
peer_config_permission_denied::awk: cannot open /config/.*\.conf \(Permission denied\)::Peer config file denied inside container startup path::Run ssl-proxy in compose compatibility mode (root) or relax host file ownership/permissions::manual
qr_permission_denied::Permission denied::Peer config unreadable on host filesystem::Read profile from /config bind mount inside container::auto
SIGEOF
}

set_failure_from_text() {
    local text="$1"
    local line class rest pattern cause fix retry
    LAST_FAILURE_CLASS="unknown"
    LAST_FAILURE_CAUSE="Unclassified failure"
    LAST_FAILURE_FIX="Inspect diagnostics bundle"
    LAST_FAILURE_RETRY="manual"
    LAST_FAILURE_TEXT="$text"

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

was_auto_fixed() {
    local class="$1"
    [[ "$AUTO_FIXED_CLASSES" == *"|$class|"* ]]
}

mark_auto_fixed() {
    local class="$1"
    AUTO_FIXED_CLASSES+="$class|"
}

require_command() {
    local cmd="$1"
    command -v "$cmd" >/dev/null 2>&1 || fail "Missing required command: $cmd"
}

require_profile_mode() {
    case "$PROFILE_MODE" in
        iphone|linux-shim|linux-direct) ;;
        *)
            cat >&2 <<'EOF_MODE'
[up-ready][ERROR] PROFILE_MODE is required.
Allowed values: iphone | linux-shim | linux-direct
Example: make up-ready PROFILE_MODE=iphone SERVER_IP=192.168.1.221 CLIENT_IP=192.168.1.68
EOF_MODE
            exit 1
            ;;
    esac
}

register_peer_config() {
    local key="$1"
    local cfg="$2"
    PEER_KEYS+="$key|"
    PEER_CONFIGS+="$cfg|"
}

lookup_peer_config() {
    local target_key="$1"
    local keys_rest cfgs_rest key cfg
    keys_rest="${PEER_KEYS#|}"
    cfgs_rest="${PEER_CONFIGS#|}"

    while [ -n "$keys_rest" ] && [ -n "$cfgs_rest" ]; do
        key="${keys_rest%%|*}"
        keys_rest="${keys_rest#*|}"
        cfg="${cfgs_rest%%|*}"
        cfgs_rest="${cfgs_rest#*|}"
        if [ "$key" = "$target_key" ]; then
            printf '%s' "$cfg"
            return 0
        fi
    done
    return 1
}

to_container_config_path() {
    local host_path="$1"
    case "$host_path" in
        "$ROOT_DIR"/config/*)
            printf '/config/%s' "${host_path#"$ROOT_DIR"/config/}"
            return 0
            ;;
    esac
    return 1
}

print_qr_for_config() {
    local cfg="$1"
    local container_cfg

    if [ -r "$cfg" ]; then
        qrencode -t "$QR_TYPE" -m "$QR_MARGIN" <"$cfg"
        return 0
    fi

    container_cfg="$(to_container_config_path "$cfg" || true)"
    if [ -n "$container_cfg" ] && compose exec -T "$SERVICE_NAME" sh -lc "test -r '$container_cfg'"; then
        compose exec -T "$SERVICE_NAME" sh -lc "cat '$container_cfg'" | qrencode -t "$QR_TYPE" -m "$QR_MARGIN"
        return 0
    fi

    return 1
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

compose_up() {
    step S03 "compose_up: docker compose up -d --build"
    local output
    if output="$(compose up -d --build 2>&1)"; then
        printf '%s\n' "$output"
        return 0
    fi

    printf '%s\n' "$output" >&2
    set_failure_from_text "$output"
    if auto_fix "$LAST_FAILURE_CLASS" "$output"; then
        return 0
    fi
    return 1
}

wait_for_container_healthy() {
    local service="${1:-$SERVICE_NAME}"
    local elapsed=0
    while [ "$elapsed" -lt "$HEALTH_TIMEOUT_SECS" ]; do
        local cid status health
        cid="$(compose ps -q "$service")"
        if [ -n "$cid" ]; then
            status="$(docker inspect -f '{{.State.Status}}' "$cid" 2>/dev/null || true)"
            health="$(docker inspect -f '{{if .State.Health}}{{.State.Health.Status}}{{else}}none{{end}}' "$cid" 2>/dev/null || true)"
            if [ "$status" = "running" ] && { [ "$health" = "healthy" ] || [ "$health" = "none" ]; }; then
                return 0
            fi
        fi
        sleep 1
        elapsed=$((elapsed + 1))
    done
    return 1
}

classify_service_failure() {
    local service="$1"
    local logs
    logs="$(compose logs --tail "$LOG_TAIL_LINES" "$service" 2>&1 || true)"
    case "$service" in
        zig-coordinator)
            set_failure_from_text "$logs"$'\n'"zig-coordinator unhealthy"
            ;;
        oracle-worker)
            set_failure_from_text "$logs"$'\n'"oracle-worker unhealthy"
            ;;
        postgres)
            set_failure_from_text "$logs"$'\n'"postgres unhealthy"
            ;;
        nats)
            set_failure_from_text "$logs"$'\n'"nats unhealthy"
            ;;
        *)
            set_failure_from_text "$logs"$'\n'"${service} unhealthy"
            ;;
    esac
}

run_check_with_retry() {
    local label="$1"
    shift
    local elapsed=0
    while true; do
        if "$@"; then
            return 0
        fi
        if [ "$elapsed" -ge "$CHECK_RETRY_SECS" ]; then
            LAST_FAILED_CHECK="$label"
            return 1
        fi
        sleep 1
        elapsed=$((elapsed + 1))
    done
}

check_admin_health() {
    if curl -fsS --max-time 2 http://127.0.0.1:3002/health >/dev/null 2>&1; then
        return 0
    fi
    if compose exec -T "$SERVICE_NAME" curl -fsS --max-time 2 http://127.0.0.1:3002/health >/dev/null 2>&1; then
        warn "Host-local admin check failed, but in-container admin health is OK"
        return 0
    fi
    return 1
}

health_checks() {
    step S04 "health_checks: stack + admin + ready"
    LAST_FAILED_CHECK=""

    local service
    for service in $STACK_HEALTH_SERVICES; do
        if ! wait_for_container_healthy "$service"; then
            LAST_FAILED_CHECK="${service}_health"
            classify_service_failure "$service"
            return 1
        fi
    done

    run_check_with_retry "admin_health" check_admin_health || return 1

    local ready_code body_file ready_body
    body_file="$(mktemp)"
    ready_code="$(curl -sS -o "$body_file" -w '%{http_code}' --max-time 2 http://127.0.0.1:3002/ready 2>/dev/null || true)"
    if [ "$ready_code" = "000" ]; then
        ready_code="$(compose exec -T "$SERVICE_NAME" curl -sS -o /tmp/up-ready-ready-body.txt -w '%{http_code}' --max-time 2 http://127.0.0.1:3002/ready 2>/dev/null || true)"
        compose exec -T "$SERVICE_NAME" sh -lc 'cat /tmp/up-ready-ready-body.txt' >"$body_file" 2>/dev/null || true
    fi
    ready_body="$(tr -d '\n' <"$body_file")"
    rm -f "$body_file"

    if [ "$ready_code" = "200" ]; then
        step S04 "ready endpoint: 200"
    else
        warn "ready endpoint: ${ready_code} (non-blocking) ${ready_body}"
    fi
    return 0
}

check_udp_listener() {
    local port="$1"
    compose exec -T "$SERVICE_NAME" sh -lc "ss -H -lun '( sport = :${port} )' | grep -q ."
}

check_tcp_listener() {
    local port="$1"
    compose exec -T "$SERVICE_NAME" sh -lc "ss -H -ltn '( sport = :${port} )' | grep -q ."
}

network_checks() {
    step S05 "network_checks: wg/listeners"
    run_check_with_retry "wg_interface" compose exec -T "$SERVICE_NAME" /app/ssl-proxy boringtun show wg0 >/dev/null || return 1
    run_check_with_retry "udp_443" check_udp_listener 443 || return 1
    run_check_with_retry "udp_53" check_udp_listener 53 || return 1
    run_check_with_retry "tcp_3001" check_tcp_listener 3001 || return 1
    run_check_with_retry "tcp_3002" check_tcp_listener 3002 || return 1

    local obfs_enabled
    obfs_enabled="$(runtime_obfuscation_value || true)"
    if [ "$obfs_enabled" = "true" ]; then
        run_check_with_retry "udp_51820" check_udp_listener 51820 || return 1
    fi
    return 0
}

mode_guardrails() {
    step S02 "mode_guardrails: PROFILE_MODE=${PROFILE_MODE} SERVER_IP=${SERVER_IP} CLIENT_IP=${CLIENT_IP} arch=${HOST_ARCH}"
    local expected actual
    expected="$(desired_obfuscation_value)"
    actual="$(runtime_obfuscation_value || true)"

    if [ -z "$actual" ]; then
        warn "Could not read runtime obfuscation from logs yet; proceeding"
        return 0
    fi

    if [ "$actual" != "$expected" ]; then
        LAST_FAILED_CHECK="mode_guardrails"
        set_failure_from_text "profile mismatch: expected obfuscation=$expected actual=$actual wg_obfuscation_enabled=$actual"
        if auto_fix "profile_obfuscation_mismatch" "expected=$expected actual=$actual"; then
            return 0
        fi
        return 1
    fi

    if [ "$PROFILE_MODE" = "iphone" ]; then
        warn "iPhone mode: do not use local shim endpoint 127.0.0.1:51821 in iPhone profile"
    fi
    return 0
}

peer_checks() {
    step S06 "peer_checks: snapshot"
    local snapshot
    snapshot="$(compose exec -T "$SERVICE_NAME" /app/ssl-proxy boringtun dump wg0 2>&1 || true)"
    printf '%s\n' "$snapshot"
    if printf '%s\n' "$snapshot" | awk 'NR > 1 && $5 + 0 > 0 { found = 1 } END { exit found ? 0 : 1 }'; then
        step S06 "peer handshake present"
    else
        warn "No peer handshake yet. Toggle client tunnel and re-check"
        return 1
    fi
}

discover_peer_configs() {
    local peer_dir key_file key obfuscated_cfg fallback_cfg selected_cfg
    for peer_dir in "$ROOT_DIR"/config/*; do
        [ -d "$peer_dir" ] || continue
        case "$(basename "$peer_dir")" in
            coredns|templates|client|server) continue ;;
        esac

        key_file="$(find "$peer_dir" -maxdepth 1 -type f -name 'publickey-*' | sort | head -n 1)"
        [ -n "$key_file" ] || continue
        key="$(tr -d '\r\n[:space:]' <"$key_file")"
        [ -n "$key" ] || continue

        obfuscated_cfg="$(find "$peer_dir" -maxdepth 1 -type f -name '*obfuscated*.conf*' | sort | head -n 1)"
        fallback_cfg="$(find "$peer_dir" -maxdepth 1 -type f -name '*.conf' ! -name '*obfuscated*' | sort | head -n 1)"
        selected_cfg="$obfuscated_cfg"
        [ -n "$selected_cfg" ] || selected_cfg="$fallback_cfg"
        [ -n "$selected_cfg" ] && register_peer_config "$key" "$selected_cfg"
    done
}

qr_render() {
    step S07 "qr_render: real peers"
    local peers peer_key cfg qr_failures
    qr_failures=0

    peers="$(compose exec -T "$SERVICE_NAME" /app/ssl-proxy boringtun dump wg0 | awk 'NR > 1 { if (!seen[$1]++) print $1 }')"
    [ -n "$peers" ] || {
        warn "No peers listed in wg dump"
        return 0
    }

    while IFS= read -r peer_key; do
        [ -n "$peer_key" ] || continue
        cfg="$(lookup_peer_config "$peer_key" || true)"
        if [ -z "$cfg" ]; then
            warn "No local config mapping for peer key: $peer_key"
            continue
        fi
        printf '\n=== Peer %s ===\nConfig: %s\n' "$peer_key" "$cfg"
        if ! print_qr_for_config "$cfg"; then
            warn "QR render failed for config: $cfg"
            set_failure_from_text "Permission denied while QR rendering $cfg"
            qr_failures=$((qr_failures + 1))
        fi
    done <<<"$peers"

    [ "$qr_failures" -eq 0 ] || return 1
    return 0
}

diagnostics() {
    step S08 "diagnostics"
    echo "--- docker compose ps ---"
    compose ps || true
    echo "--- service health ---"
    local service cid status health
    for service in $STACK_HEALTH_SERVICES; do
        cid="$(compose ps -q "$service" 2>/dev/null || true)"
        status="$(docker inspect -f '{{.State.Status}}' "$cid" 2>/dev/null || echo unknown)"
        health="$(docker inspect -f '{{if .State.Health}}{{.State.Health.Status}}{{else}}none{{end}}' "$cid" 2>/dev/null || echo unknown)"
        echo "$service status=$status health=$health"
    done
    for service in $STACK_HEALTH_SERVICES; do
        echo "--- docker compose logs --tail ${LOG_TAIL_LINES} ${service} ---"
        compose logs --tail "$LOG_TAIL_LINES" "$service" || true
    done
    echo "--- boringtun show wg0 ---"
    compose exec -T "$SERVICE_NAME" /app/ssl-proxy boringtun show wg0 || true
    echo "--- listener dump (ss -lunt) ---"
    compose exec -T "$SERVICE_NAME" sh -lc 'ss -lunt' || true

    local text
    text="$(compose logs --tail "$LOG_TAIL_LINES" 2>&1 || true)"
    [ -n "$LAST_FAILED_CHECK" ] && text+=$'\n'"LAST_FAILED_CHECK=$LAST_FAILED_CHECK"
    set_failure_from_text "$text"

    echo "--- classified failure ---"
    echo "class=${LAST_FAILURE_CLASS}"
    echo "cause=${LAST_FAILURE_CAUSE}"
    echo "fix=${LAST_FAILURE_FIX}"
    echo "retry=${LAST_FAILURE_RETRY}"
}

auto_fix() {
    local class="$1"
    local _text="${2:-}"

    [ -n "$class" ] || return 1
    if was_auto_fixed "$class"; then
        warn "auto_fix skipped (already attempted): $class"
        return 1
    fi

    case "$class" in
        docker_registry_dns_timeout)
            step S09 "auto_fix[$class]: fallback to --no-build"
            if compose up -d --no-build --force-recreate; then
                mark_auto_fixed "$class"
                return 0
            fi
            ;;
        profile_obfuscation_mismatch)
            local desired
            desired="$(desired_obfuscation_value)"
            step S09 "auto_fix[$class]: recreate with WG_OBFUSCATION_ENABLED=$desired"
            if WG_OBFUSCATION_ENABLED="$desired" compose up -d --no-build --force-recreate; then
                mark_auto_fixed "$class"
                return 0
            fi
            ;;
        admin_loopback_false_negative|qr_permission_denied)
            step S09 "auto_fix[$class]: no-op (handled by fallback path)"
            mark_auto_fixed "$class"
            return 0
            ;;
    esac

    return 1
}

ensure_memory_schema() {
    [ -f "$MEMORY_FILE" ] || fail "Missing memory file: $MEMORY_FILE"
    grep -q '^## Environment Matrix' "$MEMORY_FILE" || fail "Memory file schema invalid: missing Environment Matrix"
    grep -q '^## Known Failure Signatures' "$MEMORY_FILE" || fail "Memory file schema invalid: missing Known Failure Signatures"
    grep -q '^## Last Known Good' "$MEMORY_FILE" || fail "Memory file schema invalid: missing Last Known Good"
    grep -q '^## Incident Timeline' "$MEMORY_FILE" || fail "Memory file schema invalid: missing Incident Timeline"
    grep -q '^## Open Risks' "$MEMORY_FILE" || fail "Memory file schema invalid: missing Open Risks"
}

memo_write() {
    local result="$1"
    local signature="$2"
    local action="$3"
    local line

    line="- ${RUN_TS} | result=${result} | mode=${PROFILE_MODE} | server=${SERVER_IP} | client=${CLIENT_IP} | arch=${HOST_ARCH} | signature=${signature} | action=${action}"
    printf '%s\n' "$line" >> "$MEMORY_FILE"
}

preflight() {
    step S01 "preflight"
    require_command docker
    require_command curl
    require_command qrencode
    require_profile_mode
    ensure_memory_schema
}

main() {
    preflight

    if ! compose_up; then
        diagnostics
        memo_write "fail" "$LAST_FAILURE_CLASS" "$LAST_FAILURE_FIX"
        fail "compose_up failed: $LAST_FAILURE_CAUSE"
    fi

    if ! mode_guardrails; then
        diagnostics
        memo_write "fail" "${LAST_FAILURE_CLASS:-mode_guardrails}" "${LAST_FAILURE_FIX:-align runtime mode}"
        fail "mode_guardrails failed"
    fi

    if ! health_checks || ! network_checks; then
        diagnostics
        if auto_fix "$LAST_FAILURE_CLASS" "$LAST_FAILURE_TEXT"; then
            if ! health_checks || ! network_checks; then
                diagnostics
                memo_write "fail" "$LAST_FAILURE_CLASS" "$LAST_FAILURE_FIX"
                fail "checks failed after bounded auto-fix"
            fi
        else
            memo_write "fail" "$LAST_FAILURE_CLASS" "$LAST_FAILURE_FIX"
            fail "checks failed"
        fi
    fi

    peer_checks || true
    discover_peer_configs
    if ! qr_render; then
        diagnostics
        memo_write "fail" "${LAST_FAILURE_CLASS:-qr_permission_denied}" "${LAST_FAILURE_FIX:-fix config file permissions}"
        fail "qr_render failed"
    fi

    memo_write "pass" "none" "up-ready completed"
    step S10 "completed"
}

main "$@"
