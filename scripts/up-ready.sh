#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

SERVICE_NAME="${UP_READY_SERVICE_NAME:-ssl-proxy}"
FRONTDOOR_SERVICE_NAME="${UP_READY_FRONTDOOR_SERVICE_NAME:-wg-udp-frontdoor}"
STACK_HEALTH_SERVICES="${UP_READY_STACK_HEALTH_SERVICES:-redpanda postgres java-coordinator ssl-proxy wg-udp-frontdoor}"
MEMORY_FILE="${UP_READY_MEMORY_FILE:-$ROOT_DIR/ops-memory.md}"
PROFILE_MODE="${PROFILE_MODE:-}"
SERVER_IP="${SERVER_IP:-192.168.1.221}"
CLIENT_IP="${CLIENT_IP:-192.168.1.68}"
WG_PEERS="${WG_PEERS:-${ROTATOR_PEERS:-peer1,peer2}}"
HEALTH_TIMEOUT_SECS="${UP_READY_HEALTH_TIMEOUT_SECS:-120}"
CHECK_RETRY_SECS="${UP_READY_CHECK_RETRY_SECS:-15}"
LOG_TAIL_LINES="${UP_READY_LOG_TAIL_LINES:-200}"
QR_TYPE="${UP_READY_QR_TYPE:-ansiutf8}"
QR_MARGIN="${UP_READY_QR_MARGIN:-0}"
CREDENTIAL_HANDOFF_FILE="${UP_READY_CREDENTIAL_HANDOFF_FILE:-$ROOT_DIR/secrets/up-ready-credentials.txt}"
export WG_PEERS

RUN_TS="$(TZ="${TZ:-America/New_York}" date +%Y-%m-%dT%H:%M:%S%z)"
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
PEER_KEY_HELPER_READY=0

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

trim_spaces() {
    local value="$1"
    value="${value#"${value%%[![:space:]]*}"}"
    value="${value%"${value##*[![:space:]]}"}"
    printf '%s' "$value"
}

validate_peer_name() {
    local peer_id="$1"

    case "$peer_id" in
        ""|*[!A-Za-z0-9_-]*)
            fail "Invalid peer id in WG_PEERS: $peer_id"
            ;;
    esac
}

peer_names() {
    local raw_peer peer_id

    printf '%s' "$WG_PEERS" | tr ',' '\n' | while IFS= read -r raw_peer; do
        peer_id="$(trim_spaces "$raw_peer")"
        [ -n "$peer_id" ] || continue
        validate_peer_name "$peer_id"
        printf '%s\n' "$peer_id"
    done
}

signature_table() {
    cat <<'SIGEOF'
profile_obfuscation_mismatch::magic_byte_mismatch::Mode/runtime mismatch: direct client sent raw packets to obfuscated endpoint::Set runtime obfuscation to match PROFILE_MODE and recreate container::auto
compose_unresolved_placeholder::<server-local-ip>|invalid reference format::Compose image reference still contains an unresolved placeholder::Materialize .env with concrete REGISTRY/SERVER_IP before pulling images::manual
secret_file_owner_mismatch::WG_OBFUSCATION_KEY_FILE is invalid: .*must be owned by uid::Stale ssl-proxy image rejects host-owned file-backed WireGuard obfuscation secret::Use the direct obfuscation key env fallback for this run, then rebuild/push ssl-proxy with root-runtime host-owned secret support::auto
docker_registry_plain_http_untrusted::server gave HTTP response to HTTPS client|http: server gave HTTP response to HTTPS client::Docker daemon is treating the plain-HTTP local registry as HTTPS::Add REGISTRY to Docker daemon insecure-registries and restart Docker, or put TLS in front of the registry::manual
docker_registry_dns_timeout::lookup registry-1\.docker\.io .* i/o timeout::Host resolver cannot resolve Docker registry::Recover host DNS; retry after required images are present locally::auto
docker_buildkit_snapshot_missing::failed to stat active key during commit|snapshot .* does not exist::Docker BuildKit cache snapshot is missing or stale::Use docker-compose.build.yaml for local rebuilds and prune stale BuildKit cache if needed::manual
dns_upstream_timeout::plugin/errors: .* i/o timeout::CoreDNS upstream reachability failure::Adjust upstream DNS or host egress firewall::manual
admin_loopback_false_negative::host-local 127\\.0\\.0\\.1:3002 check failed, but in-container admin health is OK::Admin bind is container-local loopback::Treat in-container health as authoritative::auto
coordinator_unhealthy::java-coordinator unhealthy::Coordinator failed health, Redpanda, Postgres, or Oracle checks::Inspect java-coordinator logs and DATABASE_URL/SYNC_REDPANDA_BOOTSTRAP_SERVERS/Oracle wallet settings::manual
postgres_unavailable::postgres unhealthy|Postgres unavailable::Postgres dependency unavailable::Ensure postgres is healthy and DATABASE_URL points to postgres:5432::manual
redpanda_unavailable::redpanda unhealthy|Redpanda unavailable::Redpanda dependency unavailable::Ensure redpanda is healthy and SYNC_REDPANDA_BOOTSTRAP_SERVERS points to redpanda:9092::manual
coordinator_wallet_missing::missing Oracle wallet artifact|wallet directory missing|missing Oracle password file::Coordinator Oracle assets are missing::Mount wallet and secrets into java-coordinator::manual
rust_toolchain_mismatch::rustc [0-9]+\.[0-9]+\.[0-9]+ is not supported by the following packages::Builder Rust toolchain too old for locked dependencies::Bump the builder Rust image (or pin compatible crate versions) and rebuild::manual
wg_client_listenport_conflict::RTNETLINK answers: Address already in use::Client ListenPort conflict (often 443 in local tests)::Remove/adjust ListenPort in client config::manual
wg_client_ipv6_route_failure::RTNETLINK answers: No such device::Client IPv6 default route setup failed::Temporarily remove the IPv6 default route from AllowedIPs on that client::manual
peer_config_permission_denied::awk: cannot open /config/.*\.conf \(Permission denied\)::Peer config file denied inside container startup path::Run ssl-proxy in compose compatibility mode (root) or relax host file ownership/permissions::manual
qr_permission_denied::Permission denied::Peer config unreadable on host filesystem::Read profile from /config bind mount inside container::auto
wg_peer_material_missing::missing peer public key|missing peer preshared key|invalid config: peer [0-9]+ is missing PublicKey::WireGuard peer material is missing::Bootstrap local peer configs or provide config/peer*/ key files::auto
compose_dependency_unhealthy::dependency failed to start|container .* is unhealthy::Compose dependency failed to become healthy::Inspect the named service logs and healthcheck output::manual
compose_image_unavailable::manifest unknown|pull access denied|repository does not exist|not found: manifest unknown::Required image is missing from the configured registry::Build and push the missing image tag to REGISTRY, then rerun up-ready::manual
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

ensure_secret_file() {
    local path="$1"
    local label="$2"

    if [ -s "$path" ]; then
        return 0
    fi

    fail "Missing $label secret at $path; run scripts/gen-secrets generate"
}

ensure_admin_api_key_file() {
    if [ -n "${ADMIN_API_KEY:-}" ]; then
        return 0
    fi

    ensure_secret_file "$ROOT_DIR/secrets/admin_api_key" "admin API key"
}

ensure_obfuscation_key_file() {
    if [ -n "${WG_OBFUSCATION_KEY:-}" ]; then
        return 0
    fi

    ensure_secret_file "$ROOT_DIR/secrets/wg_obfuscation_key" "WireGuard obfuscation key"
}

activate_obfuscation_key_env_fallback() {
    local value

    ensure_secret_file "$ROOT_DIR/secrets/wg_obfuscation_key" "WireGuard obfuscation key"
    value="$(trim_key_value <"$ROOT_DIR/secrets/wg_obfuscation_key" || true)"
    if is_placeholder_value "$value"; then
        fail "WireGuard obfuscation key is empty or unresolved"
    fi

    export WG_OBFUSCATION_KEY="$value"
}

read_dotenv_value() {
    local key="$1"
    local line value

    [ -f "$ROOT_DIR/.env" ] || return 1
    line="$(grep -E "^${key}=" "$ROOT_DIR/.env" | tail -n 1 || true)"
    [ -n "$line" ] || return 1

    value="${line#*=}"
    value="${value%$'\r'}"
    case "$value" in
        \"*\")
            value="${value#\"}"
            value="${value%\"}"
            ;;
    esac
    printf '%s' "$value"
}

contains_unresolved_placeholder() {
    local value="$1"

    case "$value" in
        *"<"*|*">"*|*"generated by scripts/gen-secrets env"*) return 0 ;;
        *) return 1 ;;
    esac
}

require_concrete_endpoint_values() {
    case "$SERVER_IP" in
        ""|*"<"*|*">"*) fail "SERVER_IP must be concrete, for example SERVER_IP=192.168.1.221" ;;
    esac

    case "$CLIENT_IP" in
        ""|*"<"*|*">"*) fail "CLIENT_IP must be concrete, for example CLIENT_IP=192.168.1.53" ;;
    esac
}

default_registry_value() {
    printf '%s:5000' "$SERVER_IP"
}

registry_host_value() {
    local registry="$1"
    registry="${registry#http://}"
    registry="${registry#https://}"
    printf '%s' "${registry%%/*}"
}

registry_plain_http_enabled() {
    local registry_host="$1"
    local plain_http="${REGISTRY_PLAIN_HTTP:-auto}"

    case "$plain_http" in
        auto)
            case "$registry_host" in
                localhost:*|127.*|10.*|192.168.*|172.1[6-9].*|172.2[0-9].*|172.3[0-1].*) return 0 ;;
                *) return 1 ;;
            esac
            ;;
        1|true|yes) return 0 ;;
        0|false|no) return 1 ;;
        *)
            fail "REGISTRY_PLAIN_HTTP must be auto, 1, or 0"
            ;;
    esac
}

docker_daemon_lists_insecure_registry() {
    local registry_host="$1"
    local info host_ip

    case "$registry_host" in
        localhost:*|127.*) return 0 ;;
    esac

    info="$(docker info 2>/dev/null || true)"
    [ -n "$info" ] || return 1
    if printf '%s\n' "$info" | grep -Fq "$registry_host"; then
        return 0
    fi

    host_ip="${registry_host%%:*}"
    case "$host_ip" in
        10.*)
            if printf '%s\n' "$info" | grep -Fq "10.0.0.0/8"; then
                return 0
            fi
            ;;
        172.1[6-9].*|172.2[0-9].*|172.3[0-1].*)
            if printf '%s\n' "$info" | grep -Fq "172.16.0.0/12"; then
                return 0
            fi
            ;;
        192.168.*)
            if printf '%s\n' "$info" | grep -Fq "192.168.0.0/16"; then
                return 0
            fi
            ;;
        *)
            return 1
            ;;
    esac

    return 1
}

print_insecure_registry_fix() {
    local registry_host="$1"

    cat >&2 <<EOF_REGISTRY_FIX
[up-ready][ERROR] Docker daemon is not configured for plain-HTTP registry ${registry_host}.

Docker Desktop: Settings -> Docker Engine, add:
{ "insecure-registries": ["${registry_host}"] }

Linux Docker Engine: add the same JSON key to /etc/docker/daemon.json.
Restart Docker, then rerun:
make up-ready PROFILE_MODE=${PROFILE_MODE} SERVER_IP=${SERVER_IP} CLIENT_IP=${CLIENT_IP}

If Docker is configured through an equivalent trusted CIDR that this preflight
cannot detect, rerun with UP_READY_SKIP_REGISTRY_PREFLIGHT=1.
EOF_REGISTRY_FIX
}

verify_registry_transport() {
    local registry_host

    case "${UP_READY_SKIP_REGISTRY_PREFLIGHT:-0}" in
        1|true|yes) return 0 ;;
    esac

    registry_host="$(registry_host_value "$REGISTRY")"
    [ -n "$registry_host" ] || return 0
    registry_plain_http_enabled "$registry_host" || return 0

    if ! curl -fsS --max-time 2 "http://${registry_host}/v2/" >/dev/null 2>&1; then
        warn "plain-HTTP registry ${registry_host} is not reachable at /v2/ yet"
        return 0
    fi

    if docker_daemon_lists_insecure_registry "$registry_host"; then
        return 0
    fi

    set_failure_from_text "http: server gave HTTP response to HTTPS client"
    print_insecure_registry_fix "$registry_host"
    return 1
}

ensure_compose_env_defaults() {
    local existing_registry existing_image_tag registry image_tag

    existing_registry=""
    if [ -z "${REGISTRY:-}" ]; then
        existing_registry="$(read_dotenv_value REGISTRY || true)"
    fi

    if [ -n "${REGISTRY:-}" ]; then
        registry="$REGISTRY"
    elif [ -n "$existing_registry" ] && ! contains_unresolved_placeholder "$existing_registry"; then
        registry="$existing_registry"
    else
        registry="$(default_registry_value)"
    fi

    if contains_unresolved_placeholder "$registry"; then
        fail "REGISTRY resolved to a placeholder; set REGISTRY or SERVER_IP before running up-ready"
    fi

    existing_image_tag=""
    if [ -z "${IMAGE_TAG:-}" ]; then
        existing_image_tag="$(read_dotenv_value IMAGE_TAG || true)"
    fi

    if [ -n "${IMAGE_TAG:-}" ]; then
        image_tag="$IMAGE_TAG"
    elif [ -n "$existing_image_tag" ] && ! contains_unresolved_placeholder "$existing_image_tag"; then
        image_tag="$existing_image_tag"
    else
        image_tag="latest"
    fi

    if contains_unresolved_placeholder "$image_tag"; then
        fail "IMAGE_TAG resolved to a placeholder; set IMAGE_TAG before running up-ready"
    fi

    export REGISTRY="$registry"
    export IMAGE_TAG="$image_tag"
}

require_dotenv_value_resolved() {
    local key="$1"
    local value

    value="$(read_dotenv_value "$key" || true)"
    if [ -z "$value" ]; then
        fail "$key is missing or empty in .env after scripts/gen-secrets env"
    fi

    if contains_unresolved_placeholder "$value"; then
        fail "$key still contains an unresolved placeholder in .env after scripts/gen-secrets env"
    fi
}

validate_materialized_env() {
    local key dotenv_registry dotenv_image_tag

    [ -f "$ROOT_DIR/.env" ] || fail ".env missing after scripts/gen-secrets env"

    for key in \
        REGISTRY \
        IMAGE_TAG \
        POSTGRES_PASSWORD \
        MINIO_ACCESS_KEY_ID \
        MINIO_SECRET_ACCESS_KEY \
        GRAFANA_ADMIN_PASSWORD \
        ATHSEARCH_API_TOKEN_SHA256 \
        ADMIN_API_KEY_FILE \
        WG_OBFUSCATION_KEY_FILE \
        WAHA_API_KEY \
        WAHA_DASHBOARD_PASSWORD \
        WHATSAPP_SWAGGER_PASSWORD
    do
        require_dotenv_value_resolved "$key"
    done

    dotenv_registry="$(read_dotenv_value REGISTRY || true)"
    if [ "$dotenv_registry" != "$REGISTRY" ]; then
        fail ".env REGISTRY=$dotenv_registry does not match runtime REGISTRY=$REGISTRY"
    fi

    dotenv_image_tag="$(read_dotenv_value IMAGE_TAG || true)"
    if [ "$dotenv_image_tag" != "$IMAGE_TAG" ]; then
        fail ".env IMAGE_TAG=$dotenv_image_tag does not match runtime IMAGE_TAG=$IMAGE_TAG"
    fi
}

materialize_secret_env() {
    ensure_compose_env_defaults
    "$ROOT_DIR/scripts/gen-secrets" env >/dev/null
    validate_materialized_env
}

ensure_secret_bootstrap() {
    step S00 "secret_bootstrap: checking generated secrets"
    if "$ROOT_DIR/scripts/gen-secrets" check >/dev/null 2>&1; then
        materialize_secret_env
        step S00 "secret_bootstrap: .env materialized (REGISTRY=${REGISTRY} IMAGE_TAG=${IMAGE_TAG})"
        return 0
    fi

    if [ -f "$ROOT_DIR/secrets/ONE_TIME_TOKENS" ]; then
        materialize_secret_env 2>/dev/null || true
        "$ROOT_DIR/scripts/gen-secrets" check || true
        fail "Consume secrets/ONE_TIME_TOKENS, delete it, then rerun up-ready"
    fi

    step S00 "secret_bootstrap: repairing generated secrets"
    if "$ROOT_DIR/scripts/gen-secrets" repair >/dev/null 2>&1; then
        materialize_secret_env
        step S00 "secret_bootstrap: repaired generated secrets"
        return 0
    fi

    step S00 "secret_bootstrap: generating missing secrets"
    if ! "$ROOT_DIR/scripts/gen-secrets" generate; then
        "$ROOT_DIR/scripts/gen-secrets" check || true
        fail "secret generation failed"
    fi

    materialize_secret_env
    if ! "$ROOT_DIR/scripts/gen-secrets" check; then
        fail "Consume secrets/ONE_TIME_TOKENS, delete it, then rerun up-ready"
    fi
}

read_ini_value() {
    local file="$1"
    local section="$2"
    local key="$3"

    [ -f "$file" ] || return 1
    awk -F= -v section="$section" -v key="$key" '
        BEGIN { in_section = 0 }
        /^\[/ {
            in_section = ($0 == "[" section "]")
            next
        }
        in_section {
            lhs = $1
            gsub(/^[[:space:]]+|[[:space:]]+$/, "", lhs)
            if (lhs == key) {
                rhs = substr($0, index($0, "=") + 1)
                gsub(/^[[:space:]]+|[[:space:]]+$/, "", rhs)
                print rhs
                exit
            }
        }
    ' "$file"
}

trim_key_value() {
    tr -d '\r\n[:space:]'
}

is_placeholder_value() {
    local value="$1"
    case "$value" in
        ""|"<"*) return 0 ;;
        *) return 1 ;;
    esac
}

read_peer_config_value() {
    local peer_id="$1"
    local section="$2"
    local key="$3"
    local peer_dir="$ROOT_DIR/config/$peer_id"
    local cfg value

    for cfg in "$peer_dir/$peer_id.conf" "$peer_dir/$peer_id-obfuscated.conf"; do
        [ -f "$cfg" ] || continue
        value="$(read_ini_value "$cfg" "$section" "$key" | trim_key_value || true)"
        if ! is_placeholder_value "$value"; then
            printf '%s' "$value"
            return 0
        fi
    done

    return 1
}

peer_tunnel_address() {
    local peer_id="$1"
    local peer_number
    local peer_octet

    case "$1" in
        peer1) printf '10.13.13.2/32' ;;
        peer2) printf '10.13.13.3/32' ;;
        peer[0-9]*)
            peer_number="${peer_id#peer}"
            case "$peer_number" in
                ""|*[!0-9]*)
                    fail "Unsupported peer id: $peer_id"
                    ;;
            esac
            peer_octet="$((10#$peer_number + 1))"
            if [ "$peer_octet" -lt 2 ] || [ "$peer_octet" -gt 254 ]; then
                fail "Unsupported peer id: $peer_id"
            fi
            printf '10.13.13.%d/32' "$peer_octet"
            ;;
        *)
            # Derive a deterministic address for arbitrary peer IDs.
            peer_octet=$(printf '%s' "$peer_id" | cksum | awk '{print ($1 % 252) + 2}')
            printf '10.13.13.%d/32' "$peer_octet"
            ;;
    esac
}

escape_sed_replacement() {
    local value="$1"
    value="${value//\\/\\\\}"
    value="${value//&/\\&}"
    printf '%s' "$value"
}

uri_encode() {
    local value="$1"
    local length="${#value}"
    local index char

    for ((index = 0; index < length; index++)); do
        char="${value:index:1}"
        case "$char" in
            [a-zA-Z0-9.~_-]) printf '%s' "$char" ;;
            *) printf '%%%02X' "'$char" ;;
        esac
    done
}

ensure_peer_key_helper() {
    if [ "$PEER_KEY_HELPER_READY" -eq 1 ]; then
        return 0
    fi

    step S00 "peer_bootstrap: docker compose pull ssl-proxy"
    compose pull ssl-proxy || return 1
    PEER_KEY_HELPER_READY=1
}

run_peer_key_helper() {
    compose run --rm --no-deps -T --entrypoint /app/ssl-proxy ssl-proxy boringtun "$@" | trim_key_value
}

generate_peer_private_key() {
    run_peer_key_helper genkey
}

derive_peer_public_key() {
    local private_key="$1"
    run_peer_key_helper pubkey "$private_key"
}

generate_peer_preshared_key() {
    require_command openssl
    openssl rand -base64 32 | trim_key_value
}

write_secret_text() {
    local path="$1"
    local value="$2"
    local mode="${3:-600}"

    mkdir -p "$(dirname "$path")" || return 1
    umask 077
    printf '%s\n' "$value" >"$path" || return 1
    chmod "$mode" "$path" || return 1
}

render_direct_peer_config() {
    local peer_id="$1"
    local private_key="$2"
    local preshared_key="$3"
    local output="$ROOT_DIR/config/$peer_id/$peer_id.conf"
    local address endpoint_port

    address="$(peer_tunnel_address "$peer_id")"
    endpoint_port="${WG_PORT:-443}"
    mkdir -p "$(dirname "$output")" || return 1
    umask 077
    cat >"$output" <<EOF_PEER_DIRECT || return 1
# Raw direct WireGuard reference profile only.
# This profile is not usable against an obfuscation-only public server port.
# When WG_OBFUSCATION_ENABLED=true on the server, use ${peer_id}-obfuscated.conf plus a local UDP shim instead.
[Interface]
Address = $address
PrivateKey = $private_key
ListenPort = 51820
MTU = ${WG_MTU:-1420}
DNS = 10.13.13.1

[Peer]
PublicKey = <server-public-key>
PresharedKey = $preshared_key
# Endpoint must be the Docker host's LAN/public IP, not a container bridge IP.
Endpoint = ${SERVER_IP}:${endpoint_port}
AllowedIPs = 0.0.0.0/0, ::/0
EOF_PEER_DIRECT
    chmod 600 "$output" || return 1
    step S00 "peer_bootstrap: wrote $output"
}

render_obfuscated_peer_config() {
    local peer_id="$1"
    local private_key="$2"
    local preshared_key="$3"
    local peer_dir="$ROOT_DIR/config/$peer_id"
    local example="$peer_dir/$peer_id-obfuscated.conf.example"
    local output="$peer_dir/$peer_id-obfuscated.conf"
    local escaped_private escaped_psk address

    if [ -f "$example" ]; then
        escaped_private="$(escape_sed_replacement "$private_key")"
        escaped_psk="$(escape_sed_replacement "$preshared_key")"
        sed \
            -e "s|<${peer_id}-private-key>|$escaped_private|g" \
            -e "s|<${peer_id}-preshared-key>|$escaped_psk|g" \
            "$example" >"$output" || return 1
    else
        address="$(peer_tunnel_address "$peer_id")"
        umask 077
        cat >"$output" <<EOF_PEER_OBFUSCATED || return 1
# Supported client path when UDP obfuscation is enabled on the server.
[Interface]
Address = $address
PrivateKey = $private_key
ListenPort = 443
MTU = ${WG_MTU:-1419}
DNS = 10.13.13.1

[Peer]
PublicKey = <server-public-key>
PresharedKey = $preshared_key
Endpoint = 127.0.0.1:51821
AllowedIPs = 0.0.0.0/0, ::/0
EOF_PEER_OBFUSCATED
    fi
    chmod 600 "$output" || return 1
    step S00 "peer_bootstrap: wrote $output"
}

peer_material_complete() {
    local peer_id="$1"
    local peer_dir="$ROOT_DIR/config/$peer_id"

    [ -s "$peer_dir/publickey-$peer_id" ] &&
        [ -s "$peer_dir/presharedkey-$peer_id" ] &&
        [ -s "$peer_dir/$peer_id.conf" ] &&
        [ -s "$peer_dir/$peer_id-obfuscated.conf" ]
}

ensure_one_peer_material() {
    local peer_id="$1"
    local peer_dir="$ROOT_DIR/config/$peer_id"
    local private_key_file="$peer_dir/privatekey-$peer_id"
    local public_key_file="$peer_dir/publickey-$peer_id"
    local preshared_key_file="$peer_dir/presharedkey-$peer_id"
    local private_key public_key preshared_key

    mkdir -p "$peer_dir" || return 1

    private_key="$(test -s "$private_key_file" && trim_key_value <"$private_key_file" || true)"
    if is_placeholder_value "$private_key"; then
        private_key="$(read_peer_config_value "$peer_id" "Interface" "PrivateKey" || true)"
    fi
    if is_placeholder_value "$private_key"; then
        private_key="$(generate_peer_private_key)" || return 1
        step S00 "peer_bootstrap: generated private key for $peer_id"
    fi
    [ -n "$private_key" ] || fail "Unable to resolve private key for $peer_id"
    [ -s "$private_key_file" ] || write_secret_text "$private_key_file" "$private_key" 600 || return 1

    public_key="$(test -s "$public_key_file" && trim_key_value <"$public_key_file" || true)"
    if is_placeholder_value "$public_key"; then
        public_key="$(derive_peer_public_key "$private_key")" || return 1
        write_secret_text "$public_key_file" "$public_key" 644 || return 1
        step S00 "peer_bootstrap: wrote public key for $peer_id"
    fi

    preshared_key="$(test -s "$preshared_key_file" && trim_key_value <"$preshared_key_file" || true)"
    if is_placeholder_value "$preshared_key"; then
        preshared_key="$(read_peer_config_value "$peer_id" "Peer" "PresharedKey" || true)"
    fi
    if is_placeholder_value "$preshared_key"; then
        preshared_key="$(generate_peer_preshared_key)" || return 1
        step S00 "peer_bootstrap: generated preshared key for $peer_id"
    fi
    [ -n "$preshared_key" ] || fail "Unable to resolve preshared key for $peer_id"
    [ -s "$preshared_key_file" ] || write_secret_text "$preshared_key_file" "$preshared_key" 600 || return 1

    [ -s "$peer_dir/$peer_id.conf" ] || render_direct_peer_config "$peer_id" "$private_key" "$preshared_key" || return 1
    [ -s "$peer_dir/$peer_id-obfuscated.conf" ] || render_obfuscated_peer_config "$peer_id" "$private_key" "$preshared_key" || return 1
}

ensure_local_peer_material() {
    local needs_bootstrap=0
    local peer_id

    while IFS= read -r peer_id; do
        if ! peer_material_complete "$peer_id"; then
            needs_bootstrap=1
        fi
    done < <(peer_names)

    [ "$needs_bootstrap" -eq 1 ] || return 0
    ensure_peer_key_helper || return 1

    while IFS= read -r peer_id; do
        ensure_one_peer_material "$peer_id" || return 1
    done < <(peer_names)
}

require_profile_mode() {
    case "$PROFILE_MODE" in
        iphone|linux-shim|linux-direct|mac) ;;
        *)
            cat >&2 <<'EOF_MODE'
[up-ready][ERROR] PROFILE_MODE is required.
Allowed values: iphone | linux-shim | linux-direct | mac
Example: make up-ready PROFILE_MODE=mac SERVER_IP=192.168.1.221 CLIENT_IP=192.168.1.53
EOF_MODE
            exit 1
            ;;
    esac
}

apply_profile_runtime_env() {
    ensure_admin_api_key_file

    case "$PROFILE_MODE" in
        iphone|linux-direct)
            export WG_OBFUSCATION_ENABLED=false
            export WG_PORT=443
            export WG_INTERNAL_PORT=51820
            ;;
        linux-shim)
            export WG_OBFUSCATION_ENABLED=true
            export WG_PORT=443
            export WG_INTERNAL_PORT=51820
            activate_obfuscation_key_env_fallback
            ;;
        mac)
            export WG_OBFUSCATION_ENABLED=true
            export WG_PORT=51820
            export WG_INTERNAL_PORT=443
            activate_obfuscation_key_env_fallback
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
            printf '/config/%s' "${host_path#${ROOT_DIR}/config/}"
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
    if [ -n "$container_cfg" ] && compose exec -T "$SERVICE_NAME" test -r "$container_cfg"; then
        compose exec -T "$SERVICE_NAME" cat "$container_cfg" | qrencode -t "$QR_TYPE" -m "$QR_MARGIN"
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
        linux-shim|mac) printf 'true' ;;
        iphone|linux-direct) printf 'false' ;;
    esac
}

compose_up() {
    step S03 "compose_pull: docker compose pull"
    local output
    if output="$(compose pull 2>&1)"; then
        printf '%s\n' "$output"
    else
        printf '%s\n' "$output" >&2
        set_failure_from_text "$output"
        if auto_fix "$LAST_FAILURE_CLASS" "$output"; then
            return 0
        fi
        if recover_required_compose_stack "compose pull" "$output"; then
            return 0
        fi
        return 1
    fi

    step S03 "compose_up: docker compose up -d"
    if output="$(compose up -d 2>&1)"; then
        printf '%s\n' "$output"
        return 0
    fi

    printf '%s\n' "$output" >&2
    set_failure_from_text "$output"
    if auto_fix "$LAST_FAILURE_CLASS" "$output"; then
        return 0
    fi
    if recover_required_compose_stack "compose up -d" "$output"; then
        return 0
    fi
    return 1
}

required_stack_healthy() {
    local service
    for service in $STACK_HEALTH_SERVICES; do
        wait_for_container_healthy "$service" || return 1
    done
}

recover_required_compose_stack() {
    local phase="$1"
    local failure_output="$2"
    local output
    local pull_output=""

    warn "${phase} failed; retrying readiness-critical services only: ${STACK_HEALTH_SERVICES}"

    step S03 "compose_pull_required: docker compose pull --include-deps ${STACK_HEALTH_SERVICES}"
    if output="$(compose pull --include-deps $STACK_HEALTH_SERVICES 2>&1)"; then
        printf '%s\n' "$output"
    else
        printf '%s\n' "$output" >&2
        pull_output="$output"
        warn "compose_pull_required failed; attempting compose_up_required with locally available images"
    fi

    step S03 "compose_up_required: docker compose up -d ${STACK_HEALTH_SERVICES}"
    if output="$(compose up -d $STACK_HEALTH_SERVICES 2>&1)"; then
        printf '%s\n' "$output"
    else
        printf '%s\n' "$output" >&2
        set_failure_from_text "${failure_output}"$'\n'"${pull_output}"$'\n'"${output}"
        return 1
    fi

    if required_stack_healthy; then
        warn "Full compose operation failed, but readiness-critical services are healthy; continuing"
        set_failure_from_text "${failure_output}"$'\n'"${pull_output}"
        return 0
    fi

    set_failure_from_text "${failure_output}"$'\n'"${pull_output}"
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
        java-coordinator)
            set_failure_from_text "$logs"$'\n'"java-coordinator unhealthy"
            ;;
        postgres)
            set_failure_from_text "$logs"$'\n'"postgres unhealthy"
            ;;
        redpanda)
            set_failure_from_text "$logs"$'\n'"redpanda unhealthy"
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
    trap 'rm -f "$body_file"' RETURN
    ready_code="$(curl -sS -o "$body_file" -w '%{http_code}' --max-time 2 http://127.0.0.1:3002/ready 2>/dev/null || true)"
    if [ "$ready_code" = "000" ]; then
        ready_code="$(compose exec -T "$SERVICE_NAME" curl -sS -o /tmp/up-ready-ready-body.txt -w '%{http_code}' --max-time 2 http://127.0.0.1:3002/ready 2>/dev/null || true)"
        compose exec -T "$SERVICE_NAME" sh -lc 'cat /tmp/up-ready-ready-body.txt' >"$body_file" 2>/dev/null || true
    fi
    ready_body="$(tr -d '\n' <"$body_file")"
    rm -f "$body_file"
    trap - RETURN

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

check_frontdoor_udp_listener() {
    local port="$1"
    compose exec -T "$FRONTDOOR_SERVICE_NAME" sh -lc "ss -H -lun '( sport = :${port} )' | grep -q ."
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

    run_check_with_retry "frontdoor_udp_443" check_frontdoor_udp_listener 443 || return 1
    run_check_with_retry "frontdoor_udp_51820" check_frontdoor_udp_listener 51820 || return 1
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
        case "$PROFILE_MODE" in
            iphone|linux-direct)
                selected_cfg="$fallback_cfg"
                [ -n "$selected_cfg" ] || selected_cfg="$obfuscated_cfg"
                ;;
            mac|linux-shim)
                selected_cfg="$obfuscated_cfg"
                [ -n "$selected_cfg" ] || selected_cfg="$fallback_cfg"
                ;;
        esac
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

append_file_section() {
    local output="$1"
    local title="$2"
    local path="$3"

    if [ -s "$path" ]; then
        {
            printf '\n## %s\n' "$title"
            printf 'path=%s\n\n' "$path"
            cat "$path"
            printf '\n'
        } >>"$output"
    else
        {
            printf '\n## %s\n' "$title"
            printf 'missing=%s\n' "$path"
        } >>"$output"
    fi
}

read_handoff_secret() {
    local path="$1"

    [ -s "$path" ] || return 0
    trim_key_value <"$path"
}

write_credential_handoff() {
    step S09 "credential_handoff"

    local output tmp postgres_password postgres_password_url grafana_password admin_api_key wg_obfuscation_key grafana_user
    local wg_magic_byte wg_session_idle_secs wg_public_port shim_server_addr
    local peer_id peer_dir direct_cfg obfuscated_cfg selected_cfg
    local old_umask

    output="$CREDENTIAL_HANDOFF_FILE"
    mkdir -p "$(dirname "$output")" || return 1
    tmp="$(mktemp "${output}.XXXXXX")" || return 1

    postgres_password="$(read_handoff_secret "$ROOT_DIR/secrets/postgres.key" || true)"
    postgres_password_url="$(uri_encode "$postgres_password")"
    grafana_password="$(read_handoff_secret "$ROOT_DIR/secrets/grafana_admin_password.key" || true)"
    admin_api_key="$(read_handoff_secret "$ROOT_DIR/secrets/admin_api_key" || true)"
    wg_obfuscation_key="$(read_handoff_secret "$ROOT_DIR/secrets/wg_obfuscation_key" || true)"
    grafana_user="${GRAFANA_ADMIN_USER:-admin}"
    wg_magic_byte="${WG_OBFUSCATION_MAGIC_BYTE:-0xAA}"
    wg_session_idle_secs="${WG_OBFUSCATION_SESSION_IDLE_SECS:-300}"
    wg_public_port="${WG_PORT:-443}"
    shim_server_addr="${SERVER_IP}:${wg_public_port}"

    old_umask="$(umask)"
    umask 077
    {
        printf '# ssl-proxy credential handoff\n'
        printf 'generated_at=%s\n' "$RUN_TS"
        printf 'profile_mode=%s\n' "$PROFILE_MODE"
        printf 'server_ip=%s\n' "$SERVER_IP"
        printf 'client_ip=%s\n' "$CLIENT_IP"
        printf '\n## Proxy admin API\n'
        printf 'url=http://127.0.0.1:3002\n'
        printf 'admin_api_key=%s\n' "$admin_api_key"
        printf '\n## WireGuard shim\n'
        printf 'enabled=%s\n' "$(desired_obfuscation_value)"
        printf 'shim_pass=%s\n' "$wg_obfuscation_key"
        printf 'magic_byte=%s\n' "$wg_magic_byte"
        printf 'WG_OBFS_SERVER_ADDR=%s\n' "$shim_server_addr"
        printf 'WG_OBFS_SHIM_LISTEN_ADDR=127.0.0.1:51821\n'
        printf 'WG_OBFUSCATION_KEY=%s\n' "$wg_obfuscation_key"
        printf 'WG_OBFUSCATION_MAGIC_BYTE=%s\n' "$wg_magic_byte"
        printf 'WG_OBFUSCATION_SESSION_IDLE_SECS=%s\n' "$wg_session_idle_secs"
        printf '\n## Postgres\n'
        printf 'host=127.0.0.1\n'
        printf 'port=5432\n'
        printf 'database=sync\n'
        printf 'username=sync\n'
        printf 'password=%s\n' "$postgres_password"
        printf 'url=postgres://sync:%s@127.0.0.1:5432/sync\n' "$postgres_password_url"
        printf '\n## Grafana\n'
        printf 'url=http://127.0.0.1:3004\n'
        printf 'username=%s\n' "$grafana_user"
        printf 'password=%s\n' "$grafana_password"
    } >"$tmp" || {
        umask "$old_umask"
        rm -f "$tmp"
        return 1
    }
    umask "$old_umask"

    while IFS= read -r peer_id; do
        peer_dir="$ROOT_DIR/config/$peer_id"
        direct_cfg="$peer_dir/$peer_id.conf"
        obfuscated_cfg="$peer_dir/$peer_id-obfuscated.conf"
        case "$PROFILE_MODE" in
            iphone|linux-direct) selected_cfg="$direct_cfg" ;;
            mac|linux-shim) selected_cfg="$obfuscated_cfg" ;;
        esac

        append_file_section "$tmp" "WireGuard ${peer_id} selected config" "$selected_cfg" || {
            rm -f "$tmp"
            return 1
        }
        append_file_section "$tmp" "WireGuard ${peer_id} direct config" "$direct_cfg" || {
            rm -f "$tmp"
            return 1
        }
        append_file_section "$tmp" "WireGuard ${peer_id} obfuscated config" "$obfuscated_cfg" || {
            rm -f "$tmp"
            return 1
        }
    done < <(peer_names)

    chmod 600 "$tmp" || {
        rm -f "$tmp"
        return 1
    }
    mv "$tmp" "$output" || {
        rm -f "$tmp"
        return 1
    }
    chmod 600 "$output" || return 1

    step S09 "credential_handoff: wrote $output (0600)"
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
    if [ -z "$LAST_FAILURE_CLASS" ] || [ "$LAST_FAILURE_CLASS" = "unknown" ]; then
        set_failure_from_text "$text"
    fi

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
            step S09 "auto_fix[$class]: recreate with locally available images"
            if compose up -d --force-recreate; then
                mark_auto_fixed "$class"
                return 0
            fi
            ;;
        profile_obfuscation_mismatch)
            local desired
            desired="$(desired_obfuscation_value)"
            apply_profile_runtime_env
            step S09 "auto_fix[$class]: recreate with WG_OBFUSCATION_ENABLED=$desired"
            if compose up -d --force-recreate; then
                mark_auto_fixed "$class"
                return 0
            fi
            ;;
        secret_file_owner_mismatch)
            step S09 "auto_fix[$class]: use direct WG_OBFUSCATION_KEY env fallback and recreate"
            activate_obfuscation_key_env_fallback
            if compose up -d --force-recreate "$SERVICE_NAME" "$FRONTDOOR_SERVICE_NAME"; then
                mark_auto_fixed "$class"
                return 0
            fi
            ;;
        admin_loopback_false_negative|qr_permission_denied)
            step S09 "auto_fix[$class]: no-op (handled by fallback path)"
            mark_auto_fixed "$class"
            return 0
            ;;
        wg_peer_material_missing)
            step S09 "auto_fix[$class]: bootstrap peer material and recreate"
            ensure_local_peer_material || return 1
            if compose up -d --force-recreate; then
                mark_auto_fixed "$class"
                return 0
            fi
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
    require_concrete_endpoint_values
    ensure_secret_bootstrap
    verify_registry_transport
    ensure_memory_schema
}

main() {
    preflight
    apply_profile_runtime_env
    ensure_local_peer_material || fail "peer bootstrap failed"

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

    if ! write_credential_handoff; then
        memo_write "fail" "credential_handoff" "write credential handoff"
        fail "credential_handoff failed"
    fi

    memo_write "pass" "none" "up-ready completed"
    step S10 "completed"
}

main "$@"
