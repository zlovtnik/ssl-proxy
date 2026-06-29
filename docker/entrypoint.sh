#!/usr/bin/env bash
set -euo pipefail

PROXY_BIN="${PROXY_BIN:-/app/ssl-proxy}"
BORINGTUN_BIN="${BORINGTUN_BIN:-/usr/local/bin/boringtun-cli}"
COREDNS_CONFIG="${COREDNS_CONFIG:-/config/coredns/Corefile}"
WG_INTERFACE_NAME="${WG_INTERFACE_NAME:-wg0}"
WG_CONFIG_PATH="${WG_CONFIG_PATH:-/run/wireguard/${WG_INTERFACE_NAME}.conf}"
WG_UAPI_SOCKET_DIR="${WG_UAPI_SOCKET_DIR:-/var/run/wireguard}"
WG_TEMPLATE_PATH="${WG_TEMPLATE_PATH:-/config/templates/server.conf}"
WG_SERVER_PRIVATE_KEY_FILE="${WG_SERVER_PRIVATE_KEY_FILE:-/config/server/privatekey-server}"
WG_SERVER_PUBLIC_KEY_FILE="${WG_SERVER_PUBLIC_KEY_FILE:-/config/server/publickey-server}"
WG_PEERS="${WG_PEERS:-${ROTATOR_PEERS:-peer1,peer2}}"
WG_PEER_CONFIG_BASE="${WG_PEER_CONFIG_BASE:-/config}"
WG_SERVER_ADDRESS="${WG_SERVER_ADDRESS:-10.13.13.1/24}"
WG_PORT="${WG_PORT:-443}"
WG_INTERNAL_PORT="${WG_INTERNAL_PORT:-51820}"
WG_OBFUSCATION_ENABLED="${WG_OBFUSCATION_ENABLED:-true}"
WG_MTU="${WG_MTU:-1420}"
WG_WAN_INTERFACE="${WG_WAN_INTERFACE:-auto}"
WG_SYSCTL_RETRIES="${WG_SYSCTL_RETRIES:-3}"
WG_SYSCTL_RETRY_DELAY_MS="${WG_SYSCTL_RETRY_DELAY_MS:-200}"
ENABLE_NETWORK_SEGMENTATION="${ENABLE_NETWORK_SEGMENTATION:-true}"
ADMIN_BIND_ADDR="${ADMIN_BIND_ADDR:-127.0.0.1}"
ADMIN_PORT="${ADMIN_PORT:-3002}"
PROXY_PORT="${PROXY_PORT:-3000}"
TPROXY_PORT="${TPROXY_PORT:-3001}"
PROXY_RESTART_LIMIT="${PROXY_RESTART_LIMIT:-5}"
PROXY_RESTART_BACKOFF="${PROXY_RESTART_BACKOFF:-1}"
RAW_WG_SERVER_ADDRESS=""
WG_RUNTIME_LISTEN_PORT=""

cmd() {
	echo "[#] $*"
	"$@"
}

is_truthy() {
	case "${1,,}" in
	true | 1 | yes | on) return 0 ;;
	*) return 1 ;;
	esac
}

trim() {
	local value="$1"
	value="${value#"${value%%[![:space:]]*}"}"
	value="${value%"${value##*[![:space:]]}"}"
	printf '%s' "$value"
}

validate_peer_name() {
	local peer="$1"

	case "$peer" in
	"" | *[!A-Za-z0-9_-]*)
		echo "invalid WireGuard peer name: $peer" >&2
		exit 1
		;;
	esac
}

peer_names() {
	local raw_peer peer

	printf '%s' "$WG_PEERS" | tr ',' '\n' | while IFS= read -r raw_peer; do
		peer="$(trim "$raw_peer")"
		[ -n "$peer" ] || continue
		validate_peer_name "$peer"
		printf '%s\n' "$peer"
	done
}

declare -A _peer_env_claimed

peer_env_suffix() {
	printf '%s' "$1" | tr '[:lower:]-' '[:upper:]_'
}

peer_env_value() {
	local peer="$1"
	local key="$2"
	local default="$3"
	local suffix env_name legacy_name value

	suffix="$(peer_env_suffix "$peer")"
	env_name="WG_${suffix}_${key}"
	value="${!env_name-}"
	if [ -n "$value" ]; then
		if [ -n "${_peer_env_claimed[$env_name]+x}" ] && [ "${_peer_env_claimed[$env_name]}" != "$peer" ]; then
			echo "peer env collision: $env_name is already claimed by peer ${_peer_env_claimed[$env_name]}; refusing to share with $peer" >&2
			return 1
		fi
		_peer_env_claimed[$env_name]="$peer"
		printf '%s' "$value"
		return 0
	fi

	if [ "$key" = "OBFUSCATED_CONFIG_PATH" ]; then
		legacy_name="WG_OBFUSCATED_${suffix}_CONFIG_PATH"
		value="${!legacy_name-}"
		if [ -n "$value" ]; then
			if [ -n "${_peer_env_claimed[$legacy_name]+x}" ] && [ "${_peer_env_claimed[$legacy_name]}" != "$peer" ]; then
				echo "peer env collision: $legacy_name is already claimed by peer ${_peer_env_claimed[$legacy_name]}; refusing to share with $peer" >&2
				return 1
			fi
			_peer_env_claimed[$legacy_name]="$peer"
			printf '%s' "$value"
			return 0
		fi
	fi

	if [ "$peer" = "peer1" ]; then
		case "$key" in
		CONFIG_PATH) value="${WG_PEER_CONFIG_PATH-}" ;;
		OBFUSCATED_CONFIG_PATH) value="${WG_OBFUSCATED_PEER_CONFIG_PATH-}" ;;
		PUBLIC_KEY_FILE) value="${WG_PEER_PUBLIC_KEY_FILE-}" ;;
		PRESHARED_KEY_FILE) value="${WG_PEER_PRESHARED_KEY_FILE-}" ;;
		ALLOWED_IPS) value="${WG_PEER_ALLOWED_IPS-}" ;;
		*) value="" ;;
		esac
		if [ -n "$value" ]; then
			printf '%s' "$value"
			return 0
		fi
	fi

	printf '%s' "$default"
}

peer_config_path() {
	local peer="$1"
	peer_env_value "$peer" "CONFIG_PATH" "$WG_PEER_CONFIG_BASE/$peer/$peer.conf"
}

peer_obfuscated_config_path() {
	local peer="$1"
	peer_env_value "$peer" "OBFUSCATED_CONFIG_PATH" "$WG_PEER_CONFIG_BASE/$peer/$peer-obfuscated.conf"
}

peer_public_key_file() {
	local peer="$1"
	peer_env_value "$peer" "PUBLIC_KEY_FILE" "$WG_PEER_CONFIG_BASE/$peer/publickey-$peer"
}

peer_preshared_key_file() {
	local peer="$1"
	peer_env_value "$peer" "PRESHARED_KEY_FILE" "$WG_PEER_CONFIG_BASE/$peer/presharedkey-$peer"
}

peer_allowed_ips() {
	local peer="$1"
	peer_env_value "$peer" "ALLOWED_IPS" ""
}

read_trimmed_file() {
	local path="$1"
	if [ ! -f "$path" ]; then
		echo "missing required file: $path" >&2
		exit 1
	fi
	tr -d '\r' <"$path" | sed -e 's/[[:space:]]*$//' | tail -n 1
}

try_read_trimmed_file() {
	local path="$1"
	if [ ! -f "$path" ]; then
		return 1
	fi
	tr -d '\r' <"$path" | sed -e 's/[[:space:]]*$//' | tail -n 1
}

write_trimmed_file() {
	local path="$1"
	local value="$2"
	local mode="${3:-600}"
	mkdir -p "$(dirname "$path")"
	printf '%s\n' "$value" >"$path"
	chmod "$mode" "$path"
}

extract_ini_value() {
	local file="$1"
	local section="$2"
	local key="$3"
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

run_hooks() {
	local key="$1"
	awk -F= -v key="$key" '
        BEGIN { in_if = 0 }
        /^\[Interface\]/ { in_if = 1; next }
        /^\[/ { in_if = 0 }
        in_if {
            lhs = $1
            gsub(/^[[:space:]]+|[[:space:]]+$/, "", lhs)
            if (lhs == key) {
                rhs = substr($0, index($0, "=") + 1)
                gsub(/^[[:space:]]+|[[:space:]]+$/, "", rhs)
                print rhs
            }
        }
    ' "$WG_CONFIG_PATH" | while IFS= read -r line; do
		[ -n "$line" ] || continue
		line="${line//%i/$WG_INTERFACE_NAME}"
		cmd bash -lc "$line"
	done
}

extract_interface_addresses() {
	awk -F= '
        function trim(s) {
            gsub(/^[[:space:]]+|[[:space:]]+$/, "", s)
            return s
        }
        BEGIN { in_if = 0 }
        /^\[Interface\]/ { in_if = 1; next }
        /^\[/ { in_if = 0 }
        in_if {
            lhs = trim($1)
            if (lhs != "Address") {
                next
            }
            rhs = substr($0, index($0, "=") + 1)
            count = split(rhs, parts, ",")
            for (i = 1; i <= count; i++) {
                addr = trim(parts[i])
                if (addr != "") {
                    print addr
                }
            }
        }
    ' "$WG_CONFIG_PATH"
}

extract_interface_mtu() {
	extract_ini_value "$WG_CONFIG_PATH" "Interface" "MTU"
}

wait_for_boringtun_uapi() {
	local socket_path="${WG_UAPI_SOCKET_DIR}/${WG_INTERFACE_NAME}.sock"
	local attempt=0
	while [ "$attempt" -lt 50 ]; do
		if [ -S "$socket_path" ] && ip link show dev "$WG_INTERFACE_NAME" >/dev/null 2>&1; then
			return 0
		fi
		sleep 0.1
		attempt=$((attempt + 1))
	done
	echo "BoringTun userspace control socket did not appear at $socket_path" >&2
	exit 1
}

ensure_uapi_socket_dir() {
	mkdir -p "$WG_UAPI_SOCKET_DIR"
	chown root:root "$WG_UAPI_SOCKET_DIR"
	chmod 700 "$WG_UAPI_SOCKET_DIR"
}

configure_boringtun_interface() {
	local addr
	local mtu

	cmd "$PROXY_BIN" boringtun apply-config "$WG_INTERFACE_NAME" "$WG_CONFIG_PATH"

	while IFS= read -r addr; do
		[ -n "$addr" ] || continue
		if [[ "$addr" == *:* ]]; then
			cmd ip -6 address add "$addr" dev "$WG_INTERFACE_NAME"
		else
			cmd ip -4 address add "$addr" dev "$WG_INTERFACE_NAME"
		fi
	done < <(extract_interface_addresses)

	mtu="$(trim "$(extract_interface_mtu)")"
	if [ -n "$mtu" ]; then
		cmd ip link set mtu "$mtu" up dev "$WG_INTERFACE_NAME"
	else
		cmd ip link set up dev "$WG_INTERFACE_NAME"
	fi

	run_hooks PostUp
}

normalize_allowed_ips() {
	local address
	address="$(trim "${1%%,*}")"
	if [ -z "$address" ]; then
		echo "unable to derive peer tunnel address" >&2
		exit 1
	fi
	if [[ "$address" == */* ]]; then
		printf '%s' "$address"
	elif [[ "$address" == *:* ]]; then
		printf '%s/128' "$address"
	else
		printf '%s/32' "$address"
	fi
}

detect_wan_interface() {
	ip route show default 2>/dev/null | awk '/default/ {print $5; exit}'
}

resolve_wan_interface() {
	local resolved
	if [ "$WG_WAN_INTERFACE" != "auto" ] && [ -n "$WG_WAN_INTERFACE" ]; then
		resolved="$WG_WAN_INTERFACE"
	else
		resolved="$(detect_wan_interface)"
	fi

	resolved="$(trim "$resolved")"
	if [ -z "$resolved" ]; then
		echo "unable to determine WAN interface: set WG_WAN_INTERFACE explicitly" >&2
		exit 1
	fi

	WG_WAN_INTERFACE="$resolved"
}

normalize_csv_unique() {
	local input="$1"
	awk -v input="$input" '
        function trim(s) {
            gsub(/^[[:space:]]+|[[:space:]]+$/, "", s)
            return s
        }
        BEGIN {
            n = split(input, parts, ",")
            out = ""
            for (i = 1; i <= n; i++) {
                item = trim(parts[i])
                if (item == "") {
                    continue
                }
                if (!(item in seen)) {
                    seen[item] = 1
                    out = (out == "" ? item : out "," item)
                }
            }
            print out
        }
    '
}

sha256_file() {
	sha256sum "$1" | awk '{print $1}'
}

normalize_server_address() {
	local normalized_server_address

	RAW_WG_SERVER_ADDRESS="$WG_SERVER_ADDRESS"
	normalized_server_address="$(normalize_csv_unique "$WG_SERVER_ADDRESS")"
	if [ -z "$normalized_server_address" ]; then
		echo "WG_SERVER_ADDRESS resolved to empty value after normalization" >&2
		exit 1
	fi
	if [ "$normalized_server_address" != "$WG_SERVER_ADDRESS" ]; then
		echo "[#] Normalized WG_SERVER_ADDRESS: $WG_SERVER_ADDRESS -> $normalized_server_address"
	fi
	WG_SERVER_ADDRESS="$normalized_server_address"
}

escape_sed_value() {
	local value="$1"
	value="${value//\\/\\\\}"
	value="${value//&/\\&}"
	printf '%s' "$value"
}

log_startup_fingerprint() {
	local entrypoint_sha

	entrypoint_sha="$(sha256_file /usr/local/bin/start-proxy-wg)"
	echo "[startup-fingerprint] revision=${IMAGE_VCS_REF:-unknown} build_date=${IMAGE_BUILD_DATE:-unknown} entrypoint_sha256=$entrypoint_sha"
	echo "[startup-fingerprint] raw_wg_server_address=${RAW_WG_SERVER_ADDRESS:-$WG_SERVER_ADDRESS} normalized_wg_server_address=$WG_SERVER_ADDRESS wg_config_path=$WG_CONFIG_PATH wg_public_port=$WG_PORT wg_internal_port=$WG_INTERNAL_PORT wg_obfuscation_enabled=$WG_OBFUSCATION_ENABLED"
}

resolve_wireguard_runtime_ports() {
	if is_truthy "$WG_OBFUSCATION_ENABLED"; then
		if [ "$WG_PORT" = "$WG_INTERNAL_PORT" ]; then
			echo "WG_PORT and WG_INTERNAL_PORT must differ when WG_OBFUSCATION_ENABLED=true" >&2
			exit 1
		fi
		WG_RUNTIME_LISTEN_PORT="$WG_INTERNAL_PORT"
	else
		WG_RUNTIME_LISTEN_PORT="$WG_PORT"
	fi
}

configure_network_segmentation() {
	if ! is_truthy "$ENABLE_NETWORK_SEGMENTATION"; then
		echo "[#] Network segmentation disabled (ENABLE_NETWORK_SEGMENTATION=$ENABLE_NETWORK_SEGMENTATION)"
		return 0
	fi

	if ! command -v iptables >/dev/null 2>&1; then
		echo "[!] iptables not available; cannot enforce network segmentation" >&2
		return 1
	fi

	echo "[#] Applying network segmentation policy"
	# Idempotent chain setup.
	iptables -N SSL_PROXY_SEGMENT 2>/dev/null || true
	iptables -F SSL_PROXY_SEGMENT
	iptables -D INPUT -j SSL_PROXY_SEGMENT 2>/dev/null || true
	iptables -I INPUT 1 -j SSL_PROXY_SEGMENT
	if command -v ip6tables >/dev/null 2>&1; then
		ip6tables -N SSL_PROXY_SEGMENT 2>/dev/null || true
		ip6tables -F SSL_PROXY_SEGMENT
		ip6tables -D INPUT -j SSL_PROXY_SEGMENT 2>/dev/null || true
		ip6tables -I INPUT 1 -j SSL_PROXY_SEGMENT
	elif [ -f /proc/net/if_inet6 ]; then
		echo "[!] ip6tables not available while IPv6 is active; cannot enforce IPv6 network segmentation" >&2
		return 1
	fi

	# Baseline allows.
	iptables -A SSL_PROXY_SEGMENT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
	iptables -A SSL_PROXY_SEGMENT -i lo -j ACCEPT
	if command -v ip6tables >/dev/null 2>&1; then
		ip6tables -A SSL_PROXY_SEGMENT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
		ip6tables -A SSL_PROXY_SEGMENT -i lo -j ACCEPT
	fi

	# Admin/control-plane must remain host-local only.
	iptables -A SSL_PROXY_SEGMENT -p tcp --dport "$ADMIN_PORT" -s 127.0.0.1/32 -j ACCEPT
	iptables -A SSL_PROXY_SEGMENT -p tcp --dport "$ADMIN_PORT" -j REJECT
	if command -v ip6tables >/dev/null 2>&1; then
		ip6tables -A SSL_PROXY_SEGMENT -p tcp --dport "$ADMIN_PORT" -s ::1/128 -j ACCEPT
		ip6tables -A SSL_PROXY_SEGMENT -p tcp --dport "$ADMIN_PORT" -j REJECT
	fi

	# Data-plane ports must arrive through WireGuard interface only.
	iptables -A SSL_PROXY_SEGMENT -i "$WG_INTERFACE_NAME" -p tcp -m multiport --dports "$PROXY_PORT","$TPROXY_PORT" -j ACCEPT
	iptables -A SSL_PROXY_SEGMENT -p tcp -m multiport --dports "$PROXY_PORT","$TPROXY_PORT" -j REJECT
	if command -v ip6tables >/dev/null 2>&1; then
		ip6tables -A SSL_PROXY_SEGMENT -i "$WG_INTERFACE_NAME" -p tcp -m multiport --dports "$PROXY_PORT","$TPROXY_PORT" -j ACCEPT
		ip6tables -A SSL_PROXY_SEGMENT -p tcp -m multiport --dports "$PROXY_PORT","$TPROXY_PORT" -j REJECT
	fi

	# Leave all other traffic untouched for explicit deployment policy control.
	iptables -A SSL_PROXY_SEGMENT -j RETURN
	if command -v ip6tables >/dev/null 2>&1; then
		ip6tables -A SSL_PROXY_SEGMENT -j RETURN
	fi
	echo "[#] Network segmentation policy active (admin_bind=${ADMIN_BIND_ADDR}:${ADMIN_PORT})"
}

duplicate_interface_addresses() {
	local file="$1"
	awk -F= '
        function trim(s) {
            gsub(/^[[:space:]]+|[[:space:]]+$/, "", s)
            return s
        }
        BEGIN { in_if = 0 }
        /^\[Interface\]/ { in_if = 1; next }
        /^\[/ { in_if = 0 }
        in_if {
            lhs = trim($1)
            if (lhs != "Address") {
                next
            }
            rhs = substr($0, index($0, "=") + 1)
            count = split(rhs, parts, ",")
            for (i = 1; i <= count; i++) {
                addr = trim(parts[i])
                if (addr == "") {
                    continue
                }
                seen[addr]++
                if (seen[addr] == 2) {
                    if (!(addr in duplicate_seen)) {
                        duplicate_seen[addr] = 1
                        out = (out == "" ? addr : out "," addr)
                    }
                }
            }
        }
        END { print out }
    ' "$file"
}

collect_unique_interface_addresses() {
	local file="$1"
	awk -F= '
        function trim(s) {
            gsub(/^[[:space:]]+|[[:space:]]+$/, "", s)
            return s
        }
        BEGIN { in_if = 0; out = "" }
        /^\[Interface\]/ { in_if = 1; next }
        /^\[/ { in_if = 0 }
        in_if {
            lhs = trim($1)
            if (lhs != "Address") {
                next
            }
            rhs = substr($0, index($0, "=") + 1)
            count = split(rhs, parts, ",")
            for (i = 1; i <= count; i++) {
                addr = trim(parts[i])
                if (addr == "") {
                    continue
                }
                if (!(addr in seen)) {
                    seen[addr] = 1
                    out = (out == "" ? addr : out "," addr)
                }
            }
        }
        END { print out }
    ' "$file"
}

canonicalize_rendered_wireguard_config() {
	local addresses
	local tmp_file

	addresses="$(collect_unique_interface_addresses "$WG_CONFIG_PATH")"
	if [ -z "$addresses" ]; then
		return 0
	fi

	tmp_file="$(mktemp)"
	awk -v addresses="$addresses" -F= '
        function trim(s) {
            gsub(/^[[:space:]]+|[[:space:]]+$/, "", s)
            return s
        }
        BEGIN {
            in_if = 0
            wrote_address = 0
        }
        /^\[Interface\]/ {
            in_if = 1
            print
            next
        }
        /^\[/ {
            if (in_if && !wrote_address && addresses != "") {
                print "Address = " addresses
                wrote_address = 1
            }
            in_if = 0
            print
            next
        }
        in_if {
            lhs = trim($1)
            if (lhs == "Address") {
                if (!wrote_address && addresses != "") {
                    print "Address = " addresses
                    wrote_address = 1
                }
                next
            }
        }
        { print }
        END {
            if (in_if && !wrote_address && addresses != "") {
                print "Address = " addresses
            }
        }
    ' "$WG_CONFIG_PATH" >"$tmp_file"
	mv "$tmp_file" "$WG_CONFIG_PATH"
	chmod 600 "$WG_CONFIG_PATH"
	echo "[#] Canonicalized rendered WireGuard interface addresses: $addresses"
}

validate_rendered_wireguard_config() {
	local duplicates

	duplicates="$(duplicate_interface_addresses "$WG_CONFIG_PATH")"
	if [ -n "$duplicates" ]; then
		echo "duplicate WireGuard interface addresses rendered in $WG_CONFIG_PATH: $duplicates" >&2
		exit 1
	fi
}

resolve_peer_public_key() {
	local peer_public_key_file="$1"
	local peer_config="$2"
	local peer_public_key=""
	local legacy_peer_public_key_file=""
	local peer_private_key=""

	peer_public_key="$(try_read_trimmed_file "$peer_public_key_file" || true)"
	if [ -n "$peer_public_key" ]; then
		printf '%s' "$peer_public_key"
		return 0
	fi

	legacy_peer_public_key_file="$(dirname "$peer_public_key_file")/pubickey-$(basename "$peer_public_key_file" | sed 's/^publickey-//')"
	peer_public_key="$(try_read_trimmed_file "$legacy_peer_public_key_file" || true)"
	if [ -n "$peer_public_key" ]; then
		echo "[#] Using legacy peer public key file: $legacy_peer_public_key_file" >&2
		write_trimmed_file "$peer_public_key_file" "$peer_public_key" 644
		echo "[#] Synced peer public key to $peer_public_key_file" >&2
		printf '%s' "$peer_public_key"
		return 0
	fi

	if [ ! -f "$peer_config" ]; then
		echo "missing peer public key: set $peer_public_key_file or provide $peer_config with Interface.PrivateKey" >&2
		return 1
	fi

	peer_private_key="$(trim "$(extract_ini_value "$peer_config" "Interface" "PrivateKey")")"
	if [ -n "$peer_private_key" ]; then
		if ! peer_public_key="$("$PROXY_BIN" boringtun pubkey "$peer_private_key")"; then
			echo "invalid peer private key in $peer_config" >&2
			return 1
		fi
		echo "[#] Derived peer public key from $peer_config" >&2
		write_trimmed_file "$peer_public_key_file" "$peer_public_key" 644
		echo "[#] Wrote derived peer public key to $peer_public_key_file" >&2
		printf '%s' "$peer_public_key"
		return 0
	fi

	echo "missing peer public key: set $peer_public_key_file or include Interface.PrivateKey in $peer_config" >&2
	return 1
}

resolve_peer_preshared_key() {
	local peer_config="$1"
	local peer_preshared_key_file="$2"
	local peer_preshared_key=""

	if [ -f "$peer_preshared_key_file" ]; then
		peer_preshared_key="$(read_trimmed_file "$peer_preshared_key_file")"
	else
		if [ ! -f "$peer_config" ]; then
			echo "missing peer preshared key; set $peer_preshared_key_file or provide $peer_config" >&2
			return 1
		fi
		peer_preshared_key="$(extract_ini_value "$peer_config" "Peer" "PresharedKey")"
		peer_preshared_key="$(trim "$peer_preshared_key")"
	fi

	if [ -z "$peer_preshared_key" ]; then
		echo "missing peer preshared key; set $peer_preshared_key_file or populate $peer_config" >&2
		return 1
	fi

	printf '%s' "$peer_preshared_key"
}

resolve_peer_allowed_ips() {
	local peer_allowed_ips="$1"
	local peer_config="$2"
	local peer_address

	if [ -n "$peer_allowed_ips" ]; then
		printf '%s' "$peer_allowed_ips"
		return 0
	fi

	if [ ! -f "$peer_config" ]; then
		echo "missing peer allowed IPs: set WG_PEER*_ALLOWED_IPS or provide $peer_config with Interface.Address" >&2
		return 1
	fi

	peer_address="$(extract_ini_value "$peer_config" "Interface" "Address")"
	normalize_allowed_ips "$peer_address"
}

choose_peer_config_path() {
	local primary="$1"
	local secondary="$2"
	local secondary_example="${secondary}.example"

	if [ -f "$secondary" ]; then
		printf '%s' "$secondary"
		return 0
	fi
	if [ -f "$primary" ]; then
		printf '%s' "$primary"
		return 0
	fi
	if [ -f "$secondary_example" ]; then
		printf '%s' "$secondary_example"
		return 0
	fi

	printf '%s' "$secondary"
}

format_handshake_timestamp() {
	local epoch="$1"
	local rendered
	if [ -z "$epoch" ] || [ "$epoch" = "0" ]; then
		printf '%s' "never"
		return
	fi

	# Prefer GNU date formatting when available, fall back to raw epoch.
	rendered="$(TZ="${TZ:-America/New_York}" date -d "@$epoch" '+%Y-%m-%dT%H:%M:%S%z' 2>/dev/null || true)"
	if [ -n "$rendered" ]; then
		printf '%s' "$rendered"
	else
		printf '%s' "epoch:$epoch"
	fi
}

log_wireguard_peer_status() {
	local dump
	local peer_count
	local public_key
	local _preshared_key
	local endpoint
	local allowed_ips
	local latest_handshake
	local transfer_rx
	local transfer_tx
	local persistent_keepalive
	local handshake_readable

	if ! dump="$("$PROXY_BIN" boringtun dump "$WG_INTERFACE_NAME" 2>/dev/null)"; then
		echo "[wg] warning: unable to read peer status for interface $WG_INTERFACE_NAME" >&2
		return 0
	fi

	peer_count="$(printf '%s\n' "$dump" | awk 'NR > 1 {count++} END {print count + 0}')"
	echo "[wg] interface $WG_INTERFACE_NAME is up; peer_count=$peer_count"

	if [ "$peer_count" -eq 0 ]; then
		echo "[wg] no peers configured on $WG_INTERFACE_NAME"
		return 0
	fi

	while IFS=$'\t' read -r public_key _preshared_key endpoint allowed_ips latest_handshake transfer_rx transfer_tx persistent_keepalive; do
		[ -n "$public_key" ] || continue
		handshake_readable="$(format_handshake_timestamp "$latest_handshake")"
		[ -n "$endpoint" ] || endpoint="(none)"
		[ -n "$allowed_ips" ] || allowed_ips="(none)"
		[ -n "$persistent_keepalive" ] || persistent_keepalive="off"

		echo "[wg] peer=$public_key endpoint=$endpoint allowed_ips=$allowed_ips last_handshake=$handshake_readable rx_bytes=$transfer_rx tx_bytes=$transfer_tx keepalive_s=$persistent_keepalive"
	done < <(printf '%s\n' "$dump" | awk 'NR > 1')
}

sync_peer_server_public_key() {
	local public_key="$1"
	local peer_config="$2"
	local peer_config_dir
	local tmp_file
	local current_public_key

	if [ ! -f "$peer_config" ]; then
		return
	fi

	current_public_key="$(trim "$(extract_ini_value "$peer_config" "Peer" "PublicKey")")"
	if [ "$current_public_key" = "$public_key" ]; then
		return
	fi

	peer_config_dir="$(dirname "$peer_config")"
	if ! tmp_file="$(mktemp "${peer_config_dir}/.$(basename "$peer_config").tmp.XXXXXX" 2>/dev/null)"; then
		echo "[#] Peer config is read-only; leaving server public key unchanged in $peer_config" >&2
		return
	fi

	awk -v public_key="$public_key" '
        BEGIN { in_peer = 0 }
        /^\[Peer\]/ { in_peer = 1; print; next }
        /^\[/ { in_peer = 0; print; next }
        in_peer {
            line = $0
            stripped = line
            gsub(/^[[:space:]]+|[[:space:]]+$/, "", stripped)
            if (stripped ~ /^PublicKey[[:space:]]*=/) {
                print "PublicKey = " public_key
                next
            }
        }
        { print }
    ' "$peer_config" >"$tmp_file"
	if ! mv "$tmp_file" "$peer_config"; then
		rm -f "$tmp_file"
		echo "failed to sync server public key into $peer_config" >&2
		return 1
	fi
}

ensure_wireguard_server_keys() {
	local server_private_key
	local server_public_key
	local current_public_key

	mkdir -p "$(dirname "$WG_SERVER_PRIVATE_KEY_FILE")"
	mkdir -p "$(dirname "$WG_SERVER_PUBLIC_KEY_FILE")"

	if [ ! -f "$WG_SERVER_PRIVATE_KEY_FILE" ]; then
		echo "[#] Generating BoringTun server keypair at $WG_SERVER_PRIVATE_KEY_FILE"
		umask 077
		server_private_key="$("$PROXY_BIN" boringtun genkey)"
		write_trimmed_file "$WG_SERVER_PRIVATE_KEY_FILE" "$server_private_key" 600
	else
		server_private_key="$(read_trimmed_file "$WG_SERVER_PRIVATE_KEY_FILE")"
	fi

	server_public_key="$("$PROXY_BIN" boringtun pubkey "$server_private_key")"

	if [ -f "$WG_SERVER_PUBLIC_KEY_FILE" ]; then
		current_public_key="$(read_trimmed_file "$WG_SERVER_PUBLIC_KEY_FILE")"
	else
		current_public_key=""
	fi

	if [ "$current_public_key" != "$server_public_key" ]; then
		echo "[#] Syncing WireGuard server public key to $WG_SERVER_PUBLIC_KEY_FILE"
		write_trimmed_file "$WG_SERVER_PUBLIC_KEY_FILE" "$server_public_key" 644
	fi

	while IFS= read -r peer; do
		for peer_config in "$(peer_config_path "$peer")" "$(peer_obfuscated_config_path "$peer")" "$(peer_obfuscated_config_path "$peer").example"; do
			if [ -f "$peer_config" ]; then
				echo "[#] Syncing server public key into $peer_config"
				sync_peer_server_public_key "$server_public_key" "$peer_config" || exit 1
			fi
		done
	done < <(peer_names)
}

render_peer_values() {
	local peer_public_key_file="$1"
	local peer_preshared_key_file="$2"
	local primary_peer_config="$3"
	local secondary_peer_config="$4"
	local peer_allowed_ips="$5"
	local peer_config
	local peer_public_key
	local peer_preshared_key
	local peer_allowed_ips_value

	peer_config="$(choose_peer_config_path "$primary_peer_config" "$secondary_peer_config")"
	peer_public_key="$(resolve_peer_public_key "$peer_public_key_file" "$peer_config")" || return 1
	peer_preshared_key="$(resolve_peer_preshared_key "$peer_config" "$peer_preshared_key_file")" || return 1
	peer_allowed_ips_value="$(resolve_peer_allowed_ips "$peer_allowed_ips" "$peer_config")" || return 1

	printf '%s\n%s\n%s' "$peer_public_key" "$peer_preshared_key" "$peer_allowed_ips_value"
}

render_peer_block() {
	local peer="$1"
	local values
	local peer_public_key
	local peer_preshared_key
	local allowed_ips

	if ! values="$(render_peer_values "$(peer_public_key_file "$peer")" "$(peer_preshared_key_file "$peer")" "$(peer_config_path "$peer")" "$(peer_obfuscated_config_path "$peer")" "$(peer_allowed_ips "$peer")")"; then
		return 1
	fi

	peer_public_key="$(printf '%s\n' "$values" | sed -n '1p')"
	peer_preshared_key="$(printf '%s\n' "$values" | sed -n '2p')"
	allowed_ips="$(printf '%s\n' "$values" | sed -n '3p')"

	printf '[Peer]\nPublicKey = %s\nPresharedKey = %s\nAllowedIPs = %s\n' "$peer_public_key" "$peer_preshared_key" "$allowed_ips"
}

render_peer_blocks() {
	local peer block rendered=""

	while IFS= read -r peer; do
		if ! block="$(render_peer_block "$peer")"; then
			return 1
		fi
		if [ -n "$rendered" ]; then
			rendered="${rendered}"$'\n'"${block}"
		else
			rendered="$block"
		fi
	done < <(peer_names)

	if [ -z "$rendered" ]; then
		echo "WG_PEERS resolved to no peers" >&2
		return 1
	fi

	printf '%s\n' "$rendered"
}

render_wireguard_config() {
	local server_private_key
	local peer_blocks
	local escaped_server_private_key
	local escaped_server_address
	local escaped_public_port
	local escaped_internal_port
	local escaped_mtu
	local escaped_wan_interface
	local escaped_sysctl_retries
	local escaped_sysctl_retry_delay_ms

	if [ ! -f "$WG_TEMPLATE_PATH" ]; then
		echo "missing WireGuard template: $WG_TEMPLATE_PATH" >&2
		exit 1
	fi

	server_private_key="$(read_trimmed_file "$WG_SERVER_PRIVATE_KEY_FILE")"
	if ! peer_blocks="$(render_peer_blocks)"; then
		exit 1
	fi

	mkdir -p "$(dirname "$WG_CONFIG_PATH")"

	escaped_server_private_key="$(escape_sed_value "$server_private_key")"
	escaped_server_address="$(escape_sed_value "$WG_SERVER_ADDRESS")"
	escaped_public_port="$(escape_sed_value "$WG_PORT")"
	escaped_internal_port="$(escape_sed_value "$WG_RUNTIME_LISTEN_PORT")"
	escaped_mtu="$(escape_sed_value "$WG_MTU")"
	escaped_wan_interface="$(escape_sed_value "$WG_WAN_INTERFACE")"
	escaped_sysctl_retries="$(escape_sed_value "$WG_SYSCTL_RETRIES")"
	escaped_sysctl_retry_delay_ms="$(escape_sed_value "$WG_SYSCTL_RETRY_DELAY_MS")"

	sed \
		-e "s|__WG_SERVER_ADDRESS__|$escaped_server_address|g" \
		-e "s|__WG_PUBLIC_PORT__|$escaped_public_port|g" \
		-e "s|__WG_INTERNAL_PORT__|$escaped_internal_port|g" \
		-e "s|__WG_MTU__|$escaped_mtu|g" \
		-e "s|__WG_SERVER_PRIVATE_KEY__|$escaped_server_private_key|g" \
		-e "s|__WG_WAN_INTERFACE__|$escaped_wan_interface|g" \
		-e "s|__WG_SYSCTL_RETRIES__|$escaped_sysctl_retries|g" \
		-e "s|__WG_SYSCTL_RETRY_DELAY_MS__|$escaped_sysctl_retry_delay_ms|g" \
		"$WG_TEMPLATE_PATH" |
		awk -v peer_blocks="$peer_blocks" '
            $0 == "__WG_PEERS__" {
                print peer_blocks
                next
            }
            { print }
        ' >"$WG_CONFIG_PATH"

	chmod 600 "$WG_CONFIG_PATH"
}

cleanup() {
	set +e

	# Signal processes first (in correct order)
	if [ -n "${PROXY_PID:-}" ]; then
		kill -TERM "$PROXY_PID" 2>/dev/null || true
	fi
	if [ -n "${COREDNS_PID:-}" ]; then
		kill -TERM "$COREDNS_PID" 2>/dev/null || true
	fi
	if [ -n "${WG_UP:-}" ]; then
		run_hooks PostDown || true
	fi
	if [ -n "${BORINGTUN_PID:-}" ]; then
		kill -TERM "$BORINGTUN_PID" 2>/dev/null || true
		wait "$BORINGTUN_PID" 2>/dev/null || true
	fi
	if [ -n "${WG_UP:-}" ]; then
		WG_UP=""
	fi
}

trap cleanup EXIT INT TERM

if [ ! -f "$COREDNS_CONFIG" ]; then
	echo "missing CoreDNS config: $COREDNS_CONFIG" >&2
	exit 1
fi

ensure_wireguard_server_keys
resolve_wan_interface
resolve_wireguard_runtime_ports
echo "[#] Using WAN interface: $WG_WAN_INTERFACE"
normalize_server_address
log_startup_fingerprint
render_wireguard_config
canonicalize_rendered_wireguard_config
validate_rendered_wireguard_config
ensure_uapi_socket_dir
echo "starting BoringTun userspace interface $WG_INTERFACE_NAME: $WG_CONFIG_PATH"
"$BORINGTUN_BIN" -f --disable-drop-privileges "$WG_INTERFACE_NAME" &
BORINGTUN_PID=$!
wait_for_boringtun_uapi
configure_boringtun_interface
WG_UP=1
log_wireguard_peer_status
configure_network_segmentation

echo "starting CoreDNS: $COREDNS_CONFIG"
/usr/local/bin/coredns -conf "$COREDNS_CONFIG" &
COREDNS_PID=$!

# Auto-generate self-signed TLS certificate only when explicit proxy mode is enabled.
if [ "${EXPLICIT_PROXY_ENABLED:-false}" = "true" ] && [ "${DISABLE_TLS:-false}" != "true" ] && [ -z "${TLS_CERT_PATH:-}" ] && [ -z "${TLS_KEY_PATH:-}" ]; then
	if [ ! -f "/ssl/tls.crt" ] || [ ! -f "/ssl/tls.key" ]; then
		echo "[#] Generating self-signed TLS certificate for proxy listener"
		mkdir -p /ssl
		if ! openssl req -x509 -nodes -days 365 -newkey rsa:4096 \
			-keyout /ssl/tls.key \
			-out /ssl/tls.crt \
			-subj "/CN=ssl-proxy.local" \
			-addext "subjectAltName=DNS:ssl-proxy.local,DNS:localhost,IP:127.0.0.1"; then
			echo "[!] Failed to generate TLS certificate" >&2
			exit 1
		fi
		chmod 600 /ssl/tls.key
		export TLS_CERT_PATH="/ssl/tls.crt"
		export TLS_KEY_PATH="/ssl/tls.key"
		echo "[#] TLS certificate generated at /ssl/tls.crt"
	else
		export TLS_CERT_PATH="/ssl/tls.crt"
		export TLS_KEY_PATH="/ssl/tls.key"
	fi
fi

# Force plaintext mode when DISABLE_TLS is set or explicit proxy mode is disabled.
if [ "${DISABLE_TLS:-false}" = "true" ] || [ "${EXPLICIT_PROXY_ENABLED:-false}" != "true" ]; then
	unset TLS_CERT_PATH
	unset TLS_KEY_PATH
	echo "[#] Explicit proxy TLS disabled"
fi

echo "starting ssl-proxy"
"$PROXY_BIN" &
PROXY_PID=$!
PROXY_RESTART_COUNT=0

# Monitor critical child processes
while true; do
	# Wait for any child to exit
	wait -n
	exit_code=$?

	if ! kill -0 "$BORINGTUN_PID" 2>/dev/null; then
		echo "boringtun-cli exited unexpectedly, restarting container"
		exit 1
	fi

	if ! kill -0 "$COREDNS_PID" 2>/dev/null; then
		echo "coredns exited unexpectedly, restarting container"
		exit 1
	fi

	# If ssl-proxy died, restart it
	if ! kill -0 "$PROXY_PID" 2>/dev/null; then
		PROXY_RESTART_COUNT=$((PROXY_RESTART_COUNT + 1))
		if [ "$PROXY_RESTART_COUNT" -gt "$PROXY_RESTART_LIMIT" ]; then
			echo "ssl-proxy exited ${PROXY_RESTART_COUNT} consecutive times; restart limit ${PROXY_RESTART_LIMIT} exceeded" >&2
			exit 1
		fi
		echo "ssl-proxy exited, restarting after ${PROXY_RESTART_BACKOFF}s (attempt ${PROXY_RESTART_COUNT}/${PROXY_RESTART_LIMIT})..."
		sleep "$PROXY_RESTART_BACKOFF"
		PROXY_RESTART_BACKOFF=$((PROXY_RESTART_BACKOFF * 2))
		"$PROXY_BIN" &
		PROXY_PID=$!
	fi
done
