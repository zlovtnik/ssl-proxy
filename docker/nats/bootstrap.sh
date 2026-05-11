#!/bin/sh
set -eu

NATS_URL="${SYNC_NATS_URL:-nats://nats:4222}"
STREAM_NAME="${AUDIT_STREAM_NAME:-AUDIT_STREAM}"
RESULT_STREAM_NAME="${SYNC_RESULT_STREAM_NAME:-ORACLE_RESULT_STREAM}"
WIRELESS_BACKLOG_STREAM="${WIRELESS_BACKLOG_STREAM:-WIRELESS_BACKLOG_STREAM}"
WIRELESS_MAC_STREAM="${WIRELESS_MAC_STREAM:-WIRELESS_MAC_STREAM}"
WIRELESS_NETWORKS_STREAM="${WIRELESS_NETWORKS_STREAM:-WIRELESS_NETWORKS_STREAM}"
WIRELESS_PROBE_STREAM="${WIRELESS_PROBE_STREAM:-WIRELESS_PROBE_STREAM}"
WIRELESS_BANDWIDTH_STREAM="${WIRELESS_BANDWIDTH_STREAM:-WIRELESS_BANDWIDTH_STREAM}"
WIRELESS_ALERT_STREAM="${WIRELESS_ALERT_STREAM:-WIRELESS_ALERT_STREAM}"
SCAN_CONSUMER="${SYNC_SCAN_CONSUMER:-zig-coordinator-scan}"
LOAD_CONSUMER="${SYNC_LOAD_CONSUMER:-oracle-worker-load}"
RESULT_CONSUMER="${SYNC_RESULT_CONSUMER:-zig-coordinator-result}"
SCAN_SUBJECT="${SYNC_SCAN_SUBJECT:-sync.scan.request}"
LOAD_SUBJECT="${SYNC_LOAD_SUBJECT:-sync.oracle.load}"
RESULT_SUBJECT="${SYNC_RESULT_SUBJECT:-sync.oracle.result}"
AUDIT_SUBJECTS="${SCAN_SUBJECT},${LOAD_SUBJECT},wireless.audit,wireless.audit.config,wireless.config.authorized_networks,wireless.config.sensor,wireless.client.inventory,audit.threat.shadow_device"
BANDWIDTH_SUBJECTS="audit.wireless.bandwidth"
ALERT_SUBJECTS="wireless.alert.rogue_ap,wireless.alert.deauth_flood,wireless.alert.attack_sequence,wifi.alert.handshake"

ensure_stream() {
  stream_name="$1"
  subjects="$2"
  max_age="$3"
  dupe_window="${4:-2m}"
  max_msgs="${5:--1}"

  if nats --server "${NATS_URL}" str info "${stream_name}" >/dev/null 2>&1; then
    set +e
    edit_output=$(nats --server "${NATS_URL}" str edit "${stream_name}" \
      --force \
      --subjects "${subjects}" \
      --max-age="${max_age}" \
      --dupe-window="${dupe_window}" \
      --max-msgs="${max_msgs}" 2>&1)
    edit_status=$?
    set -e
    if [ "${edit_status}" -ne 0 ]; then
      echo "warning: stream edit failed for ${stream_name} exit_code=${edit_status}: ${edit_output}" >&2
    fi
  else
    nats --server "${NATS_URL}" str add "${stream_name}" \
      --defaults \
      --subjects "${subjects}" \
      --storage file \
      --retention limits \
      --discard old \
      --max-msgs="${max_msgs}" \
      --max-bytes=-1 \
      --max-age="${max_age}" \
      --max-msg-size=-1 \
      --dupe-window="${dupe_window}" \
      --replicas 1
  fi
}

ensure_consumer() {
  stream_name="$1"
  consumer_name="$2"
  filter_subject="$3"

  if nats --server "${NATS_URL}" consumer info "${stream_name}" "${consumer_name}" >/dev/null 2>&1; then
    nats --server "${NATS_URL}" consumer edit "${stream_name}" "${consumer_name}" \
      --filter "${filter_subject}" \
      --max-deliver=-1 \
      --wait=5s \
      --max-pending=1000 \
      --max-waiting=512 \
      --force
  else
    nats --server "${NATS_URL}" consumer add "${stream_name}" "${consumer_name}" \
      --filter "${filter_subject}" \
      --max-deliver=-1 \
      --deliver=all \
      --replay=instant \
      --pull \
      --ack=explicit \
      --wait=5s \
      --defaults
  fi
}

verify_consumer_filter() {
  stream_name="$1"
  consumer_name="$2"
  expected_filter="$3"

  consumer_info=$(nats --server "${NATS_URL}" consumer info "${stream_name}" "${consumer_name}" --json)
  compact_info=$(printf '%s' "${consumer_info}" | tr -d '[:space:]')
  if ! printf '%s' "${compact_info}" | grep -Fq "\"filter_subject\":\"${expected_filter}\""; then
    echo "error: consumer ${consumer_name} on stream ${stream_name} does not have filter_subject=${expected_filter}" >&2
    echo "consumer info: ${consumer_info}" >&2
    return 1
  fi
}

until nats --server "${NATS_URL}" str ls >/dev/null 2>&1; do
  sleep 1
done

# ── AUDIT_STREAM ───────────────────────────────────────────────────────────
# Holds sync-plane subjects and general audit traffic. Alert and bandwidth
# subjects have been moved to dedicated streams for independent retention.

if nats --server "${NATS_URL}" str info "${STREAM_NAME}" >/dev/null 2>&1; then
  set +e
  edit_output=$(nats --server "${NATS_URL}" str edit "${STREAM_NAME}" \
    --force \
    --subjects "${AUDIT_SUBJECTS}" \
    --max-age=720h 2>&1)
  edit_status=$?
  set -e
  if [ "${edit_status}" -ne 0 ]; then
    echo "warning: stream edit failed for ${STREAM_NAME} exit_code=${edit_status}: ${edit_output}" >&2
  fi

  set +e
  stream_info=$(nats --server "${NATS_URL}" str info "${STREAM_NAME}" --json 2>&1)
  info_status=$?
  set -e
  if [ "${info_status}" -ne 0 ]; then
    echo "warning: stream info failed for ${STREAM_NAME} exit_code=${info_status}: ${stream_info}" >&2
  else
    if ! printf '%s\n' "${stream_info}" | grep -q '"max_age"[[:space:]]*:[[:space:]]*2592000000000000'; then
      echo "warning: stream ${STREAM_NAME} max_age differs from expected 720h" >&2
    fi
    old_ifs="${IFS}"
    IFS=","
    for subject in ${AUDIT_SUBJECTS}; do
      if ! printf '%s\n' "${stream_info}" | grep -Fq "\"${subject}\""; then
        echo "warning: stream ${STREAM_NAME} subjects missing ${subject}" >&2
      fi
    done
    IFS="${old_ifs}"
  fi
else
  nats --server "${NATS_URL}" str add "${STREAM_NAME}" \
    --defaults \
    --subjects "${AUDIT_SUBJECTS}" \
    --storage file \
    --retention limits \
    --discard old \
    --max-msgs=-1 \
    --max-bytes=-1 \
    --max-age=720h \
    --max-msg-size=-1 \
    --dupe-window=2m \
    --replicas 1
fi

# ── ORACLE_RESULT_STREAM ───────────────────────────────────────────────────

if nats --server "${NATS_URL}" str info "${RESULT_STREAM_NAME}" >/dev/null 2>&1; then
  set +e
  result_edit_output=$(nats --server "${NATS_URL}" str edit "${RESULT_STREAM_NAME}" \
    --force \
    --subjects "${RESULT_SUBJECT}" \
    --max-age=720h 2>&1)
  result_edit_status=$?
  set -e
  if [ "${result_edit_status}" -ne 0 ]; then
    echo "warning: stream edit failed for ${RESULT_STREAM_NAME} exit_code=${result_edit_status}: ${result_edit_output}" >&2
  fi
else
  nats --server "${NATS_URL}" str add "${RESULT_STREAM_NAME}" \
    --defaults \
    --subjects "${RESULT_SUBJECT}" \
    --storage file \
    --retention limits \
    --discard old \
    --max-msgs=-1 \
    --max-bytes=-1 \
    --max-age=720h \
    --max-msg-size=-1 \
    --dupe-window=2m \
    --replicas 1
fi

# ── Sync-plane consumers (main stream) ─────────────────────────────────────

ensure_consumer "${STREAM_NAME}" "${SCAN_CONSUMER}" "${SCAN_SUBJECT}"
ensure_consumer "${STREAM_NAME}" "${LOAD_CONSUMER}" "${LOAD_SUBJECT}"
ensure_consumer "${RESULT_STREAM_NAME}" "${RESULT_CONSUMER}" "${RESULT_SUBJECT}"
verify_consumer_filter "${STREAM_NAME}" "${LOAD_CONSUMER}" "${LOAD_SUBJECT}"

# ── Wireless backlog stream ────────────────────────────────────────────────

ensure_stream "${WIRELESS_BACKLOG_STREAM}" "wireless.backlog.>" "720h" "2m" "-1"

# ── Wireless MAC lookup stream ─────────────────────────────────────────────
# Request/reply stream for device registry lookups. dupe-window=0s prevents
# dropped requests when the same MAC is looked up within a short window.

ensure_stream "${WIRELESS_MAC_STREAM}" "wireless.mac.>" "720h" "0s" "-1"

# ── Wireless networks stream ───────────────────────────────────────────────
# Key-value store for current authorized network config. max-msgs=1 keeps
# only the latest push. dupe-window=0s prevents request/reply dedup.
# max-age=720h ensures the record survives extended sensor uptime.

ensure_stream "${WIRELESS_NETWORKS_STREAM}" "wireless.networks.>" "720h" "0s" "1"

# ── Wireless probe stream ──────────────────────────────────────────────────

ensure_stream "${WIRELESS_PROBE_STREAM}" "wireless.probe.>" "1h" "2m" "-1"

# ── Wireless bandwidth stream ──────────────────────────────────────────────
# Dedicated stream for audit.wireless.bandwidth with shorter retention (7 days).

ensure_stream "${WIRELESS_BANDWIDTH_STREAM}" "${BANDWIDTH_SUBJECTS}" "168h" "2m" "-1"

# ── Wireless alert stream ──────────────────────────────────────────────────
# Dedicated stream for all wireless security alerts, queryable independently.

ensure_stream "${WIRELESS_ALERT_STREAM}" "${ALERT_SUBJECTS}" "720h" "2m" "-1"

# ── Wireless backlog consumers ─────────────────────────────────────────────

ensure_consumer "${WIRELESS_BACKLOG_STREAM}" "wireless-backlog-save" "wireless.backlog.save"
ensure_consumer "${WIRELESS_BACKLOG_STREAM}" "wireless-backlog-list" "wireless.backlog.list"
ensure_consumer "${WIRELESS_BACKLOG_STREAM}" "wireless-backlog-synced" "wireless.backlog.synced"
ensure_consumer "${WIRELESS_BACKLOG_STREAM}" "wireless-backlog-prune" "wireless.backlog.prune"
ensure_consumer "${WIRELESS_MAC_STREAM}" "wireless-mac-lookup" "wireless.mac.lookup"
ensure_consumer "${WIRELESS_NETWORKS_STREAM}" "wireless-networks-authorized" "wireless.networks.authorized"
ensure_consumer "${WIRELESS_PROBE_STREAM}" "wireless-probe-flush" "wireless.probe.flush"

# ── Verify critical wireless request/reply consumer filters ────────────────

verify_consumer_filter "${WIRELESS_BACKLOG_STREAM}" "wireless-backlog-list" "wireless.backlog.list"
verify_consumer_filter "${WIRELESS_NETWORKS_STREAM}" "wireless-networks-authorized" "wireless.networks.authorized"