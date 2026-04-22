#!/bin/sh
set -eu

NATS_URL="${SYNC_NATS_URL:-nats://nats:4222}"
STREAM_NAME="${AUDIT_STREAM_NAME:-AUDIT_STREAM}"
SCAN_CONSUMER="${SYNC_SCAN_CONSUMER:-zig-coordinator-scan}"
LOAD_CONSUMER="${SYNC_LOAD_CONSUMER:-oracle-worker-load}"
RESULT_CONSUMER="${SYNC_RESULT_CONSUMER:-zig-coordinator-result}"
SCAN_SUBJECT="${SYNC_SCAN_SUBJECT:-sync.scan.request}"
LOAD_SUBJECT="${SYNC_LOAD_SUBJECT:-sync.oracle.load}"
RESULT_SUBJECT="${SYNC_RESULT_SUBJECT:-sync.oracle.result}"
SUBJECTS="${SCAN_SUBJECT},${LOAD_SUBJECT},${RESULT_SUBJECT},wireless.audit,wireless.audit.config,wifi.alert.handshake"

until nats --server "${NATS_URL}" str ls >/dev/null 2>&1; do
  sleep 1
done

if nats --server "${NATS_URL}" str info "${STREAM_NAME}" >/dev/null 2>&1; then
  set +e
  edit_output=$(nats --server "${NATS_URL}" str edit "${STREAM_NAME}" \
    --subjects "${SUBJECTS}" \
    --max-age=720h \
    --defaults 2>&1)
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
    for subject in ${SUBJECTS}; do
      if ! printf '%s\n' "${stream_info}" | grep -Fq "\"${subject}\""; then
        echo "warning: stream ${STREAM_NAME} subjects missing ${subject}" >&2
      fi
    done
    IFS="${old_ifs}"
  fi
else
  nats --server "${NATS_URL}" str add "${STREAM_NAME}" \
    --defaults \
    --subjects "${SUBJECTS}" \
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

if nats --server "${NATS_URL}" consumer info "${STREAM_NAME}" "${RESULT_CONSUMER}" >/dev/null 2>&1; then
  nats --server "${NATS_URL}" consumer info "${STREAM_NAME}" "${RESULT_CONSUMER}" >/dev/null
else
  nats --server "${NATS_URL}" consumer add "${STREAM_NAME}" "${RESULT_CONSUMER}" \
    --filter "${RESULT_SUBJECT}" \
    --ack explicit \
    --deliver all \
    --replay instant \
    --pull \
    --defaults
fi

if nats --server "${NATS_URL}" consumer info "${STREAM_NAME}" "${SCAN_CONSUMER}" >/dev/null 2>&1; then
  nats --server "${NATS_URL}" consumer info "${STREAM_NAME}" "${SCAN_CONSUMER}" >/dev/null
else
  nats --server "${NATS_URL}" consumer add "${STREAM_NAME}" "${SCAN_CONSUMER}" \
    --filter "${SCAN_SUBJECT}" \
    --ack explicit \
    --deliver all \
    --replay instant \
    --pull \
    --defaults
fi

if nats --server "${NATS_URL}" consumer info "${STREAM_NAME}" "${LOAD_CONSUMER}" >/dev/null 2>&1; then
  nats --server "${NATS_URL}" consumer info "${STREAM_NAME}" "${LOAD_CONSUMER}" >/dev/null
else
  nats --server "${NATS_URL}" consumer add "${STREAM_NAME}" "${LOAD_CONSUMER}" \
    --filter "${LOAD_SUBJECT}" \
    --ack explicit \
    --deliver all \
    --replay instant \
    --pull \
    --defaults
fi
