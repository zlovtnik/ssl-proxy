#!/bin/sh
set -eu

NATS_URL="${SYNC_NATS_URL:-nats://nats:4222}"
STREAM_NAME="${AUDIT_STREAM_NAME:-AUDIT_STREAM}"
SCAN_CONSUMER="${SYNC_SCAN_CONSUMER:-zig-coordinator-scan}"
LOAD_CONSUMER="${SYNC_LOAD_CONSUMER:-oracle-worker-load}"
SCAN_SUBJECT="${SYNC_SCAN_SUBJECT:-sync.scan.request}"
LOAD_SUBJECT="${SYNC_LOAD_SUBJECT:-sync.oracle.load}"
SUBJECTS="sync.scan.request,sync.oracle.load,sync.oracle.result,wireless.audit"

until nats --server "${NATS_URL}" str ls >/dev/null 2>&1; do
  sleep 1
done

if nats --server "${NATS_URL}" str info "${STREAM_NAME}" >/dev/null 2>&1; then
  nats --server "${NATS_URL}" str info "${STREAM_NAME}" >/dev/null
else
  nats --server "${NATS_URL}" str add "${STREAM_NAME}" \
    --defaults \
    --subjects "${SUBJECTS}" \
    --storage file \
    --retention limits \
    --discard old \
    --max-msgs=-1 \
    --max-bytes=-1 \
    --max-age=168h \
    --max-msg-size=-1 \
    --dupe-window=2m \
    --replicas 1
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
