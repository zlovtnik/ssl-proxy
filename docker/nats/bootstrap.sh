#!/bin/sh
set -eu

NATS_URL="${SYNC_NATS_URL:-nats://nats:4222}"
STREAM_NAME="${AUDIT_STREAM_NAME:-AUDIT_STREAM}"
SUBJECTS="sync.scan.request,sync.oracle.load,sync.oracle.result,wireless.audit"

until nats --server "${NATS_URL}" str ls >/dev/null 2>&1; do
  sleep 1
done

if nats --server "${NATS_URL}" str info "${STREAM_NAME}" >/dev/null 2>&1; then
  nats --server "${NATS_URL}" str edit "${STREAM_NAME}" \
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
else
  nats --server "${NATS_URL}" str add "${STREAM_NAME}" \
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
