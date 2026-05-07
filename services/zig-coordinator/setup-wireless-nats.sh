#!/bin/bash
# NATS Stream and Consumer Setup for Phase 5 Wireless Operations
# Run this script to create the required NATS infrastructure

set -e

NATS_SERVER="${NATS_SERVER:-nats://localhost:4222}"

echo "Creating NATS streams and consumers for wireless operations..."
echo "NATS Server: $NATS_SERVER"
echo ""

ensure_stream() {
  local stream="$1"
  local subjects="$2"
  local max_age="$3"
  local action="add"
  if nats --server "$NATS_SERVER" stream info "$stream" >/dev/null 2>&1; then
    action="edit"
  fi
  nats --server "$NATS_SERVER" stream "$action" "$stream" \
    --subjects "$subjects" \
    --storage file \
    --retention limits \
    --max-msgs=-1 \
    --max-bytes=-1 \
    --max-age="$max_age" \
    --max-msg-size=-1 \
    --discard old \
    --replicas 1 \
    --no-allow-rollup \
    --no-deny-delete \
    --no-deny-purge
}

ensure_consumer() {
  local stream="$1"
  local consumer="$2"
  local filter="$3"
  local action="add"
  if nats --server "$NATS_SERVER" consumer info "$stream" "$consumer" >/dev/null 2>&1; then
    action="edit"
  fi
  if [ "$action" = "edit" ]; then
    nats --server "$NATS_SERVER" consumer edit "$stream" "$consumer" \
      --filter "$filter" \
      --max-deliver=-1 \
      --wait=5s \
      --max-pending=1000 \
      --max-waiting=512 \
      --force
  else
    nats --server "$NATS_SERVER" consumer add "$stream" "$consumer" \
      --filter "$filter" \
      --ack explicit \
      --pull \
      --deliver all \
      --max-deliver=-1 \
      --replay instant \
      --wait=5s
  fi
}

# Create WIRELESS_BACKLOG_STREAM
echo "Creating WIRELESS_BACKLOG_STREAM..."
ensure_stream WIRELESS_BACKLOG_STREAM "wireless.backlog.>" 7d

# Create consumers for backlog operations
echo "Creating wireless-backlog-save consumer..."
ensure_consumer WIRELESS_BACKLOG_STREAM wireless-backlog-save "wireless.backlog.save"

echo "Creating wireless-backlog-list consumer..."
ensure_consumer WIRELESS_BACKLOG_STREAM wireless-backlog-list "wireless.backlog.list"

echo "Creating wireless-backlog-synced consumer..."
ensure_consumer WIRELESS_BACKLOG_STREAM wireless-backlog-synced "wireless.backlog.synced"

echo "Creating wireless-backlog-prune consumer..."
ensure_consumer WIRELESS_BACKLOG_STREAM wireless-backlog-prune "wireless.backlog.prune"

# Create WIRELESS_MAC_STREAM
echo ""
echo "Creating WIRELESS_MAC_STREAM..."
ensure_stream WIRELESS_MAC_STREAM "wireless.mac.>" 1h

echo "Creating wireless-mac-lookup consumer..."
ensure_consumer WIRELESS_MAC_STREAM wireless-mac-lookup "wireless.mac.lookup"

# Create WIRELESS_NETWORKS_STREAM
echo ""
echo "Creating WIRELESS_NETWORKS_STREAM..."
ensure_stream WIRELESS_NETWORKS_STREAM "wireless.networks.>" 1h

echo "Creating wireless-networks-authorized consumer..."
ensure_consumer WIRELESS_NETWORKS_STREAM wireless-networks-authorized "wireless.networks.authorized"

# Create WIRELESS_PROBE_STREAM
echo ""
echo "Creating WIRELESS_PROBE_STREAM..."
ensure_stream WIRELESS_PROBE_STREAM "wireless.probe.>" 1h

echo "Creating wireless-probe-flush consumer..."
ensure_consumer WIRELESS_PROBE_STREAM wireless-probe-flush "wireless.probe.flush"

echo ""
echo "[OK] All NATS streams and consumers created successfully!"
echo ""
echo "Verify with:"
echo "  nats --server $NATS_SERVER stream list"
echo "  nats --server $NATS_SERVER consumer list WIRELESS_BACKLOG_STREAM"
echo "  nats --server $NATS_SERVER consumer list WIRELESS_MAC_STREAM"
echo "  nats --server $NATS_SERVER consumer list WIRELESS_NETWORKS_STREAM"
echo "  nats --server $NATS_SERVER consumer list WIRELESS_PROBE_STREAM"
