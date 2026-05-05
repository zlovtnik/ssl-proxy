#!/bin/bash
# NATS Stream and Consumer Setup for Phase 5 Wireless Operations
# Run this script to create the required NATS infrastructure

set -e

NATS_SERVER="${NATS_SERVER:-nats://localhost:4222}"

echo "Creating NATS streams and consumers for wireless operations..."
echo "NATS Server: $NATS_SERVER"
echo ""

# Create WIRELESS_BACKLOG_STREAM
echo "Creating WIRELESS_BACKLOG_STREAM..."
nats --server "$NATS_SERVER" stream add WIRELESS_BACKLOG_STREAM \
  --subjects "wireless.backlog.>" \
  --storage file \
  --retention limits \
  --max-msgs=-1 \
  --max-bytes=-1 \
  --max-age=7d \
  --max-msg-size=-1 \
  --discard old \
  --replicas 1 \
  --no-allow-rollup \
  --no-deny-delete \
  --no-deny-purge

# Create consumers for backlog operations
echo "Creating wireless-backlog-save consumer..."
nats --server "$NATS_SERVER" consumer add WIRELESS_BACKLOG_STREAM wireless-backlog-save \
  --filter "wireless.backlog.save" \
  --ack explicit \
  --pull \
  --deliver all \
  --max-deliver=-1 \
  --replay instant \
  --wait=5s

echo "Creating wireless-backlog-list consumer..."
nats --server "$NATS_SERVER" consumer add WIRELESS_BACKLOG_STREAM wireless-backlog-list \
  --filter "wireless.backlog.list" \
  --ack explicit \
  --pull \
  --deliver all \
  --max-deliver=-1 \
  --replay instant \
  --wait=5s

echo "Creating wireless-backlog-synced consumer..."
nats --server "$NATS_SERVER" consumer add WIRELESS_BACKLOG_STREAM wireless-backlog-synced \
  --filter "wireless.backlog.synced" \
  --ack explicit \
  --pull \
  --deliver all \
  --max-deliver=-1 \
  --replay instant \
  --wait=5s

echo "Creating wireless-backlog-prune consumer..."
nats --server "$NATS_SERVER" consumer add WIRELESS_BACKLOG_STREAM wireless-backlog-prune \
  --filter "wireless.backlog.prune" \
  --ack explicit \
  --pull \
  --deliver all \
  --max-deliver=-1 \
  --replay instant \
  --wait=5s

# Create WIRELESS_MAC_STREAM
echo ""
echo "Creating WIRELESS_MAC_STREAM..."
nats --server "$NATS_SERVER" stream add WIRELESS_MAC_STREAM \
  --subjects "wireless.mac.>" \
  --storage file \
  --retention limits \
  --max-msgs=-1 \
  --max-bytes=-1 \
  --max-age=1h \
  --max-msg-size=-1 \
  --discard old \
  --replicas 1 \
  --no-allow-rollup \
  --no-deny-delete \
  --no-deny-purge

echo "Creating wireless-mac-lookup consumer..."
nats --server "$NATS_SERVER" consumer add WIRELESS_MAC_STREAM wireless-mac-lookup \
  --filter "wireless.mac.lookup" \
  --ack explicit \
  --pull \
  --deliver all \
  --max-deliver=-1 \
  --replay instant \
  --wait=5s

# Create WIRELESS_NETWORKS_STREAM
echo ""
echo "Creating WIRELESS_NETWORKS_STREAM..."
nats --server "$NATS_SERVER" stream add WIRELESS_NETWORKS_STREAM \
  --subjects "wireless.networks.>" \
  --storage file \
  --retention limits \
  --max-msgs=-1 \
  --max-bytes=-1 \
  --max-age=1h \
  --max-msg-size=-1 \
  --discard old \
  --replicas 1 \
  --no-allow-rollup \
  --no-deny-delete \
  --no-deny-purge

echo "Creating wireless-networks-authorized consumer..."
nats --server "$NATS_SERVER" consumer add WIRELESS_NETWORKS_STREAM wireless-networks-authorized \
  --filter "wireless.networks.authorized" \
  --ack explicit \
  --pull \
  --deliver all \
  --max-deliver=-1 \
  --replay instant \
  --wait=5s

# Create WIRELESS_PROBE_STREAM
echo ""
echo "Creating WIRELESS_PROBE_STREAM..."
nats --server "$NATS_SERVER" stream add WIRELESS_PROBE_STREAM \
  --subjects "wireless.probe.>" \
  --storage file \
  --retention limits \
  --max-msgs=-1 \
  --max-bytes=-1 \
  --max-age=1h \
  --max-msg-size=-1 \
  --discard old \
  --replicas 1 \
  --no-allow-rollup \
  --no-deny-delete \
  --no-deny-purge

echo "Creating wireless-probe-flush consumer..."
nats --server "$NATS_SERVER" consumer add WIRELESS_PROBE_STREAM wireless-probe-flush \
  --filter "wireless.probe.flush" \
  --ack explicit \
  --pull \
  --deliver all \
  --max-deliver=-1 \
  --replay instant \
  --wait=5s

echo ""
echo "✅ All NATS streams and consumers created successfully!"
echo ""
echo "Verify with:"
echo "  nats --server $NATS_SERVER stream list"
echo "  nats --server $NATS_SERVER consumer list WIRELESS_BACKLOG_STREAM"
echo "  nats --server $NATS_SERVER consumer list WIRELESS_MAC_STREAM"
echo "  nats --server $NATS_SERVER consumer list WIRELESS_NETWORKS_STREAM"
echo "  nats --server $NATS_SERVER consumer list WIRELESS_PROBE_STREAM"
