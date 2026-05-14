#!/bin/sh
set -eu

BOOTSTRAP_SERVERS="${SYNC_REDPANDA_BOOTSTRAP_SERVERS:-redpanda:9092}"
TOPIC_MANIFEST="${SYNC_REDPANDA_TOPIC_MANIFEST:-/config/topics.manifest}"
PARTITIONS="${SYNC_REDPANDA_TOPIC_PARTITIONS:-3}"
REPLICAS="${SYNC_REDPANDA_TOPIC_REPLICAS:-1}"

if [ ! -f "${TOPIC_MANIFEST}" ]; then
  echo "error: Redpanda topic manifest not found: ${TOPIC_MANIFEST}" >&2
  exit 1
fi

until rpk cluster info --brokers "${BOOTSTRAP_SERVERS}" >/dev/null 2>&1; do
  sleep 1
done

topic_count=0

while IFS='|' read -r topic partitions replicas retention_ms retention_bytes; do
  case "${topic}" in
    ""|\#*) continue ;;
  esac

  topic_partitions="${partitions:-${PARTITIONS}}"
  topic_replicas="${replicas:-${REPLICAS}}"
  topic_retention_ms="${retention_ms:-2592000000}"
  topic_retention_bytes="${retention_bytes:--1}"

  if rpk topic describe "${topic}" --brokers "${BOOTSTRAP_SERVERS}" >/dev/null 2>&1; then
    echo "Topic ${topic} already exists"
  else
    echo "Creating topic ${topic}"
    rpk topic create "${topic}" \
      --brokers "${BOOTSTRAP_SERVERS}" \
      --partitions "${topic_partitions}" \
      --replicas "${topic_replicas}"
  fi

  rpk topic alter-config "${topic}" \
    --brokers "${BOOTSTRAP_SERVERS}" \
    --set "retention.ms=${topic_retention_ms}" \
    --set "retention.bytes=${topic_retention_bytes}" >/dev/null

  if ! rpk topic describe "${topic}" --brokers "${BOOTSTRAP_SERVERS}" >/dev/null 2>&1; then
    echo "error: Redpanda topic verification failed: ${topic}" >&2
    exit 1
  fi

  topic_count=$((topic_count + 1))
  echo "Verified topic ${topic}"
done < "${TOPIC_MANIFEST}"

echo "Verified ${topic_count} Redpanda topics from ${TOPIC_MANIFEST}"
