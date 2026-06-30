#!/bin/sh
set -eu

SERVICE_NAME="redpanda-init"
INSTANCE_NAME="${INSTANCE_NAME:-$(hostname 2>/dev/null || printf unknown)}"
BOOTSTRAP_SERVERS="${SYNC_REDPANDA_BOOTSTRAP_SERVERS:-redpanda:9092}"
TOPIC_MANIFEST="${SYNC_REDPANDA_TOPIC_MANIFEST:-/config/topics.manifest}"
PARTITIONS="${SYNC_REDPANDA_TOPIC_PARTITIONS:-3}"
REPLICAS="${SYNC_REDPANDA_TOPIC_REPLICAS:-1}"
PUSHGATEWAY_URL="${PUSHGATEWAY_URL:-http://pushgateway:9091}"
STARTED_AT="$(date +%s)"
RUN_SUCCESS=0

json_escape() {
  printf '%s' "$1" | sed 's/\\/\\\\/g; s/"/\\"/g'
}

log_line() {
  level="$1"
  event="$2"
  message="$3"
  error="${4:-}"
  ts="$(date -u +"%Y-%m-%dT%H:%M:%SZ")"
  escaped_message="$(json_escape "$message")"
  if [ -n "$error" ]; then
    escaped_error="$(json_escape "$error")"
    printf '{"timestamp":"%s","level":"%s","service":"%s","instance":"%s","trace_id":null,"span_id":null,"event":"%s","error":"%s","message":"%s"}\n' \
      "$ts" "$level" "$SERVICE_NAME" "$INSTANCE_NAME" "$event" "$escaped_error" "$escaped_message"
  else
    printf '{"timestamp":"%s","level":"%s","service":"%s","instance":"%s","trace_id":null,"span_id":null,"event":"%s","error":null,"message":"%s"}\n' \
      "$ts" "$level" "$SERVICE_NAME" "$INSTANCE_NAME" "$event" "$escaped_message"
  fi
}

push_result_metrics() {
  finished_at="$(date +%s)"
  duration="$((finished_at - STARTED_AT))"
  success="$1"
  if command -v curl >/dev/null 2>&1; then
    cat <<EOF | curl --silent --show-error --fail --data-binary @- "${PUSHGATEWAY_URL%/}/metrics/job/redpanda-init/service/redpanda-init/instance/${INSTANCE_NAME}" >/dev/null || true
observability_job_last_success ${success}
observability_job_last_duration_seconds ${duration}
observability_job_last_run_unixtime ${finished_at}
EOF
  fi
}

finish() {
  if [ "$RUN_SUCCESS" -eq 1 ]; then
    push_result_metrics 1
    log_line "info" "job_complete" "Verified ${topic_count:-0} Redpanda topics from ${TOPIC_MANIFEST}"
  else
    push_result_metrics 0
  fi
}

trap finish EXIT

if [ ! -f "${TOPIC_MANIFEST}" ]; then
  log_line "error" "manifest_missing" "Redpanda topic manifest not found" "${TOPIC_MANIFEST}"
  exit 1
fi

log_line "info" "bootstrap_start" "Waiting for Redpanda cluster availability at ${BOOTSTRAP_SERVERS}"
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
    log_line "info" "topic_exists" "Topic already exists: ${topic}"
  else
    log_line "info" "topic_create" "Creating topic ${topic}"
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
    log_line "error" "topic_verify_failed" "Redpanda topic verification failed" "${topic}"
    exit 1
  fi

  topic_count=$((topic_count + 1))
  log_line "info" "topic_verified" "Verified topic ${topic}"
done < "${TOPIC_MANIFEST}"

RUN_SUCCESS=1
