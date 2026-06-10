#!/bin/bash
set -euo pipefail

SERVICE_NAME="minio-init"
INSTANCE_NAME="${HOSTNAME:-unknown}"
PUSHGATEWAY_URL="${PUSHGATEWAY_URL:-http://pushgateway:9091}"
STARTED_AT="$(date +%s)"
RUN_SUCCESS=0

json_escape() {
  printf '%s' "$1" | sed 's/\\/\\\\/g; s/"/\\"/g'
}

log_line() {
  local level="$1"
  local event="$2"
  local message="$3"
  local error="${4:-}"
  local ts
  local escaped_message

  ts="$(date -u +"%Y-%m-%dT%H:%M:%SZ")"
  escaped_message="$(json_escape "$message")"
  if [ -n "$error" ]; then
    local escaped_error
    escaped_error="$(json_escape "$error")"
    printf '{"timestamp":"%s","level":"%s","service":"%s","instance":"%s","trace_id":null,"span_id":null,"event":"%s","error":"%s","message":"%s"}\n' \
      "$ts" "$level" "$SERVICE_NAME" "$INSTANCE_NAME" "$event" "$escaped_error" "$escaped_message"
  else
    printf '{"timestamp":"%s","level":"%s","service":"%s","instance":"%s","trace_id":null,"span_id":null,"event":"%s","error":null,"message":"%s"}\n' \
      "$ts" "$level" "$SERVICE_NAME" "$INSTANCE_NAME" "$event" "$escaped_message"
  fi
}

push_result_metrics() {
  local success="$1"
  local finished_at duration raw host_port host port base_path path body content_length

  finished_at="$(date +%s)"
  duration="$((finished_at - STARTED_AT))"
  raw="${PUSHGATEWAY_URL#http://}"
  host_port="${raw%%/*}"
  host="${host_port%%:*}"
  port="${host_port##*:}"
  if [ "$host" = "$port" ]; then
    port="80"
  fi
  base_path="/${raw#${host_port}}"
  if [ "$base_path" = "/${raw}" ]; then
    base_path="/"
  fi
  path="${base_path%/}/metrics/job/minio-init/service/minio-init/instance/${INSTANCE_NAME}"
  body="$(cat <<EOF
observability_job_last_success ${success}
observability_job_last_duration_seconds ${duration}
observability_job_last_run_unixtime ${finished_at}
EOF
)"
  content_length="$(printf '%s' "$body" | wc -c | tr -d ' ')"

  exec 3<>"/dev/tcp/${host}/${port}" || return 0
  {
    printf 'PUT %s HTTP/1.1\r\n' "$path"
    printf 'Host: %s\r\n' "$host"
    printf 'Content-Type: text/plain; version=0.0.4\r\n'
    printf 'Content-Length: %s\r\n' "$content_length"
    printf 'Connection: close\r\n\r\n'
    printf '%s' "$body"
  } >&3
  cat <&3 >/dev/null 2>&1 || true
  exec 3<&-
  exec 3>&-
}

finish() {
  if [ "$RUN_SUCCESS" -eq 1 ]; then
    push_result_metrics 1
    log_line "info" "job_complete" "Initialized MinIO buckets"
  else
    push_result_metrics 0
  fi
}

trap finish EXIT

log_line "info" "bootstrap_start" "Waiting for MinIO API endpoint"
MAX_ATTEMPTS=60
attempt=1
until mc alias set local "http://minio:9000" "${MINIO_ACCESS_KEY_ID}" "${MINIO_SECRET_ACCESS_KEY}" >/dev/null 2>&1; do
  if [ "$attempt" -ge "$MAX_ATTEMPTS" ]; then
    log_line "error" "bootstrap_failed" "MinIO API endpoint http://minio:9000 did not become ready after ${MAX_ATTEMPTS} attempts"
    exit 1
  fi
  attempt=$((attempt + 1))
  sleep 1
done

BUCKETS="${MINIO_BUCKET}"
if [ -n "${MINIO_EXTRA_BUCKETS:-}" ]; then
  BUCKETS="${BUCKETS},${MINIO_EXTRA_BUCKETS}"
fi

IFS=',' read -r -a bucket_list <<< "$BUCKETS"
for bucket in "${bucket_list[@]}"; do
  bucket="$(printf '%s' "$bucket" | xargs)"
  if [ -n "$bucket" ]; then
    mc mb --ignore-existing "local/${bucket}" >/dev/null
    log_line "info" "bucket_ready" "Initialized MinIO bucket ${bucket}"
  fi
done
RUN_SUCCESS=1
