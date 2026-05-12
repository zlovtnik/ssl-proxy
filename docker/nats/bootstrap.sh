#!/bin/sh
set -eu

NATS_URL="${SYNC_NATS_URL:-nats://nats:4222}"
TOPOLOGY_FILE="${SYNC_NATS_TOPOLOGY_FILE:-${NATS_TOPOLOGY_FILE:-/config/topology.manifest}}"

resolve_env_list() {
  env_names="$1"
  default_value="$2"
  old_ifs="${IFS}"
  IFS=","
  for env_name in ${env_names}; do
    IFS="${old_ifs}"
    env_name=$(printf '%s' "${env_name}" | tr -d '[:space:]')
    if [ -n "${env_name}" ]; then
      eval "env_value=\${${env_name}:-}"
      if [ -n "${env_value}" ]; then
        printf '%s' "${env_value}"
        return
      fi
    fi
    IFS=","
  done
  IFS="${old_ifs}"
  expand_template "${default_value}"
}

expand_template() {
  raw="$1"
  eval "expanded=\"${raw}\""
  printf '%s' "${expanded}"
}

ensure_stream() {
  stream_name="$1"
  subjects="$2"
  max_age="$3"
  dupe_window="$4"
  max_msgs="$5"

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

stream_name_for_key() {
  wanted_key="$1"
  while IFS='|' read -r kind key env_vars default_name subjects max_age dupe_window max_msgs; do
    case "${kind}" in
      ""|\#*) continue ;;
    esac
    if [ "${kind}" = "stream" ] && [ "${key}" = "${wanted_key}" ]; then
      resolve_env_list "${env_vars}" "${default_name}"
      return
    fi
  done < "${TOPOLOGY_FILE}"
  echo "error: stream key ${wanted_key} not found in ${TOPOLOGY_FILE}" >&2
  return 1
}

if [ ! -f "${TOPOLOGY_FILE}" ]; then
  echo "error: NATS topology file not found: ${TOPOLOGY_FILE}" >&2
  exit 1
fi

until nats --server "${NATS_URL}" str ls >/dev/null 2>&1; do
  sleep 1
done

while IFS='|' read -r kind key env_vars default_name subjects max_age dupe_window max_msgs; do
  case "${kind}" in
    ""|\#*) continue ;;
  esac
  if [ "${kind}" != "stream" ]; then
    continue
  fi

  stream_name=$(resolve_env_list "${env_vars}" "${default_name}")
  stream_subjects=$(expand_template "${subjects}")
  echo "Ensuring stream ${stream_name} (${key})"
  ensure_stream "${stream_name}" "${stream_subjects}" "${max_age}" "${dupe_window}" "${max_msgs}"
done < "${TOPOLOGY_FILE}"

while IFS='|' read -r kind key stream_key env_vars default_name filter_subject; do
  case "${kind}" in
    ""|\#*) continue ;;
  esac
  if [ "${kind}" != "consumer" ]; then
    continue
  fi

  stream_name=$(stream_name_for_key "${stream_key}")
  consumer_name=$(resolve_env_list "${env_vars}" "${default_name}")
  filter=$(expand_template "${filter_subject}")
  echo "Ensuring consumer ${consumer_name} on ${stream_name} (${key})"
  ensure_consumer "${stream_name}" "${consumer_name}" "${filter}"
  verify_consumer_filter "${stream_name}" "${consumer_name}" "${filter}"
done < "${TOPOLOGY_FILE}"
