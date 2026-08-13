#!/bin/sh
set -eu

readonly inotify_instances_path=/proc/sys/fs/inotify/max_user_instances
readonly requested_instances="${JENKINS_DOCKER_INOTIFY_MAX_USER_INSTANCES:-1024}"

case "$requested_instances" in
  ''|*[!0-9]*)
    echo "JENKINS_DOCKER_INOTIFY_MAX_USER_INSTANCES must be a positive integer" >&2
    exit 64
    ;;
esac

if [ "$requested_instances" -lt 1 ]; then
  echo "JENKINS_DOCKER_INOTIFY_MAX_USER_INSTANCES must be a positive integer" >&2
  exit 64
fi

current_instances="$(cat "$inotify_instances_path")"
if [ "$current_instances" -lt "$requested_instances" ]; then
  echo "$requested_instances" > "$inotify_instances_path"
fi

exec /usr/local/bin/dockerd-entrypoint.sh "$@"
