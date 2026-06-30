#!/bin/sh
# Compatibility wrapper for the canonical Redpanda topic_manifest bootstrap.

set -eu

script_dir=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
repo_root=$(CDPATH='' cd -- "${script_dir}/../.." && pwd)

export SYNC_REDPANDA_BOOTSTRAP_SERVERS="${SYNC_REDPANDA_BOOTSTRAP_SERVERS:-${Redpanda_SERVER:-localhost:9092}}"
export SYNC_REDPANDA_TOPIC_MANIFEST="${SYNC_REDPANDA_TOPIC_MANIFEST:-${repo_root}/docker/redpanda/topics.manifest}"

exec "${repo_root}/docker/redpanda/bootstrap.sh"
