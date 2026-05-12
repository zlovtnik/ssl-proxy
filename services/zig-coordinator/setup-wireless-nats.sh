#!/bin/sh
# Compatibility wrapper for the canonical NATS topology bootstrap.

set -eu

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
repo_root=$(CDPATH= cd -- "${script_dir}/../.." && pwd)

export SYNC_NATS_URL="${SYNC_NATS_URL:-${NATS_SERVER:-nats://localhost:4222}}"
export SYNC_NATS_TOPOLOGY_FILE="${SYNC_NATS_TOPOLOGY_FILE:-${repo_root}/docker/nats/topology.manifest}"

exec "${repo_root}/docker/nats/bootstrap.sh"
