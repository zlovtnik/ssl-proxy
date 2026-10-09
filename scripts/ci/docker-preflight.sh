#!/usr/bin/env bash
set -euo pipefail
source scripts/ci/common.sh
ci_check_inotify
ci_refresh_context
docker_cmd version
if [ "$SUBMODULE_CI_READY" != true ] && {
  [ "$SHOULD_RUN_OCTOPUS" = true ] || [ "$SHOULD_RUN_SCHEMA_MIGRATOR" = true ];
}; then
  docker_cmd pull pgvector/pgvector:pg16
fi
