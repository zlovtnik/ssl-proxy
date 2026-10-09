#!/usr/bin/env bash
set -euo pipefail
source scripts/ci/common.sh
ci_install_cleanup
if [ "$SUBMODULE_CI_READY" = true ] || [ "$SHOULD_RUN_SCHEMA_MIGRATOR" != true ]; then echo 'skipped: delegated or no schema-migrator bump'; exit 0; fi
tar -cf - . | ci_run schema-migrator-1 --rm -i -w /workspace \
  -v /var/run/docker.sock:/var/run/docker.sock \
  azul/zulu-openjdk:21 \
  sh -c 'tar --no-same-owner -xf - && sh /workspace/scripts/ci/tasks/schema-migrator-1.sh'
