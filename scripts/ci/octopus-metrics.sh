#!/usr/bin/env bash
set -euo pipefail
source scripts/ci/common.sh
ci_install_cleanup
if [ "$SHOULD_RUN_OCTOPUS_METRICS" != true ]; then echo 'skipped: no Octopus metrics inputs'; exit 0; fi
tar -cf - services/octopus-metrics sql/postgres/octopus_core scripts/ci/tasks/octopus-metrics-1.sh | \
  ci_run octopus-metrics-1 --rm -i -w /workspace \
    --network "${METRICS_CI_NETWORK:-host}" -v /var/run/docker.sock:/var/run/docker.sock \
    -e TESTCONTAINERS_HOST_OVERRIDE="${TESTCONTAINERS_HOST_OVERRIDE:-127.0.0.1}" \
    debian:trixie-slim \
    sh -c 'tar --no-same-owner -xf - && sh /workspace/scripts/ci/tasks/octopus-metrics-1.sh'
