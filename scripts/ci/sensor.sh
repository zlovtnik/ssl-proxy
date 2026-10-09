#!/usr/bin/env bash
set -euo pipefail
source scripts/ci/common.sh
ci_install_cleanup
if [ "$SHOULD_RUN_SENSOR" != true ]; then echo 'skipped: no sensor changes'; exit 0; fi
tar -cf - . | ci_run sensor-1 --rm -i -w /workspace \
  rust:1.95.0-slim-bookworm \
  sh -c 'tar --no-same-owner -xf - && sh /workspace/scripts/ci/tasks/sensor-1.sh'
tar -cf - . | ci_run sensor-2 --rm -i -w /workspace \
  rust:1.95.0-slim-bookworm \
  sh -c 'tar --no-same-owner -xf - && sh /workspace/scripts/ci/tasks/sensor-2.sh'
