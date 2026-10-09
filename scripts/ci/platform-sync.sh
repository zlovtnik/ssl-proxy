#!/usr/bin/env bash
set -euo pipefail
source scripts/ci/common.sh
ci_install_cleanup
if [ "$SHOULD_RUN_PLATFORM_SYNC" != true ]; then echo 'skipped: no platform-sync changes'; exit 0; fi
tar -cf - . | ci_run platform-sync-1 --rm -i -w /workspace \
  golang:1.26-bookworm \
  sh -c 'tar --no-same-owner -xf - && make platform-sync-lint'
