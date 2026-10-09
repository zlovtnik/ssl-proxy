#!/usr/bin/env bash
set -euo pipefail
source scripts/ci/common.sh
ci_install_cleanup
if [ "$SHOULD_RUN_STATS_READER" != true ]; then echo 'skipped: no stats-reader changes'; exit 0; fi
tar -cf - services/stats-reader | ci_run stats-reader-1 --rm -i -w /workspace \
  golang:1.26-bookworm \
  sh -c 'tar --no-same-owner -xf - && cd services/stats-reader && go test ./...'
