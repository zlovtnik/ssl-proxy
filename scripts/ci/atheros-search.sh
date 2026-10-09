#!/usr/bin/env bash
set -euo pipefail
source scripts/ci/common.sh
ci_install_cleanup
if [ "$SUBMODULE_CI_READY" = true ] || [ "$SHOULD_RUN_ATHEROS_SEARCH" != true ]; then echo 'skipped: delegated or no Search inputs'; exit 0; fi
tar -cf - . | ci_run atheros-search-1 --rm -i -w /workspace \
  golang:1.26-bookworm \
  sh -c 'tar --no-same-owner -xf - && make atheros-search-test'
