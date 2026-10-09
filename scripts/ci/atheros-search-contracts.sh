#!/usr/bin/env bash
set -euo pipefail
source scripts/ci/common.sh
ci_install_cleanup
if [ "$SHOULD_RUN_ATHEROS_SEARCH_CONTRACTS" != true ]; then echo 'skipped: no Search contract inputs'; exit 0; fi
test "$(git -C apps/integration-console rev-parse HEAD)" = "$(git rev-parse HEAD:apps/integration-console)"
tar --exclude=node_modules --exclude=.git -cf - . | ci_run atheros-search-contracts-1 --rm -i -w /workspace \
  --network host -v /var/run/docker.sock:/var/run/docker.sock \
  -e TESTCONTAINERS_HOST_OVERRIDE=127.0.0.1 -e GOTOOLCHAIN=local \
  golang:1.26-bookworm \
  sh -c 'tar --no-same-owner -xf - && sh /workspace/scripts/ci/tasks/atheros-search-contracts-1.sh'
