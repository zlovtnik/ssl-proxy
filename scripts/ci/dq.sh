#!/usr/bin/env bash
set -euo pipefail
source scripts/ci/common.sh
ci_install_cleanup
if [ "$SHOULD_RUN_DQ" != true ]; then echo 'skipped: no DQ inputs'; exit 0; fi
tar --exclude=.git --exclude=node_modules --exclude=dist -cf - services/dq | ci_run dq-go --rm -i -w /workspace \
  golang:1.26-bookworm \
  sh -c 'tar --no-same-owner -xf - && apt-get update && apt-get install -y --no-install-recommends ripgrep make && cd services/dq && make check && make build'
tar --exclude=node_modules --exclude=dist -cf - services/dq/ui | ci_run dq-ui --rm -i -w /workspace \
  oven/bun:1.4.0 \
  sh -c 'tar --no-same-owner -xf - && cd services/dq/ui && bun install --frozen-lockfile && bun run test && bun run build'
