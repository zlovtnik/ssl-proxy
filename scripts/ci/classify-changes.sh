#!/usr/bin/env bash
set -euo pipefail
source scripts/ci/common.sh
if [ "${FULL_BUILD:-false}" = true ]; then
  python3 scripts/classify_changes.py --full \
    --json-out artifacts/changed-paths.json --env-out artifacts/changed-paths.env
  exit 0
fi
# The Pipeline records its own successful checkout revision. Git-plugin
# previous-commit values can point at an aborted run and omit earlier changes.
if [ -n "${CI_PREVIOUS_SUCCESSFUL_REVISION:-}" ]; then
  if ! git cat-file -e "${CI_PREVIOUS_SUCCESSFUL_REVISION}^{commit}" 2>/dev/null; then
    git fetch --no-tags --deepen=200 origin HEAD || git fetch --no-tags --unshallow origin HEAD || true
  fi
fi
if [ -n "${CI_PREVIOUS_SUCCESSFUL_REVISION:-}" ] && \
   git cat-file -e "${CI_PREVIOUS_SUCCESSFUL_REVISION}^{commit}" 2>/dev/null && \
   git merge-base --is-ancestor "$CI_PREVIOUS_SUCCESSFUL_REVISION" HEAD; then
  python3 scripts/classify_changes.py --base "$CI_PREVIOUS_SUCCESSFUL_REVISION" \
    --json-out artifacts/changed-paths.json --env-out artifacts/changed-paths.env
else
  echo 'No trusted successful-build baseline; validating and publishing every image candidate.'
  python3 scripts/classify_changes.py --full \
    --json-out artifacts/changed-paths.json --env-out artifacts/changed-paths.env
fi
