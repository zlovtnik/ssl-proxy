#!/usr/bin/env bash
set -euo pipefail
source scripts/ci/common.sh
# Jenkins shallow clones often omit GIT_PREVIOUS_SUCCESSFUL_COMMIT.
# Resolving that base must not silently select a full rebuild.
if [ -n "${GIT_PREVIOUS_SUCCESSFUL_COMMIT:-}" ]; then
  if ! git cat-file -e "${GIT_PREVIOUS_SUCCESSFUL_COMMIT}^{commit}" 2>/dev/null; then
    git fetch --no-tags --deepen=200 origin HEAD || git fetch --no-tags --unshallow origin HEAD || true
  fi
fi
if [ -n "${GIT_PREVIOUS_SUCCESSFUL_COMMIT:-}" ] && \
   git cat-file -e "${GIT_PREVIOUS_SUCCESSFUL_COMMIT}^{commit}" 2>/dev/null; then
  python3 scripts/classify_changes.py --base "$GIT_PREVIOUS_SUCCESSFUL_COMMIT" \
    --json-out artifacts/changed-paths.json --env-out artifacts/changed-paths.env
elif git rev-parse --verify HEAD^ >/dev/null 2>&1; then
  python3 scripts/classify_changes.py --base HEAD^ \
    --json-out artifacts/changed-paths.json --env-out artifacts/changed-paths.env
else
  python3 scripts/classify_changes.py --full \
    --json-out artifacts/changed-paths.json --env-out artifacts/changed-paths.env
fi
