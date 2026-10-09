#!/usr/bin/env bash
set -euo pipefail
source scripts/ci/common.sh
ci_install_cleanup
theme_container="$(ci_container_name keycloak-theme)"
cleanup_theme_container() {
  mkdir -p artifacts/keycloak-theme
  docker_cmd cp "$theme_container:/workspace/scripts/tests/keycloak-theme/test-results/." \
    artifacts/keycloak-theme/ >/dev/null 2>&1 || true
  ci_cleanup
}
trap cleanup_theme_container EXIT
tar --exclude=node_modules --exclude=test-results -cf - \
  scripts/tests/keycloak-theme \
  cyber-stack/base/schema-migrator/configmaps/keycloak-theme | \
  ci_run keycloak-theme --init --shm-size=256m -i -w /workspace \
    mcr.microsoft.com/playwright:v1.60.0-noble \
    sh -c 'tar --no-same-owner -xf - && cd scripts/tests/keycloak-theme && npm ci --ignore-scripts && npm test'
