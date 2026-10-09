#!/usr/bin/env bash
set -euo pipefail
source scripts/ci/common.sh
recovery_command='docker compose -f docker-compose.ci.yaml up -d --no-deps --force-recreate jenkins'
expected_registry="$(python3 scripts/image_contract.py registry-authority --environment prod)"
if [ -z "${CI_REGISTRY:-}" ]; then
  echo "controller environment drift: CI_REGISTRY is not set; production requires $expected_registry" >&2
  echo 'Confirm SERVER_IP in the deployment .env, then recreate the Jenkins controller:' >&2
  echo "$recovery_command" >&2
  exit 1
fi
if [ "$CI_REGISTRY" != "$expected_registry" ]; then
  echo "controller environment drift: CI_REGISTRY=$CI_REGISTRY, but production requires $expected_registry" >&2
  echo 'Confirm SERVER_IP in the deployment .env, then recreate the Jenkins controller:' >&2
  echo "$recovery_command" >&2
  exit 1
fi
