#!/usr/bin/env bash
set -euo pipefail
source scripts/ci/common.sh
ci_install_cleanup
if [ "$SUBMODULE_CI_READY" = true ] || [ "$SHOULD_RUN_OCTOPUS" != true ]; then echo 'skipped: delegated or no Octopus bump'; exit 0; fi
coverage_container="$(ci_container_name octopus)"
tar -cf - . | ci_run octopus -i -w /workspace \
  -v /var/run/docker.sock:/var/run/docker.sock \
  azul/zulu-openjdk:21 \
  sh -c 'tar --no-same-owner -xf - && sh /workspace/scripts/ci/tasks/octopus-1.sh'
mkdir -p artifacts/octopus-coverage
docker_cmd cp "$coverage_container:/workspace/services/octopus/target/scala-3.3.8/jacoco/report" artifacts/octopus-coverage/jacoco
docker_cmd cp "$coverage_container:/workspace/services/octopus/target/cucumber" artifacts/octopus-coverage/cucumber
