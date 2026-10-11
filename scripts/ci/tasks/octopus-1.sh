#!/bin/sh
set -eu
cd services/octopus
sh /workspace/scripts/ci/tasks/install-sbt.sh python3
OCTOPUS_REQUIRE_DOCKER=true sbt -Dsbt.supershell=false scalafmtCheckAll "scalafixAll --check" jacoco assembly
python3 scripts/check_coverage.py target/scala-3.3.8/jacoco/report/jacoco.xml
python3 ../../scripts/octopus_image_contract.py jar target/scala-3.*/octopus.jar
