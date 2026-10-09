#!/bin/sh
set -eu
cd apps/schema-migrator
sh /workspace/scripts/ci/tasks/install-sbt.sh
sbt -Dsbt.supershell=false "Test / testFull"
