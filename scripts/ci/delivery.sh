#!/usr/bin/env bash
set -euo pipefail
source scripts/ci/common.sh
ci_install_cleanup
python3 -c "import json, glob; [json.load(open(f)) for f in glob.glob('cyber-stack/base/telemetry/config/grafana/dashboards/*.json')]"
bash -n cyber-stack/base/redpanda-maintenance/redpanda-daily-clean.sh
python3 scripts/check_redpanda_maintenance.py
tar -cf - cyber-stack/base/redpanda-maintenance/redpanda-daily-clean.sh | ci_run delivery-1 --rm -i koalaman/shellcheck-alpine:v0.10.0 \
  sh -c 'tar --no-same-owner -xf - && shellcheck /cyber-stack/base/redpanda-maintenance/redpanda-daily-clean.sh'
awk -F'|' '
  /^[[:space:]]+[[:alnum:]._-]+\|/ && (NF != 5 || $5 == "") {
    print "topic manifest row is missing retention.bytes: " $0 > "/dev/stderr"
    invalid = 1
  }
  END { exit invalid }
' cyber-stack/base/platform-config/configmap.yaml
tar -cf - cyber-stack/base/telemetry/config/prometheus/rules | ci_run delivery-2 --rm -i \
  --entrypoint sh \
  prom/prometheus:v3.2.1@sha256:508729e0e2d18e11fd742a5a5ca70e557b940a93948c3c95fd0123a6fd538b69 \
  -c 'tar --no-same-owner -xf - && promtool check rules cyber-stack/base/telemetry/config/prometheus/rules/*.yml'
