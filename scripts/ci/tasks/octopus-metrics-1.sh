#!/bin/sh
set -eu
apt-get update
apt-get install -y --no-install-recommends \
  g++ cmake ninja-build pkg-config libpq-dev libcurl4-openssl-dev \
  libhiredis-dev libsimdjson-dev ca-certificates python3-venv
python3 -m venv /tmp/metrics-tests
/tmp/metrics-tests/bin/pip install -r services/octopus-metrics/tests/requirements.txt
cmake -S services/octopus-metrics -B /tmp/metrics-asan -G Ninja -DMETRICS_SANITIZE=ON
cmake --build /tmp/metrics-asan --parallel 2
ctest --test-dir /tmp/metrics-asan --output-on-failure
/tmp/metrics-tests/bin/python services/octopus-metrics/tests/integration_test.py --build /tmp/metrics-asan
cmake -S services/octopus-metrics -B /tmp/metrics-tsan -G Ninja -DMETRICS_TSAN=ON
cmake --build /tmp/metrics-tsan --parallel 2
ctest --test-dir /tmp/metrics-tsan --output-on-failure
