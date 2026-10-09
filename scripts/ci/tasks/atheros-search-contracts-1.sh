#!/bin/sh
set -eu
apt-get update
apt-get install -y --no-install-recommends python3-venv
python3 -m venv /tmp/contracts
/tmp/contracts/bin/pip install -r scripts/requirements-test.txt
make atheros-search-stack-contract
make atheros-search-db-contract PYTHON=/tmp/contracts/bin/python
