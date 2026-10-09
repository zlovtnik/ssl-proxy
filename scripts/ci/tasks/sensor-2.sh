#!/bin/sh
set -eu
apt-get update
apt-get install -y --no-install-recommends build-essential cmake libclang-dev pkg-config libssl-dev libcurl4-openssl-dev libsasl2-dev libpcap-dev ripgrep make
make dependency-boundaries
