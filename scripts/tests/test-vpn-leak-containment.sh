#!/usr/bin/env bash
# Run only in a disposable Linux machine. Never changes the host firewall/routes.
set -euo pipefail
root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)
validator="$root/scripts/tests/test-vpn-leak-results.py"
if [[ ${1:-} == --self-test && $# == 1 ]]; then
    exec python3 "$validator" --self-test
fi
if [[ $# != 4 || $1 != --fixture || $2 != linux || $3 != --output ]]; then
    echo "usage: $0 --self-test | --fixture linux --output <new-directory>" >&2
    exit 2
fi
if [[ $(uname -s) != Linux ]]; then
    echo "BLOCKED: Linux network namespaces, kernel WireGuard and nftables are required; host OS is $(uname -s)" >&2
    exit 1
fi
if [[ $EUID != 0 ]]; then
    echo "BLOCKED: run as administrator in a disposable Linux VM; no automatic sudo or package installation" >&2
    exit 1
fi
for tool in python3 ip wg nft tcpdump setpriv openssl cargo sysctl readlink; do
    command -v "$tool" >/dev/null || { echo "BLOCKED: missing prerequisite $tool" >&2; exit 1; }
done
# Build in the same environment as the fixture. Host/mismatched binaries do not
# establish a tested real packet path. No packages are installed by this script.
cd "$root"
cargo build -p ssl-proxy --bin wg-obfs-shim --bin ssl-proxy --target-dir "$root/target"
exec python3 "$validator" --run-linux "$4"
