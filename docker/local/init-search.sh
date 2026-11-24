#!/bin/sh
set -eu
umask 077

# The client token stays root-only. The non-root API reads its digest.
if [ ! -e /search/client.token ]; then
    openssl rand -hex 32 > /search/client.token.new
    mv /search/client.token.new /search/client.token
fi
token=$(cat /search/client.token)
[ "${#token}" -eq 64 ]
checksum=$(awk '/^manifest_sha256:/ { print $2 }' /schema/manifest.yaml)
[ "${#checksum}" -eq 64 ]
printf '%s' "$token" | sha256sum | cut -d ' ' -f1 > /search/api.sha256.new
printf '%s\n' "$checksum" > /search/manifest.sha256.new
for file in api.sha256 manifest.sha256; do
    chmod 0444 "/search/$file.new"
    mv "/search/$file.new" "/search/$file"
done
install -o 65532 -m 0400 /platform/atheros_search_runtime.password /search/password
install -m 0444 /platform/ca.crt /search/ca.crt
