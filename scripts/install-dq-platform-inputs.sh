#!/usr/bin/env bash
# Run from the reviewed DQ release worktree on Wiretrap as root.
# This installs the host synchronizer; only that service writes Kubernetes.
set -euo pipefail

if [ "$EUID" -ne 0 ]; then
  echo 'Run this installer with sudo on Wiretrap.' >&2
  exit 1
fi

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
expected_digest=7a42b187066a2c14c65dbb38f3b6d77e75e0fc0846f379704f17dc173dd260db
actual_digest="$(sha256sum "$repo_root/cyber-stack/platform-input-contract.yaml" | awk '{print $1}')"
if [ "$actual_digest" != "$expected_digest" ]; then
  echo 'This worktree does not contain the reviewed DQ platform-input contract.' >&2
  exit 1
fi

export KUBECONFIG=/run/platform-sync/kubeconfig
# Refuse to replace the installed contract until Argo has created the targets
# and extended the existing writer identity's RBAC through Git.
for input in atheros-auth control-auth manager-auth worker-auth manager-tls worker-tls broker-tls; do
  kubectl get secret "ssl-proxy-dq-$input" -n prod-ssl-proxy -o name >/dev/null
done
previous_success="$(kubectl get configmap platform-ready -n prod-ssl-proxy \
  -o jsonpath='{.data.last-success-unix}')"
case "$previous_success" in ''|*[!0-9]*) echo 'Invalid previous success timestamp.' >&2; exit 1 ;; esac

systemctl stop vault-k8s-sync.timer
if systemctl is-active --quiet vault-k8s-sync.service; then
  echo 'A sync is running. Wait for it to finish, then rerun this installer.' >&2
  echo 'The timer is stopped.' >&2
  exit 1
fi
trap 'echo "Installation or verification failed; leave vault-k8s-sync.timer stopped and inspect its journal." >&2' ERR

# Explicitly preserve the root-owned Vault token and CA already used by the
# working service. Never substitute the operator/root token for its identity.
env -u VAULT_TOKEN_SOURCE -u VAULT_CA_SOURCE bash "$repo_root/scripts/install-platform-sync.sh"
sha256sum --check /opt/platform-sync/contract/platform-input-contract.sha256
started_at="$(date --iso-8601=seconds)"
systemctl start vault-k8s-sync.service
sync_log="$(journalctl -u vault-k8s-sync.service --since "$started_at" --no-pager)"
rg -q '"inputs":31|"count":31' <<< "$sync_log"
rg -q 'all validations passed' <<< "$sync_log"
rg -q 'sync complete' <<< "$sync_log"

read -r ready digest last_success < <(kubectl get configmap platform-ready -n prod-ssl-proxy \
  -o jsonpath='{.data.ready}{" "}{.data.contract-sha256}{" "}{.data.last-success-unix}{"\n"}')
test "$ready" = true
test "$digest" = "$expected_digest"
case "$last_success" in ''|*[!0-9]*) echo 'Invalid success timestamp.' >&2; exit 1 ;; esac
test "$last_success" -gt "$previous_success"
systemctl start vault-k8s-sync.timer
trap - ERR
echo "DQ platform inputs synchronized: 31 inputs, contract $digest. DQ activation remains disabled."
