# Platform Sync Incident Runbook

Use this runbook when the platform sync identity or credentials are compromised
or when the credential generator fails.

## Compromised Credentials

If the `ssl-proxy-platform-sync` ServiceAccount token or Vault token may have
been exposed:

### Immediate Actions

1. **Revoke the Vault token:**
   ```bash
   vault token revoke <token-id>
   ```

2. **Remove the compromised Vault source token and stop the timer:**
   ```bash
   sudo systemctl stop vault-k8s-sync.timer
   sudo rm -f /etc/platform-sync/vault-token
   ```

3. **If the SA itself is suspect**, create a new SA and rebind through Git:
   - Update the RBAC manifests in `cyber-stack/base/platform-sync/`
   - Commit and push the changes
   - Argo CD will reconcile the new SA/Role/RoleBinding
   - Reinstall the service after Argo CD has reconciled the new identity

4. **Create and install a replacement read-only token, then restart the timer:**
   ```bash
   export PLATFORM_SYNC_TOKEN_FILE="$HOME/.config/platform-sync/vault-token-new"
   ./scripts/bootstrap-vault-platform-sync.sh
   sudo install -o root -g root -m 600 \
     "$PLATFORM_SYNC_TOKEN_FILE" /etc/platform-sync/vault-token
   sudo systemctl start vault-k8s-sync.timer
   sudo systemctl start vault-k8s-sync.service
   ```

### Verification

1. Check the last-run health artifact:
   ```bash
   jq . /run/platform-sync/health.json
   ```

2. Verify all 18 Secrets exist:
   ```bash
   kubectl get secrets -n prod-ssl-proxy -o name | wc -l
   ```

3. Check sync logs:
   ```bash
   journalctl -u vault-k8s-sync -f
   ```

## Credential Generator Failure

If the credential generator fails to create the short-lived Kubernetes token:

### Diagnosis

1. Check Kubernetes API:
   ```bash
   kubectl cluster-info
   ```

2. Check SA exists:
   ```bash
   kubectl get sa ssl-proxy-platform-sync -n prod-ssl-proxy
   ```

3. Check credential generator logs:
   ```bash
   journalctl -u credential-generator -f
   ```

### Recovery

1. Fix the underlying Kubernetes connectivity or ServiceAccount issue

2. Restart the credential generator:
   ```bash
   systemctl restart credential-generator
   ```

3. Verify the kubeconfig was created without printing it:
   ```bash
   ls -la /run/platform-sync/
   ```

4. Restart the sync:
   ```bash
   systemctl restart vault-k8s-sync
   ```

## Sync Failure

If the sync fails to write secrets:

### Diagnosis

1. Check sync logs:
   ```bash
   journalctl -u vault-k8s-sync -f
   ```

2. Check the last-run health artifact:
   ```bash
   jq . /run/platform-sync/health.json
   ```

3. Run a dry run:
   ```bash
   sudo systemctl set-environment SYNC_DRY_RUN=true
   sudo systemctl start vault-k8s-sync.service
   sudo systemctl unset-environment SYNC_DRY_RUN
   ```

### Recovery

1. If validation fails, check the contract and Vault data

2. If Kubernetes write fails, check RBAC by reading the Role:
   ```bash
   kubectl get role ssl-proxy-platform-sync -n prod-ssl-proxy -o yaml
   ```

3. Check for lock contention by reading the lock ConfigMap:
   ```bash
   kubectl get configmap platform-sync-lock -n prod-ssl-proxy -o yaml
   ```

## Rollback

To rollback to a previous known-good state:

1. Revert the contract change in Git

2. Force a sync with the previous contract:
   ```bash
   systemctl restart vault-k8s-sync
   ```

3. Verify the rollback:
   ```bash
   kubectl get secrets -n prod-ssl-proxy
   jq . /run/platform-sync/health.json
   ```
