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

2. **Force-expire the local credentials:**
   ```bash
   rm -f /run/platform-sync/kubeconfig /run/platform-sync/vault-token
   systemctl restart credential-generator
   ```

3. **If the SA itself is suspect**, create a new SA and rebind through Git:
   - Update the RBAC manifests in `cyber-stack/base/platform-sync/`
   - Commit and push the changes
   - Argo CD will reconcile the new SA/Role/RoleBinding
   - Update the Vault role with the new SA name:
     ```bash
     vault write auth/kubernetes/role/platform-sync \
       bound_service_account_names=ssl-proxy-platform-sync \
       bound_service_account_namespaces=prod-ssl-proxy \
       policies=platform-sync-ro \
       ttl=1h \
       max_ttl=1h
     ```

4. **Restart the sync timer:**
   ```bash
   systemctl restart vault-k8s-sync
   ```

### Verification

1. Check the health endpoint:
   ```bash
   curl http://localhost:9106/healthz
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

If the credential generator fails to create tokens:

### Diagnosis

1. Check Vault connectivity:
   ```bash
   vault status
   ```

2. Check Kubernetes API:
   ```bash
   kubectl cluster-info
   ```

3. Check SA exists:
   ```bash
   kubectl get sa ssl-proxy-platform-sync -n prod-ssl-proxy
   ```

4. Check credential generator logs:
   ```bash
   journalctl -u credential-generator -f
   ```

### Recovery

1. Fix the underlying issue (Vault/K8s connectivity, SA permissions)

2. Restart the credential generator:
   ```bash
   systemctl restart credential-generator
   ```

3. Verify tokens were created:
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

2. Check the health endpoint:
   ```bash
   curl http://localhost:9106/healthz
   ```

3. Run a dry run:
   ```bash
   VAULT_TOKEN=$(cat /run/platform-sync/vault-token) \
   KUBECONFIG=/run/platform-sync/kubeconfig \
   /opt/platform-sync/bin/platform-sync --dry-run
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
   curl http://localhost:9106/healthz
   ```
