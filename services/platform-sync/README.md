# Platform Sync

Host-side Vault-to-Kubernetes secret synchronization for the ssl-proxy production stack.

## Architecture

```
┌─────────────┐     ┌──────────────┐     ┌──────────────┐
│   Vault     │────▶│ platform-sync│────▶│  Kubernetes  │
│  (KV-v2)    │     │   (Go binary)│     │   (prod-ssl-proxy) │
└─────────────┘     └──────────────┘     └──────────────┘
                           │
                    ┌──────┴──────┐
                    │  cred-gen   │
                    │ (short-lived│
                    │   tokens)   │
                    └─────────────┘
```

The platform sync program reads all 18 required inputs from Vault, validates them (TLS chain, PostgreSQL, Loki, PgBouncer, WireGuard), performs Kubernetes server-side dry runs, and atomically writes Secrets and ConfigMaps to the `prod-ssl-proxy` namespace.

## Prerequisites

- Vault server with KV-v2 engine enabled at `secret/ssl-proxy/prod`
- Kubernetes cluster with the `ssl-proxy-platform-sync` ServiceAccount (Phase 1 RBAC)
- Vault K8s auth method configured (run `scripts/bootstrap-vault-platform-sync.sh`)
- Ubuntu server with systemd

## Installation

```bash
sudo ./scripts/install-platform-sync.sh
```

This will:
1. Create the `platform-sync` user
2. Install binaries to `/opt/platform-sync/bin/`
3. Install the contract to `/opt/platform-sync/contract/`
4. Install systemd units
5. Enable the timers

## Configuration

Edit `/etc/platform-sync/platform-sync.conf`:

```bash
VAULT_ADDR=https://127.0.0.1:8200
VAULT_KV_MOUNT=secret
VAULT_KV_PREFIX=ssl-proxy/prod
SYNC_NAMESPACE=prod-ssl-proxy
CONTRACT_PATH=/opt/platform-sync/contract/platform-input-contract.yaml
SYNC_DRY_RUN=false
SYNC_LOCK_TTL_SECONDS=600
LOG_LEVEL=info
```

## First Run

```bash
# Start the credential generator
sudo systemctl start credential-generator.timer

# Wait for credentials to be generated
sleep 5

# Start the sync
sudo systemctl start vault-k8s-sync.timer

# Check status
sudo systemctl status vault-k8s-sync
sudo journalctl -u vault-k8s-sync -f
```

## Monitoring

### Health Endpoint

The health endpoint is available on `localhost:9106/healthz`:

```bash
curl http://localhost:9106/healthz
```

### Prometheus Metrics

Metrics are exposed on `localhost:9105/metrics`:

```bash
curl http://localhost:9105/metrics
```

Key metrics:
- `sync_runs_total{result}` - Total sync runs by result (success, error, dry_run)
- `sync_duration_seconds` - Sync duration
- `sync_inputs_written_total{type}` - Inputs written by type (Secret, ConfigMap)
- `sync_lock_contention_total` - Lock contention events

### Systemd Timers

```bash
# Check timer status
systemctl list-timers --all | grep platform-sync

# View recent logs
journalctl -u credential-generator -n 50
journalctl -u vault-k8s-sync -n 50
```

## Recovery

### Credential Generator Failure

If the credential generator fails:

1. Check Vault connectivity: `vault status`
2. Check Kubernetes API: `kubectl cluster-info`
3. Restart the timer: `systemctl restart credential-generator.timer`
4. Verify tokens: `ls -la /run/platform-sync/`

### Sync Failure

If the sync fails:

1. Check logs: `journalctl -u vault-k8s-sync -f`
2. Verify all 18 Secrets exist: `kubectl get secrets -n prod-ssl-proxy`
3. Check the health endpoint: `curl localhost:9106/healthz`
4. Run a dry run: `SYNC_DRY_RUN=true /opt/platform-sync/bin/platform-sync`

### Lock Contention

If the sync reports lock contention:

1. Check for stale locks: `kubectl get configmap platform-sync-lock -n prod-ssl-proxy -o yaml`
2. If the lock is stale (older than TTL), the sync will automatically acquire it on the next run
3. If the lock is held by another process, wait for it to complete or investigate the other process

## Local Generator Boundaries

The credential generator (`cred-gen`) is a host-only tool that:
- Creates short-lived Kubernetes SA tokens (1-hour lifetime)
- Obtains Vault tokens via K8s auth
- Writes credentials to `/run/platform-sync/` (tmpfs)

**Never commit kubeconfig or Vault tokens to Git.** The credentials are ephemeral and reside only on the host filesystem.

## Configuration Reference

| Variable | Default | Description |
|----------|---------|-------------|
| `VAULT_ADDR` | `https://127.0.0.1:8200` | Vault server address |
| `VAULT_KV_MOUNT` | `secret` | KV v2 mount path |
| `VAULT_KV_PREFIX` | `ssl-proxy/prod` | Secret path prefix |
| `SYNC_NAMESPACE` | `prod-ssl-proxy` | Target Kubernetes namespace |
| `CONTRACT_PATH` | `cyber-stack/platform-input-contract.yaml` | Contract file path |
| `SYNC_DRY_RUN` | `false` | Validate only, don't write |
| `SYNC_LOCK_TTL_SECONDS` | `600` | Lock TTL in seconds |
| `LOG_LEVEL` | `info` | Log level (debug, info, warn, error) |
