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
                    │  K8s token) │
                    └─────────────┘
```

The platform sync program reads all 20 required inputs from Vault, retains only contract-declared keys, validates them (TLS chains, key pairs, DNS identities including the PgBouncer listener, live PostgreSQL identity/grants, Loki, PgBouncer, and WireGuard), and performs Kubernetes server-side dry runs before applying. If a later apply fails, it restores objects already changed in that run from its in-memory preflight snapshot.

## Prerequisites

- Vault server with KV-v2 engine enabled at `secret/ssl-proxy/prod`
- Kubernetes cluster with the `ssl-proxy-platform-sync` ServiceAccount (Phase 1 RBAC)
- Renewable read-only Vault token created by `scripts/bootstrap-vault-platform-sync.sh`
- Vault CA certificate available as a host file
- Ubuntu server with systemd
- Go 1.25+ or Docker. When Go is absent, the installer uses a pinned, hardened
  Go builder container and installs only the resulting static binaries.

## Installation

```bash
export VAULT_ADDR=https://192.168.1.242:8200
export VAULT_CACERT="$HOME/.config/vault/ca.crt"
export PLATFORM_SYNC_TOKEN_FILE="$HOME/.config/platform-sync/vault-token"

# Capture the administrator token without storing it in shell history.
if [ -n "${ZSH_VERSION:-}" ]; then
  read -rs "VAULT_TOKEN?Vault administrator token: "
else
  read -rsp 'Vault administrator token: ' VAULT_TOKEN
fi
export VAULT_TOKEN
printf '\n'

./scripts/bootstrap-vault-platform-sync.sh
unset VAULT_TOKEN

sudo VAULT_TOKEN_SOURCE="$PLATFORM_SYNC_TOKEN_FILE" \
  VAULT_CA_SOURCE="$VAULT_CACERT" \
  ./scripts/install-platform-sync.sh
```

This will:
1. Create the `platform-sync` user
2. Install binaries to `/opt/platform-sync/bin/`
3. Install the contract to `/opt/platform-sync/contract/`
4. Install systemd units
5. Install the Vault token and CA as root-only systemd credential sources
6. Enable the single sync timer

The installer records the SHA-256 digest of the installed input contract. The
systemd service verifies that digest before every run, so an ad hoc or partial
contract replacement fails closed. Re-run the installer to deploy a reviewed
contract update; do not copy the file independently.

## Configuration

Edit `/etc/platform-sync/platform-sync.conf`:

```bash
VAULT_ADDR=https://192.168.1.242:8200
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
sudo systemctl start vault-k8s-sync.timer
sudo systemctl start vault-k8s-sync.service

# Check status
sudo systemctl status vault-k8s-sync
sudo journalctl -u vault-k8s-sync -f
sudo sha256sum --check /opt/platform-sync/contract/platform-input-contract.sha256
```

## Monitoring

### Health Status

Because the synchronizer is a timer-driven one-shot process, its latest health
status is an atomic JSON file rather than a transient HTTP endpoint:

```bash
jq . /run/platform-sync/health.json
```

### Prometheus Metrics

Prometheus textfile metrics persist across timer activations at:

```bash
cat /run/platform-sync/metrics.prom
```

Configure a node-exporter textfile collector to scrape that file when host
monitoring is required.

Key metrics:
- `platform_sync_runs_total{result}` - Completed runs by result
- `platform_sync_last_run_duration_seconds` - Most recent run duration
- `platform_sync_last_inputs_written` - Inputs written by the most recent run
- `platform_sync_last_run_timestamp_seconds` - Most recent completion time

### Systemd Timers

```bash
# Check timer status
systemctl list-timers --all | grep vault-k8s-sync

# View recent logs
journalctl -u credential-generator -n 50
journalctl -u vault-k8s-sync -n 50
```

## Recovery

### Credential Generator Failure

If the credential generator fails:

1. Check Kubernetes API: `kubectl cluster-info`
2. Check the source K3s kubeconfig: `sudo test -r /etc/rancher/k3s/k3s.yaml`
3. Restart the generator: `sudo systemctl restart credential-generator.service`
4. Verify `/run/platform-sync/kubeconfig` exists without printing it

### Sync Failure

If the sync fails:

1. Check logs: `journalctl -u vault-k8s-sync -f`
2. Verify all 18 Secrets exist: `kubectl get secrets -n prod-ssl-proxy`
3. Check the health file: `jq . /run/platform-sync/health.json`
4. Run a dry run: `SYNC_DRY_RUN=true /opt/platform-sync/bin/platform-sync`

### Lock Contention

If the sync reports lock contention:

1. Check for stale locks: `kubectl get configmap platform-sync-lock -n prod-ssl-proxy -o yaml`
2. If the lock is stale (older than TTL), the sync will automatically acquire it on the next run
3. If the lock is held by another process, wait for it to complete or investigate the other process

## Local Generator Boundaries

The credential generator (`cred-gen`) is a host-only tool that:
- Creates short-lived Kubernetes SA tokens (1-hour lifetime)
- Writes the generated kubeconfig to `/run/platform-sync/` (tmpfs)

The independent renewable Vault token and Vault CA are root-owned source files
under `/etc/platform-sync/` and are exposed to the one-shot service only through
systemd credentials. The sync renews the token before reading Vault.

**Never commit kubeconfig or Vault tokens to Git.**

## Configuration Reference

| Variable | Default | Description |
|----------|---------|-------------|
| `VAULT_ADDR` | `https://192.168.1.242:8200` | Vault server address |
| `VAULT_KV_MOUNT` | `secret` | KV v2 mount path |
| `VAULT_KV_PREFIX` | `ssl-proxy/prod` | Secret path prefix |
| `SYNC_NAMESPACE` | `prod-ssl-proxy` | Target Kubernetes namespace |
| `CONTRACT_PATH` | `cyber-stack/platform-input-contract.yaml` | Contract file path |
| `SYNC_DRY_RUN` | `false` | Validate only, don't write |
| `SYNC_LOCK_TTL_SECONDS` | `600` | Lock TTL in seconds |
| `SYNC_HEALTH_PATH` | `/run/platform-sync/health.json` | Last-run health artifact |
| `SYNC_METRICS_PATH` | `/run/platform-sync/metrics.prom` | Prometheus textfile metrics |
| `LOG_LEVEL` | `info` | Log level (debug, info, warn, error) |
