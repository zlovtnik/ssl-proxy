# sslproxy-ops

`sslproxy-ops` is the typed Python operator CLI behind the root Make targets
and compatibility shell wrappers. It coordinates builds, registry checks,
Helm/stackctl deployment, diagnostics and operational evidence; it does not own
application runtime behavior.

Run it from the repository root. The Makefile uses `uv` when available and
otherwise bootstraps `ops/.venv`.

```bash
make ops-test
make diagnose
make pipeline-health
make up-ready
```

Direct module execution:

```bash
cd ops
uv run python -m sslproxy_ops --help
```

## Deployment modes

`make up-ready` uses the registry-backed umbrella Helm workflow by default.
Set `UP_READY_KUBE_CONTEXT` when the current kubeconfig context is not the
target. The workflow performs a real node-runtime pull probe before Helm.

Use `make up-ready-stackctl` for the opt-in split-release deployment. Set
`UP_READY_DEPLOYMENT_TARGET=compose` only for the compatibility Compose path.
Architecture and deployment limits are documented in
[System Architecture](../docs/architecture.md).

For a plain-HTTP node registry:

```bash
make configure-containerd-registry REGISTRY=192.0.2.10:5000
```

## Make target map

| Operator task | Make target |
|---|---|
| Deploy umbrella chart | `make up-ready` |
| Deploy split releases | `make up-ready-stackctl` |
| Non-mutating diagnosis | `make diagnose` |
| Check direct database connections | `make db-check-connections` |
| Inspect pipeline state | `make pipeline-health` |
| Kubernetes snapshot | `make k8s-status` |
| Smoke tests | `make smoke` |
| WireGuard path benchmark | `make bench-wg-path` |
| Prepare Atheros host | `make prep-ath` |
| Show/append operational memory | `make memo-show` / `make memo-log` |

Compatibility wrappers such as `scripts/diagnose.sh`, `scripts/up-ready.sh`,
`scripts/sync-status.sh` and `scripts/check-db-connections.sh` delegate to the
same Python command surface.

Container PID 1 and init-container scripts remain shell by design. Validate
them with `make shellcheck-tier-b`; do not add Python to minimal runtime images
only to replace boot scripts. New Python code must pass `cwd=` through
`sslproxy_ops.shell.run()` instead of changing global process state.
