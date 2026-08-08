# sslproxy-ops

`sslproxy-ops` is the typed Python operator CLI behind compatibility shell
wrappers. It coordinates registry checks,
Helm/stackctl deployment, diagnostics and operational evidence; it does not own
application runtime behavior.

Run it directly from `ops/`. The root Makefile is intentionally limited to
image build/publication and Argo CD promotion.

```bash
cd ops
uv run python -m sslproxy_ops --help
uv run python -m unittest discover -s tests -v
```

## Deployment modes

The `up-ready` command uses the registry-backed umbrella Helm workflow.
Set `UP_READY_KUBE_CONTEXT` when the current kubeconfig context is not the
target. The workflow performs a real node-runtime pull probe before Helm.

Use the CLI's split mode for the opt-in split-release deployment. Set
`UP_READY_DEPLOYMENT_TARGET=compose` only for the compatibility Compose path.
Architecture and deployment limits are documented in
[System Architecture](../docs/architecture.md).

Compatibility wrappers such as `scripts/diagnose.sh`, `scripts/up-ready.sh`,
`scripts/sync-status.sh` and `scripts/check-db-connections.sh` delegate to the
same Python command surface.

Container PID 1 and init-container scripts remain shell by design. Validate
them with `shellcheck`; do not add Python to minimal runtime images
only to replace boot scripts. New Python code must pass `cwd=` through
`sslproxy_ops.shell.run()` instead of changing global process state.
