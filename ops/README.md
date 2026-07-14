# sslproxy-ops

Typed Python operator CLI for the host-side `ssl-proxy` scripts.

Run from the repository root through the Makefile or script wrappers. They use
`uv` when available and otherwise bootstrap `ops/.venv`:

```sh
make ops-test
./scripts/diagnose.sh --help
```

`make up-ready` defaults to the registry-backed Kubernetes/Helm deployment.
It uses standard `kubectl` and `helm` with `UP_READY_KUBE_CONTEXT` when set,
or the current kubeconfig context otherwise. Set
`UP_READY_DEPLOYMENT_TARGET=compose` for the compatibility Compose path.

For direct module execution, install the ops package first or use `uv`:

```sh
cd ops
uv run python -m sslproxy_ops --help
```

## Initial command mapping

| Legacy entrypoint | Python command |
| --- | --- |
| `scripts/memo-show.sh` | `ops memo show` |
| `scripts/memo-log.sh` | `ops memo log` |
| `scripts/check-db-connections.sh` | `ops db check-connections` |
| `scripts/sync-status.sh` | `ops pipeline status` |
| `scripts/bench-wg-path.sh` | `ops bench wg-path` |
| `tests/smoke.sh` | `ops smoke` |
| `scripts/smoke_test.sh` | `ops schema-migrator smoke` |
| `scripts/prep_ath.sh` | `ops host prep-ath` |
| `setup-ubuntu.sh` | `ops host setup-ubuntu` |
| `scripts/up-ready.sh` | `ops up-ready` |
| `scripts/diagnose.sh` | `ops diagnose` |

Container PID 1 and init-container scripts remain shell by design. Validate them
with `ops host shellcheck-tier-b`; do not add Python to the minimal runtime image
only to replace those boot scripts. New Python code must pass `cwd=` explicitly
through `sslproxy_ops.shell.run()` instead of calling `os.chdir()`.
