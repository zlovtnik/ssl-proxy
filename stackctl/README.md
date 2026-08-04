# stackctl

stackctl is the opt-in split-release Kubernetes orchestrator for ssl-proxy. It
resolves component dependencies, renders Helm releases, runs gates and checks,
and blocks descendants after a failure. It does not build images, create
secrets, generate TLS or prepare nodes.

The umbrella Helm release remains the compatibility default. See
[System Architecture](../docs/architecture.md#opt-in-stackctl-split-releases).

## Stages

[`stack.yaml`](stack.yaml) declares this order:

1. `bootstrap`: `platform-config`
2. `infrastructure`: TiDB, Redpanda, MinIO, Redis and telemetry
3. `schema-executor`: the canonical TiDB DDL job
4. `schema-migrator`: Schema Migrator, UI, Keycloak and edge
5. `applications`: Octopus, Atheros Search/UI and the sensor
6. `proxy`: WireGuard and transparent proxy

Component dependencies, Kubernetes resource gates and HTTP/TCP checks are
explicit in the stack file. A gate proves only its declared condition; current
runtime gaps remain documented in
[Architecture known gaps](../docs/architecture.md#known-gaps).

## Make targets

```bash
make stackctl-plan
make stackctl-validate
make stackctl-render
make stackctl-compare
make stackctl-preflight
make stackctl-dry-run
make stackctl-deploy
make stackctl-status
make stackctl-smoke
```

Override the manifest with `STACKCTL_FILE` and pass additional CLI options
through `STACKCTL_ARGS`.

The full opt-in operations workflow is:

```bash
make up-ready-stackctl \
  PROFILE_MODE=iphone \
  SERVER_IP=192.0.2.10 \
  REGISTRY=192.0.2.10:5000
```

## Direct CLI

```bash
python3 stackctl/stackctl.py plan
python3 stackctl/stackctl.py validate
python3 stackctl/stackctl.py deploy
python3 stackctl/stackctl.py deploy --component atheros-search
```

Install the Python requirements only for direct use:

```bash
python3 -m pip install -r stackctl/requirements.txt
python3 -m pytest stackctl/tests
```

Prefer the Make/ops wrappers in normal repository workflows because they share
artifact paths, environment validation and deployment diagnostics.
