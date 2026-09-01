# Local Registry Image Workflow

This workflow publishes Linux images from a development host to the registry
used by local and production Kubernetes nodes. Kubernetes management is
documented in the [GitOps guide](../cyber-stack/README.md).

## Local development CI and registry

The dedicated private CI stack runs the registry, Jenkins controller and its
isolated Docker build engine. Create the Jenkins administrator password as a
local secret and set the concrete server address in `.env` before starting the
stack:

```bash
umask 077
openssl rand -base64 32 > secrets/jenkins-admin-password
docker compose -f docker-compose.ci.yaml up -d --build
```

`SERVER_IP` binds registry port `5000` to the private server address. The
canonical Wiretrap values are `SERVER_IP=192.168.1.242` and
`REGISTRY=192.168.1.242:5000`;
`JENKINS_BIND_ADDRESS`, `JENKINS_HTTP_PORT` and `JENKINS_URL` control the UI.
The Jenkins administrator password is consumed through a Docker secret and is
never committed or placed in container environment variables. The controller
does not hold a GitHub write token or a Kubernetes credential. It runs as the
image's non-root `jenkins` user and talks over mutual TLS to a dedicated
privileged Docker-in-Docker engine. Treat that engine as a
root-equivalent build boundary and never expose its network or Jenkins to the
public internet.

Jenkins publication and production Kubernetes use the same externally
reachable registry authority, `192.168.1.242:5000`. The pipeline compares the
controller's `CI_REGISTRY` with the production Kustomize image contract before
running the test matrix and fails closed if the value is absent or stale.
Compose derives `CI_REGISTRY` from `SERVER_IP`; changing `.env` or the Compose
environment does not update an existing controller container. With no build
running, confirm the rendered Jenkins environment and recreate only the
controller:

```bash
docker compose -f docker-compose.ci.yaml config
docker compose -f docker-compose.ci.yaml up -d --no-deps --force-recreate jenkins
docker compose -f docker-compose.ci.yaml ps jenkins
docker compose -f docker-compose.ci.yaml exec jenkins printenv CI_REGISTRY
```

The final command must print `192.168.1.242:5000`. This recreation preserves
the registry, Docker-in-Docker engine, `jenkins-home` volume, and Kubernetes
desired state. After the controller is healthy, retry the failed pipeline; its
Buildx preflight will replace a builder whose insecure-registry configuration
does not match the external authority.

If the registry uses plain HTTP, configure every Kubernetes node runtime to
trust the exact `SERVER_IP:5000` authority, then verify a CRI pull. Keep port
`5000` behind a host firewall. Use TLS and authentication when the network is
shared or untrusted.

## Environment-aware Kubernetes publication

```bash
export TAG="$(git rev-parse --short HEAD)"
make publish ENV=prod REGISTRY_PLAIN_HTTP=1
```

Registry publishing uses HTTPS by default. Set `REGISTRY_PLAIN_HTTP=1`
explicitly only for an isolated local HTTP registry whose host and port are
trusted by every builder and Kubernetes node runtime. `PLATFORM` defaults to
`linux/amd64`; override it only when the target architecture differs.

`make publish` defaults to `ENV=prod`. It validates the owning app-stack or
data-plane Kustomization, then publishes the eight
Kubernetes-deployed first-party images to the exact repositories configured
there. It pushes `$TAG` and `latest`, reads the pushed manifest digest from
Buildx metadata, and reports either `MATCH` or `UNPINNED` against the selected
Kustomize pin. `UNPINNED` is a successful publication result; the report prints
the exact `make bump-digest-<service> ENV=<env> DIGEST=<digest>` command for the
separate deliberate Git change. `REGISTRY` never determines deployment identity
for this target.

Kubernetes pulls the committed `repository@sha256:...` reference. Registry
tags such as `$TAG` and `latest` are publication and discovery handles only;
moving either tag does not deploy or promote an image.

## Jenkins and component publication

The existing `make publish-all REGISTRY=...` interface and all
`publish-<service>` component targets remain registry-directed for Jenkins and
local workflows:

```bash
make publish-all REGISTRY=10.0.0.10:5000 REGISTRY_PLAIN_HTTP=1
```

First-party publish targets are:

| Target | Image |
|---|---|
| `publish-ssl-proxy` | `$REGISTRY/ssl-proxy:$TAG` |
| `publish-java-coordinator` | `$REGISTRY/java-coordinator:$TAG` |
| `publish-atheros-sensor` | `$REGISTRY/atheros-sensor:$TAG` |
| `publish-atheros-search` | `$REGISTRY/atheros-search:$TAG` |
| `publish-wg-key-rotator` | `$REGISTRY/wg-key-rotator:$TAG` |
| `publish-atheros-search-ui` | `$REGISTRY/atheros-search-ui:$TAG` |
| `publish-schema-migrator-backend` | `$REGISTRY/schema-migrator-backend:$TAG` |
| `publish-schema-migrator-ui` | `$REGISTRY/schema-migrator-ui:$TAG` |
| `publish-postgres-runtime-schema` | `$REGISTRY/postgres-runtime-schema:$TAG` |

The deployment identity `java-coordinator` is the Scala Octopus service. The
former standalone vec-worker is retired. Third-party images are not mirrored by
the root Makefile. The Compose-only `wg-key-rotator` remains part of
`publish-all`; it is intentionally excluded from environment-aware
`make publish` because it has no Kubernetes image contract.

Octopus publication is fail-closed. Before `publish-java-coordinator` can build
or push, the parent checkout and `services/octopus` worktree must both be clean,
and the checked-out Octopus commit must exactly equal the parent's gitlink. The
image build rejects assembled JARs containing the retired cutover package,
`CutoverConfig`, cutover verifier classes, or the obsolete replication-factor
and mandatory-TLS validation. The runtime image records the parent revision in
`org.opencontainers.image.revision` and the submodule revision in
`io.ssl-proxy.octopus.revision`.

Inspect a locally loaded candidate before accepting its digest:

```bash
make check-java-coordinator-image IMAGE=ssl-proxy-local/java-coordinator:$TAG
```

The same clean source-integrity check runs before either dev or production
`bump-digest-java-coordinator`; a digest cannot be promoted from an unrelated,
dirty, or mis-pinned checkout.

## UI API base

For a standalone static UI build, set a reachable API origin:

```bash
make publish-atheros-search-ui \
  REGISTRY=10.0.0.10:5000 \
  ATHEROS_SEARCH_UI_API_BASE=http://10.0.0.10:8080
```

The Kubernetes UI uses same-origin nginx proxying for `/v1`; the default API
base is therefore empty.

Publishing updates the registry's commit tag and `latest` channel without
changing Kubernetes desired state. Use the digest and bump command printed by
`make publish ENV=prod`, then validate the local dev render. Production receives
only reviewed digests copied from accepted dev desired state.

The Jenkins `ssl-proxy-images` job polls `main`, initializes the pinned
submodules and shared Buildx builder, validates the repository, then publishes
the eight Kubernetes image contracts with bounded concurrency. Its final
console section and archived `artifacts/bump-digest-commands.txt` contain only
the manual production bump commands needed for digests that differ from the
current pins. Jenkins never changes Git or Kubernetes. Jenkins publication and
Kubernetes pulls both use the private server authority declared by the
production image contract.

## Retention and garbage collection

The registry allows manifest deletion so storage can be reclaimed, but cleanup
is never automatic. The retention planner protects every digest pinned under
`cyber-stack/matrix/`, every digest used by a live pod, the `latest` target and
the newest retained window for each repository. Manifests with unknown creation
timestamps are kept rather than guessed about.

After adding or changing the registry service configuration, recreate only the
registry container so manifest deletion is enabled without requiring the
unrelated Jenkins environment:

```bash
make registry-recreate REGISTRY=192.168.1.242:5000
```

The target preserves the named registry data volume and verifies that the
recreated process received `REGISTRY_STORAGE_DELETE_ENABLED=true`.

Run the read-only plan first:

```bash
make registry-clean-plan \
  REGISTRY=192.168.1.242:5000 \
  REGISTRY_PLAIN_HTTP=1 \
  REGISTRY_KEEP_RECENT=12
```

The apply step requires an HTTPS registry, a reachable live cluster, and a
working pod inventory so the script can distinguish live digests from removable
ones. Ensure a Kubernetes context is active (the `kube-context-check`
prerequisite enforces this), or pass one explicitly. Plain HTTP is supported
for read-only planning only.

```bash
make registry-clean \
  REGISTRY=registry.example.internal:5000 \
  REGISTRY_KEEP_RECENT=12 \
  KUBE_CONTEXT=<context> \
  REGISTRY_CLEAN_CONFIRM=DELETE-UNPINNED-MANIFESTS
```

Manifest deletion does not immediately release filesystem blocks. Run offline
garbage collection only after publication is idle; the target always restarts
the registry even when garbage collection fails:

```bash
make registry-gc REGISTRY_GC_CONFIRM=GC-REGISTRY-BLOBS
```

The garbage collector intentionally omits `--delete-untagged`. A digest-pinned
release can remain pullable without a tag, so deleting all untagged manifests
would violate the Git image contract. Re-run `make stack-health` and prove a CRI
pull after cleanup.

## Verify

```bash
curl -fsS http://10.0.0.10:5000/v2/
docker buildx inspect
make stack-health
make stack-health
```

`stack-health` is read-only. It reports the resolved context and namespace,
renders the canonical Kustomize sources, compares desired and live image
references/runtime IDs, lists required platform object and key presence without
values, and includes workload health and recent warning events. Production also reports the three
Argo Applications; dev deliberately skips that controller query. An
unreachable registry tag endpoint is `UNKNOWN`, not an image-drift result.
Registry reachability proves only distribution; application readiness still
follows the [operations runbook](runbook.md).
