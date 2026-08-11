# Local Registry Image Workflow

This workflow publishes Linux images from a development host to the registry
used by local and production Kubernetes nodes. Kubernetes management is
documented in the [GitOps guide](../cyber-stack/README.md).

## Local development CI and registry

The dedicated private CI stack runs the registry, Jenkins controller and its
isolated Docker build engine. Create the Jenkins administrator password as a
local secret, set the concrete server address in `.env`, and start the stack:

```bash
umask 077
openssl rand -base64 32 > secrets/jenkins-admin-password
docker compose -f docker-compose.ci.yaml up -d --build
```

`SERVER_IP` binds registry port `5000` to the private server address;
`JENKINS_BIND_ADDRESS`, `JENKINS_HTTP_PORT` and `JENKINS_URL` control the UI.
The Jenkins administrator password is consumed through a Docker secret and is
never committed or placed in container environment variables. The controller
runs as the image's non-root `jenkins` user and talks over mutual TLS to a
dedicated privileged Docker-in-Docker engine. Treat that engine as a
root-equivalent build boundary and never expose its network or Jenkins to the
public internet.

If the registry uses plain HTTP, configure every Kubernetes node runtime to
trust the exact `SERVER_IP:5000` authority, then verify a CRI pull. Keep port
`5000` behind a host firewall. Use TLS and authentication when the network is
shared or untrusted.

## Build configuration

```bash
export REGISTRY=10.0.0.10:5000
export TAG="$(git rev-parse --short HEAD)"
make publish-all REGISTRY_PLAIN_HTTP=1
```

Registry publishing uses HTTPS by default. Set `REGISTRY_PLAIN_HTTP=1`
explicitly only for an isolated local HTTP registry whose host and port are
trusted by every builder and Kubernetes node runtime. `PLATFORM` defaults to
`linux/amd64`; override it only when the target architecture differs.

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
| `publish-tidb-runtime-schema` | `$REGISTRY/tidb-runtime-schema:$TAG` |

The deployment identity `java-coordinator` is the Scala Octopus service. The
former standalone vec-worker is retired. Third-party images are not mirrored by
the root Makefile.

## UI API base

For a standalone static UI build, set a reachable API origin:

```bash
make publish-atheros-search-ui \
  REGISTRY=10.0.0.10:5000 \
  ATHEROS_SEARCH_UI_API_BASE=http://10.0.0.10:8080
```

The Kubernetes UI uses same-origin nginx proxying for `/v1`; the default API
base is therefore empty.

## Local development

Docker Compose may consume locally built images only as a development test
harness:

```bash
REGISTRY=local IMAGE_TAG=dev \
  docker compose -f docker-compose.yaml -f docker-compose.build.yaml up -d --build
```

Publishing updates the registry's immutable commit tag and `latest` channel.
Resolve the immutable digest, record it with
`make bump-digest-<service> ENV=dev DIGEST=sha256:<digest>`, and validate the
local dev render. Production receives only reviewed digests copied from dev.

The Jenkins `ssl-proxy-images` job polls `main` and accepts GitHub push events,
initializes the pinned submodules and shared Buildx builder, then publishes the
same target set as `make publish-all` in independently retried branches.
Documentation and GitOps validation run alongside publication and still fail
the overall build without cancelling successful image pushes. Jenkins uses the
registry's internal Compose name while Kubernetes uses the private server
address; both names reach the same registry storage.

## Verify

```bash
curl -fsS http://10.0.0.10:5000/v2/
docker buildx inspect
kubectl get applications.argoproj.io -n argocd
kubectl get pods -A
```

Also confirm the registry is unreachable from the public interface and that
deployed image IDs match the intended build. Registry reachability proves only
distribution; application readiness still follows the
[operations runbook](runbook.md).
