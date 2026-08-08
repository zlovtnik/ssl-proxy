# Local Registry Image Workflow

This workflow publishes Linux images from a development host to the registry
used by Kubernetes nodes and Argo CD Image Updater. Kubernetes management is
documented in the [GitOps guide](../cyber-stack/README.md).

## Run a LAN registry

Bind an unauthenticated development registry to a private address, never every
interface:

```bash
docker run -d \
  --name registry \
  --restart=always \
  -p 10.0.0.10:5000:5000 \
  registry:2
```

Replace `10.0.0.10` with the actual private server address. If the registry
uses plain HTTP, configure both Docker daemons and every Kubernetes node
runtime to trust that exact host and port. Configure the node runtime outside
the root Makefile, then verify a CRI pull. Keep port `5000` behind a host
firewall. Use TLS and authentication when the network is shared or untrusted.

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
Image Updater resolves `latest` to an immutable digest and opens the dev pull
request. Production receives only reviewed digests copied from dev.

## Verify

```bash
curl -fsS http://10.0.0.10:5000/v2/
docker buildx inspect
kubectl get applications.argoproj.io -n argocd
kubectl get imageupdaters.argocd-image-updater.argoproj.io -n argocd
kubectl get pods -A
```

Also confirm the registry is unreachable from the public interface and that
deployed image IDs match the intended build. Registry reachability proves only
distribution; application readiness still follows the
[operations runbook](runbook.md).
