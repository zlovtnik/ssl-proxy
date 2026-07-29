# Local Registry Image Workflow

This workflow publishes Linux images from a development host to a registry
reachable by the target server or Kubernetes nodes. The deployment paths are
summarized in the [root README](../README.md).

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
runtime to trust that exact host and port. For the repository's single-node
containerd workflow:

```bash
make configure-containerd-registry REGISTRY=10.0.0.10:5000
```

The command configures a pull-only containerd registry host and verifies a CRI
pull. Keep port `5000` behind a host firewall. Use TLS and authentication when
the network is shared or untrusted.

## Build configuration

```bash
export REGISTRY=10.0.0.10:5000
export IMAGE_TAG=latest
make registry-buildx
make registry-build-all
```

`REGISTRY_PLAIN_HTTP=auto` recognizes loopback and RFC1918 IPv4 registries.
Set it to `1` for another plain-HTTP host or `0` when a private address uses
HTTPS. `PLATFORM` defaults to `linux/amd64`; override it only when the target
architecture differs.

First-party build targets are:

| Target | Image |
|---|---|
| `ssl-proxy` | `$REGISTRY/ssl-proxy:$IMAGE_TAG` |
| `java-coordinator` | `$REGISTRY/java-coordinator:$IMAGE_TAG` |
| `atheros-sensor` | `$REGISTRY/atheros-sensor:$IMAGE_TAG` |
| `atheros-search` | `$REGISTRY/atheros-search:$IMAGE_TAG` |
| `wg-key-rotator` | `$REGISTRY/wg-key-rotator:$IMAGE_TAG` |
| `atheros-search-ui` | `$REGISTRY/atheros-search-ui:$IMAGE_TAG` |
| `schema-migrator-backend` | `$REGISTRY/schema-migrator-backend:$IMAGE_TAG` |
| `schema-migrator-ui` | `$REGISTRY/schema-migrator-ui:$IMAGE_TAG` |
| `tidb-runtime-schema` | `$REGISTRY/tidb-runtime-schema:$IMAGE_TAG` |

The deployment identity `java-coordinator` is the Scala Octopus service. The
former standalone vec-worker is retired; `make registry-build-vec-worker`
delegates to the Atheros Search image.

`make registry-mirror-all` mirrors the third-party images listed in the root
Makefile, including Redpanda, MinIO, Prometheus, Loki, Promtail, Jaeger, the OTel
Collector, Grafana, exporters, Keycloak, Traefik, BusyBox and TiDB. Review tags
before a production promotion; `latest` tags are compatibility defaults, not
immutable provenance.

## UI API base

For a standalone static UI build, set a reachable API origin:

```bash
make registry-build-atheros-search-ui \
  REGISTRY=10.0.0.10:5000 \
  ATHEROS_SEARCH_UI_API_BASE=http://10.0.0.10:8080
```

The Kubernetes UI uses same-origin nginx proxying for `/v1`; the normal
`make up-ready` path therefore builds with an empty API base.

## Deploy

Compose pull-only deployment:

```bash
REGISTRY=10.0.0.10:5000 IMAGE_TAG=latest docker compose pull
REGISTRY=10.0.0.10:5000 IMAGE_TAG=latest docker compose up -d
```

Local Compose builds are explicit:

```bash
REGISTRY=local IMAGE_TAG=dev \
  docker compose -f docker-compose.yaml -f docker-compose.build.yaml up -d --build
```

Kubernetes `make up-ready` publishes images, probes the node runtime and then
deploys the umbrella chart. The opt-in split path is
`make up-ready-stackctl`.

## Verify

```bash
curl -fsS http://10.0.0.10:5000/v2/
docker buildx inspect
make k8s-status
```

Also confirm the registry is unreachable from the public interface and that
deployed image IDs match the intended build. Registry reachability proves only
distribution; application readiness still follows the
[operations runbook](runbook.md).
