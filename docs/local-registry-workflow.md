# Local Registry Image Workflow

This workflow is for an arm64 development machine publishing linux/amd64 images
to a local Docker registry that the amd64 server pulls from. The server compose
file consumes prebuilt images; it does not build application images.

## Registry

Run the registry on the server or on a shared LAN host reachable by both the
developer machine and the server. Bind it to the LAN address, not to every
interface:

```bash
docker run -d \
  --name registry \
  --restart=always \
  -p <server-local-ip>:5000:5000 \
  registry:2
```

If the registry is not using TLS, add it as an insecure registry on both the
developer machine and the server:

```json
{ "insecure-registries": ["<server-local-ip>:5000"] }
```

On Docker Desktop, edit Settings -> Docker Engine and apply/restart Docker. On
Linux Docker Engine, edit `/etc/docker/daemon.json` and restart Docker.

This host daemon setting is separate from the Buildx builder setting below. If
it is missing, `docker compose pull` fails with `http: server gave HTTP response
to HTTPS client` even when `make registry-build-all` can push images.

Kubernetes nodes use containerd rather than the Docker daemon. Configure every
node that pulls the canonical `REGISTRY/...` image names separately. For the
single-node server, run once from the repository checkout on that node:

```bash
make configure-containerd-registry REGISTRY=<server-local-ip>:5000
```

The command writes a containerd 2.x CRI `config_path` drop-in and a pull-only
`/etc/containerd/certs.d/<registry>/hosts.toml`, restarts containerd only when
the files change, and verifies a CRI pull. This follows containerd's supported
[registry host configuration](https://github.com/containerd/containerd/blob/main/docs/hosts.md).
It intentionally keeps `<server-local-ip>:5000` as the image registry; it does
not rewrite Kubernetes images to `localhost`.

The Makefile also configures the container-based buildx builder for plain HTTP.
`REGISTRY_PLAIN_HTTP=auto` is the default and treats `localhost`, `127.*`,
`10.*`, `172.16.*`-`172.31.*`, and `192.168.*` registries as HTTP. For a
plain-HTTP registry outside those ranges, set `REGISTRY_PLAIN_HTTP=1`. For a
private-IP registry that really does use HTTPS, set `REGISTRY_PLAIN_HTTP=0`.

Keep port 5000 off the public interface:

```bash
# Should succeed from another machine on the LAN.
curl http://<server-local-ip>:5000/v2/

# Should time out or refuse from outside the LAN.
curl http://<public-ip>:5000/v2/

# ufw
ufw deny in on <public-interface> to any port 5000

# or iptables
iptables -I INPUT -i <public-interface> -p tcp --dport 5000 -j DROP
```

Find the WAN-facing NIC with `ip link`; common names are `eth0` or `ens3`.
No registry auth is configured for this controlled-LAN setup. If the LAN is
shared or untrusted, put nginx with TLS and basic auth in front of the registry.

## Images

Set the registry at runtime rather than committing an IP address:

```bash
export REGISTRY=<server-local-ip>:5000
export IMAGE_TAG=latest
```

Image names:

| Component | Image |
|---|---|
| ssl-proxy, wg-udp-frontdoor, ssl-proxy-next | `$REGISTRY/ssl-proxy:$IMAGE_TAG` |
| java-coordinator | `$REGISTRY/java-coordinator:$IMAGE_TAG` |
| integration-console roles | `$REGISTRY/integration-console:$IMAGE_TAG` |
| atheros-sensor | `$REGISTRY/atheros-sensor:$IMAGE_TAG` |
| atheros-search | `$REGISTRY/atheros-search:$IMAGE_TAG` |
| wg-key-rotator | `$REGISTRY/wg-key-rotator:$IMAGE_TAG` |
| postgres extension image | `$REGISTRY/ssl-proxy-postgres:$IMAGE_TAG` |
| atheros-search-ui | `$REGISTRY/atheros-search-ui:$IMAGE_TAG` |
| schema-migrator backend | `$REGISTRY/schema-migrator-backend:$IMAGE_TAG` |
| schema-migrator UI | `$REGISTRY/schema-migrator-ui:$IMAGE_TAG` |

`registry-mirror-all` also mirrors the exact Schema Migrator runtime tags used
by Helm: `mongo:7.0.22`, `quay.io/keycloak/keycloak:26.2.5`,
`traefik:v3.6.2`, `postgres:16.9-alpine3.21`, and `busybox:1.37.0`.

`vec-worker` is pending in this checkout. `make registry-build-all` skips it
while `services/vec-worker/Dockerfile` is absent; `make registry-build-vec-worker`
fails clearly until that service exists.

## Build And Push

Build from the development machine for the server architecture:

```bash
make registry-buildx
make registry-build-all REGISTRY=<server-local-ip>:5000
```

For non-private plain-HTTP registries:

```bash
make registry-build-all REGISTRY=<registry-host>:5000 REGISTRY_PLAIN_HTTP=1
```

`TAG` defaults to `git rev-parse --short HEAD`, and every image is also tagged
`latest`. Override the platform only if the server architecture changes:

```bash
make registry-build-all REGISTRY=<server-local-ip>:5000 TAG=latest PLATFORM=linux/amd64
```

The standalone `atheros-search-ui` image bakes the API base URL into the static
Vite build:

```bash
make registry-build-atheros-search-ui \
  REGISTRY=<server-local-ip>:5000 \
  ATHEROS_SEARCH_UI_API_BASE=http://<server-local-ip>:8080
```

## Deploy

On the server:

```bash
export REGISTRY=<server-local-ip>:5000
export IMAGE_TAG=latest
docker compose pull
docker compose up -d
```

Or from the development machine:

```bash
make deploy DEPLOY_HOST=user@<server-local-ip> DEPLOY_PATH=/path/to/ssl-proxy
```

For Kubernetes, `make up-ready` performs a short node-runtime pull probe after
publishing images and before starting Helm. A missing containerd registry
configuration therefore fails with the relevant pod event instead of appearing
to hang during Helm readiness waiting.

For local development builds, opt into the build override explicitly:

```bash
REGISTRY=local IMAGE_TAG=dev \
  docker compose -f docker-compose.yaml -f docker-compose.build.yaml up -d --build
```
