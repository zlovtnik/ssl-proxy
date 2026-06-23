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

Restart Docker after editing `/etc/docker/daemon.json`.

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

For local development builds, opt into the build override explicitly:

```bash
REGISTRY=local IMAGE_TAG=dev \
  docker compose -f docker-compose.yaml -f docker-compose.build.yaml up -d --build
```
