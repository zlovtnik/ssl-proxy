# Local development with Docker Compose

The root [docker-compose.yaml](../docker-compose.yaml) runs the transparent
proxy and BoringTun VPN, PostgreSQL with pgvector, a single Redpanda broker,
the Rust Octopus ingestion/planning/load/result pipeline, and Atheros Search.
One-shot services generate credentials and VPN profiles, provision the canonical database
manifests, and initialize the existing topic manifest. Startup waits for these
jobs and dependency health checks.

`make local-up` and `make local-egress-up` confirm that Octopus is running
`/app/octopus`. If the image build fails, Docker can leave the previous
coordinator running. Check the Make output for the build error before relying
on logs from the existing container.

Use a current Docker Engine or Docker Desktop with Compose v2.20 or newer,
Linux containers, outbound Internet access for builds and DNS forwarding,
and at least 8 GB of Docker memory. The VPN needs `/dev/net/tun` and
`NET_ADMIN` in Docker's Linux host/VM; rootless Docker is not supported.
The initial image builds can take several minutes.

From the repository root, with submodules initialized:

```bash
git submodule update --init --recursive
docker compose -f docker-compose.yaml config --quiet
make local-up
make local-check
docker compose -f docker-compose.yaml ps -a
```

No host `.env`, pre-existing keys, external database, registry, or Kubernetes
resources are required. All generated material stays in this Compose project's
named volumes. Existing local `.env` files are left untouched; this stack only
uses variables prefixed `LOCAL_`.

| Host endpoint | Purpose |
| --- | --- |
| `127.0.0.1:51820/udp` | Standard WireGuard VPN; override the bind address for remote clients |
| `http://127.0.0.1:9098/ready` | Proxy readiness; `/health` and `/metrics` also available |
| `http://127.0.0.1:8081/ready` | Octopus readiness; `/live` and `/metrics` also available |
| `http://127.0.0.1:8082/readyz` | Atheros Search readiness; `/v1/search` accepts authenticated sparse queries |
| `127.0.0.1:5432` | PostgreSQL database `sync` with generated credentials and local TLS |
| `127.0.0.1:19092` | Kafka listener for host tools; containers use `redpanda:9092` |
| `http://127.0.0.1:9644` | Redpanda admin API |

The proxy's admin API remains inside its container on `127.0.0.1:3002`.
TCP traffic to ports 80/443 arriving through the VPN passes through policy
enforcement. DNS uses the tunnel's CoreDNS listener. No separate client HTTP
proxy setting is needed. WireGuard packet obfuscation is disabled, matching
the standard WireGuard client profiles generated here.

## Connect a VPN client

For a client on another machine, set the Docker host's reachable LAN IP or DNS
name **before starting the stack**:

```bash
export LOCAL_VPN_ENDPOINT=192.168.1.100
export LOCAL_VPN_BIND_ADDRESS=192.168.1.100
docker compose -f docker-compose.yaml up -d --build --wait --wait-timeout 300
```

The default endpoint `127.0.0.1` reaches a server on the Docker host. A
full-tunnel client on that same Mac also needs the Mac egress setup below.
Allow UDP 51820 through the host firewall for remote clients. Export one generated
profile to a private directory and import it into a WireGuard client:

```bash
mkdir -p "$HOME/.config/ssl-proxy-local"
chmod 700 "$HOME/.config/ssl-proxy-local"
docker compose -f docker-compose.yaml cp ssl-proxy:/config/peer1/peer1.conf "$HOME/.config/ssl-proxy-local/peer1.conf"
chmod 600 "$HOME/.config/ssl-proxy-local/peer1.conf"
```

These profiles contain private keys; keep them outside version control. Use
`peer2/peer2.conf` for a second device. Profiles tunnel IPv4; configure the
client's IPv6 policy separately if it must prevent IPv6 traffic outside the VPN.
To change the endpoint or published VPN port later, keep the same environment
values on subsequent commands and rerun the profile generator:

```bash
docker compose -f docker-compose.yaml run --rm --no-deps proxy-init
docker compose -f docker-compose.yaml up -d --wait
```

Export/import the updated client profile. Existing private and preshared keys
are preserved.

## Full tunnel on the same Mac

Docker Desktop opens container connections through the Mac's networking
backend. If the same Mac installs a full-tunnel WireGuard default route, the
VPN server's upstream connections enter its own tunnel again. Handshakes still
work, but DNS and web connections time out. Changing DNS alone does not fix
this loop. See [Docker Desktop networking](https://docs.docker.com/desktop/features/networking/).

The [Mac egress helper](../scripts/local-mac-egress.py) uses Python 3's standard
library on the Mac and binds Internet sockets to the physical interface
(usually `en0`, including an iPhone Wi-Fi hotspot). A small Rust reverse relay
shares the proxy container's network namespace. The Mac initiates authenticated
connections through Docker's published loopback port 18081; Docker never needs
to connect back to the Mac. Proxy policy still applies, and CoreDNS retains
end-to-end verified DNS-over-TLS.

`UPSTREAM_PROXY` must point to a separate HTTP CONNECT proxy. Operators must
ensure its host and port cannot route back to this service's `PROXY_PORT` or
`TPROXY_PORT`, including through loopback addresses, local interface addresses,
DNS aliases, or published Docker ports. Both service listeners bind `0.0.0.0`.
The upstream dial helper validates URL syntax but has no listener configuration
or deployment routing information, so it does not detect these loops at startup.
The Mac egress override uses the separate relay on port 18080.

Start or update the local stack with the [Mac egress override](../docker-compose.mac-egress.yaml).
Run the helper in its own terminal and keep it running:

```bash
make local-egress-up
make local-egress
```

Use `make local-egress LOCAL_MAC_EGRESS_INTERFACE=en7` to select the physical
interface when it differs from the default `en0`. The target reads the
published relay port from Compose and removes its private temporary token
file when the helper exits. Enable WireGuard manually, then verify the full
path from a second terminal:

```bash
make local-egress-check
```

The check verifies the proxy readiness endpoint, both PostgreSQL schema
checksums, a sparse Search request, a synthetic Redpanda message with durable
ingestion evidence and a committed consumer offset, and a fresh PostgreSQL
proxy event after DNS and HTTPS requests through WireGuard. For manual Compose
commands in this mode, include both `-f` arguments.

The local VPN proxy, WireGuard, Mac egress bridge, and Mac helper default to
`info` logging. Set `LOCAL_LOG_LEVEL=debug` on both Make commands for verbose
proxy, bridge, and helper logs. Set `LOCAL_WG_LOG_LEVEL=debug` for verbose
WireGuard logs. Set `LOCAL_COREDNS_DEBUG=false` to disable CoreDNS query logs,
`LOCAL_POSTGRES_LOG_LEVEL=warning` for normal PostgreSQL verbosity, or
`LOCAL_REDPANDA_LOG_LEVEL=debug` for broker diagnostics.
The relay logs worker availability, assignment time, stream byte counts, and
the stage where a connection failed. The Mac helper starts 96 CONNECT workers
and reserves 24 separate workers for DNS-over-TLS, so HTTPS connections cannot
take the DNS slots. After updating the bridge, rebuild it with `make local-egress-up`
and restart any running Mac helper to use the updated registration protocol.
With WireGuard disconnected, you can
check relay HTTPS from the proxy container while the Mac helper is running:

```bash
docker compose -f docker-compose.yaml -f docker-compose.mac-egress.yaml exec -T ssl-proxy \
  curl -4fsS --noproxy '' --proxy http://127.0.0.1:18080 https://example.com/ -o /dev/null
```

This supports browser HTTP/HTTPS and DNS over the IPv4 VPN. Other forwarded
UDP protocols and IPv6 egress are outside the helper's scope. Keep `::/0` in
an IPv4-only client profile if IPv6 should remain blocked. When the helper
stops or the physical interface is unavailable, configured proxy connections
fail without falling back to the looping route. Restart the helper with the
new interface if `en0` changes. Changes to the hotspot's IP do not require
rebuilding or changing the client profile. Container readiness checks do not
prove that the host helper is connected; verify browsing after starting it.

To return to a separate-device client, stop the helper and reverse bridge,
then restore the base configuration:

```bash
docker compose -f docker-compose.yaml -f docker-compose.mac-egress.yaml stop mac-egress-bridge
docker compose -f docker-compose.yaml run --rm --no-deps proxy-init
docker compose -f docker-compose.yaml up -d --no-build --wait ssl-proxy
```

## Inspect and operate

```bash
curl -fsS http://127.0.0.1:9098/ready
curl -fsS http://127.0.0.1:8081/ready
curl -fsS http://127.0.0.1:8082/readyz
docker compose -f docker-compose.yaml logs --tail=100 ssl-proxy octopus atheros-search postgres-schema redpanda-init
docker compose -f docker-compose.yaml exec redpanda rpk topic list --brokers redpanda:9092
docker compose -f docker-compose.yaml exec postgres psql -U platform_admin -d sync -c 'TABLE octopus_core.schema_readiness'
```

PostgreSQL uses generated local CA/server certificates and isolated
`schema_owner`/`octopus_runtime` roles. The
[existing schema executor](../k8s/postgres-schema-executor/entrypoint.sh)
applies all four canonical domain manifests and grants over verified TLS.
Octopus reads the current Octopus manifest checksum from the checkout and
fails closed on schema drift. To apply new append-only manifests after a pull:

```bash
docker compose -f docker-compose.yaml build postgres-schema octopus
docker compose -f docker-compose.yaml run --rm postgres-schema
docker compose -f docker-compose.yaml up -d --build --wait
```

The proxy and Octopus share the durable proxy outbox; Octopus mounts it read
only. Both run as UID 0 locally because the VPN entrypoint manages networking
and outbox payload files are owner-only. Octopus still connects with its
restricted database role and only receives its own password and the CA.
The schema executor runs as UID 0 locally to read its generated password.
Database and broker host ports bind to loopback. Broker traffic inside the
local Docker network is plaintext.

Atheros Search runs with the embedding worker disabled. Its sparse API can query
existing search documents. This local coordinator runs the sync processors and
wireless consumers with derived Search projection processors disabled. MinIO
archiving, DQ workers, public stats, the wireless sensor, and external trace
exporting are outside this stack. Production configuration remains under
[cyber-stack](../cyber-stack/).

To switch a running Scala coordinator to a prebuilt native image, run
`python3 scripts/local_octopus_cutover.py --image IMAGE`. Add `--vpn` if the
stack uses the Mac egress override and WireGuard is active. The switch tags
the running Scala image and restores it if Rust readiness or Redpanda ingestion
fails. For a manual rollback, use the
[Scala override](../docker-compose.octopus-scala.yaml) and set
`LOCAL_OCTOPUS_SCALA_IMAGE` to the retained image tag:

```bash
docker compose -f docker-compose.yaml -f docker-compose.octopus-scala.yaml up -d --no-build --pull never --no-deps --wait octopus
```

Override conflicting host ports with `LOCAL_POSTGRES_PORT`, `LOCAL_KAFKA_PORT`,
`LOCAL_REDPANDA_ADMIN_PORT`, `LOCAL_OCTOPUS_PORT`,
`LOCAL_PROXY_METRICS_PORT`, `LOCAL_ATHEROS_SEARCH_PORT`, or `LOCAL_VPN_PORT`. `LOCAL_VPN_BIND_ADDRESS`
controls the UDP bind address. To record image provenance instead of the
default `local` labels, set `LOCAL_PARENT_COMMIT` and `LOCAL_OCTOPUS_COMMIT`
before building.

Stop containers while retaining database, broker, VPN keys and outbox state:

```bash
docker compose -f docker-compose.yaml down
```

For an intentional **destructive local reset**, `docker compose -f
docker-compose.yaml down --volumes` deletes all this project's stored data and
keys. Do not remove the credentials volume while retaining the database
volume: that would replace passwords without updating PostgreSQL.
Changing `-p` creates a separate project with separate keys and data; also
change host ports if running two projects simultaneously.

If only one of `ca.key` or `ca.crt` exists, the material initializer fails
rather than overwriting the remaining CA file. To recover this local setup,
stop the stack, delete its TLS volume, and start it again so the CA and server
certificate are regenerated. Retain the credentials and database volumes:

```bash
docker compose -f docker-compose.yaml down
docker volume rm ssl-proxy-local_postgres-tls
docker compose -f docker-compose.yaml up -d --build --wait --wait-timeout 300
```

Use your project's actual volume name if you set `-p`, and include the Mac
egress override on the Compose commands when using the same-Mac setup.
