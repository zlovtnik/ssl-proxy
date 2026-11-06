# Ubuntu host hardening

The target policy allows only WireGuard UDP 51820 as a new inbound WAN
service. All inbound WAN TCP is blocked, including SSH, HTTP, HTTPS,
Kubernetes API, Kubelet, NodePorts and container-published ports. Apply the
policy to IPv4 and IPv6 at the router and host. Preserve established reply
traffic for outbound Cloudflare Tunnel connections. This policy reduces
exposure; it does not guarantee that the host cannot be discovered or scanned.

## Current evidence and prerequisites

Read-only inspection of `wiretrap` found private addresses 192.168.1.221 and
192.168.1.242 on enp2s0f0, with a router at 192.168.1.1. SSH 22, Kubernetes
API 6443, Kubelet 10250, Samba 139/445 and Erlang 4369 had wildcard TCP
listeners. No host WireGuard interface or UDP 51820 socket was observed.
These bindings do not prove WAN reachability. Firewall rules and router
forwarding remain unverified because privileged inspection was unavailable.

Before changing access, establish whether the proxy's pod-based WireGuard
endpoint provides host administration or only proxy traffic. Do not bind SSH
to the illustrative 10.8.0.1 address unless that address exists on the host.
Keep a tested private administration path and console recovery available.

## Platform configuration requirements

- Remove router TCP forwarding and automatic UPnP mappings. Allow only UDP
  51820 to the actual WireGuard endpoint; remove any legacy UDP 443 forwarding.
- Enforce the WAN policy in both host INPUT and forwarded container traffic.
  Review Docker NAT and Kubernetes service/NodePort handling; an INPUT-only
  rule does not cover them. Do not flush Kubernetes-managed firewall chains.
- Restrict SSH to loopback and an actual WireGuard or private host address.
  Inspect `ssh.socket` as well as effective daemon configuration: socket
  activation can control the listener independently of the daemon. Validate
  the configuration and test a second private session before ending access.
- Configure K3s through its platform configuration owner: restrict API server
  binding to the private host address, verify Kubelet anonymous authentication
  is disabled and Webhook authorization is enabled, and firewall both ports.
  Check effective configuration rather than assuming a standalone Kubelet
  configuration file is used by K3s. Node-to-node CNI traffic stays private.
- Keep cluster configuration changes under the GitOps ownership described in
  the [Kubernetes guide](../cyber-stack/README.md).

## Public and private routing

The [production tunnel configuration](../cyber-stack/matrix/prod/patches/cloudflare-edge.yaml)
targets ClusterIP Traefik over verified TLS. Its public routes allow middleware
realm authentication, Keycloak resources and selected application API paths.
Keycloak admin, master realm authentication and management endpoints have no
public route. A 404 for unmatched admin paths is an acceptable denial.

Private Keycloak administration needs a separate private hostname/listener,
WireGuard reachability, a source restriction using the actual VPN subnet,
and Keycloak authentication/MFA. Include the admin console's master realm login
and static assets on that private route. Keep dashboards, SSH and Kubernetes
API private; do not add an admin route to the public tunnel.

Traefik currently trusts no forwarded headers. Before preserving client IPs,
identify the immediate tunnel proxy source addresses and restrict origin access
to those proxies with an enforcing network policy. Trust only those immediate
peers, never all pod or Internet addresses. Cloudflare public IP ranges alone
do not describe the in-cluster tunnel connection. Verify spoofed forwarding
headers cannot affect access controls and that logs record the external client.
See the [Traefik forwarding rules](https://doc.traefik.io/traefik/reference/install-configuration/entrypoints/)
and [Keycloak reverse proxy guidance](https://www.keycloak.org/server/reverseproxy).

## Read-only verification

Run the [host audit](../scripts/audit-host-security.sh) on the server:

```bash
sudo bash scripts/audit-host-security.sh
```

The report includes IPv4/IPv6 listeners, SSH socket activation, firewall/NAT
rules and host tunnel process evidence. Missing tools or privileges are marked
UNVERIFIED. Its exit status is not a security compliance verdict. Check tunnel
pods and effective Kubelet configuration separately with read-only diagnostics.

From an independent Internet connection, scan all TCP ports on the origin's
public IPv4 and each routed public IPv6 address, rather than the Cloudflare
hostname. No TCP port should be open. Verify a WireGuard handshake over UDP
51820, private administrative access over the VPN, public OIDC login, and
denial of admin/master realm/metrics routes through the public tunnel.
Record router/firewall evidence alongside scan results before declaring the
policy enforced.
