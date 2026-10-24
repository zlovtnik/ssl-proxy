# Plan 005 containment and DNS evidence

> **Status: BLOCKED.** Repository checks do not establish client OS containment
> or encrypted external DNS. Transport promotion remains blocked.

This is the execution record for [Plan 005](005-vpn-leak-containment-dns.md).
No production routing, firewall, resolver, Secret, or workload was changed.
The existing dirty index and submodule worktrees are preserved.

## Baseline and implementation contract

On 2026-10-23, HEAD was `f639c705`. The required
`git diff --stat f639c705..HEAD -- config/client config/peer1 config/peer2 config/templates tests/wireguard_template.rs config/coredns src/wg_shim_sections/runtime.rs`
returned no changes. `git status --short` showed the pre-existing modified
advisory index, Integration Console and Octopus submodules, and untracked plans
003 through 008. None of those unrelated changes are discarded.

Implementation order: define the evidence contract; build the isolated failure
harness and its validator; add persistent Linux containment, routing guidance
and template checks; run local checks and record unavailable OS/DNS evidence.
The bounded write scope is the client service/environment/peer examples,
the template test, the three new test/policy artifacts, this evidence document,
the plan and its index row. Rust resolver and server policy are read-only.

## Support and capture contract

| Profile | OS and client | Transport | Status | Missing evidence |
| --- | --- | --- | --- | --- |
| Disposable Linux namespaces | Record kernel/distribution and `wg --version` in each run | Kernel WG via loopback shim and real relay; direct WG control | BLOCKED | Administrator namespace access, equipped Linux environment and real packet captures |
| Actual Linux client | Distribution, kernel and WG client version pending | UDP obfuscation | PENDING | Device-specific startup, suspend/resume, interface changes, resolver selection and capture matrix |
| macOS | Observed Darwin 27.0.0 arm64; wireguard-tools v1.0.20260223 | No OS containment adapter in this scope | BLOCKED | OS policy adapter, actual WG client and packet matrix |
| Windows | OS and WG client version pending | No OS containment adapter in this scope | PENDING | OS policy adapter and packet matrix |
| iOS / Android | OS and WG client version pending | No OS containment adapter in this scope | PENDING | Platform VPN containment, resolver and network transition evidence |
| IPv6-only outer obfuscation | Any client | Existing relay uses IPv4 bind/backend | BLOCKED | Separately reviewed relay IPv6 support and matching server policy |
| Production relay CoreDNS | Effective image/configuration unknown | Configured DoT | BLOCKED | Effective configuration, authenticated upstream and failure captures |
| Rust proxy external DNS | Effective cluster/node forwarding unknown | System resolver through kube-dns | BLOCKED | External hop configuration, captures and failure validation |

No row is currently supported. A Linux namespace test is a repository fixture,
not certification of a distribution's network manager or a mobile VPN stack.
Plans [006](006-masque-connect-udp.md), [007](007-https-transport-fallback.md)
and [008](008-authenticated-transport-selection.md) must reuse this matrix.

Each run must identify the OS/version, WG tool/client version, binary hashes,
shim profile, physical and WG interfaces, exact candidate IP/port/protocol,
owned HTTP/UDP/DNS fixture endpoints, unique test DNS names, resolver selection,
external DNS forwarding chain, LAN policy and link bootstrap allowances.
Only synthetic fixture traffic may be captured. Never store WG private keys,
preshared/obfuscation keys, tokens, real browsing data or private packet bodies.
Keep generated ephemeral secrets in a private temporary directory and delete
them during cleanup. Capture metadata and known synthetic packets are evidence.

The fixture uses static addresses: no DHCP and no LAN exceptions. ARP is needed
for IPv4 neighbor discovery; IPv6 ND is restricted to the physical interface,
hop limit 255, code 0 and link scope. No unrestricted established-connection
allowance is permitted: pre-existing application sockets must also be contained.
DHCP, Router Solicitation and LAN access on a real device require explicit
reviewed rules and separate positive and negative tests; absence of a test is
not permission. IPv6 application egress must enter WG or be dropped.

Required per-scenario fields include `unexpected_application_packets`,
`unexpected_dns_packets`, `outer_route_uses_physical_interface`,
`protected_dns_verified` and `capture_valid`. Counts are nonnegative integers;
booleans must be actual booleans. Both interface captures must be nonempty,
readable, healthy, and include expected synthetic traffic on the selected path.
A fresh kernel WG handshake and successful application/DNS baseline are required.
During an intentional outage the generator must still run; tunnel packet
absence is acceptable only with valid baseline evidence and explicit expected
blocking. Known application and DNS leaks must be detected in separate positive
controls and the deliberately uncontained failure case. Blocked, missing,
malformed, empty or truncated results fail validation; they never mean zero leaks.

The required matrix covers startup before WG, reconnect, shim crash/restart,
WG removal, protected DNS outage/timeout, upstream certificate rejection,
sleep/resume, interface/network change, IPv4-only, IPv6-only, dual-stack and
forced outer UDP blocking, for each claimed OS/transport and permitted LAN rule.
Do not infer suspend or TLS certificate behavior from a namespace link toggle.

## Linux operator lifecycle

The [nftables example](../config/client/leak-containment-linux.nft.example)
is an operator-rendered reference, not an installer. Provision it before WG
activation, including at boot, using a separate privileged oneshot service named
`wg-client-containment.service`. The shim's
[unit](../config/client/wg-obfs-shim.service) requires that service and keeps an
empty capability set. Provision the account with a stable dedicated numeric UID;
applications must not share it. The UID is the socket owner, not the WG kernel
interface. Kernel direct WG needs a separately reviewed exact tuple exception
for its control fixture, never a general port exception in the shim profile.

Render all placeholders into a root-owned, mode 0600 file. Check with
`nft --check --file` inside the disposable namespace before applying there.
Never use `flush ruleset`: the example owns only table `inet wg_containment`.
Do not load it into a remote management host. The unit must fail if table/routing
provisioning fails. A generic running `nftables.service` is insufficient evidence
that this particular policy is active.

Startup has two stages: `wg-client-containment.service` loads the policy before
`network-pre.target`, without waiting for network availability or an interface.
Then `wg-client-routes.service` provisions candidate routes after networking and
the physical interface are ready. Both use `Type=oneshot`, `RemainAfterExit=yes`
and order before WG and the shim. Require and order both services before
`wg-quick@wg0.service` and `wg-obfs-shim.service` in local drop-ins. The
containment service must have no firewall-removing
`ExecStop`, no `PartOf`/`BindsTo` tying its lifetime to WG, and no `PostDown`
policy removal. Do not reload generic firewall services in a way that deletes
this table. Loading policy followed by routes can cause temporary unavailability,
which is preferable to a startup leak. Installation is incomplete until the
boot-time WG ordering and effective policy are checked on the target OS.

IPv4-only static reference unit bodies follow. Supply the root-owned rendered
policy, replace all interface/address/UID values, verify executable paths on the
target distribution, and first test them in the disposable namespace. These units
do not implement DHCP, endpoint refresh or a network-manager adapter. A real
boot profile stays blocked until those applicable lifecycle paths are validated.

```ini
# wg-client-containment.service
[Unit]
Description=Persistent client egress containment
DefaultDependencies=no
After=local-fs.target
Wants=network-pre.target
Before=network-pre.target wg-client-routes.service wg-obfs-shim.service wg-quick@wg0.service shutdown.target
Conflicts=shutdown.target

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStartPre=/usr/sbin/nft --check --file /etc/wireguard/leak-containment-linux.nft
ExecStart=/usr/sbin/nft --file /etc/wireguard/leak-containment-linux.nft

[Install]
WantedBy=multi-user.target
```

```ini
# wg-client-routes.service
[Unit]
Description=Client candidate routes after physical network configuration
Requires=wg-client-containment.service sys-subsystem-net-devices-eth0.device
Wants=network-online.target
After=wg-client-containment.service network-online.target sys-subsystem-net-devices-eth0.device
Before=wg-obfs-shim.service wg-quick@wg0.service

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/usr/sbin/ip -4 route replace unreachable default table 51819 metric 42760
ExecStart=/usr/sbin/ip -4 route replace 192.0.2.2/32 via 192.0.2.1 dev eth0 onlink table 51819
ExecStart=/usr/sbin/ip -4 rule add priority 90 to 192.0.2.2/32 lookup 51819

[Install]
WantedBy=multi-user.target
```

Enable both units. The physical network manager must honor `network-pre.target`
and require successful containment startup through a local dependency/drop-in;
ordering alone does not prevent networking after a policy-load failure.
Configure its wait-online service for `eth0` so that route setup waits for the
static address and gateway as well as device presence. A route-setup failure
leaves the earlier drop policy installed and prevents WG/shim startup.

First activation assumes this table and priority are unallocated. Do not restart
the oneshot to refresh inventory: repeated loads can retain rules or reset tuple
timeouts. A reviewed refresh operation must atomically replace just owned set
elements, bound by the original absolute expiry. Installation must also verify
the route lookup, firewall bytes, UID ownership and boot ordering before calling
the profile supported. An already active oneshot does not attest current policy
after another privileged firewall manager changes it.

Stopping/crashing WG, stopping/restarting the shim or rolling back a transport
must leave this table installed. Explicit operator disconnect is the only action
that may restore physical application egress; it needs local recovery access,
a deliberate policy decision and its own test. The fixture's namespace teardown
is safe because those interfaces and rules never exist on the management host.

### Candidate routes and DNS-free bootstrap

The current shim accepts numeric socket addresses. Provision every failover
candidate IP; WG's `Endpoint = 127.0.0.1:51821` cannot create remote exceptions.
Use a dedicated route table and destination rules with priority before WG's
rules. For example, inside the disposable client namespace, with an inventoried
unused table 51819, physical `eth0`, gateway `192.0.2.1` and relay `192.0.2.2`:

```sh
ip -4 route replace unreachable default table 51819 metric 42760
ip -4 route replace 192.0.2.2/32 via 192.0.2.1 dev eth0 onlink table 51819
ip -4 rule add priority 90 to 192.0.2.2/32 lookup 51819
ip -6 route replace unreachable default table 51819 metric 42760
ip -6 route replace 2001:db8:1::2/128 via fe80::1 dev eth0 onlink table 51819
ip -6 rule add priority 90 to 2001:db8:1::2/128 lookup 51819
ip -4 route get 192.0.2.2 uid 995
ip -6 route get 2001:db8:1::2 uid 995
```

These documentation addresses are placeholders, not usable relay endpoints.
Replace UID, gateway, interface and every candidate together. The unreachable
default prevents recursion into WG if an exact route disappears. IPv6 routes
illustrate the policy contract; current IPv6 outer transport remains blocked.
Verify lookups with WG up, down, after interface replacement, and for every
candidate, recording the actual interface/source/table. For an IPv4-only client,
retain the inet drop policy and do not enable physical IPv6 application egress.

Candidate tuples in the policy expire after at most one hour. Refresh only
after authenticating endpoint inventory through an already working tunnel,
checking its signature/trust source, intended transport/TLS name, expiry and
tuple scope. Persist signed last-known-good inventory with an absolute expiry;
reboot must not reset validity. Limit element timeouts to the remaining validity,
validate routes before the atomic allowlist update, and expire/remove stale
tuples on interface changes. Failure or expiry keeps the drop policy installed.
No automatic updater is implemented here; unattended endpoint rotation remains
blocked until such provisioning is reviewed and tested.

No plaintext resolver bootstrap is allowed. For a future TLS transport, retain
the provisioned IP separately from its authenticated TLS server name and trust
roots; connecting to an IP must not disable hostname/certificate verification.
The existing UDP obfuscation environment has no TLS server-name setting and does
not prove any TLS/DNS property. An unavailable protected resolver or expired
inventory causes an outage until an authenticated update or explicit local
operator recovery, never a public UDP/TCP 53 exception.

For a profile without supported IPv6 outer transport, leave `relay6` empty
(remove its `elements` statement when rendering) and do not provision an IPv6
outer route. Keep the inet output drop policy so IPv6 applications cannot
fall back to the physical interface. A reserved example IPv6 address is not
an authenticated candidate.

Reference semantics were checked against the primary
[nftables manual](https://netfilter.org/projects/nftables/manpage.html),
[element timeout guidance](https://wiki.nftables.org/wiki-nftables/index.php/Element_timeouts)
and [systemd unit documentation](https://www.freedesktop.org/software/systemd/man/257/systemd.unit.html).
The early firewall ordering follows
[systemd's network-pre.target contract](https://www.freedesktop.org/software/systemd/man/latest/systemd.special.html#network-pre.target).
This source review does not replace an actual `nft --check` and boot test on Linux.

## DNS boundaries and release gates

The repository [Corefile](../config/coredns/Corefile) configures only
`tls://1.1.1.1` and `tls://1.0.0.1` with server name
`cloudflare-dns.com`. This is configuration intent. Effective mounted bytes,
CoreDNS image/version, trust roots, hostname validation, working queries and
outage/timeout/invalid-certificate captures are still required. Plain client DNS
to `10.13.13.1` inside WG is intentional; external relay UDP/TCP 53 is forbidden.
Do not inspect or export whole Secrets. No production Secret was read here.
The [deployment](../cyber-stack/base/proxy/deployment.yaml) projects its effective
Corefile from `wireguard-config` and copies it to the runtime volume during init;
the [entrypoint](../docker/entrypoint.sh) launches that copy. The
[image source](../Dockerfile) pins CoreDNS 1.12.3 and installs CA certificates,
but that does not attest the deployed image. Primary
[CoreDNS forward documentation](https://coredns.io/plugins/forward/) describes
TLS server-name and CA-based upstream authentication; actual rejection and
fallback behavior still require controlled runtime tests.

The proxy's [system resolver](../src/main_sections/startup.rs) intentionally
uses kube-dns for internal discovery. Trace its external queries independently
through kube-dns, node forwarding and the actual upstream. A passing WG CoreDNS
path says nothing about this chain. Capture only owned synthetic query names
at each external boundary; test certificate failure, outage and timeout with
internal service discovery continuing. Do not replace the global resolver with
a public resolver. The missing cluster/node chain evidence blocks completion.
External dialing in [dial.rs](../src/tunnel/dial.rs) and blocked-host enrichment
in [connect.rs](../src/tunnel/connect.rs) and
[transparent decisions](../src/tunnel/transparent_sections/decisions.rs) use that
resolver too. No authoritative kube-dns/node upstream policy was found under
the GitOps configuration.

The [server template](../config/templates/server.conf) enables IPv6 forwarding
but has IPv4-only TCP redirects and UDP/443 enforcement. A client kill switch
cannot establish matching server IPv6 application policy. Block the IPv6 release
profile pending a separate small reviewed server-policy change and actual
effective firewall evidence; do not repair it within this plan's write scope.
The entrypoint does install IPv6 INPUT segmentation; that is distinct from
IPv6 forwarding and transparent-proxy enforcement. The blocker is the missing
matching FORWARD/redirect policy evidence, not a claim of absent IPv6 INPUT rules.

## Command results

Execution began on Darwin 27.0.0 arm64, UID 501. `wg --version` reported
wireguard-tools v1.0.20260223; `tcpdump --version` reported 4.99.1 / libpcap 1.10.1.
`ip` and `nft` are unavailable. No capture or host firewall mutation was attempted.
Docker reports Linux / Docker Desktop. A read-only, network-disabled, capability-
dropped `postgres:17` probe reported Linux 7.0.14-linuxkit and no `ip`, `wg`,
`nft`, `tcpdump` or `cargo`. No packages or Linux OS adapters were installed.
The macOS binaries cannot substitute for built Linux binaries.

`cargo build -p ssl-proxy --bin wg-obfs-shim --bin ssl-proxy` exited 0 on this
macOS host (dev profile). Generated Cargo build output is confined to `target/`.
This is build evidence, not Linux packet evidence.

Read-only effective DNS inspection against context `wiretrap-k3s` with a five-
second request timeout failed: `Unable to connect to the server: context deadline
exceeded`. No Secret was accessed. Production DNS capture counts are **unknown**,
not zero. All actual-client physical/tunnel capture counts are also **unknown**.

Remaining test command results will be recorded after artifacts are complete.
