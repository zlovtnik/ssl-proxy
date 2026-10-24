# Plan 005: Contain client egress and verify encrypted DNS

> **Executor instructions:** Implement and verify this P0 before transport
> promotion. Preserve unrelated worktree edits. Update this plan and its row in
> [the index](README.md) with command results and actual OS evidence.
>
> **Drift check:** Run `git diff --stat f639c705..HEAD -- config/client config/peer1 config/peer2 config/templates tests/wireguard_template.rs config/coredns src/wg_shim_sections/runtime.rs`.
> Also run `git status --short`; compare local edits and the excerpts below.
> Resolve material drift before implementation.

## Status

- Priority: P0. Effort: L, including client OS validation. Risk: HIGH, because
  incorrect client firewall changes can disrupt connectivity.
- Category: security / tests. Status: IN PROGRESS; repository implementation
  underway; actual client OS and effective external DNS evidence remain blocked.
- Planned at: `f639c705`, 2026-10-23. Dependencies: none.
- Outcome: a fail-closed Linux reference client plus evidence for each client
  OS actually claimed supported. This is not relay camouflage.
- Execution record: [OS support, lifecycle, DNS boundaries and command evidence](005-vpn-leak-evidence.md).

## Why this matters

Full-tunnel routes and encrypted DNS configuration do not prove containment
during startup, failures or network changes. The local shim adds a routing
hazard: WireGuard sees a loopback endpoint, while the real relay connection
needs its own physical-interface route. Containment must survive shim failure
and transport switching without enabling a direct application route.

## Baseline state and conventions

These excerpts describe the planning baseline at `f639c705`. The execution record
tracks the changed client policy and lifecycle contract.

- [Peer example](../config/peer1/peer1-obfuscated.conf.example):10-17:

  ```ini
  DNS = 10.13.13.1
  Endpoint = 127.0.0.1:51821
  AllowedIPs = 0.0.0.0/0, ::/0
  ```

- [Shim socket](../src/wg_shim_sections/runtime.rs):485-502 creates a tuned UDP
  socket on a wildcard bind address, then calls `socket.connect(server_addr)`.
  This function does not pin the outer route to the physical interface.
- [Client service](../config/client/wg-obfs-shim.service):3-18 uses
  `After=network-online.target` and `Restart=on-failure`, without an egress rule.
- [Corefile](../config/coredns/Corefile):2-3 uses
  `forward . tls://1.1.1.1 tls://1.0.0.1` and
  `tls_servername cloudflare-dns.com`.
- [Production projection](../cyber-stack/base/proxy/deployment.yaml):195-204
  mounts Corefile from Secret `wireguard-config`. Read only that non-secret
  configuration key when authorized; never dump the whole Secret.
- [Rust resolver](../src/main_sections/startup.rs):265-271 uses system DNS for
  Kubernetes discovery. Do not replace it with public DNS globally.
- [Server template](../config/templates/server.conf):10-17 contains IPv4 TCP
  redirection and inner UDP/443 restrictions; IPv6 forwarding is enabled later
  without matching IPv6 policy in this file. Actual effective policy is unknown.
- Model static checks after [wireguard_template.rs](../tests/wireguard_template.rs):
  use `fs::read_to_string` and explicit assertions. These checks complement
  packet-level tests; they cannot prove OS containment.

## Scope and Git workflow

Allowed existing files: `config/client/wg-obfs-shim.service`,
`config/client/wg-obfs-shim.env.example`, both obfuscated peer examples under
`config/peer1/` and `config/peer2/`, and `tests/wireguard_template.rs`.
Allowed new artifacts: `config/client/leak-containment-linux.nft.example`,
`scripts/tests/test-vpn-leak-containment.sh`,
`scripts/tests/test-vpn-leak-results.py`, and
`advisor-plans/005-vpn-leak-evidence.md`. These are proposed paths, not existing
tools. Any required OS adapter belongs to a follow-up scope decision.
Update this plan and index status when done.

Read-only evidence: CoreDNS, deployment, Rust resolver and server template.
Exclude production Secrets, live routing/firewall changes, managed cluster
mutations, unrelated Rust edits, ECH and application DNS interception.
If server IPv6 policy needs repair, block that release profile until a separate
small reviewed fix exists; do not invent IPv6 policy here.

Use branch `advisor/005-vpn-containment` if a branch is needed. No commit or
push is implied. Any requested commits follow the repository Lore format,
including why, tested conditions and missing OS evidence.

## Steps and verification

### 1. Define support and the capture contract

Create the evidence document with OS/version, WG client/version, shim profile,
physical and WG interfaces, owned relay and DNS test endpoints, external DNS
path, LAN access policy, and permitted DHCP/ARP/NDP/bootstrap traffic. Start
with a disposable Linux VM/namespace fixture because the supplied service is
Linux-specific. Record other actual OS profiles as pending until tested there.
Store no keys, bearer tokens, user browsing captures or private packet bodies.

Define machine-readable results per OS, transport and scenario, including
`unexpected_application_packets`, `unexpected_dns_packets`,
`outer_route_uses_physical_interface`, `protected_dns_verified`, and
`capture_valid`. A failed capture, missing interface or absent expected test
traffic is a failure, never zero leaks. Define supported/pending/blocked rows.

**Verify:** `python3 scripts/check-docs.py` exits 0. Inspect
`git diff --stat` for scope; evidence explicitly lists untested OS profiles.

### 2. Build the isolated failure harness before changing examples

Create the shell harness and standard-library Python result validator above.
The harness must create disposable client/router/relay namespaces, assert it
is isolated from host management interfaces, and clean up only resources it
created. Require Linux, administrator namespace privileges, WireGuard kernel
support/tools, nftables, iproute2, tcpdump, the built `wg-obfs-shim` and
`ssl-proxy` binaries, and owned DNS/HTTP fixtures; return nonzero if unavailable.
Do not install packages or edit a host's active firewall automatically.

Run the actual WG client with its loopback shim endpoint, the real shim binary,
and an isolated relay/kernel-WG backend with matching ephemeral test keys.
Use a second direct-WG profile as the control; never substitute an ordinary
veth route for the shim profile. Capture validity requires a kernel WG handshake
and known application/DNS traffic traversing the selected real packet path.
Before the fixture, `cargo build -p ssl-proxy --bin wg-obfs-shim --bin ssl-proxy`
must exit 0; isolate process configuration and test keys from the host runtime.

Capture physical and tunnel interfaces simultaneously while generating known
IPv4/IPv6 TCP, UDP and unique DNS query traffic to owned fixtures. Include
deliberately leaking positive controls so the detector proves it sees a leak.
Provide `--self-test` for result validation, including malformed/missing results
and empty captures, plus `--fixture linux --output <directory>` for live runs.

**Verify (new commands after creation):**
`python3 scripts/tests/test-vpn-leak-results.py --self-test` exits 0 and proves
known leaks/missing captures are rejected.
`bash scripts/tests/test-vpn-leak-containment.sh --fixture linux --output /tmp/vpn-leak-005`
initially demonstrates the uncontained failure case; use a negative-control
test assertion, not a permanently failing test suite.

### 3. Add persistent client containment and explicit outer routing

Provide the Linux nftables example and lifecycle documentation in the evidence
document. Install fail-closed egress before activating WG. Permit loopback and
necessary link control traffic; allow application egress through WG only.
Outer exceptions must be exact candidate IP/port/protocol tuples bound to the
shim identity/interface where feasible. General UDP/443 or TCP/443 exemptions
are forbidden. Preserve containment after WG shutdown/crash until an explicit
operator disconnect action; keep recovery access in the disposable fixture.

Route all real shim candidates over the physical path using explicit routes
or policy marks independent of WG's loopback endpoint. Record IPv4 and IPv6
route lookups and ensure remote candidate traffic never recurses into WG.
For DNS-free bootstrap, use provisioned candidate IPs plus the configured TLS
server name. Define authenticated endpoint-IP updates through an already
working tunnel; retain last-known-good IPs with bounded validity. No plaintext
DNS escape when bootstrap or protected resolution fails.

Keep firewall provisioning separate from the unprivileged shim process.
Do not grant it NET_ADMIN merely to manage policy. Add template regression
checks for dual-stack handling, exact tuple allowances and lifecycle guidance.

**Verify:** `cargo test -p ssl-proxy --test wireguard_template` exits 0.
Repeat the Linux fixture: positive controls are detected and the contained
profile has zero unexpected application/DNS packets with a valid capture.

### 4. Verify all DNS paths and the failure matrix

Check client resolver selection and parallel physical/tunnel captures.
Separately inspect effective relay CoreDNS configuration and capture relay
external DNS egress: confirm authenticated DoT to the configured server,
certificate/hostname validation, and no plaintext external fallback on upstream
failure, invalid certificate or DNS timeout. Client-to-CoreDNS DNS may be
plaintext inside WG; cluster-internal DNS remains intentional. Distinguish that
from external plaintext relay DNS. Verify internal Kubernetes service discovery
still works without exposing secret configuration.

Trace the Rust proxy's separate external-resolution chain from its system
resolver through kube-dns and node/upstream forwarding. Use known external
test names and capture the external hops; confirm protected upstream transport,
certificate/hostname validation where applicable and fail-closed behavior
without breaking internal discovery. A passing WG CoreDNS path cannot establish
privacy for this separate chain. If effective upstream configuration or capture
access is unavailable, record proxy-side external DNS as BLOCKED; if plaintext
external forwarding is observed, report the exact boundary needing a separate
platform change. Do not claim encrypted DNS verification is complete.

Run startup before WG is ready, reconnect, shim crash/restart, WG interface
removal, DNS/DoT outage, certificate failure, sleep/resume, network/interface
change, IPv4-only, IPv6-only, dual-stack and forced outer UDP blocking.
Unsupported IPv6 must be blocked explicitly, not left to physical routing.
Test each allowed LAN exception separately. Reuse this matrix for 006/007/008.

**Verify:** the harness exits 0 only when all fixture scenarios pass;
`python3 scripts/tests/test-vpn-leak-results.py --validate /tmp/vpn-leak-005`
rejects any nonzero unexpected count or missing expected scenario. Record
actual OS commands/capture counts in the evidence document. Lack of client OS
or effective relay DNS access leaves those rows BLOCKED.

## Done criteria and commands

- [ ] Harness positive/negative controls and result validator pass.
- [ ] Every supported OS/transport/scenario has valid physical+tunnel captures,
  zero unexpected application/DNS packets and a verified physical outer route.
- [ ] Effective relay and proxy-side external DNS chains validate their protected
  upstreams and fail without external plaintext fallback; internal discovery
  remains functional. Missing chain evidence leaves completion BLOCKED.
- [ ] `cargo test -p ssl-proxy --test wireguard_template`,
  `bash -n scripts/tests/test-vpn-leak-containment.sh` and
  `python3 scripts/check-docs.py` exit 0.
- [ ] `git diff --check` passes; status rows distinguish repository fixture
  success from actual client OS and live relay evidence.

## STOP conditions and maintenance

Stop the affected step if administrator/capture access is unavailable, a test
would touch a real host management firewall, effective DNS cannot be inspected,
the OS cannot enforce required tuple restrictions, or IPv6 bypasses policy.
Record the missing prerequisite and continue independent documentation/unit
work; do not claim containment. A repeated check failure or required change
outside scope needs a revised plan.

Every added transport candidate changes the firewall/route allowlist. Every OS
upgrade, resolver change, endpoint rotation and network transition can invalidate
the evidence. Review lifecycle ordering and avoid restoring unrestricted egress
during rollback. This plan proves a bounded privacy policy, not anonymity.
