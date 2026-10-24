# Proxy ISP privacy: selected implementation workmap

> **Status: Advisor plan complete; implementation NOT_STARTED.**
> Selected scope: four priorities only. Reviewed 2026-10-23 against `f639c705`.
> This document replaces the earlier broad recommendation list with the selected
> work packages below. No application, client firewall or deployment change has
> been implemented or verified by this planning update.

## Decision and execution order

Keep WireGuard as the inner authenticated tunnel and preserve existing policy
and audit behavior. Establish leak containment first, add two independently
selectable outer transports, then integrate authenticated selection. Transport
diversity improves availability; it does not make the relay unobservable.

| Priority | Selected work | Executor plan | Completion gate |
| --- | --- | --- | --- |
| P0 | Leak containment and encrypted DNS verification | [005](005-vpn-leak-containment-dns.md) | Actual supported client OS passes route, DNS and failure captures |
| P1 | MASQUE CONNECT-UDP over HTTP/3 | [006](006-masque-connect-udp.md) | Standards interoperability, bounded datagrams, WG round trip, policy parity |
| P1 | Genuine HTTPS fallback with normal public service behavior | [007](007-https-transport-fallback.md) | Real website behavior, authenticated tunnel, UDP-blocked recovery and loss tests |
| P1 | Authenticated liveness and bounded transport selection | [008](008-authenticated-transport-selection.md) | Fresh candidate-bound challenge responses, bounded recovery and no flapping |

All four plans are self-contained handoffs. Their commands describe future
implementation checks, not tests run during this documentation update.

1. Execute 005 on a disposable Linux client first. Confirm the actual client OS
   inventory; other OS profiles stay unsupported until exercised on that OS.
2. Design 006 and 007 in parallel after the 005 route/DNS contract is recorded.
   Use distinct files for adapters and serialize shared shim/config edits.
   Manual transport selection must work before automatic selection.
3. Design and unit-test the 008 state machine alongside adapter work; integrate
   and release it only after both adapter contracts and containment tests pass.
4. Re-run the 005 leak matrix for every candidate and every switch. Promote
   through reviewed GitOps changes only after the external deployment gates pass.

## Verified repository baseline

| Evidence | Consequence for the selected plans |
| --- | --- |
| [Client example](../config/peer1/peer1-obfuscated.conf.example):10-17 sets tunnel DNS, loopback shim endpoint and full IPv4/IPv6 routes | Route intent is present; OS kill-switch and IPv6 behavior remain unproven |
| [Shim service](../config/client/wg-obfs-shim.service):3-18 orders startup and restarts the process | Process restart is not a client egress firewall |
| [Shim upstream socket](../src/wg_shim_sections/runtime.rs):485-502 binds a wildcard address and connects to the relay | The outer route needs an explicit bypass because WG sees its endpoint as loopback |
| [CoreDNS example](../config/coredns/Corefile):2-3 uses DoT with a TLS server name | Verify actual mounted configuration, certificate validation and outage behavior |
| [Deployment](../cyber-stack/base/proxy/deployment.yaml):195-204 projects Corefile from Secret `wireguard-config` | The checked-in Corefile does not prove live DNS behavior |
| [Rust DNS startup](../src/main_sections/startup.rs):265-271 uses system resolution | Preserve cluster discovery; external resolver privacy is a separate path |
| [H3 handler](../src/quic_sections/requests.rs):69-82,172-187 implements CONNECT to TCP | It is not an existing MASQUE client/server |
| [H3 listener](../src/quic_sections/listener.rs):130-131 binds UDP 443; [WG relay](../src/wg_relay_sections/runtime.rs):447-448 binds configured WG port | Same-address UDP 443 ownership must be resolved before integration |
| [Deployment](../cyber-stack/base/proxy/deployment.yaml):74-87 sets WG port 443 and disables obfuscation | Available codec/shim code does not prove production uses that codec |
| [Proxy Service](../cyber-stack/base/proxy/service.yaml):16-23 exposes WG UDP ports | New H3/HTTPS reachability requires topology review |
| [Threat model](../docs/threat-model.md) limits public ingress and WAN TCP 443 | A real HTTPS endpoint cannot be published by silently widening current edge policy |
| [Shim failover](../src/wg_shim_sections/runtime.rs):379-424 reacts to send errors | A successful UDP send cannot establish reachability |
| [Reply handling](../src/wg_shim_sections/runtime.rs):247-294 touches activity before decoding, then records decoded replies | Separate unauthenticated receive activity from authenticated health |
| [Reply timing](../src/wg_shim_sections/sessions.rs):172-190 uses the latest send timestamp | It is not a nonce-correlated probe RTT |
| [Codec](../src/wg_packet_obfuscation_sections/encode_decode.rs):174-179 rejects empty chaff payloads | Chaff does not supply an acknowledged liveness probe |
| [Server policy](../config/templates/server.conf):10-17 redirects inner TCP 80/443 and drops inner UDP 443 | Preserve inner policy while enabling outer transport UDP/TCP |

## Architecture decisions to carry into every plan

- WG public keys and encrypted WG packet semantics remain the inner boundary.
  MASQUE/HTTPS deliver raw WG UDP to a fixed authorized WG destination, not an
  arbitrary Internet UDP forwarding service. The legacy v2 adapter keeps its
  own framing. Never reinterpret legacy packets as a new control protocol.
- Separate relay transport health from WG peer handshake, tunnel DNS and
  application reachability. A working TLS handshake or CONNECT response proves
  neither the WG listener nor Internet egress is working.
- Use authenticated identity and bounded allocation before creating UDP
  associations. A shared-secret admission tag alone is insufficient evidence
  of fresh peer liveness.
- Outer endpoint exceptions are exact IP/port/protocol tuples, with process or
  interface binding where supported. A blanket physical-interface TCP 443
  exemption would allow application leaks.
- Keep explicit proxy CONNECT compatibility, admin isolation, policy events,
  inner UDP restrictions and database boundaries.
- New dependencies need a separate explicit decision. Plan 006 starts with a
  capability spike; the presence of Quinn/H3 does not establish a complete
  HTTP Datagram API. Do not invent a replacement QUIC stack to evade this gate.
- Production promotion requires endpoint ownership, valid TLS, provisioning
  references, digest-pinned images and a reviewed publication design. No
  interactive managed-cluster patching or firewall repair.

## Protocol references and chosen design direction

Use [RFC 9298](https://www.rfc-editor.org/rfc/rfc9298.html) for CONNECT-UDP.
Use [RFC 9297](https://www.rfc-editor.org/rfc/rfc9297.html) for request-associated
HTTP Datagrams and reliable capsules. Plan 006 requires QUIC DATAGRAM carriage
for WG payloads; it must not silently change to a reliable outer stream.

For 007, first evaluate HTTPS HTTP/1.1 Upgrade `connect-udp` plus capsules,
using the existing Hyper/TLS stack. This is a standards-based starting point
that can reuse the restricted destination policy. It is not a claim of
WebTunnel interoperability. [Tor's WebTunnel design](https://blog.torproject.org/introducing-webtunnel-evading-censorship-by-hiding-in-plain-sight/)
is the reference for coexistence with an ordinary website and realistic public
behavior. The reverse proxy's support for the actual upgrade and streaming
semantics must be tested before choosing this integration.

## Evidence and release gates

The 005 report must record client OS/version, route/resolver/firewall snapshots,
capture interfaces, permitted control traffic and sanitized packet-count results.
A missing OS test is BLOCKED, never a pass inferred from a template.

The 006/007 reports must record exact client/server versions, independent-peer
interoperability, MTU behavior, authentication failures, cancellation, task/queue
bounds and packet loss conditions. Record baseline goodput, CPU, RSS and p95/p99
latency before setting numerical performance gates. Do not invent measured
improvements or silently loosen a frozen gate to pass.

The 008 report must distinguish timeout from diagnosed censorship. Test idle
sessions, one-way blackholes, total outage, replays, credential/certificate
failure, NAT rebinding, network change and cancellation. Exhaustion leaves the
client contained and offline.

Rollback restores the previously pinned client/server transport configuration
and Git revision while retaining the client kill switch. Existing WG transport
stays available during additive rollout; automatic selection is opt-in.

## Scope exclusions

ECH, traffic shaping/padding research, multi-hop trust separation, alternative
VPN ecosystems, Tor integration, DPI desynchronization, general copy-loop
optimization, key-cache optimization and unrelated replay-window redesign are
deferred. They are not dependencies or extra deliverables in these four plans.
If a selected feature exposes a correctness blocker, record the smallest
necessary prerequisite and its regression test instead of reopening that list.

## Verification record

- This update re-read relevant client, DNS, shim, relay, H3, tests, dependencies
  and deployment contracts, with independent read-only transport and
  containment/liveness review.
- The earlier draft recorded 219 passing Rust library tests. That is historical
  baseline evidence only; this documentation update did not rerun Rust tests.
- Documentation and whitespace validation are recorded in the advisor index
  after the final checks.
- No actual client OS, live DNS configuration, packet captures, ISP filtering,
  throughput or new transport implementation has been tested.
