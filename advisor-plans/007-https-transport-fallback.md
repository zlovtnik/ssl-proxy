# Plan 007: Provide a genuine HTTPS fallback for WireGuard

> **Executor instructions:** Complete the contract/integration spike first.
> Keep fallback opt-in and preserve existing WG and explicit-proxy behavior.
> Record actual verification and update [the index](README.md).
>
> **Drift check:** `git diff --stat f639c705..HEAD -- Cargo.toml Cargo.lock src/lib.rs src/main_sections/listeners.rs src/wg_shim_sections src/bin/wg-obfs-shim_sections config/client docs/threat-model.md`.
> Inspect local changes with `git status --short` too. Reconcile material drift.

## Status and intent

- Priority: P1. Effort: L. Risk: HIGH; new client/server and public endpoint.
- Category: direction / transport. Status: TODO; front integration and
  publication gates pending. Planned at: `f639c705`, 2026-10-23.
- Depends on: [005](005-vpn-leak-containment-dns.md) containment contract and
  coordination with [006](006-masque-connect-udp.md) on the packet interface.
  H3 implementation is not required to prototype this transport independently.
- Outcome: a manually selected TCP/TLS WG adapter that functions when outer
  UDP is blocked and shares its endpoint with a genuine ordinary website.
  Reliable outer transport can amplify loss and queueing.

## Current state and conventions

- [Listener code](../src/main_sections/listeners.rs):89-115 makes TLS optional
  for the existing explicit proxy. CONNECT auth and 407 handling at :280-299
  identify it as a proxy. It is not a ready-made normal-web fallback endpoint.
- [Manifest](../Cargo.toml) already includes Hyper 1, Hyper-Util, Tokio-Rustls,
  Rustls and Axum with server WebSocket support. There is no direct WebSocket
  client dependency. Reuse the established HTTP/TLS stack; do not assume Axum's
  server feature supplies a maintained public client API.
- [Shim](../src/wg_shim_sections/sessions.rs):424-446 encodes packets before
  queueing; [runtime](../src/wg_shim_sections/runtime.rs):392 sends on a concrete
  UDP socket. A shared raw-WG boundary must select encoding per transport.
- [Relay I/O](../src/wg_relay_sections/session_io.rs):28-44 uses isolated
  connected UDP sockets to the internal WG listener. Preserve that isolation.
- [Threat model](../docs/threat-model.md) currently permits route-free public
  TCP 80, with WAN TCP 443 closed. The proxy
  [Service](../cyber-stack/base/proxy/service.yaml):16-23 exposes WG UDP only.
  Public HTTPS publication therefore needs a separate reviewed design.
- Follow [shim integration tests](../src/wg_shim_test_sections/integration.rs):264-320
  for ephemeral loopback ports, cancellation and bounded waits. Keep packet
  ownership and queue accounting consistent with those tests.

## Scope and Git workflow

Allowed existing files: `src/lib.rs`, `src/wg_shim_sections/`,
`src/wg_shim_test_sections/`, `src/bin/wg-obfs-shim_sections/`,
`src/bin/wg-obfs-shim_tests/mod.rs`, and `config/client/wg-obfs-shim.env.example`.
Allowed new/shared artifacts: `src/wg_transport.rs` (coordinate with 006),
`src/wg_transport/https.rs`, `src/bin/wg-https-relay.rs`,
`tests/wg_https.rs`, `advisor-plans/007-https-contract.md`,
`advisor-plans/007-https-evidence.md`. These new paths are proposed.
Update this plan/index. Add no dependency without explicit authorization.

Exclude existing proxy auth/CONNECT semantics, managed edge/routes/firewalls,
production Secrets, deployed website source, WG cryptography, inner application
UDP policy, ECH and traffic shaping. Use local/owned fixtures for public-service
tests. Publication is a separate GitOps release unit; do not widen the current
edge policy to make a test pass. Suggested branch: `advisor/007-https-wg`.
No commit/push implied; any requested commit follows Lore.

## Steps and verification

### 1. Specify and spike the actual HTTPS integration

Write the contract before the data path. Preferred first candidate: genuine
TLS with HTTP/1.1 Upgrade `connect-udp` and RFC 9297 DATAGRAM capsules, using
existing Hyper/TLS APIs. This permits a shared fixed-target policy with MASQUE
and avoids a new bespoke TLS protocol. It is a design choice to validate,
not proven compatibility with the current front or a claim of WebTunnel
interoperability. Use [RFC 9298 sections 3.2-3.3](https://www.rfc-editor.org/rfc/rfc9298.html#section-3.2)
for GET/Upgrade/101 semantics and
[RFC 9297](https://www.rfc-editor.org/rfc/rfc9297.html) for capsules.

Specify origin, configured URI template, client admission header, per-client
credential provisioning/rotation, certificate roots/server name, fixed WG
target allowlist, max packet/capsule sizes, queue byte/packet limits and timeout
values. Credentials and private path material must not appear in logs or URL
query strings. A path alone is not authentication. Validate admission before
allocating a WG UDP association. Keep one connected association per tunnel.

Spike real Upgrade and full-duplex streaming through the selected reverse
proxy, checking buffering, header preservation, idle lifetime and TLS/ALPN.
Use HTTP/1.1 explicitly for this version; do not silently negotiate HTTP/2 and
then attempt an H1 Upgrade. Reject certificate/hostname failures and redirects
that would move credentials or the tunnel to an unconfigured origin. No
plaintext retry. Freeze the choice only after this test passes.

Also test an independent RFC 9298 HTTP/1.1 peer in both directions using the
same restricted destination policy. Record its version, exact invocation and
packet-preservation results. Select the peer during the spike; if none is
available, record interoperability as BLOCKED rather than treating two copies
of this implementation as independent evidence.

If that front cannot support `connect-udp`, document the exact blocker and a
bounded WebSocket adapter alternative/API/dependency decision. Do not implement
both speculatively. [Tor WebTunnel](https://blog.torproject.org/introducing-webtunnel-evading-censorship-by-hiding-in-plain-sight/)
is the model for genuine website coexistence; it is not a drop-in WG protocol.

**Verify:** record the front's exact version/config, client/server spike command
and a successful bidirectional UDP fixture result in the contract. Run
`cargo check -p ssl-proxy --all-targets --no-default-features` and
`python3 scripts/check-docs.py`; both exit 0. Missing front access blocks front
compatibility claims while loopback design/tests may continue.

### 2. Serve normal public behavior and isolate tunnel admission

Use a dedicated server binary/front, separate from the explicit proxy and all
admin endpoints. It must serve genuine site content on ordinary GET/HEAD,
normal missing-path responses and normal TLS behavior on the same origin/IP/
port as the tunnel. Choose real content owned by the operator during the
design step; do not expose the Integration Console as camouflage.

Missing path/admission and invalid credentials must follow the normal website
failure path without a proxy banner, 407 or private error diagnostic. Define
which requests enter tunnel parsing and which are ordinary site requests;
malformed authenticated tunnel requests still receive protocol-correct errors.
Compare unauthenticated GET/HEAD, unknown paths, wrong method and malformed
requests with the same site's normal routing baseline. Apply resource limits
to ordinary HTTP and admission too; do not promise identical timing or probe
invisibility from status-code parity alone.

Keep public health/admin/config routes absent. Protect secrets, redact
admission headers and avoid logging private paths. Rate-limit costly admission
and cap connection/header/time budgets before UDP/session allocation.

**Verify:** `cargo test -p ssl-proxy --test wg_https` executes site-behavior and
admission tests: real GET body, correct HEAD behavior, ordinary 404, denied
admission with zero UDP allocations, valid admission and admin isolation.

### 3. Preserve packets through bounded reliable carriage

Queue raw WG packets at the transport boundary; keep the old codec in its
legacy adapter. On valid H1 upgrade, send Context ID zero WG payloads in
DATAGRAM capsules. Implement incremental bounded parsing across arbitrary read
splits and multiple capsules/read; TLS/TCP read chunks are not UDP boundaries.
Check lengths before allocation. Skip unknown capsule types according to the
standard without buffering their full body. Close on truncated/invalid framing;
never reinterpret bytes as legacy v2 data. Keep control traffic separate from
WG UDP delivery.

Cap queued bytes, packet count, max packet age, parser state, sessions and task
count. Treat outer TCP stalls as backpressure; drop/expire waiting WG packets
according to the recorded policy instead of building an unlimited backlog.
Use absolute setup/write/idle/drain deadlines and cancellation-aware I/O.
Closing either side closes its association and releases all buffers/tasks.
Advertise and validate a WG MTU based on this path's packet limit; preserve
005 IPv6 policy. Default remains the existing transport, with explicit manual
selection for HTTPS until 008 is verified.

**Verify:** `cargo test -p ssl-proxy --test wg_https` covers packet boundaries,
bidirectional concurrent clients, disallowed target, partial/oversize/truncated
capsules, unknown capsule skipping, slow reader, expired packets, idle expiry,
disconnect and cancellation; all pass. Add explicit rejection tests for an
untrusted/expired certificate, wrong TLS hostname, redirects to unconfigured
origins and plaintext endpoints. Assert credentials never reach the redirect
target and no plaintext retry/socket is created. Validate the successful 101,
Upgrade and Capsule-Protocol headers; reject malformed upgrade responses and
forbidden capsule message headers per the RFCs. Run existing
`cargo test -p ssl-proxy wg_shim` and
`cargo test -p ssl-proxy --bin wg-obfs-shim` with unchanged legacy defaults.

### 4. Prove UDP-blocked operation and document release gates

On the isolated Linux fixture, block client outer UDP while permitting only
the configured HTTPS TCP tuple. Confirm TLS+upgrade and kernel WG handshake,
bidirectional application traffic, DNS and existing transparent policy/audit
behavior. Re-run all 005 leak scenarios including candidate-IP update and a
failed HTTPS attempt. Both outer transports blocked must remain offline and
contained. Unit UDP echo tests do not prove kernel WG behavior.

Measure direct baseline and HTTPS under declared RTT, bandwidth, random/burst
loss and slow receivers: goodput, CPU/RSS, queue bytes/age, drops and p95/p99.
Record actual impairment commands and freeze acceptance budgets before release.
Report TCP head-of-line and nested congestion costs; never call the fallback
performance-neutral. Validate front idle timeout and long-lived operation.

Document production prerequisites: origin ownership, TLS renewal, real website
owner/content, endpoint reachability, exact routing/header/streaming support,
rate limits, Secret references and digest-pinned GitOps deployment/rollback.
The existing edge publication ban remains until that review is complete.

**Verify:** the evidence document records exact front, WG and impairment commands
and results. `python3 scripts/check-docs.py` exits 0. Missing production endpoint
authority is a release gate, not permission for interactive cluster changes.

## Done criteria and final checks

- [ ] A single tested HTTPS contract is chosen, with ordinary website behavior,
  authenticated admission and no plaintext downgrade.
- [ ] Independent HTTP/1.1 peer interoperability passes in both directions,
  with exact peer/version/commands recorded.
- [ ] Real WG works with outer UDP blocked; 005 captures/policy parity pass.
- [ ] Slow-reader/loss tests prove bounded memory, queues and shutdown.
- [ ] `cargo test -p ssl-proxy --test wg_https`,
  `cargo check -p ssl-proxy --all-targets --no-default-features`,
  `cargo clippy -p ssl-proxy --all-targets --all-features -- -D warnings`,
  `make dependency-boundaries`, `python3 scripts/check-docs.py` and
  `git diff --check` exit 0.
- [ ] Local delivery status is distinct from production publication status;
  record all external gates in the index/evidence.

## STOP conditions and maintenance

Stop the affected step on unsupported Upgrade/streaming semantics, missing
dependency authority, loss tests exceeding the frozen budget, publication
conflicts, secret logging, weakened inner policy or required out-of-scope
changes. After two unsuccessful gate fixes, report the exact blocker.

Revalidate reverse-proxy buffering/timeouts, certificate renewal, ALPN, content
ownership and admission error routing after front upgrades. Endpoint-IP changes
must update 005 route/firewall exceptions atomically. 008 adds automatic
selection only after the manual adapter is proven. Website coexistence does
not hide relay IP, traffic volume or all tunnel fingerprints.
