# Plan 006: Carry WireGuard UDP through MASQUE over HTTP/3

> **Executor instructions:** Start with the API/topology spike, then implement
> the additive path only when its gates pass. Preserve unrelated edits and
> record verification in this plan and [the index](README.md).
>
> **Drift check:** `git diff --stat f639c705..HEAD -- Cargo.toml Cargo.lock src/lib.rs src/quic_sections src/wg_shim_sections src/bin/wg-obfs-shim_sections src/wg_relay_sections tests/wireguard_template.rs`.
> Inspect `git status --short` and compare the current-state excerpts too.

## Status and intent

- Priority: P1. Effort: L. Risk: HIGH; new wire/client/server contract.
- Category: direction / transport. Status: TODO; API/dependency and topology
  gates are unresolved. Planned at: `f639c705`, 2026-10-23.
- Depends on: [005 containment contract](005-vpn-leak-containment-dns.md).
  Design may start before its live matrix finishes; release may not.
- Result: manually selected, authenticated CONNECT-UDP/H3 adapter carrying WG
  packets using QUIC DATAGRAM. QUIC/IP blocking remains possible.

## Current state and conventions

- [Cargo manifest](../Cargo.toml) declares optional Quinn/H3/H3-Quinn with
  default feature `quic`. Locked H3 is 0.0.8; H3-Quinn is 0.0.10.
- [H3 request handler](../src/quic_sections/requests.rs):69-82 checks ordinary
  CONNECT and extracts authority; :172-187 calls
  `dial_upstream_with_resolver(&state, &host)` for a TCP stream. It has no
  CONNECT-UDP dispatch. For Extended CONNECT the authority is the proxy origin,
  not the WG destination; do not reuse the current authority-to-TCP behavior.
- [H3 connection](../src/quic_sections/listener.rs):225-227 uses
  `h3::server::Connection::new(h3_quinn::Connection::new(connection))`.
  Request tasks at :243 are detached; new adapter requests need tracked bounds.
- The H3 bind at :130-131 is UDP 443. The
  [WG relay bind](../src/wg_relay_sections/runtime.rs):447-448 uses WG port,
  also configured as 443 in [deployment](../cyber-stack/base/proxy/deployment.yaml):74-87.
  That deployment disables obfuscation. Do not assume production uses v2.
- [Shim queue](../src/wg_shim_sections/sessions.rs):424-446 encodes before
  queueing, while the upstream type at :220-224 holds a concrete UDP socket.
- [Relay session association](../src/wg_relay_sections/session_io.rs):28-44
  uses one connected loopback UDP socket per session. Reuse that isolation idea.
- [Loopback integration tests](../src/wg_shim_test_sections/integration.rs):264-320
  provide the existing shim/relay round-trip pattern: ephemeral ports,
  cancellation tokens and timeout-bounded waits. Match these conventions.

## Scope, boundaries and Git workflow

Existing write scope: `src/lib.rs`, `src/wg_shim_sections/`,
`src/wg_shim_test_sections/`, `src/bin/wg-obfs-shim_sections/`,
`src/bin/wg-obfs-shim_tests/mod.rs`, and `config/client/wg-obfs-shim.env.example`.
Allowed new files: `src/wg_transport.rs`, `src/wg_transport/masque.rs`,
`src/bin/wg-masque-relay.rs`, `tests/wg_masque.rs`,
`advisor-plans/006-masque-contract.md`,
`advisor-plans/006-masque-evidence.md`. New paths are proposed artifacts.
Keep the server in a dedicated binary initially so enabling the explicit
proxy is unnecessary. Conditional extraction scope is limited to
`src/wg_relay_sections/session_io.rs` and `src/wg_relay_tests.rs`: a small shared
destination-association helper may be extracted with existing tests retained.

Cargo manifest/lock edits are conditional on explicit dependency authorization;
none is granted by this plan. Read existing H3/proxy and deployment code, but
do not change legacy CONNECT behavior, public listeners, production manifests,
WG keys/wire semantics, inner UDP policy or database wiring. A production
GitOps change is a later gated release unit. Branch suggestion:
`advisor/006-masque-wg`; any requested commit follows Lore; no push is implied.

## Steps and verification

### 1. Freeze API, endpoint and packet contracts

Create the contract document. Specify a bounded transport enum with legacy v2
UDP, MASQUE and future HTTPS variants, using existing session/queue ownership.
Queue raw WG bytes at the common boundary; apply the old codec only in the
legacy adapter. First add regression coverage that legacy encoded bytes and
message boundaries are unchanged. Coordinate this shared file with 007/008.

Use [RFC 9298](https://www.rfc-editor.org/rfc/rfc9298.html) Extended CONNECT and
[RFC 9297](https://www.rfc-editor.org/rfc/rfc9297.html) request-associated
datagrams. Freeze URI template, target allowlist, auth header semantics,
certificate trust/server name, limits, errors and session shutdown behavior.
Use per-client provisioned high-entropy credentials over verified TLS; keep
values in private files and redact headers. One tunnel may target only its
configured WG endpoint; never arbitrary UDP, loopback ports or DNS names from
untrusted requests. Each authenticated request owns an isolated connected UDP
association. Disable admission and forwarding in 0-RTT initially.

Spike the pinned APIs: H3 0.0.8 documents
[`enable_extended_connect` and `enable_datagram`](https://docs.rs/h3/0.0.8/h3/server/struct.Builder.html)
and [`Protocol::CONNECT_UDP`](https://docs.rs/h3/0.0.8/h3/ext/struct.Protocol.html).
This does not prove integrated datagram carriage. The upstream
[`h3-datagram` 0.0.2 extension](https://docs.rs/crate/h3-datagram/0.0.2)
is a dependency candidate, not an authorized addition. If public pinned APIs
are insufficient, document the minimal dependency/version decision and stop
the blocked implementation step. Do not fork or reimplement H3 framing.

Choose a separate endpoint/IP or reviewed port migration for public UDP 443.
Use distinct ephemeral ports locally; do not attempt to bind two listeners to
the same socket or add an ad hoc raw-WG/QUIC demultiplexer.

**Verify:** contract review names all limits and port owners;
`cargo check -p ssl-proxy --all-targets` and
`cargo check -p ssl-proxy --all-targets --no-default-features` exit 0 for any
retained spike code. `python3 scripts/check-docs.py` exits 0.

### 2. Implement manually selected client/server adapters

Create the dedicated server, client adapter and minimal transport enum. Do
not couple activation to `EXPLICIT_PROXY_ENABLED`. Add validated opt-in client
configuration, preserving the legacy default. Feature-gate H3 code with `quic`;
reject selecting it in a build without that feature. Require verified server
TLS and authenticated client admission before UDP socket/session allocation.

Negotiate Extended CONNECT and H3 datagrams explicitly. A request's stream
association/QUIC stream ID and Context ID zero must be correct. Carry one
unmodified WG packet per HTTP Datagram; never tunnel UDP in ordinary H3 DATA
as a substitute. Implement required capsule/control processing with bounded
length/skip logic, no unbounded buffering of unknown requests/contexts, and
defined malformed-message errors. No silent reliable-stream fallback here.

Bound connections, requests, auth work, header/capsule size, UDP associations,
queued packets/bytes and close/drain time. Track child tasks and use a single
absolute shutdown deadline. Reject disallowed targets before resolution/dial.
The UDP association lifetime follows its CONNECT stream. Keep application
policy inside the WG server path: outer UDP is distinct from inner UDP/443.

**Verify:** add and run
`cargo test -p ssl-proxy --test wg_masque` plus
`cargo test -p ssl-proxy wg_shim` and
`cargo test -p ssl-proxy wg_relay`; all exit 0 with actual tests executed.

### 3. Test MTU, isolation, lifecycle and independent interoperability

Calculate maximum WG UDP payload from live QUIC datagram capacity minus HTTP
association/context overhead. WG interface MTU also needs WG's own overhead;
the old example MTU 1419 is not evidence it fits QUIC. Specify a conservative
client MTU per tested path and reject oversize without truncation or a new
fragmentation/reassembly protocol. If capacity cannot carry the required inner
IPv6 packet, block that profile or block IPv6 per 005; do not claim dual-stack.

In `tests/wg_masque.rs`, cover bidirectional exact packet preservation,
simultaneous clients, bad auth/cert/target, absent settings, wrong stream/context,
late datagrams, malformed capsules, unknown capsule skipping, size boundaries,
queue saturation, idle expiry, socket failure and cancellation. Rejection must
leave no UDP association or detached task. Follow existing loopback tests and
use deterministic injected time for lifecycle decisions.

Run client and server against an independent RFC 9298 implementation in both
directions, recording peer/version, exact invocation and expected success.
Its package/API is selected during the spike; unavailable independent tooling
is a release blocker, not permission to count self-interoperability as enough.
Then run real WG through the adapter on an owned Linux fixture, verify kernel
handshake, bidirectional application traffic and unchanged policy/audit events.
Re-run the 005 capture matrix. Record goodput/CPU/RSS/p95/p99 at baseline and
under declared loss/reordering; freeze tolerances before promotion.

**Verify:** `cargo test -p ssl-proxy --test wg_masque` exits 0;
the evidence document includes the independent-peer commands/results and WG
fixture captures. No claim of real WG support from UDP echo tests alone.

## Done criteria and final checks

- [ ] Capability/dependency and UDP 443 topology decisions are recorded.
- [ ] Manual client and server pass protocol tests, independent interop and
  real WG/policy/005 containment tests; no deployment mutation is required.
- [ ] `cargo check -p ssl-proxy --all-targets --no-default-features`,
  `cargo clippy -p ssl-proxy --all-targets --all-features -- -D warnings`,
  `make dependency-boundaries`, `python3 scripts/check-docs.py` and
  `git diff --check` exit 0. No unused/new dependency slips through the gate.
- [ ] Shared shim changes pass existing binary tests with
  `cargo test -p ssl-proxy --bin wg-obfs-shim` and preserve legacy defaults.
- [ ] Record unsupported profiles/gates honestly; update the index to DONE
  only for the stated delivery scope, with production promotion separately gated.

## STOP conditions and maintenance

Stop the affected step on missing pinned APIs/dependency authority, ambiguous
port ownership, failed independent interop, inadequate MTU, changed inner
policy, material source drift or two failed fixes of a verification gate.
Keep independently executable tests/docs moving; do not replace standards
carriage with raw Quinn datagrams and label it MASQUE.

Review H3 version changes, auth rotation, endpoint-IP updates, negotiated
datagram limits and stream close handling together. This adapter provides a
standard transport, not ECH or proof against traffic classification. 008 owns
automatic transport selection; 007 owns reliable HTTPS fallback.
