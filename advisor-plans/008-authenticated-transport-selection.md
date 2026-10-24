# Plan 008: Select transports using authenticated bounded liveness

> **Executor instructions:** Freeze the control contract before changing wire
> behavior. Keep automatic selection opt-in. Update this plan and
> [the index](README.md) with evidence, not inferred health.
>
> **Drift check:** `git diff --stat f639c705..HEAD -- src/wg_shim_sections src/wg_shim_test_sections src/wg_relay_sections src/wg_relay_tests.rs src/wg_packet_obfuscation_sections src/bin/wg-obfs-shim_sections src/bin/wg-obfs-shim_tests config/client`.
> Inspect local edits and reconcile the code excerpts before implementation.

## Status and intent

- Priority: P1. Effort: L. Risk: HIGH; authentication, wire contract and routing.
- Category: correctness / security / transport. Status: TODO.
- Planned at: `f639c705`, 2026-10-23.
- Dependencies: [005](005-vpn-leak-containment-dns.md) containment and the manual
  adapter contracts from [006](006-masque-connect-udp.md) and
  [007](007-https-transport-fallback.md). Pure state-machine design/tests may run
  earlier; integrated automatic selection depends on proven adapters.
- Outcome: detect silent path failure and move among explicitly configured
  transports within fixed time/resource budgets while staying contained.
  Timeout is an observation, not proof of censorship.

## Current state and conventions

- [Shim failover](../src/wg_shim_sections/runtime.rs):346-375 rotates socket
  selection. At :392-399, `connection.socket.send(packet.bytes()).await`
  returns success before any reply. Silent blackholes need a separate signal.
- [Receive handling](../src/wg_shim_sections/runtime.rs):247-294 calls
  `session.touch(now)` before decoding, and `session.record_server_reply(now)`
  only after decode/replay success. Unauthenticated activity must not refresh
  authenticated liveness or keep a dead path healthy.
- [Reply timing](../src/wg_shim_sections/sessions.rs):177-185 computes
  `now_millis.saturating_sub(last_send)`. This is not correlated request RTT.
- [Codec](../src/wg_packet_obfuscation_sections/encode_decode.rs):174-179 returns
  `PacketDecodeError::ChaffFrame` for zero-length payload. The relay
  [runtime](../src/wg_relay_sections/runtime.rs):624-639 drops decode errors.
  Existing chaff does not ask the relay for an acknowledgment.
- [Replay state](../src/wg_packet_obfuscation_sections/types.rs):266-288 resets
  its window on salt change. New liveness must bind freshness to a current
  challenge/generation independently; do not depend solely on this window.
- [Health snapshot](../src/wg_shim_sections/config_metrics.rs):393-443 describes
  queue state, not authenticated remote reachability. Preserve existing fields
  and semantics unless a versioned consumer change is explicitly reviewed.
- Existing loopback tests are in
  [shim integration tests](../src/wg_shim_test_sections/integration.rs):45-105,264-320;
  reply-time tests are in [unit tests](../src/wg_shim_test_sections/unit.rs):338-354.
  Reuse cancellation tokens and injected clock/events for deterministic tests.

## Scope and Git workflow

Existing write scope: `src/wg_shim_sections/`, `src/wg_shim_test_sections/`,
`src/wg_relay_sections/`, `src/wg_relay_tests.rs`,
`src/bin/wg-obfs-shim_sections/`, `src/bin/wg-obfs-shim_tests/mod.rs`,
`config/client/wg-obfs-shim.env.example`, and `src/lib.rs` for module wiring.
New/shared proposed paths: `src/wg_transport.rs`, `src/wg_transport/liveness.rs`,
`src/wg_transport/masque.rs`, `src/wg_transport/https.rs`,
`tests/wg_transport_selection.rs`,
`advisor-plans/008-transport-control-contract.md`,
`advisor-plans/008-transport-selection-evidence.md`.
Serialize shared interface/config edits with 006/007; update plan/index status.

Exclude legacy v2 codec/wire changes, unrelated replay-window fixes, arbitrary
Internet probing, inner application policy, production manifests/Secrets and
new dependencies. A raw-UDP control extension requires its own explicit
versioned endpoint and contract; do not reinterpret existing WG/v2 data.
Suggested branch: `advisor/008-transport-selection`. No commit/push implied;
any requested commit follows Lore with control-version compatibility recorded.

## Steps and verification

### 1. Freeze candidate identity, health meanings and control protocol

Create the control contract with configured candidate ID, transport, endpoint
IP/port, TLS name/trust, credential reference, preference and capability
version. Candidate identity must survive NAT rebinding without trusting an
unverified source address. Endpoint-IP changes follow 005 bootstrap/route rules.
Default order is an explicit operator list; switching cannot discover arbitrary
new relays or expose direct application traffic.

Use fresh random nonce challenges authenticated inside each adapter's secure
control channel. Responses bind nonce, candidate, control version and session
generation, with one bounded outstanding challenge per candidate. Only an
unexpired matching response updates probe RTT/health; duplicates, old
generations, wrong candidates and unsolicited traffic cannot. Define message
size, rate, retry, expiry and credential-rotation behavior before implementation.
HTTP adapter control must use a specified negotiated control mechanism separate
from Context ID zero WG packets; do not send private control bytes to a generic
MASQUE peer or alter CONNECT-UDP payload semantics.

For legacy/raw UDP, keep automatic liveness-based selection disabled until a
separate versioned AEAD-authenticated control endpoint is implemented and
reviewed. That optional endpoint must use domain-separated existing crypto,
bound identity/nonce/generation, bounded pre-auth work, no unauthenticated reply
and no reflection amplification. It is not part of the existing v2 codec.
If that endpoint is not selected for this delivery, label legacy health
UNKNOWN and retain manual legacy selection; never fabricate a health probe.
Do not use XOR/header-tag-only mode, empty WG packets or chaff for strong
liveness. No new cryptographic primitive or dependency is authorized here.

Define three separate facts: outer relay control reachability, inner WG peer
handshake/data reachability, and protected DNS/application readiness. A TLS
handshake, CONNECT success, QUIC ACK or ordinary reply is insufficient to prove
all three. Specify how owned inner checks are performed and reported; a healthy
outer relay with failed WG/DNS should show degraded service, not hide failure.

**Verify:** contract explicitly lists each binding and unsupported adapter;
`python3 scripts/check-docs.py` exits 0. Do not start wire implementation until
the chosen control mechanism can coexist with standard independent peers.

### 2. Implement the pure bounded selection state machine

Use a small explicit enum: unknown, probing, healthy, suspect, cooldown and
all-unavailable. Keep time injectable rather than sleeping in unit tests.
Proposed initial configurable defaults: 5 s active probe interval, 3 s response
deadline, three consecutive misses, 30 s minimum dwell, cooldown 5 s doubling
to 120 s, bounded 20% jitter, two successive valid probes before returning to
a preferred path. Clamp/validate values and document battery/traffic costs.
These are design defaults, not measured optimal thresholds.

Limit to four configured candidates, one outstanding probe per candidate and
one migration at a time. Stagger idle probes (default 30 s), then require a
fresh active probe before selecting an idle alternative. Freeze a global
60 s initial recovery-attempt budget; when exhausted, remain contained and
retry candidates only at bounded cooldown intervals. Hard auth/certificate
failures disable that candidate until credentials/config change; do not use a
failing credential to cycle endlessly. Transport unavailability may select an
independently authenticated configured alternative, never a TLS downgrade.

Specify an absolute bound from last valid ack to first migration attempt based
on probe schedule/deadline/miss count, and test that bound. Switching is allowed
only after the threshold and a fresh alternate proof; all-unavailable is a
normal explicit state. Successful sends never reset missed-ack counters.
Keep healthy idle clients healthy through bounded probes rather than requiring
application traffic. Delayed replies, transient loss and preference recovery
must respect hysteresis and dwell.

**Verify:** add deterministic tests named `transport_selection_*`; run
`cargo test -p ssl-proxy transport_selection` with a nonzero test count.
Assert exact transition times, retry caps, dwell and attempt limits.

### 3. Wire authenticated health and migration into adapters

Integrate secure control receive paths, separating authenticated activity from
raw receive metrics. Move only the health/idle activity that requires
authentication after validation; preserve existing packet accounting.
Ordinary data-path replies remain useful counters, but cannot satisfy a
nonce-correlated pending challenge. Use fresh generation on reconnect, clear
pending challenges on cancellation/credential change and prevent stale replies
from the retired path updating the selected path.

Migrate one local WG session at a time at a packet boundary. Cancel/drain the
old association under a single absolute deadline, expire queued old packets,
preserve local client addressing, and route new packets to the authenticated
candidate. Do not duplicate packets across candidates or share internal WG UDP
associations between clients. A new transport may require WG re-handshake/NAT
roaming; verify behavior rather than promising session continuity. Serialize
server-side endpoint migration and require real inner reachability before
reporting application ready. If control succeeds but the WG backend fails,
enter degraded service with bounded alternate trials; no infinite switching.

Use existing bounded pools/queues. Health/probe/cancel work must progress even
when the data queue or buffer pool is full. If existing pool/dequeue or chaff
timer behavior blocks that guarantee, add a focused failing regression and
repair only that prerequisite. Do not start a general performance refactor.

**Verify:** `cargo test -p ssl-proxy --test wg_transport_selection` covers
silent bidirectional and one-way blackholes despite successful sends, wrong
nonce/auth/candidate/generation, replay, delayed ack, congestion, all-down,
idle, pool exhaustion, queue saturation, shutdown/backoff interruption, client
isolation and inner-backend outage. Run existing shim/relay tests too.

### 4. Add honest status and execute end-to-end release tests

Expose additive bounded fields/metrics for selected configured ID/transport,
control health, inner readiness, last valid ack age, correlated probe RTT,
transition reason, cooldown and attempt count. Avoid addresses, secrets,
nonces or unbounded error strings in metric labels. Preserve existing queue
and process health; remote outage must not create an endless supervisor restart
loop. Missing probes/status are unknown, never healthy.

On owned Linux fixtures, run raw/manual legacy, H3 and HTTPS independently,
then opt-in automatic H3-to-HTTPS switching under UDP blocking, preference
restoration, NAT/network change and total outage. If legacy secure control
was omitted, demonstrate its manual availability and explicit exclusion from
the auto-selection set. Capture both client interfaces across every transition,
reusing 005 validation. Prove actual WG/application recovery and policy/audit
parity; a probe echo is not enough. Record measured recovery time against the
frozen configured bound and bounded retry traffic during prolonged outage.

**Verify:** retain exact fixture commands/results in the evidence document;
`cargo test -p ssl-proxy --bin wg-obfs-shim` checks configuration/health
compatibility, and `cargo test -p ssl-proxy --features metrics wg_shim` passes.

## Done criteria and final checks

- [ ] Control protocol/version, freshness, limits and adapter capabilities are
  specified; legacy wire compatibility and manual selection remain intact.
- [ ] Deterministic state tests and `tests/wg_transport_selection.rs` pass with
  actual tests executed, including silent loss, forged/stale health and all-down.
- [ ] Real WG recovery meets recorded bounds; 005 captures show zero unexpected
  egress for every supported migration and total outage.
- [ ] `cargo test -p ssl-proxy wg_shim`, `cargo test -p ssl-proxy wg_relay`,
  `cargo check -p ssl-proxy --all-targets --no-default-features`,
  `cargo clippy -p ssl-proxy --all-targets --all-features -- -D warnings`,
  `make dependency-boundaries`, `python3 scripts/check-docs.py` and
  `git diff --check` exit 0.
- [ ] Recovery/latency/retry metrics and untested production/client OS gates are
  recorded; automatic selection stays opt-in until integrated evidence passes.

## STOP conditions and maintenance

Stop the affected step if probe freshness cannot be bound to an authenticated
candidate, a protocol change would break standard peers/legacy v2, the selection
logic needs unbounded retries or direct-route escape, or migration weakens
005 containment/inner policy. Material drift, out-of-scope changes or two failed
fixes of a verification gate require a revised handoff.

Every added candidate/control version needs negative-auth, replay, MTU,
migration and containment tests. Tune defaults from measured network conditions,
not a presumption of censorship. Review clock behavior across suspend/resume,
NAT roaming, endpoint rotation and metrics consumers together. Rollback disables
auto-selection and restores a known transport while retaining the kill switch.
