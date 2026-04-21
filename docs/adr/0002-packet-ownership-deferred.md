# ADR-0002: Defer Embedded Packet Ownership During Cutover Core

## Status
Accepted

## Context

The repo contains active tunnel logic built around the current WireGuard and
transparent-proxy runtime boundaries. The immediate cutover risk is not missing
packet-level introspection; it is weak sync-plane production hardening and
documentation drift between the live runtime and the planned coordinator/worker
ownership split.

Moving the proxy to embedded BoringTun plus direct TUN ownership would:

- expand the change surface across ingress, routing, and audit paths
- introduce new packet-loop correctness and lifecycle risk
- delay the sync-plane work needed to make `sync.scan.request` production-grade

## Decision

Defer embedded packet ownership, direct TUN reads, and packet-loop ownership to
a later architecture spike.

During the cutover core phase, the proxy remains responsible for:

- producing sync-plane work signals and payload references
- local traffic classification and event emission
- transport-level proxying and transparent interception

It does not take over:

- coordinator batching or dedupe
- Oracle sink ownership
- embedded packet decryption and routing control

## Consequences

- The current kernel-routed transparent path remains the supported runtime.
- TLS preview and timing classification stay intentionally lightweight for now.
- Cutover work can focus on resolvable payload references, NATS auth/TLS, and
  operator-facing readiness clarity.

## Follow-up

- Define a separate spike for packet ownership, including TUN lifecycle,
  decrypted-packet handoff, and audit pipeline boundaries.
- Evaluate fragmented ClientHello parsing and timing-aware flow heuristics only
  after the sync-plane contract is stable.
