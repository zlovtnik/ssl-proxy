# Proxy to Coordinator Cutover

## Completed in this repo
- Removed the `oracle-db` build dependency path from the Rust proxy build.
- Added sync-plane contracts for:
  - `sync.scan.request`
  - `sync.oracle.load`
  - `sync.oracle.result`
- Added a thin proxy publisher seam that records and publishes `ScanRequest` messages.
- Replaced placeholder `payload_ref` values with resolvable runtime references:
  - `inline://json/<base64url>` for bounded envelopes
  - `outbox://<file>` for spooled payloads under the configured outbox directory
- Added sync publisher auth/TLS configuration and readiness-facing publisher health snapshots.
- Tightened sync publishing to an explicit allowlist of sink-worthy traffic events.
- Removed dashboard WebSocket routes from the active admin surface.
- Switched the Svelte dashboard to polling for live stats.
- Reworked the hostname classifier toward the v1 taxonomy.
- Triaged the live tunnel/proxy TODOs into durable docs and ADRs instead of speculative inline prompts.

## Remaining proxy work
- Teach the coordinator/worker side to resolve `outbox://...` payload references from the shared runtime location.
- Decide whether the outbox remains filesystem-backed or moves to object storage/shared durable media.
- Remove or isolate the remaining Oracle-era `#[cfg(feature = "oracle-db")]` dead paths that still live inside tunnel handlers.
- Expose subject/payload-ref contract examples in coordinator and worker operator docs.

## Required proxy behavior changes
- Keep header-aware request and response handling instead of blind header copying.
- Add optional tracking-header stripping behind configuration.
- Keep browser profile separation.
- Preserve WebRTC leak prevention.
- Preserve timezone consistency across emitted events.

## Explicitly out of scope
- Fake persona generation.
- Automated noise browsing.
- Identity manipulation logic.
- Embedded BoringTun/TUN packet ownership during the cutover core phase.

## Ownership boundary
- The proxy produces work signals and metadata.
- `services/zig-coordinator` owns orchestration, batching, dedupe, and cursor advancement.
- `services/oracle-worker` owns Oracle sink behavior.
