# Proxy to Coordinator Cutover

## Completed in this repo
- Removed the `oracle-db` build dependency path from the Rust proxy build.
- Added sync-plane contracts for:
  - `sync.scan.request`
  - `sync.oracle.load`
  - `sync.oracle.result`
- Added a thin proxy publisher seam that records and publishes `ScanRequest` messages.
- Replaced placeholder `payload_ref` values with resolvable runtime references:
  - `inline://json/<base64url>` for bounded envelopes; base64url is only the transport wrapper and must decode to UTF-8 JSON.
  - `outbox://<file>` for spooled payloads under the configured outbox directory; files must be `.json` content and parse as JSON before ingest.
- Hardened proxy payload previews so decoded audit events remain readable JSON. Captured request/response previews use `payload_preview.schema_version = 2` with JSON/text fields or metadata-only omission for binary data; nested raw/base64 body bytes are not allowed.
- Added sync publisher auth/TLS configuration and readiness-facing publisher health snapshots.
- Tightened sync publishing to an explicit allowlist of sink-worthy traffic events.
- Removed dashboard WebSocket routes from the active admin surface.
- Switched the Svelte dashboard to polling for live stats.
- Reworked the hostname classifier toward the v1 taxonomy.
- Triaged the live tunnel/proxy TODOs into durable docs and ADRs instead of speculative inline prompts.

## Remaining proxy work
- Decide whether the outbox remains filesystem-backed or moves to object storage/shared durable media.
- Remove or isolate the remaining Oracle-era `#[cfg(feature = "oracle-db")]` dead paths that still live inside tunnel handlers.
- Expose topic/payload-ref contract examples in coordinator operator docs.
- Add a compatibility window only if an external producer still emits legacy nested `payload_preview.up` / `payload_preview.down` base64 fields.

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
- `services/zig-coordinator` owns orchestration, batching, dedupe, cursor advancement, and Oracle sink behavior.
