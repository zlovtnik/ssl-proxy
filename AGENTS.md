# AGENTS.md

## Scope
This file governs the entire repository rooted here.

## Working Style
- Read the codebase before changing it.
- Prefer `rg` / `rg --files` for search and file discovery.
- Use `apply_patch` for edits. Avoid ad hoc file rewrites.
- Keep changes ASCII unless a file already uses Unicode for a clear reason.
- Do not revert, overwrite, or “tidy up” edits you did not make.
- Assume the workspace may be dirty; stay inside your assignment.

## Repo Anatomy
- `src/` is the Rust service core.
- `apps/ssl-proxy-dashboard/` is the SvelteKit dashboard.
- `services/zig-coordinator/` is the control plane scaffold for Postgres state and JetStream orchestration.
- `services/oracle-worker/` is the Oracle sink worker scaffold.
- `sql/` contains schema, views, and migrations.
- `scripts/` and `setup-ubuntu.sh` are operational helpers.
- `docs/` holds design, threat-model, compliance, and runbook material.

## Architecture Guardrails
- Treat the Rust proxy as a producer of sync-plane work, not as an Oracle client.
- Keep Oracle ownership in `services/oracle-worker/`; do not reintroduce direct Oracle wiring into `src/`.
- Keep coordinator concerns in `services/zig-coordinator/`: cursoring, dedupe, job state, batching, and result handling.
- Use the locked subjects and meanings:
  - `sync.scan.request` for proxy-to-coordinator work discovery
  - `sync.oracle.load` for coordinator-to-worker batch dispatch
  - `sync.oracle.result` for worker-to-coordinator batch outcomes
- Keep delivery semantics at-least-once with dedupe in Postgres.

## Change Rules
- Keep Rust changes localized and deliberate.
- Treat SQL migrations as append-only unless a task explicitly says otherwise.
- Preserve dashboard structure and API contracts unless the user asks for a UI or contract change.
- Avoid introducing new dependencies unless they clearly earn their keep.
- If you touch generated, runtime, or environment-specific files, say so plainly.
- Do not add a new direct Oracle path, wallet dependency, or `oracle-db` feature gate back into the proxy.
- Keep the dashboard on HTTP polling unless the user explicitly asks for a streaming transport.
- Keep proxy classification aligned to the current taxonomy:
  - `ads_tracker`
  - `analytics`
  - `cdn`
  - `essential_api`
  - `auth`
  - `unknown`

## Verification
- Run the smallest meaningful checks for the files you changed.
- Prefer targeted tests over broad test suites when possible.
- If a check cannot be run, state the blocker and the risk.
- Do not claim success without evidence from a command, test, or build result.

## Review Discipline
- Call out correctness, security, and regression risks first.
- Keep feedback concrete: file, line, behavior, impact.
- If a fix has tradeoffs, name them rather than smoothing them over.

## House Rules
- Respect existing conventions before inventing new ones.
- Keep commits, branches, and filenames boring where possible.
- When the codebase is loud, answer with precision.
