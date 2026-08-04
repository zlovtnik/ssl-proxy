# ERED DEPLOYMENT REFACTORING WORKMAP

> **Status: Historical / superseded.** This document preserves an earlier
> Schema Migrator refactoring plan. Current internal state is TiDB-only; use
> [System Architecture](architecture.md) and
> [TiDB Runtime and Cutover](tidb-runtime-cutover.md).

## Actionable Step-by-Step Guide (No Code Required)

**Version:** 1.0  
**Source:** ered deployment document  
**Date:** 2026-07-18  
**Status:** Superseded by the TiDB state-store implementation

> Historical reference only. MongoDB-specific tasks in this document must not be
> implemented; Schema Migrator persistence now belongs to its dedicated TiDB
> account and `schema_migrator` database.

---

## TABLE OF CONTENTS

1. [How to Use This Workmap](#1-how-to-use-this-workmap)
2. [Phase 0: Pre-Flight Checklist](#2-phase-0-pre-flight-checklist)
3. [Phase 1: Establish Clean Safety Baseline](#3-phase-1-establish-clean-safety-baseline)
4. [Phase 2: Collapse Scala Core to Concrete Effects](#4-phase-2-collapse-scala-core-to-concrete-effects)
5. [Phase 3: Unify Execution and Persistence](#5-phase-3-unify-execution-and-persistence)
6. [Phase 4: Compact SQL Without Losing State](#6-phase-4-compact-sql-without-losing-existing-state)
7. [Phase 5: Simplify Web UI and Documentation](#7-phase-5-simplify-web-ui-and-documentation)
8. [Phase 6: Public Interfaces and Compatibility](#8-phase-6-public-interfaces-and-compatibility)
9. [Phase 7: Test and Acceptance](#9-phase-7-test-and-acceptance)
10. [Appendix A: Role Assignments](#appendix-a-role-assignments)
11. [Appendix B: Definition of Done](#appendix-b-definition-of-done)
12. [Appendix C: Risk Mitigation](#appendix-c-risk-mitigation)

---

## 1. HOW TO USE THIS WORKMAP

### Principles
- Each task is **independently green** — it can be merged without breaking anything
- Tasks are **ordered by dependency** — earlier phases unblock later ones
- Every task has a **Definition of Done (DoD)** — check it before moving on
- **No code blocks** — all instructions are procedural and human-readable

### Team Roles Required
| Role | Responsibility |
|------|---------------|
| **Backend Lead** | Scala refactoring, compiler flags, dependency alignment |
| **Frontend Lead** | React/TypeScript cleanup, Zod migration, SSE rewrite |
| **DevOps Lead** | CI/CD gates, Docker/Compose updates, credential rotation |
| **QA Lead** | Characterization tests, integration validation, Oracle verification |
| **Architect** | Cross-service coordination, API contract review, Mongo schema decisions |
| **Security Lead** | Credential audit, Keycloak config, git history cleanup |

### Status Tracking
Use this legend in your tracker:
- ⬜ Not started
- 🟡 In progress
- 🟢 Complete / green
- 🔴 Blocked
- ⏸️ Paused (waiting for dependency)

---

## 2. PHASE 0: PRE-FLIGHT CHECKLIST

**Goal:** Ensure the team can start safely without breaking production.

**Duration:** 1–2 days  
**Owner:** DevOps Lead + Backend Lead

### Task 0.1: Freeze Production Deployments
- [ ] Announce code freeze in team channels (Slack/email)
- [ ] Tag current production commit as `baseline-2026-07-18`
- [ ] Confirm no hotfixes are pending — if yes, merge them first and retag
- [ ] Verify production database backups are current (last 24 hours)
- [ ] Document current running versions in shared doc

**DoD:** Team agrees freeze is active; baseline tag exists; backups verified.

### Task 0.2: Set Up Feature Branches
- [ ] Create long-lived branch `refactor/ered-baseline` from main
- [ ] Set branch protection: require 2 reviews, CI must pass
- [ ] Create sub-branches for each phase (naming: `refactor/phase-1-baseline`, `refactor/phase-2-effects`, etc.)
- [ ] Document branch merge strategy in README (merge forward, not rebase)

**DoD:** All phase branches exist; protection rules active; team knows naming convention.

### Task 0.3: Inventory Current State
- [ ] List all active endpoints (backend lead reviews router/controller files)
- [ ] List all database collections and their document shapes (architect reviews Mongo)
- [ ] List all environment variables in use (security lead reviews `.env` files)
- [ ] List all frontend routes and components (frontend lead reviews `src/` tree)
- [ ] Identify which files are currently tracked in git that should not be (security lead runs `git ls-files`)

**DoD:** Shared document exists with complete inventory; no surprises later.

### Task 0.4: Verify Tooling Versions
- [ ] Check Java version on all developer machines — must be 21 (backend lead)
- [ ] Check Bun version — must be 1.3.11 (frontend lead)
- [ ] Check sbt version — document it (backend lead)
- [ ] Check Node is NOT being used — confirm Bun is the only package manager (frontend lead)
- [ ] Verify Docker Compose can spin up full stack locally (DevOps lead)

**DoD:** Every developer can run `java -version`, `bun --version`, and `docker compose up` successfully.

---

## 3. PHASE 1: ESTABLISH CLEAN SAFETY BASELINE

**Goal:** Fix formatting, enable compiler warnings-as-errors, add characterization tests, and standardize tooling before any structural changes.

**Duration:** 3–5 days  
**Owner:** Backend Lead (primary), Frontend Lead (secondary), QA Lead (tests)

### Task 1.1: Fix Existing Formatting Failures
- [ ] Run `sbt scalafmtAll` on entire backend codebase
- [ ] Review diff — if changes are only whitespace/formatting, commit directly
- [ ] If any non-formatting changes appear, stop and investigate with backend lead
- [ ] Run `bun run lint --fix` on entire frontend codebase
- [ ] Review diff — same protocol as backend
- [ ] Commit both with message: `style: apply formatting baseline`

**DoD:** `sbt scalafmtCheckAll` passes; `bun run lint` passes with zero errors.

### Task 1.2: Enable Scala Unused/Value-Discard Diagnostics as Errors
- [ ] Open `build.sbt` (or project settings file)
- [ ] Add compiler flags: `-Wvalue-discard`, `-Wunused:imports`, `-Wunused:locals`, `-Wunused:privates`
- [ ] Set `-Werror` (treat warnings as errors)
- [ ] Run `sbt compile` — expect it to FAIL with many warnings-now-errors
- [ ] Create a spreadsheet of all failures: file, line, warning type, suggested fix
- [ ] Assign fixes to backend developers (one file per person to avoid merge conflicts)
- [ ] Each developer fixes their assigned files (remove unused imports, add explicit `()` for value-discard, etc.)
- [ ] Re-run `sbt compile` until it passes
- [ ] Commit with message: `chore: enable unused/value-discard warnings as errors`

**DoD:** `sbt compile` passes with zero warnings; no `-Werror` bypasses exist.

### Task 1.3: Make Frontend Lint Fail on Warnings + Enable TypeScript Unused Checks
- [ ] Open frontend lint configuration file
- [ ] Change `max-warnings` from current value (likely 100+) to `0`
- [ ] Enable TypeScript strict mode if not already on: `strict: true` in `tsconfig.json`
- [ ] Enable `noUnusedLocals`, `noUnusedParameters` in `tsconfig.json`
- [ ] Run `bun run lint` — expect FAILURE with warnings-now-errors
- [ ] Create spreadsheet of failures: file, line, type
- [ ] Assign fixes to frontend developers
- [ ] Re-run until `bun run lint` passes with zero warnings
- [ ] Commit with message: `chore: enforce zero lint warnings and unused checks`

**DoD:** `bun run lint` exits 0; `tsc --noEmit` passes with no unused variable errors.

### Task 1.4: Add One Repository Check Command
- [ ] Create a new script/command in your build system (e.g., `sbt check` or `make check`)
- [ ] This command must run ALL of the following in sequence:
  1. Backend compile + test
  2. Frontend lint + typecheck + test
  3. SQL fixture validation (if applicable)
  4. Deployment config validation (e.g., `docker compose config`)
- [ ] If any step fails, the entire command exits with non-zero status
- [ ] Document the command in README: "Run `./check.sh` before every push"
- [ ] Commit with message: `build: add unified repository check command`

**DoD:** Running `./check.sh` (or equivalent) locally gives a single pass/fail answer for the entire repo.

### Task 1.5: Make CI Invoke the Same Check Command
- [ ] Open your CI configuration file (GitHub Actions, GitLab CI, etc.)
- [ ] Replace individual job steps with a single step that runs your unified check command
- [ ] Ensure CI uses the SAME Java 21 and Bun 1.3.11 versions as local dev
- [ ] Verify CI fails if the check command fails (test by pushing a branch with a deliberate lint error, then revert)
- [ ] Commit with message: `ci: use unified check command in pipeline`

**DoD:** A red X appears on PRs that fail any check; green checkmark only when everything passes.

### Task 1.6: Run Integration Commands Through Packaged CLI
- [ ] Identify all integration test commands currently run via `sbt run` (not `sbt test`)
- [ ] For each, create a proper CLI entry point (e.g., `sbt "runMain com.ered.cli.Validate"` becomes `java -jar ered-cli.jar validate`)
- [ ] Package the CLI as a JAR or native binary
- [ ] Update all scripts/documentation to use the packaged CLI
- [ ] Verify that a nonzero exit code from the CLI actually fails the CI step (test with invalid input)
- [ ] Commit with message: `build: package CLI and use for integration validation`

**DoD:** No `sbt run` commands in CI; all integration validation uses packaged CLI with proper exit codes.

### Task 1.7: Standardize Java 21 and Bun 1.3.11
- [ ] Update all Dockerfiles to use `eclipse-temurin:21-jdk` base image
- [ ] Update all CI matrices to specify Java 21
- [ ] Update `package.json` engines field to require Bun 1.3.11
- [ ] Add `.tool-versions` (for asdf) or `.mise.toml` specifying Java 21 and Bun 1.3.11
- [ ] Remove any Node.js or pnpm references from documentation
- [ ] Verify every developer reinstalls dependencies with `bun install` (not `npm install`)
- [ ] Commit with message: `build: standardize on Java 21 and Bun 1.3.11`

**DoD:** `docker compose build` uses Java 21; `bun --version` returns 1.3.11 on every dev machine.

### Task 1.8: Align Dependency Versions
- [ ] Open `build.sbt` — update Cats Effect to 3.7.0, FS2 to 3.13.0, log4cats to 2.8.0, PostgreSQL JDBC to 42.7.7
- [ ] Open frontend `package.json` — update React typings to 19.x
- [ ] Remove `cats-mtl` from library dependencies (search for it, delete the line)
- [ ] Add `evictionErrorLevel := Level.Error` to build settings (fails build on unresolved binary evictions)
- [ ] Run `sbt update` — if eviction errors appear, resolve them by adding explicit dependency overrides
- [ ] Run `bun install` to update lockfile
- [ ] Commit with message: `deps: align Cats Effect 3.7.0, FS2 3.13.0, log4cats 2.8.0, pg JDBC 42.7.7, React 19`

**DoD:** `sbt dependencyTree` shows correct versions; no eviction errors; `bun.lockb` updated.

### Task 1.9: Standardize Frontend Dependency Management on Bun
- [ ] Delete `pnpm-lock.yaml` if it exists
- [ ] Delete `pnpm-workspace.yaml` if it exists
- [ ] Remove any pnpm-specific scripts from `package.json`
- [ ] Delete any duplicate frontend build directories (e.g., `build/`, `dist/` that are generated but not `.gitignore`d)
- [ ] Delete unused backend entrypoint file (identify by checking which `main` method is actually invoked)
- [ ] Verify `bun install` works cleanly from scratch (delete `node_modules`, re-run)
- [ ] Commit with message: `build: remove pnpm metadata, duplicate build surfaces, unused entrypoint`

**DoD:** No pnpm files in repo; `bun install` from clean clone works; no unused backend entrypoints.

### Task 1.10: Stop Tracking Rendered Realm/Runtime Configuration
- [ ] Run `git ls-files | grep -E "(realm-export|runtime-config|\.env\.production)"` — list all tracked credential/config files
- [ ] For each file found:
  - Copy it to a template version (e.g., `realm-export.json` → `realm-export.template.json`) with placeholders like `{{PASSWORD}}`
  - Add the original file to `.gitignore`
  - Run `git rm --cached <file>` to stop tracking it without deleting local copy
- [ ] Create a `deployment-state/` directory
- [ ] Add `deployment-state/` to `.gitignore`
- [ ] Update Docker Compose to mount `deployment-state/` as read-only where needed
- [ ] Update Kubernetes manifests to use `Secret` or `ConfigMap` instead of mounted files for credentials
- [ ] Document in README: "Credential rotation is an operator action required during rollout. See OPERATIONS.md."
- [ ] Commit template files with message: `security: add config templates, stop tracking rendered credentials`
- [ ] **CRITICAL:** Do NOT rewrite git history (no `git filter-branch`) — document that old commits still contain credentials and rotation is required

**DoD:** `git ls-files` shows no credential files; templates exist; `.gitignore` updated; Compose/K8s mounts updated; ops doc written.

### Task 1.11: Add Characterization Tests
- [ ] For each area in the test plan, create a test that captures CURRENT behavior (not desired behavior):
  - Migration planning: record what `MigrationPlan.prepare` returns for a known manifest
  - Locking: record what happens when two jobs try to lock the same target simultaneously
  - Callback order: record the exact sequence of callbacks fired during a successful migration
  - Retries: record how many retries occur and with what backoff for a failing connection
  - Job transitions: record the state machine transitions (queued → running → completed)
  - SSE reconnection: record the client behavior when the server drops the connection
  - Keycloak initialization: record the initialization sequence and retry behavior
  - Schema-upgrade workflows: record the upgrade orchestration steps
  - Legacy API payloads: record the exact JSON shape of current `/patches` and `/runs` responses
- [ ] Each test should use "golden file" testing: run once, save output to `test/resources/golden/`, future runs compare against saved output
- [ ] Mark these tests as `characterization` in your test framework (tag/category)
- [ ] Commit with message: `test: add characterization tests for critical behavior areas`

**DoD:** 9+ characterization test areas covered; golden files committed; tests fail if behavior changes unexpectedly.

---

## 4. PHASE 2: COLLAPSE SCALA CORE TO CONCRETE EFFECTS

**Goal:** Remove abstract `F[_]` from orchestration/validation/discovery; make `IO` concrete everywhere except Postgres internals; delete unused abstractions.

**Duration:** 5–7 days  
**Owner:** Backend Lead (primary), Architect (review)

**⚠️ Dependency:** Phase 1 must be complete (compiler warnings-as-errors enabled, tests green).

### Task 2.1: Identify All Abstract Effect Usage
- [ ] Search codebase for `F[_]` type parameters outside of `*.persistence.*` packages
- [ ] Create a spreadsheet: file name, line number, function/class name, what `F` is currently bound to
- [ ] Categorize each occurrence:
  - Category A: Orchestration layer (must become `IO`)
  - Category B: Validation layer (must become `IO`)
  - Category C: Discovery layer (must become `IO`)
  - Category D: Callbacks (must become `IO`)
  - Category E: HTTP/routes (must become `IO`)
  - Category F: Persistence (keep as `ConnectionIO` or similar — do NOT touch yet)

**DoD:** Spreadsheet complete; every `F[_]` occurrence categorized; team agrees on categorization.

### Task 2.2: Refactor Orchestration Layer to Concrete IO
- [ ] Pick one file from Category A (e.g., `MigrationOrchestrator.scala`)
- [ ] Replace `F[_]` with `IO` in the class/trait signature
- [ ] Update all method return types from `F[Something]` to `IO[Something]`
- [ ] Update all callers of this class to expect `IO` instead of generic `F`
- [ ] Run `sbt compile` — fix any type errors that appear
- [ ] Run characterization tests — ensure behavior is identical
- [ ] Commit with message: `refactor: make MigrationOrchestrator concrete IO`
- [ ] Repeat for each Category A file, one commit per file

**DoD:** All Category A files use `IO` directly; no generic `F[_]` in orchestration; tests pass.

### Task 2.3: Refactor Validation, Discovery, Callbacks, and HTTP Layers
- [ ] Repeat the same process as Task 2.2 for Categories B, C, D, and E
- [ ] Do one category per day to keep commits small and reviewable
- [ ] For HTTP layer: ensure `IO` is used in route handlers, but `ConnectionIO` remains inside repository calls
- [ ] Commit pattern: `refactor: make <Layer> concrete IO`

**DoD:** All non-persistence layers use `IO` directly; no `F[_]` outside `*.persistence.*`.

### Task 2.4: Verify ConnectionIO Remains Private to Persistence
- [ ] Search for `ConnectionIO` or `Transactor` imports outside `*.persistence.postgres.*`
- [ ] If any found, refactor: the outer layer should call a repository method that returns `IO[A]`, not `ConnectionIO[A]`
- [ ] The repository method internally lifts `ConnectionIO` to `IO` using `transactor.transact`
- [ ] Add an ArchUnit-style test (or Scala reflection test) that asserts: "No file outside `*.persistence.postgres.*` may import `doobie.free.connection.ConnectionIO`"
- [ ] Commit with message: `refactor: ensure ConnectionIO is private to persistence`

**DoD:** `grep -r "ConnectionIO" --include="*.scala" | grep -v "persistence/postgres"` returns empty; boundary test passes.

### Task 2.5: Delete Unused Effect Primitives and Abstractions
- [ ] Confirm `EffectPrimitives.scala` has zero references (use IDE find-usages or `grep`)
- [ ] Confirm `Jdbc.scala` has zero references
- [ ] Confirm `Transaction.scala` has zero references
- [ ] Confirm `MigrationContext` has zero references
- [ ] Delete each file, one per commit: `chore: delete unused <File>`
- [ ] Run `sbt compile` after each deletion to confirm nothing broke
- [ ] Also delete: redundant engine overloads, dry-run implementation (if superseded by new `MigrationPlan.prepare`)

**DoD:** Deleted files no longer exist in repo; `sbt compile` passes; no dead code remains.

### Task 2.6: Move In-Memory Repositories and Simulated Executor to Test Fixtures
- [ ] Identify `InMemoryRepository` and `SimulatedExecutor` files in `src/main`
- [ ] Move them to `src/test/scala/.../fixtures/` (or equivalent test directory)
- [ ] Update any test imports to point to new location
- [ ] Verify no production code imports these (grep for their names in `src/main`)
- [ ] Commit with message: `test: move in-memory repos and simulated executor to fixtures`

**DoD:** Files exist only in `src/test`; production code has no test fixture imports; tests pass.

### Task 2.7: Introduce Single MigrationPlan.prepare Path
- [ ] Create (or refactor existing) `MigrationPlan.prepare` method with this contract:
  - Input: list of selected source files, target configuration, optional flags
  - Steps: discover full manifest → validate headers → validate dependencies → check for duplicate identities → validate SQL structure → resolve selected files + transitive prerequisites → produce deterministic execution phases (structural then behavioral) → return plan or reject with errors
  - Must reject invalid plans BEFORE opening any database session
- [ ] Update `list` endpoint to call `MigrationPlan.prepare(..., listOnly = true)`
- [ ] Update `validate` endpoint to call `MigrationPlan.prepare(..., validateOnly = true)`
- [ ] Update `dry-run` endpoint to call `MigrationPlan.prepare(..., dryRun = true)`
- [ ] Update CLI `apply` command to call `MigrationPlan.prepare(..., execute = true)`
- [ ] Update server job execution to call `MigrationPlan.prepare(..., execute = true)`
- [ ] Update drift detection to call `MigrationPlan.prepare(..., driftCheck = true)`
- [ ] Update rollback to call `MigrationPlan.prepare(..., rollback = true)`
- [ ] Delete old `MigrationEngine.validate`, `MigrationEngine.dryRun`, `MigrationEngine.list` methods
- [ ] Commit with message: `refactor: unify all migration ops through MigrationPlan.prepare`

**DoD:** All 7 operations (list, validate, dry-run, CLI apply, server jobs, drift, rollback) call the same `prepare` method; old methods deleted; tests pass.

### Task 2.8: Replace Duplicated Hashing with Shared SHA-256 Utility
- [ ] Search for all `MessageDigest.getInstance("SHA-256")` occurrences
- [ ] Count them — if more than 1, extraction is needed
- [ ] Create `HashUtils.sha256(bytes: Array[Byte]): String` in a shared utilities package
- [ ] Replace each occurrence with `HashUtils.sha256(...)`
- [ ] Ensure the utility uses the same encoding (hex, base64, etc.) as all previous callers
- [ ] Commit with message: `refactor: extract shared SHA-256 utility`

**DoD:** Only one `MessageDigest.getInstance("SHA-256")` exists in the entire codebase (inside `HashUtils`); all previous callers use the utility.

### Task 2.9: Replace Duplicated SQL Lexical State Machines with Shared Scanner
- [ ] Identify all SQL tokenization/lexing code (search for "token", "lexer", "state machine" in SQL-related files)
- [ ] If multiple implementations exist, create `SqlScanner.tokenize(sql: String): List[Token]`
- [ ] Migrate each SQL parser to use the shared scanner
- [ ] Ensure the Postgres drift parser is split into:
  1. Lexing phase (uses `SqlScanner`)
  2. Catalog-definition extraction phase
  3. Equivalence normalization phase
- [ ] Preserve existing behavior exactly — use characterization tests to verify
- [ ] Commit with message: `refactor: extract shared SQL scanner and split drift parser`

**DoD:** One SQL scanner exists; drift parser has 3 clear phases; characterization tests show identical output.

### Task 2.10: Rewrite Rollback Validation Without Mutable/Null State
- [ ] Open rollback validation code
- [ ] Identify all `var` (mutable variables) and `null` usage
- [ ] Replace `var` with `val` + immutable transformations (e.g., `foldLeft`, `map`)
- [ ] Replace `null` with `Option` or `Either`
- [ ] Use WartRemover `Var` and `Null` warts to enforce this going forward
- [ ] Commit with message: `refactor: make rollback validation immutable and null-safe`

**DoD:** No `var` or `null` in rollback validation; WartRemover passes; tests pass.

### Task 2.11: Replace URL Sniffing with TargetConnection Parser
- [ ] Search for all string operations on JDBC URLs: `startsWith("jdbc:postgres")`, `startsWith("jdbc:oracle")`, `split(":")`, regex matching on URL patterns
- [ ] Create `TargetConnection.parse(url: String): Either[Error, TargetConnection]`
- [ ] `TargetConnection` must expose:
  - `dbKind: DatabaseKind` (Postgres, Oracle, etc.)
  - `normalizedJdbcUrl: String` (canonical form)
  - `host: String`
- [ ] Replace every URL sniffing occurrence with `TargetConnection.parse(url)`
- [ ] Update validation logic to use `parsed.dbKind` instead of string matching
- [ ] Update provider creation to use `parsed.normalizedJdbcUrl`
- [ ] Update ping logic to use `parsed.host`
- [ ] Update host authorization to use `parsed.host`
- [ ] Update schema routes to use `parsed.dbKind`
- [ ] Update drift detection to use `parsed.dbKind`
- [ ] Commit with message: `refactor: replace URL sniffing with TargetConnection parser`

**DoD:** Zero `startsWith("jdbc:` in codebase; all URL parsing goes through `TargetConnection.parse`; tests pass.

### Task 2.12: Persist and Return db_kind on Targets
- [ ] Add `dbKind: String` field to the target document/model in Mongo
- [ ] Update target creation API to accept and store `db_kind`
- [ ] Update target retrieval API to return `db_kind`
- [ ] For old targets without `db_kind`, lazily derive it on first read using `TargetConnection.parse(target.url)`
- [ ] Store the derived value back to Mongo so next read is fast
- [ ] Commit with message: `feat: persist db_kind on targets with lazy derivation for legacy`

**DoD:** New targets store `db_kind`; old targets get it derived once; API returns `db_kind`; tests pass.

### Task 2.13: Remove Frontend Database-Kind Guessing
- [ ] Search frontend code for any logic that guesses database type from URL strings
- [ ] Replace with reading `db_kind` from the target object (now always available from backend)
- [ ] Delete any frontend URL-parsing utilities for database detection
- [ ] Commit with message: `refactor: remove frontend db kind guessing, use backend field`

**DoD:** Frontend never parses JDBC URLs; `db_kind` comes from API response; UI works for Postgres and Oracle targets.

### Task 2.14: Group Server Configuration and Build ServerComponents
- [ ] Identify all configuration values scattered in server code (auth, repository, Mongo, HTTP settings)
- [ ] Group into case classes: `AuthConfig`, `RepositoryConfig`, `MongoConfig`, `HttpConfig`
- [ ] Create `ServerComponents` as a Cats Effect `Resource` that acquires all components in order (Mongo → Repositories → HTTP → Auth)
- [ ] Create one route constructor function that takes `ServerComponents` and returns HTTP routes
- [ ] Ensure graceful shutdown: `Resource` releases components in reverse order
- [ ] Commit with message: `refactor: group server config into cohesive sections and ServerComponents resource`

**DoD:** No scattered config; one `ServerComponents` resource; clean startup/shutdown; tests pass.

---

## 5. PHASE 3: UNIFY EXECUTION AND PERSISTENCE

**Goal:** Replace patch/run model with canonical `MigrationJob`; add resource-managed worker; store SQL in content-addressed artifacts; atomic repo sync.

**Duration:** 7–10 days  
**Owner:** Architect (primary), Backend Lead (implementation), QA Lead (testing)

**⚠️ Dependency:** Phase 2 complete (concrete IO, `MigrationPlan.prepare` exists).

### Task 3.1: Design Canonical MigrationJob Aggregate
- [ ] Whiteboard session with architect + backend lead
- [ ] Define `MigrationJob` document shape:
  - `source`: where the job came from (CLI, UI, scheduled)
  - `scriptMetadata`: immutable list of scripts with hash, path, order
  - `executionStatus`: enum (queued, running, completed, failed, aborted)
  - `timestamps`: createdAt, startedAt, completedAt, lastHeartbeatAt
  - `actor`: who/what triggered it (userId, serviceAccount)
  - `errors`: list of error messages with script reference
  - `perScriptProgress`: map of scriptId → {status, startedAt, completedAt, rowsAffected}
- [ ] Review with frontend lead to ensure UI can display all fields
- [ ] Document in API contract document

**DoD:** Team agrees on document shape; contract document signed off.

### Task 3.2: Define Canonical Job Request Shapes
- [ ] Design three request types:
  1. Apply: `{ target_id, kind: "apply", source_files: [...] }`
  2. Drift: `{ target_id, kind: "drift", source_files?: [...] }` (optional files)
  3. Rollback: `{ target_id, kind: "rollback", snapshot_id: "..." }`
- [ ] Document validation rules for each (e.g., apply requires at least one file, rollback requires valid snapshot)
- [ ] Commit contract document to repo

**DoD:** Three request shapes documented; validation rules clear; frontend can implement forms.

### Task 3.3: Implement /api/jobs Endpoints
- [ ] Create `POST /api/jobs` — accepts canonical request, creates job document, returns job ID
- [ ] Create `GET /api/jobs` — list jobs with filtering (by target, status, kind, date range)
- [ ] Create `GET /api/jobs/:id` — get single job with full details
- [ ] Create `POST /api/jobs/:id/abort` — request abort (worker picks this up)
- [ ] Create `POST /api/jobs/:id/resolve` — manual resolution (for stuck jobs)
- [ ] Create `GET /api/jobs/:id/stream` — SSE endpoint for real-time progress
- [ ] All endpoints must validate input using the same validators as `MigrationPlan.prepare`
- [ ] Commit with message: `feat: add canonical /api/jobs endpoints`

**DoD:** All 6 endpoints respond correctly; Postman/curl tests pass; SSE streams events.

### Task 3.4: Replace Detached Fibers with Resource-Managed Worker
- [ ] Identify all `Fiber.start` or `spawn` calls in job execution code
- [ ] Create `JobWorker` as a Cats Effect `Resource` or `Stream`
- [ ] Worker must:
  - Atomically claim one queued job from Mongo (findAndModify with status=queued → running)
  - Maintain a lease (heartbeat update every N seconds)
  - If worker crashes, lease expires and another worker requeues the job
  - Enforce: only ONE queued or running job per target at any time (database constraint)
- [ ] Remove all `Fiber.start` calls for job execution
- [ ] Commit with message: `refactor: replace detached fibers with resource-managed job worker`

**DoD:** No `Fiber.start` for jobs; worker claims atomically; lease expires properly; one job per target enforced.

### Task 3.5: Store Job Lifecycle in Mongo Document
- [ ] Ensure `MigrationJob` document is the single source of truth for job state
- [ ] Every state transition updates the Mongo document atomically
- [ ] Script progress updates are embedded in `perScriptProgress` subdocument
- [ ] Do NOT store SQL bodies in the job document (see Task 3.6)
- [ ] Commit with message: `feat: store job lifecycle and progress in canonical Mongo document`

**DoD:** Job document reflects real-time state; queries by status/target are fast; document size < 16MB.

### Task 3.6: Store Immutable SQL Bodies in Content-Addressed Artifacts
- [ ] Create new Mongo collection: `sqlArtifacts`
- [ ] Schema: `{ _id: ObjectId, sha256: String (unique index), content: Binary, size: Int, createdAt: Date }`
- [ ] When a job is created, hash each SQL file with SHA-256
- [ ] If hash not in `sqlArtifacts`, store the binary content
- [ ] In the job document, store `scriptMetadata: [{ path: "...", sha256: "...", order: N }]` (reference only, not content)
- [ ] Update snapshots to also reference artifacts by hash instead of storing base64
- [ ] Update repository generations to reference artifacts
- [ ] Commit with message: `feat: add content-addressed SQL artifact collection`

**DoD:** `sqlArtifacts` collection exists; job documents are small; same SQL file stored once; unique index on sha256.

### Task 3.7: Build Compatibility Layer for Old Patch/Run Endpoints
- [ ] Do NOT delete `/api/patches` or `/api/runs` yet
- [ ] Create adapter code that reads from `MigrationJob` collection but exposes old JSON shape
- [ ] `GET /api/patches` → query `MigrationJob` where `kind = "apply"`, format as old patch response
- [ ] `GET /api/runs/:id` → query `MigrationJob` by ID, format as old run response
- [ ] `POST /api/patches/:id/trigger` → create new `MigrationJob` with `kind = "apply"`, return old-style response
- [ ] Mark these endpoints as deprecated in API documentation: "Deprecated — no removal date scheduled. Use `/api/jobs`."
- [ ] Ensure old two-step draft behavior still works for legacy clients
- [ ] Commit with message: `feat: compatibility adapter projecting MigrationJob through legacy patch/run endpoints`

**DoD:** Old clients work without changes; deprecated headers/docs in place; new clients use `/api/jobs`.

### Task 3.8: Remove Unused Multipart POST /patches Upload
- [ ] Verify no active client uses `POST /api/patches` with `multipart/form-data`
- [ ] Check logs for last usage (if available)
- [ ] If confirmed unused, remove the multipart handler
- [ ] Keep the SQL-file compatibility adapter (different endpoint — still active)
- [ ] Commit with message: `chore: remove unused multipart patch upload endpoint`

**DoD:** Multipart handler removed; active SQL-file adapter still works; no 404s from expected clients.

### Task 3.9: Replace Repo-Sync with Atomic Generation Pointer
- [ ] Stop writing to old `repoSync` collection (make writes no-op but don't error)
- [ ] Add `activeGenerationId: ObjectId` field to `targets` collection
- [ ] Create `sqlGenerations` collection with immutable documents:
  - `{ targetId, files: [{ path, sha256, order }], artifacts: [sha256], createdAt, previousGenerationId? }`
- [ ] Repo sync workflow:
  1. Write complete new generation to `sqlGenerations`
  2. Atomically update `targets.activeGenerationId` to new generation ID (findAndModify)
  3. After successful switch, garbage-collect old unreferenced generations
- [ ] Ensure interrupted writes never expose mixed generations (test: kill process mid-write, verify target still points to old valid generation)
- [ ] Commit with message: `feat: replace repo-sync with atomic generation pointer and garbage collection`

**DoD:** `repoSync` no longer written; generations immutable; atomic switch proven; GC works; old setting accepted as no-op.

### Task 3.10: Implement Target Deletion Policy
- [ ] Implement `DELETE /api/targets/:id` with these rules:
  - Check if any jobs exist for this target (any status) → if yes, return 409 "Cannot delete target with active jobs"
  - Check if any validations are running → if yes, return 409
  - Check if any snapshots exist → if yes, return 409
  - If clean: delete cache-like SQL generations for this target, delete repo metadata, retain audit history, remove target document
- [ ] Write unit tests for each rejection case and success case
- [ ] Commit with message: `feat: enforce target deletion policy with prerequisite checks`

**DoD:** Target deletion rejects when resources exist; succeeds when clean; audit history retained; tests cover all cases.

### Task 3.11: Build Legacy Base64 Compatibility Decoders
- [ ] For reading old documents that contain inline base64 SQL:
  - Create isolated decoder function: `decodeLegacyBase64(doc): Either[Error, ArtifactRef]`
  - On read, if document has `sqlBody` (base64 string), decode and store in `sqlArtifacts`, then return artifact reference
  - New writes always use artifact references
- [ ] Ensure this decoder is only used in read paths, not write paths
- [ ] Commit with message: `feat: add isolated compatibility decoder for legacy base64 SQL documents`

**DoD:** Old documents readable; new documents use artifacts; decoder isolated; no new base64 writes.

---

## 6. PHASE 4: COMPACT SQL WITHOUT LOSING EXISTING STATE

**Goal:** Add retired paths to manifests, fix pgvector dependency, consolidate replacement chains, clean up old definitions.

**Duration:** 4–6 days  
**Owner:** Backend Lead (primary), QA Lead (Oracle verification)

**⚠️ Dependency:** Phase 3 complete (canonical jobs, artifact storage working).

### Task 4.1: Extend Manifests with Retired/Superseded Paths
- [ ] Add `retired: List[String]` field to manifest schema (paths that are history-visible but excluded from execution)
- [ ] Add `superseded: Map[String, String]` field (old path → new path that replaces it)
- [ ] Update manifest parser to read these fields
- [ ] Update execution planner to exclude retired paths from `MigrationPlan.prepare`
- [ ] Update readiness checks to ignore retired paths
- [ ] Update drift detection to ignore retired paths
- [ ] Commit with message: `feat: add retired and superseded path tracking to manifests`

**DoD:** Manifests accept retired/superseded; retired files not executed; drift not expected for retired; tests pass.

### Task 4.2: Add Retired Status to Schema Control
- [ ] In Postgres schema control table, add `retired` to the status enum (or as a boolean flag)
- [ ] In Oracle schema control table, do the same
- [ ] Logic: only rows whose stored source path is in the manifest's `retired` list get updated to `retired` status
- [ ] If an active object shares the same schema-control key as a retired one, the active one stays active
- [ ] Commit with message: `feat: add retired status to Postgres and Oracle schema control`

**DoD:** Schema control supports retired status; active/retired coexistence handled; migration tests pass.

### Task 4.3: Fix Postgres pgvector Extension Dependency
- [ ] Find SQL that says `CREATE EXTENSION pgvector` (or similar)
- [ ] Change to reference the existing `extensions` object: `SELECT extensions.ensure('pgvector')` or equivalent
- [ ] Verify this works on fresh install
- [ ] Verify this is idempotent on existing databases (doesn't error if already installed)
- [ ] Commit with message: `fix: reference pgvector through existing extensions object`

**DoD:** Fresh install creates pgvector; existing install doesn't error; extension tests pass.

### Task 4.4: Consolidate Replacement Chains
- [ ] Identify all function/object definitions that have multiple versions in the codebase (search for similar names with suffixes like `_v1`, `_v2`, `_batch`, etc.)
- [ ] For each chain, determine which version is currently active:
  - Batch-completion implementation
  - Job-lock helpers
  - Batch-ingest implementation
  - Backlog save/list behavior
  - Non-destructive embedding-job index
- [ ] Retain ONLY the final active version
- [ ] Update all callers to use the retained version
- [ ] Mark old versions as `retired` in manifest (or delete if never deployed)
- [ ] Commit with message: `refactor: consolidate replacement chains to active definitions`

**DoD:** One active definition per chain; old versions retired or removed; repeated applies don't alternate functions.

### Task 4.5: Add Append-Only Cleanup Routines
- [ ] Identify routines that need cleanup but must be append-only (no destructive updates):
  - Singular scan recording
  - Singular batch-result processing
  - Device-cluster assignment
  - Single-row similarity-pair upsert
- [ ] For each, verify the plural/batch versions are still active in coordinator/search consumers
- [ ] Add cleanup as new append-only operations (insert tombstones, don't delete)
- [ ] Ensure coordinator and search consumers handle the tombstones correctly
- [ ] Commit with message: `feat: add append-only cleanup for unreferenced routines`

**DoD:** Cleanup runs without destructive updates; coordinator/search consumers unaffected; tests pass.

### Task 4.6: Extract Clean Postgres Table Definitions
- [ ] Identify transitional Postgres SQL files that contain both table definitions and backfill/bridge logic
- [ ] Extract clean `CREATE TABLE` / `CREATE INDEX` definitions into new authoritative files
- [ ] Keep backfill/bridge logic in separate files, marked as `retired` for fresh installs
- [ ] Ensure existing deployed databases do NOT drop compatibility columns or triggers in this phase
- [ ] Document: "Existing compatibility columns/triggers remain installed; only fresh execution plans are compacted"
- [ ] Regenerate root Postgres aggregate/reference files from the active manifest
- [ ] Ensure coordinator, search, and Integration Console contracts still match
- [ ] Commit with message: `refactor: extract clean Postgres definitions and retire transitional backfill files`

**DoD:** Clean definitions in new files; backfill marked retired; existing DBs untouched; cross-service contracts aligned.

### Task 4.7: Populate Oracle Contract Manifests
- [ ] Review all Oracle objects (packages, procedures, tables) in codebase
- [ ] Cross-reference with actual service usage: which objects are called by coordinator, search, BI, etc.?
- [ ] For objects WITH confirmed callers: add to active manifest
- [ ] For objects WITHOUT confirmed callers: mark as `inventory-required` (retain but note they need confirmation)
- [ ] Do NOT delete unconfirmed objects yet — wait for operations/BI team to confirm
- [ ] Commit with message: `docs: populate Oracle contract manifests from verified cross-service usage`

**DoD:** Oracle manifest lists active + inventory-required objects; no unconfirmed deletions; ops/BI team notified.

---

## 7. PHASE 5: SIMPLIFY WEB UI AND DOCUMENTATION

**Goal:** Zod as single source of types, canonical job API, SSE reducer, schema upgrade workflow, dead code removal, Keycloak cleanup, README rewrite.

**Duration:** 5–7 days  
**Owner:** Frontend Lead (primary), Backend Lead (API support), Security Lead (Keycloak)

**⚠️ Dependency:** Phase 3 complete (`/api/jobs` endpoints exist).

### Task 5.1: Make Zod Schemas Single Source of Frontend API Types
- [ ] Identify all TypeScript `interface` declarations that duplicate API response shapes
- [ ] For each, create a Zod schema in a shared schemas file
- [ ] Example: `const MigrationJobSchema = z.object({ ... })` then `type MigrationJob = z.infer<typeof MigrationJobSchema>`
- [ ] Replace all `as MigrationJob` casts with `MigrationJobSchema.parse(response)`
- [ ] Delete duplicate interfaces once all references migrated
- [ ] Keep representative JSON fixtures in `test/fixtures/` shared with Scala contract tests
- [ ] Commit with message: `refactor: make Zod schemas single source of API types`

**DoD:** Zero manual interfaces for API types; all parsing uses Zod; fixtures shared with backend.

### Task 5.2: Move All Active Workflows to Canonical Job API
- [ ] Update frontend migration UI to call `POST /api/jobs` instead of `POST /api/patches`
- [ ] Update drift UI to call `POST /api/jobs` with `kind: "drift"`
- [ ] Update rollback UI to call `POST /api/jobs` with `kind: "rollback"`
- [ ] Update job list page to call `GET /api/jobs`
- [ ] Update job detail page to call `GET /api/jobs/:id`
- [ ] Update abort button to call `POST /api/jobs/:id/abort`
- [ ] Update resolve button to call `POST /api/jobs/:id/resolve`
- [ ] Commit with message: `feat: migrate all UI workflows to canonical /api/jobs`

**DoD:** Network tab shows only `/api/jobs` calls; no `/api/patches` or `/api/runs` from active UI; all features work.

### Task 5.3: Replace Global Error Gating with Target-Scoped Job Safety
- [ ] Identify current global error gating logic (likely a context or hook that blocks all actions when any error exists)
- [ ] Replace with per-target safety checks:
  - If target has unresolved failures → show warning but allow other targets
  - If target has active job → disable new job buttons for that target only
- [ ] Ensure error state is scoped to target, not global application state
- [ ] Commit with message: `refactor: replace global error gating with target-scoped job safety`

**DoD:** One target's failure doesn't block others; active job on target A doesn't prevent actions on target B.

### Task 5.4: Rewrite SSE Handling as Tested Reducer
- [ ] Create `sseReducer` with explicit states: `idle`, `connecting`, `connected`, `reconnecting`, `error`, `closed`
- [ ] Actions: `connect`, `message`, `error`, `retry`, `authRefresh`, `close`
- [ ] Handle authentication inside retry logic: if 401 received, refresh token before reconnecting
- [ ] Surface terminal connection failures (after max retries) to UI with clear error message
- [ ] Write unit tests for:
  - Reconnect after gap in events
  - Authentication failure during retry
  - Terminal failure (server permanently down)
- [ ] Replace all raw `EventSource` usage in components with `useSseReducer` hook
- [ ] Commit with message: `refactor: rewrite SSE as tested reducer with auth-aware retry`

**DoD:** Reducer tests pass; no raw `EventSource` in components; auth refreshes on retry; terminal failures surfaced.

### Task 5.5: Extract Schema Upgrade Orchestration into Workflow Controller
- [ ] Identify current schema upgrade logic (likely scattered in components and API calls)
- [ ] Create `SchemaUpgradeController` with explicit states: `idle`, `checking`, `upgrade_available`, `queued`, `upgrading`, `completed`, `failed`
- [ ] One server request creates and queues the upgrade job via `POST /api/jobs` with `kind: "apply"` and special flags
- [ ] UI polls or uses SSE to track upgrade job progress
- [ ] Write tests for state transitions
- [ ] Commit with message: `feat: extract schema upgrade into tested workflow controller`

**DoD:** Upgrade has clear states; one server request starts it; UI tracks progress; tests cover transitions.

### Task 5.6: Consolidate SQL File Browser
- [ ] Identify all React components that query, tree-view, or filter SQL files
- [ ] Create single `SqlFileBrowser` component backed by React Query (TanStack Query)
- [ ] Features: directory tree, file list, search/filter, retired file indicator, superseded link
- [ ] Delete old separate query/tree/filter components
- [ ] Commit with message: `refactor: consolidate SQL file queries into SqlFileBrowser`

**DoD:** One component for SQL file browsing; React Query caching works; old components deleted.

### Task 5.7: Use Shared Modal/Confirmation Primitives
- [ ] Identify all modal dialogs in the app (likely 5–10 different implementations)
- [ ] Create shared primitives: `Modal`, `ConfirmDialog`, `AlertDialog`
- [ ] Migrate all existing dialogs to use primitives
- [ ] Ensure accessibility (ARIA labels, focus trap, escape to close)
- [ ] Commit with message: `refactor: consolidate dialogs into shared modal primitives`

**DoD:** All dialogs use shared primitives; no duplicate modal code; accessibility tests pass.

### Task 5.8: Remove Dead UI Components and CSS
- [ ] Run dead code detection tool (e.g., `knip` for TypeScript)
- [ ] List all unused components, hooks, exports, helper functions
- [ ] For each, verify it's truly unused (check imports, routes, dynamic imports)
- [ ] Delete confirmed dead code
- [ ] List all CSS selectors with zero references
- [ ] Delete unused CSS rules
- [ ] Split remaining global stylesheet into:
  - `foundation.css` (variables, reset, typography)
  - `layout.css` (grid, containers, spacing)
  - `components.css` (shared components)
  - `pages.css` (page-specific styles)
- [ ] Ensure no visual changes (pixel-perfect comparison or team review)
- [ ] Commit with message: `chore: remove dead UI components, hooks, exports, and split stylesheet`

**DoD:** `knip` reports zero unused exports; CSS split into 4 files; no visual regressions.

### Task 5.9: Remove Keycloak Password/Direct-Access-Grant Flow
- [ ] Search all configs, env files, Docker files for `VITE_KEYCLOAK_DIRECT_ACCESS_GRANTS` or `directAccessGrantsEnabled`
- [ ] Remove the environment variable from all `.env` files
- [ ] Update Keycloak realm configuration: set `directAccessGrantsEnabled: false`
- [ ] Remove Docker Compose environment variables for direct access
- [ ] Remove runtime configuration for direct access
- [ ] Delete any frontend code that uses password grant flow
- [ ] Keep redirect-based PKCE flow intact
- [ ] Allow initialization retry after transient failures (e.g., Keycloak temporarily unavailable)
- [ ] Commit with message: `security: remove Keycloak direct access grant, keep PKCE redirect flow`

**DoD:** No `DIRECT_ACCESS` references; PKCE works; retry handles transient failures; login flow tested.

### Task 5.10: Rewrite README
- [ ] Structure:
  1. Supported CLI workflows (with examples)
  2. Server/UI setup and usage
  3. Verification (how to run checks)
  4. Migration compatibility (what's deprecated, what's canonical)
  5. Deployment (Docker, K8s, credential rotation)
- [ ] Remove outdated sections
- [ ] Add table of contents
- [ ] Add troubleshooting section
- [ ] Commit with message: `docs: rewrite README for current architecture and workflows`

**DoD:** README is current; new developer can set up from scratch using only README; no stale instructions.

### Task 5.11: Explicitly Exclude Electron from Scope
- [ ] Add to README: "Electron packaging is frozen and explicitly outside the support/refactor scope."
- [ ] Do not modify any Electron files in this initiative
- [ ] Commit with message: `docs: note Electron is outside refactor scope`

**DoD:** Electron files untouched; scope documented; no accidental changes.

---

## 8. PHASE 6: PUBLIC INTERFACES AND COMPATIBILITY

**Goal:** Ensure new canonical interfaces coexist with old ones; document what changed and what remains.

**Duration:** 2–3 days  
**Owner:** Architect (primary), All Leads (review)

**⚠️ Dependency:** Phases 3–5 complete (new API, new UI, compatibility layer exists).

### Task 6.1: Document New Canonical Interface
- [ ] Create `API_CONTRACT.md` in repo root
- [ ] Document `MigrationJob` aggregate shape
- [ ] Document `/api/jobs` endpoints with request/response examples
- [ ] Document canonical job requests (apply, drift, rollback)
- [ ] Commit with message: `docs: add API contract for canonical MigrationJob interface`

**DoD:** `API_CONTRACT.md` exists; examples are copy-pasteable; shapes match implementation.

### Task 6.2: Document Additive Target Field
- [ ] Note in `API_CONTRACT.md`: "Target documents now include `db_kind` field. Legacy targets without this field will have it derived lazily on first read."
- [ ] Document valid values: `postgres`, `oracle`
- [ ] Commit with message: `docs: document db_kind as additive target field`

**DoD:** `db_kind` documented; backward compatibility explained.

### Task 6.3: Document Legacy Compatibility
- [ ] In `API_CONTRACT.md`, add section: "Legacy Compatibility"
- [ ] List old endpoints (`/api/patches`, `/api/runs`) with note: "Deprecated — no removal date. Projected through compatibility adapter."
- [ ] Document that old Mongo collections, audit history, targets, snapshots, completed runs, and schema-control hashes are NOT destructively rewritten
- [ ] Document that old `repoSync` collection setting is accepted as deprecated no-op
- [ ] Commit with message: `docs: document legacy compatibility guarantees`

**DoD:** Legacy users know their integrations won't break; no removal dates promised.

### Task 6.4: Document Removed Interfaces
- [ ] List what was removed:
  - Multipart `POST /patches` upload surface
  - `VITE_KEYCLOAK_DIRECT_ACCESS_GRANTS` environment variable
- [ ] Explain why: unused, security risk
- [ ] Suggest migration path: use `/api/jobs` with file references; use PKCE redirect flow
- [ ] Commit with message: `docs: document removed interfaces and migration paths`

**DoD:** Removed items documented; migration paths clear; no surprises for users.

### Task 6.5: Verify No Payload Contract Changes
- [ ] Confirm with architect: Redpanda topics, coordinator messages, Oracle sink payloads, application database schemas are unchanged
- [ ] Document in `API_CONTRACT.md`: "No changes to Redpanda, coordinator, Oracle sink, or application database payloads."
- [ ] Commit with message: `docs: confirm no cross-service payload contract changes`

**DoD:** Cross-service teams notified; contracts stable; no integration tests needed for other services.

---

## 9. PHASE 7: TEST AND ACCEPTANCE

**Goal:** Validate everything works before lifting the code freeze.

**Duration:** 5–7 days  
**Owner:** QA Lead (primary), All Leads (support)

**⚠️ Dependency:** All previous phases complete.

### Task 7.1: Backend Formatting and Static Analysis
- [ ] Run `sbt scalafmtCheckAll` — must pass
- [ ] Run Scalafix checks — must pass
- [ ] Confirm `-Wvalue-discard` and `-Wunused` are still errors (not warnings)
- [ ] Confirm dependency eviction check fails on unresolved evictions
- [ ] Commit any last-minute fixes with message: `style: final formatting pass`

**DoD:** Zero formatting warnings; zero unused code warnings; zero eviction issues.

### Task 7.2: Unit Tests (184+)
- [ ] Run `sbt test` — count total tests
- [ ] If count < 184, identify gaps and add tests
- [ ] Ensure all new engine/job code has failure-injection tests:
  - What happens when database connection fails mid-job?
  - What happens when artifact hash doesn't match?
  - What happens when lease expires during execution?
- [ ] Commit with message: `test: add engine and job failure-injection suites`

**DoD:** 184+ unit tests passing; failure-injection coverage for new code.

### Task 7.3: Compatibility Tests
- [ ] Create test fixtures with legacy Mongo documents (pre-refactor shape)
- [ ] Verify they are readable by new code
- [ ] Create test fixtures with base64 SQL artifacts
- [ ] Verify they decode correctly through compatibility layer
- [ ] Create test fixtures with targets lacking `db_kind`
- [ ] Verify lazy derivation works
- [ ] Create test fixtures with old patch/run JSON responses
- [ ] Verify compatibility adapter produces identical output
- [ ] Commit fixtures and tests with message: `test: add legacy compatibility fixtures`

**DoD:** Legacy data readable; adapter output matches old format; no data loss.

### Task 7.4: Worker Tests
- [ ] Test: two workers try to claim the same job simultaneously — only one succeeds
- [ ] Test: worker crashes mid-job — lease expires, job requeued, another worker picks it up
- [ ] Test: restart recovery — on startup, worker finds expired leases and requeues them
- [ ] Test: abort — `POST /api/jobs/:id/abort` stops running job, releases lock
- [ ] Test: resolve — manual resolution works for stuck jobs
- [ ] Test: lock release — after job completes (success or failure), target lock is released
- [ ] Test: artifact cleanup — unreferenced artifacts are garbage-collected
- [ ] Test: audit-write failure — if audit log write fails, job still completes but error is logged
- [ ] Commit with message: `test: add worker concurrent and failure tests`

**DoD:** All 8 worker scenarios pass; no race conditions; no stuck locks.

### Task 7.5: Repo Sync Tests
- [ ] Test: interrupt a sync write mid-generation (kill process) — verify target still points to previous valid generation
- [ ] Test: two syncs run concurrently — verify atomic pointer switch prevents mixed generations
- [ ] Test: verify old generation is garbage-collected after switch
- [ ] Commit with message: `test: add repo sync atomicity and GC tests`

**DoD:** No mixed generations under any failure scenario; GC works; tests prove it.

### Task 7.6: Frontend Tests
- [ ] Run `bun run lint` — zero warnings
- [ ] Run `tsc --noEmit` — zero type errors
- [ ] Run `bun run format:check` — zero formatting issues
- [ ] Run unit tests — all pass
- [ ] Run production build — succeeds with no errors
- [ ] Manual test: target switching — switch between two targets, verify UI state resets correctly
- [ ] Manual test: multiple unresolved failures — create failures on two targets, verify both show independently
- [ ] Manual test: SSE gaps — disconnect network, reconnect, verify UI catches up
- [ ] Manual test: SSE reconnect auth failure — expire token, verify refresh and reconnect
- [ ] Manual test: transient Keycloak failure — stop Keycloak container, restart, verify app recovers
- [ ] Commit with message: `test: frontend validation and manual acceptance`

**DoD:** Zero lint/type/format errors; all unit tests pass; production build clean; 6 manual tests verified.

### Task 7.7: Postgres Tests
- [ ] Run `sbt "testOnly *Postgres*"` — validate tests pass
- [ ] Fresh apply test: spin up empty Postgres, run full migration — must pass
- [ ] Run apply a second time — must be idempotent (no changes, no errors)
- [ ] Run apply a third time — same result
- [ ] After each apply, run `pg_get_functiondef` on all functions — verify output is stable (doesn't change between applies)
- [ ] Run drift detection — must report clean (no drift)
- [ ] Create upgrade fixture with pre-refactor schema-control rows (simulate existing deployment)
- [ ] Run migration — must succeed without dropping compatibility columns/triggers
- [ ] Commit with message: `test: Postgres validate, idempotent apply, drift, and upgrade fixture`

**DoD:** Three applies idempotent; `pg_get_functiondef` stable; drift clean; upgrade fixture passes.

### Task 7.8: Oracle Tests (Conditional)
- [ ] If Oracle test target is available:
  - Run list/validate tests
  - Run SQL statement tests
  - Run connection test
  - Run apply test (if environment supports it)
- [ ] If Oracle test target is NOT available:
  - Document in test report: "Oracle validation pending — test target unavailable"
  - Ensure Oracle SQL compiles (syntax check)
- [ ] Commit with message: `test: Oracle validation (or documented pending status)`

**DoD:** Oracle tests pass if target available; otherwise documented as pending.

### Task 7.9: Cross-Service Tests
- [ ] Run coordinator tests — verify no regressions
- [ ] Run Atheros Search tests — verify no regressions
- [ ] Verify root aggregate consistency (Postgres reference files match coordinator/search expectations)
- [ ] Run `docker compose config` — validates Compose configuration
- [ ] Run image builds — `docker compose build` succeeds for all services
- [ ] Run Kubernetes client-side validation — `kubectl apply --dry-run=client -f k8s/` succeeds
- [ ] Commit with message: `test: cross-service and deployment validation`

**DoD:** All cross-service tests pass; Docker builds clean; K8s configs valid.

### Task 7.10: Deployment Readiness Gates
- [ ] Check: no unresolved legacy active runs exist in production database
- [ ] Check: job worker can claim work (verify in staging environment)
- [ ] Check: compatibility-adapter usage is logged (verify structured logs show adapter calls)
- [ ] Check: expired leases are logged with structured format
- [ ] If any check fails, deployment is blocked — fix before proceeding
- [ ] Document readiness check results in deployment runbook
- [ ] Commit with message: `ops: add deployment readiness checks`

**DoD:** All gates pass; runbook updated; deployment approved.

---

## APPENDIX A: ROLE ASSIGNMENTS

### Backend Lead
- Phase 1: Tasks 1.1, 1.2, 1.4–1.9, 1.11
- Phase 2: ALL tasks (2.1–2.14)
- Phase 3: Tasks 3.1–3.3, 3.5–3.7, 3.9–3.11
- Phase 4: Tasks 4.1–4.6
- Phase 5: Task 5.2 (API support)
- Phase 7: Tasks 7.1–7.3, 7.7–7.8

### Frontend Lead
- Phase 1: Tasks 1.1 (frontend), 1.3, 1.9
- Phase 2: Task 2.13
- Phase 5: ALL tasks (5.1–5.11)
- Phase 7: Task 7.6

### DevOps Lead
- Phase 0: ALL tasks
- Phase 1: Tasks 1.4–1.7, 1.10
- Phase 3: Tasks 3.4, 3.9
- Phase 7: Tasks 7.9–7.10

### QA Lead
- Phase 1: Task 1.11
- Phase 3: Tasks 3.5, 3.10
- Phase 4: Task 4.7
- Phase 7: ALL tasks (7.1–7.10)

### Architect
- Phase 0: Task 0.3
- Phase 2: Tasks 2.1, 2.7, 2.11, 2.14
- Phase 3: Tasks 3.1, 3.2, 3.6, 3.9
- Phase 6: ALL tasks (6.1–6.5)
- Phase 7: Task 7.4

### Security Lead
- Phase 0: Task 0.3 (env vars)
- Phase 1: Task 1.10
- Phase 5: Task 5.9
- Phase 7: Task 7.10 (readiness checks)

---

## APPENDIX B: DEFINITION OF DONE

### For Every Task
- [ ] Code changes committed to appropriate phase branch
- [ ] Commit message follows conventional commits (`feat:`, `refactor:`, `chore:`, `test:`, `docs:`, `security:`, `build:`)
- [ ] Characterization tests pass (behavior unchanged)
- [ ] Unit tests pass (`sbt test`, `bun test`)
- [ ] Lint/format checks pass (`sbt scalafmtCheckAll`, `bun run lint`)
- [ ] Type checks pass (`tsc --noEmit`, `sbt compile`)
- [ ] PR reviewed by at least one other lead
- [ ] PR merged to `refactor/ered-baseline` via merge commit (not rebase)
- [ ] Task status updated to 🟢 in tracker

### For Every Phase
- [ ] All tasks in phase are 🟢
- [ ] Phase branch passes full CI pipeline
- [ ] Integration tests pass on phase branch
- [ ] Phase demo given to team (15 min walkthrough)
- [ ] Phase document updated with any deviations from plan
- [ ] Sign-off from phase owner

---

## APPENDIX C: RISK MITIGATION

| Risk | Likelihood | Impact | Mitigation |
|------|-----------|--------|------------|
| Phase takes longer than estimated | High | Medium | Buffer days built into schedule; can parallelize tasks within phase |
| Characterization tests catch unexpected behavior change | Medium | High | Stop immediately, investigate with architect; do not override test without team agreement |
| Credential rotation required during rollout | Medium | High | Security lead prepares rotation runbook before deployment; test in staging first |
| Oracle test target unavailable | Medium | Low | Document as pending; syntax-check SQL only; schedule Oracle validation for next sprint |
| Frontend type migration breaks runtime | Medium | Medium | Add runtime validation (Zod parse) alongside types; test all API calls in staging |
| Mongo migration fails on large collections | Low | High | Test migration on production-sized dataset in staging; run during low-traffic window |
| Job worker has race condition in production | Low | Critical | Extensive worker tests (Task 7.4); staging soak test for 48 hours; monitor locks in production |
| Electron build breaks accidentally | Low | Medium | Explicitly exclude from scope; CI skips Electron directory; code review checklist includes "no Electron changes" |
| Git history still contains credentials | Medium | High | Documented in ops runbook; rotate all credentials after deployment; do NOT rewrite history (breaks tags) |
| Parent repo schema-migrator submodule pointer conflict | Low | Medium | Verify submodule pointer before each merge; architect reviews all submodule changes |

---

## ASSUMPTIONS VALIDATION

Before starting, confirm these assumptions with stakeholders:

- [ ] **Postgres and Oracle remain supported** — confirm with product owner
- [ ] **Web UI remains supported** — confirm with product owner
- [ ] **Electron is frozen and excluded** — confirm with product owner
- [ ] **Existing deployed database state takes precedence** — confirm with DBA/ops
- [ ] **Existing Postgres compatibility columns/triggers remain installed** — confirm with DBA
- [ ] **Oracle objects without confirmed owner are retained pending inventory** — confirm with BI/ops
- [ ] **Credential rotation is an operator action required during rollout** — confirm with security/ops
- [ ] **Parent repo schema-migrator submodule pointer difference is pre-existing** — confirm with architect

**Sign-off:** _______________ Date: _______________

---

## QUICK REFERENCE: COMMIT MESSAGE PREFIXES

| Prefix | Use For |
|--------|---------|
| `feat:` | New features (jobs API, artifact collection, generation pointer) |
| `refactor:` | Code restructuring (concrete IO, URL parser, plan path) |
| `chore:` | Maintenance (delete unused code, formatting, deps) |
| `test:` | Tests (characterization, worker, compatibility) |
| `docs:` | Documentation (README, API contract, ops runbook) |
| `security:` | Security changes (credential untracking, Keycloak removal) |
| `build:` | Build/CI changes (check command, version alignment) |
| `fix:` | Bug fixes (pgvector reference, drift parser) |
| `style:` | Pure formatting (scalafmt, lint fix) |

---

## END OF WORKMAP

**Next Step:** Schedule kickoff meeting with all leads. Review Phase 0 together. Assign Task 0.1 owner.
