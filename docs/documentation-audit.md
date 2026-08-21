# Documentation Audit

> **Generated:** 2026-08-19
> **Scope:** All `.md` files, Makefiles, Dockerfiles, shell scripts, YAML manifests,
> Python scripts, proto files, SQL files, TOML files, JSON files, and cross-references
> across the entire `ssl-proxy` repository.
> **Total files audited:** 48 markdown + 100+ non-markdown files

---

## Executive Summary

| Metric | Value |
|--------|-------|
| Total markdown files | 48 |
| Total markdown lines | ~7,634 |
| Historical/superseded docs | 7 (2,709 lines) |
| Legacy SQL archives | 33 files (9,696 lines) |
| Broken cross-references | 8 high-severity |
| Stale architectural references | 5 medium-severity |
| Content duplications | 7 topics duplicated 2-4x |
| Missing standard files | LICENSE, CONTRIBUTING, CHANGELOG |
| Root Makefile help target | Missing |

**The repository is well-maintained.** Historical documents are properly flagged.
The issues below are organizational (duplication, stale references in historical docs)
and structural (missing standard files, AGENTS.md redundancy) rather than content rot.

---

## 1. AGENTS.md Files — Structural Issues

### 1.1 Redundancy Across 8 Files

| Rule | Root | services/ | sensor | search | octopus | migrator | UI |
|------|------|-----------|--------|--------|---------|----------|----|
| TiDB-only, no PG runtime | x | x | x | x | x | x | - |
| No direct DB from sensor | x | x | x | - | - | - | - |
| Append-only migrations | x | x | - | - | - | - | - |
| Do not edit `target/`, `.omx/` | x | x | - | - | x | - | - |
| Structured logging, no secrets | x | x | x | x | x | x | x |
| Verification commands | x | x | x | x | x | x | x |

**Recommendation:** Each rule should exist once. Root = global. Subtree = service-specific only.

### 1.2 Root AGENTS.md Contains Service-Specific Content

The root file (151 lines) includes:
- **Architecture Guardrails** (lines 46-79) — only relevant when editing service boundaries
- **Kubernetes Management** (lines 81-99) — only relevant when editing `cyber-stack/`
- **Verification** (lines 126-141) — lists all service test commands

An agent editing `services/octopus/` loads all 151 lines when only ~25 are relevant.

### 1.3 Inconsistent Depth

| File | Lines | Role |
|------|-------|------|
| `apps/integration-console/AGENTS.md` | 12 | Just a pointer to child |
| `apps/integration-console/atheros-search-ui/AGENTS.md` | 59 | Full standalone rules |
| `services/octopus/AGENTS.md` | 39 | Focused service rules |

The 12-line pointer file adds no value — the child file's Scope section already covers it.

### 1.4 YAML Agent Config Mixed with Markdown Rules

`.agent.md` contains a YAML frontmatter block (`name: ssl-proxy-agent`, `version`,
`persona`, etc.) appended after the markdown rules. This is a separate concern (opencode
agent definition) that should live in a dedicated config file, not mixed into the rules
document.

**Recommendation:** Move agent definition to `.opencode/agents/ssl-proxy.yaml` or similar.

---

## 2. Broken Cross-References (High Severity)

### 2.1 `.agent.md` References Deleted Directory

| Line | Reference | Status |
|------|-----------|--------|
| 20 | `apps/ssl-proxy-dashboard/**` | **DOES NOT EXIST** — dashboard removed |
| 7 | `"the dashboard"` in persona text | **STALE** — no active dashboard |

### 2.2 Compliance Workmap References Non-Existent Paths

`docs/ssl-proxy-compliance-audit-enhancement-workmap.md` (marked historical) references
files/directories that never existed:

| Lines | Reference | Status |
|-------|-----------|--------|
| 92, 99, 117, 153, 179, 242, 246 | `src/db/types.rs`, `src/db/inserts.rs`, `src/db/writer.rs`, `src/db/mod.rs` | **NEVER EXISTED** |
| 92, 106, 116, 157, 160, 184, 196, 206, 289 | `sql/oracle.sql` at repo root | **NEVER EXISTED** — Oracle SQL is at `apps/schema-migrator/sql/oracle/` |
| 263 | `deploy/`, `infra/` | **NEVER EXISTED** |
| 189, 194 | `src/cache.rs` | **NEVER EXISTED** |
| 94 | `IDENTITY_HEADER` env var | **NEVER IMPLEMENTED** |
| 249 | `ORACLE_BATCH_SIZE` env var | **NEVER IMPLEMENTED** |
| 258 | `PER_USER_MAX_CONNECTIONS` env var | **NEVER IMPLEMENTED** |

### 2.3 Historical Docs Reference Deleted Services

| File | Reference | Status |
|------|-----------|--------|
| `docs/zig-coordinator-scala-migration-workmap.md` | `services/zig-coordinator` | **DELETED** — replaced by `services/octopus` |
| `docs/vec-worker-intelligence-workmap.md` | `services/vec-worker` | **DELETED** — retired |

### 2.4 `docs/bugs.md` References Sensor Paths Without Prefix

Lines 13, 42, 50, 62, 74, 95, 117, 135, 137, 143, 157, 159, 161, 163, 165 reference
`src/audit/bandwidth.rs`, `src/capture.rs`, `src/main.rs`, etc. as if they were at the
repo root `src/`. These exist only under `services/atheros-sensor/src/`.

### 2.5 `docs/readme-inventory.txt` Is Incomplete

Lists 13 README files but misses `services/traffic_audit/README.md`.

---

## 3. Stale Architectural References (Medium Severity)

### 3.1 Oracle Treated as Active Runtime

| File | Issue |
|------|-------|
| `docs/ssl-proxy-compliance-audit-enhancement-workmap.md` | Treats Oracle as primary compliance store (45+ references) |
| `docs/ered-deployment-refactoring-workmap.md` | Treats Oracle as active target (15+ references) |
| `docs/zig-coordinator-scala-migration-workmap.md` | Oracle JDBC, Oracle adapter, Oracle wallets (30+ references) |

All three are marked "Historical/superseded" but their bodies read as active planning.

### 3.2 PostgreSQL Treated as Runtime Store

| File | Issue |
|------|-------|
| `docs/zig-coordinator-scala-migration-workmap.md` | PostgreSQL as primary runtime store (50+ references) |
| `docs/ered-deployment-refactoring-workmap.md` | PostgreSQL as active target (6+ references) |
| `docs/ssl-proxy-compliance-audit-enhancement-workmap.md` | "coordinator dedupes in Postgres" (line 55) |

### 3.3 Stale Title

`services/octopus/tidb/README.md` — Title says "migrating the coordinator's Oracle
sink to TiDB" which is a completed migration. Content is still useful but title is
misleading.

---

## 4. Content Duplications

### 4.1 Topics Duplicated Across Multiple Files

| Topic | Files | Recommendation |
|-------|-------|----------------|
| Component ownership table | `README.md`, `AGENTS.md`, `docs/architecture.md` | `architecture.md` is canonical; remove from others |
| Topic contracts (`sync.scan.request`, etc.) | `README.md`, `AGENTS.md`, `architecture.md`, `octopus/README.md` | `architecture.md` is canonical |
| Common check commands | `README.md`, `AGENTS.md`, `services/AGENTS.md`, 3 service AGENTS.md files | Each service lists only its own |
| Jenkins CI / registry workflow | `docs/jenkins-ci.md`, `docs/local-registry-workflow.md` | Merge or cross-reference |
| Security/secret handling | `secret-management.md`, `threat-model.md`, `AGENTS.md` | Each is authority for its topic; acceptable |
| Observability topology | `observability-architecture-jaeger.md`, `runbooks/observability.md` | Architecture vs. runbook; acceptable |
| `make publish` commands | `local-registry-workflow.md`, `runbook.md`, `jenkins-ci.md` | Consolidate to one source |

### 4.2 Oracle/Postgres CONTRACT.md Files

`apps/schema-migrator/sql/postgres/contracts/CONTRACT.md` and
`apps/schema-migrator/sql/oracle/contracts/CONTRACT.md` are **identical** except for
the title word. Oracle is deprecated compatibility material.

---

## 5. Missing Standard Files

| File | Status | Impact |
|------|--------|--------|
| `LICENSE` | **MISSING** — README badge claims MIT but no LICENSE file exists | Legal ambiguity |
| `CONTRIBUTING.md` | **MISSING** | No contributor guidance |
| `CHANGELOG.md` | **MISSING** | No release history |
| `.editorconfig` | **MISSING** | No cross-editor formatting consistency |

---

## 6. Non-Markdown Documentation Issues

### 6.1 Root Makefile

- **No `help` target** — `apps/wg-key-rotator/Makefile` has a rich help target; root does not
- **No header comment** — first line is a variable definition
- **One inline comment** (line 32-33) explains traffic_audit/wg-key-rotator exclusion

### 6.2 Proto File

`services/atheros-search/proto/atheros/search/v1/search.proto` — **zero comments** in
114-line API contract file. The canonical search API contract has no documentation.

### 6.3 Cyber-Stack YAML Manifests

~90+ YAML files with almost no comments. Only 3 files have any comments:
- `base/kustomization.yaml` — section labels
- `base/telemetry/jaeger.yaml` — v1 preservation note
- `base/schema-migrator/traefik.yaml` — replica explanation

### 6.4 Shell Scripts Without Headers

These scripts have no header comments or docstrings:
- `scripts/lib/ops-python.sh`
- `scripts/check-column-limits.sh`
- `scripts/k8s-namespace-status.sh`
- `docker/entrypoint.sh` (1077 lines, echo-only documentation)
- `docker/jenkins/dind-entrypoint.sh`
- `docker/minio/init.sh`
- `docker/redpanda/bootstrap.sh`
- `k8s/tidb/generate-tls-secrets.sh`
- `setup-ubuntu.sh`
- `tests/smoke.sh`
- `apps/schema-migrator/deploy/instance/start.sh`

### 6.5 Dockerfiles Without Comments

These Dockerfiles have no comments explaining build stages or rationale:
- `Dockerfile` (root) — one comment on openssl-sys, otherwise bare
- `k8s/tidb-schema-executor/Dockerfile`
- `docker/jenkins/Dockerfile` (64 lines, version ARGs only)
- `services/atheros-search/Dockerfile`
- `apps/wg-key-rotator/Dockerfile`
- `apps/integration-console/atheros-search-ui/Dockerfile`

### 6.6 Cargo.toml Files

Root `Cargo.toml`, `crates/sync-plane/Cargo.toml`, `services/atheros-sensor/Cargo.toml`
all lack `description` and `documentation` fields.

---

## 7. Historical Documents — Properly Flagged

All 7 historical documents are correctly marked with status blockquotes:

| File | Lines | Status |
|------|-------|--------|
| `docs/ssl-proxy-compliance-audit-enhancement-workmap.md` | 411 | Historical workmap |
| `docs/ered-deployment-refactoring-workmap.md` | 1,086 | Historical / superseded |
| `docs/zig-coordinator-scala-migration-workmap.md` | 863 | Superseded / completed |
| `docs/proxy-zig-rust-cutover.md` | 47 | Historical / superseded |
| `docs/vec-worker-intelligence-workmap.md` | 113 | Historical / superseded |
| `docs/adr/0001-oracle-sink-v1.md` | 28 | Superseded |
| `docs/adr/0002-packet-ownership-deferred.md` | 53 | Superseded |

**Note:** While headers are correct, bodies contain active-sounding references that
could mislead readers who skip the header.

---

## 8. Well-Documented Areas

Credit where due — these areas are exemplary:

| Area | Quality |
|------|---------|
| `sql/tidb/` SQL files | Every file has `-- object`, `-- depends_on` headers plus architectural rationale |
| `scripts/*.py` Python scripts | Every script has module-level docstrings; several have class/function docs |
| `apps/wg-key-rotator/Makefile` | Full help target with descriptions, env vars, examples |
| `services/traffic_audit/Dockerfile` | Excellent inline docs on tshark/JA3 and security posture |
| `docs/architecture.md` | Canonical, Mermaid diagrams, clean tables, 13 back-references |
| `services/octopus/README.md` | Comprehensive config reference, processor ownership table |
| `cyber-stack/platform-input-contract.yaml` | Self-documenting through structured fields |
| `sql/tidb/contracts/processors.json` | Self-documenting processor catalog (25 processors) |

---

## 9. Recommendations

### Priority 1: Structural

1. **Consolidate AGENTS.md hierarchy** — Root = global rules (~60 lines). Subtree = service-specific only. Remove duplicated guardrails. Delete `apps/integration-console/AGENTS.md` (useless pointer).
2. **Separate agent config** — Move YAML agent definition from `.agent.md` into `.opencode/agents/ssl-proxy.yaml`.
3. **Add `LICENSE` file** — README claims MIT; the file must exist.

### Priority 2: Broken References

4. **Fix `.agent.md`** — Remove `apps/ssl-proxy-dashboard/**` from include patterns. Remove dashboard from persona text.
5. **Fix `docs/bugs.md`** — Prefix sensor source paths with `services/atheros-sensor/`.
6. **Update `docs/readme-inventory.txt`** — Add missing `services/traffic_audit/README.md`.

### Priority 3: Stale Content in Historical Docs

7. **Add body-level warnings** to historical docs — After the header status blockquote,
   add: "The sections below describe the superseded state and contain references to
   files, services, and technologies that no longer exist."

### Priority 4: Documentation Gaps

8. **Add `help` target to root Makefile** — Mirror `apps/wg-key-rotator/Makefile` pattern.
9. **Add comments to `search.proto`** — Document RPCs, enums, and message fields.
10. **Add header comments to undocumented shell scripts** — At minimum, a one-line
    description of purpose.
11. **Add `CONTRIBUTING.md`** — Document PR process, testing requirements, code style.

### Priority 5: Deduplication

12. **Remove component table from `README.md`** — Link to `docs/architecture.md` instead.
13. **Remove topic contracts from `AGENTS.md`** — Link to `docs/architecture.md`.
14. **Consolidate Jenkins/registry docs** — Merge `jenkins-ci.md` and
    `local-registry-workflow.md` or add explicit cross-references.
15. **Update `services/octopus/tidb/README.md` title** — Remove migration framing.

---

## 10. Cross-Reference Health Map

Most-referenced documents (hub documents):

| Document | Back-references | Role |
|----------|-----------------|------|
| `docs/architecture.md` | 13 | Central architecture hub |
| `docs/tidb-runtime-cutover.md` | 7 | TiDB operational contract |
| `docs/threat-model.md` | 5 | Security threat model |
| `docs/secret-management.md` | 4 | Secret handling policy |
| `docs/atheros-search-privacy.md` | 3 | Privacy policy |
| `docs/observability-architecture-jaeger.md` | 2 | Observability topology |
| `docs/runbook.md` | 1 | Operations runbook |

All referenced files exist. No broken inbound references to hub documents.
