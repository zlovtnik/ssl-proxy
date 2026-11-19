# Octopus Rust migration: complete file inventory

> **Status: Runtime migration in progress.** Catalogued 2026-11-15; delivery
> scaffold added 2026-11-16; native library implementation began 2026-11-17.

This inventory records baseline file dispositions and staged migration gates.
The user subsequently authorized the full G1-G5 implementation and proposed
Rust dependencies. Current implementation evidence and remaining work are
recorded in the [native capability ledger](../services/octopus-rs/INGESTION-AUDIT.md).
The source snapshot is parent `9a89488e872cded6b76735fb30750e0042609e31`,
Octopus submodule `6e94b74f219ab56a6c6104c4baa5bedf75fbce28`. Both were clean
at survey start. The inventory includes every file returned by `git -C
services/octopus ls-files`: **262 files**, including **136 production Scala
files / 25,381 lines** and **92 Scala test files / 17,436 lines**. Counts include
comments and blank lines; they are scope measurements, not complexity scores.

All production packages were assigned to a static survey. Test files were
catalogued and critical behavior suites inspected; this is not a claim that
every assertion or runtime branch has been executed or formally verified.
Generated files, local caches, and untracked runtime artifacts are excluded.
External dependencies are not counted as Octopus submodule files. The delivery
dependencies verified for this section are recorded below; the remaining
runtime migration still needs a complete dependency map.

Each file below has a migration disposition. These are proposed outcomes, not
permission to mechanically translate every file. In particular, forwarding
adapters, unused wiring, JVM configuration, source-scanning tests and sbt glue
need replacement or deliberate retirement rather than literal ports. Keep all
supported behavior until a separate retirement decision is recorded.

## Build, delivery, and documentation

**Scope: Delivery tooling implemented; native library migration IN_PROGRESS.**
The isolated [Rust workspace](../services/octopus-rs/README.md) contains an
active library manifest, lockfile, configuration/domain/catalog utilities,
PostgreSQL base and intake, broker adapter and DQ contract slices. The executable
and full runtime remain pending. This section resolves the 22 generic dispositions into
a staged handoff. The [parent Cargo workspace](../Cargo.toml) contains
the proxy, sync-plane and sensor only. Keep the functioning Scala build until
the replacement gates below pass. Line counts retain the original survey
snapshot; they are not proposed Rust sizes.

The [root instructions](../AGENTS.md), [service boundaries](../services/AGENTS.md)
and [Octopus instructions](../services/octopus/AGENTS.md) require unchanged
durable contracts, executor-owned DDL, Docker-backed integration evidence,
coverage safeguards, and reviewed Git/Argo CD delivery. The tasks below preserve
those requirements. Approved dependencies are introduced in the independent
native workspace; production build and launch paths continue to use Scala.

### Execution checkpoint: 2026-11-18

The following bounded deliverables are **DONE_VERIFIED** with Rust **1.100.0**.
This status applies to the described slice, not the whole corresponding Scala
package or migration gate. Changes are local workspace edits; no native image
has been promoted or deployed.

| Finished slice | Implementation and verification | Scope of evidence |
| --- | --- | --- |
| Independent native build and toolchain | [Cargo manifest](../services/octopus-rs/Cargo.toml), [lockfile](../services/octopus-rs/Cargo.lock), [toolchain](../services/octopus-rs/rust-toolchain.toml), [core runner](../services/octopus-rs/scripts/ci/core.sh) | Rust 1.100.0, rustfmt, warnings-as-errors Clippy, locked tests and release **library** build pass. CI and image templates use the same version; no executable exists. |
| Configuration, identities and processor catalog | [Config](../services/octopus-rs/src/config.rs), [domain](../services/octopus-rs/src/domain.rs), [utilities](../services/octopus-rs/src/util.rs), [catalog/retries](../services/octopus-rs/src/processor.rs), [redaction](../services/octopus-rs/src/errors.rs) | Tested defaults/env precedence, secrets, validation, wire decoding, distinct UTF-16/UTF-8 identity rules, streaming payload inspection, 28 known IDs/26 Octopus owners/five consumers, selection and retries. Standalone config comparisons skip at runtime when Scala resources are absent. |
| PostgreSQL resource and transaction base | [PostgreSQL module](../services/octopus-rs/src/postgres.rs), [contract tests](../services/octopus-rs/tests/postgres_contract.rs) | Schema-preflight contracts, failure classification, worker/health capacity and real Docker transaction cancellation/rollback/eviction pass. Deadline eviction compares the subsequent backend with the connection that actually timed out. Full TLS/client-store parity remains open. |
| Durable raw intake | [Intake](../services/octopus-rs/src/ingestion.rs), [wireless hydration](../services/octopus-rs/src/ingestion/wireless.rs), [integration tests](../services/octopus-rs/tests/ingestion_contract.rs) | Canonical-executor-provisioned PostgreSQL tests pass for intake/evidence atomicity, replay/conflicts, unknown-stream completion, eligible job/batch staging, heartbeat monotonicity and hydration. Thirteen typed load implementations and load/result dispatch are not completed by this slice. |
| Broker common boundary and adapter | [Kafka module](../services/octopus-rs/src/kafka.rs), [adapter test](../services/octopus-rs/tests/kafka_contract.rs) | Boundary tests and librdkafka mock test pass for partition processing, acknowledged effects, offset commits and restart. The mock restart wait accommodates its 29-second election delay. This is not five-consumer Redpanda or outage/replay parity evidence. |
| DQ pure contracts | [DQ module](../services/octopus-rs/src/dq.rs), [contract tests](../services/octopus-rs/tests/dq_contract.rs) | Ten tests pass for exact decimals/canonical hashes, schemas, scopes, principals, artifact references and dispatch budgets. DQ stores, snapshots, worker reports, fenced application and external acceptance remain pending. |
| Coverage tooling and migration inventory | [Coverage collector](../services/octopus-rs/scripts/run_coverage.py), [checker](../services/octopus-rs/scripts/check_coverage.py), [migration checker](../services/octopus-rs/scripts/check_migration.py) | 49 tooling tests pass. A real Rust 1.100/LLVM fixture excludes executed inline tests while preserving called production hits and uncalled production zeroes, including shared source lines. Source-hashed executable evidence detects directory omissions while allowing declaration-only modules. All 262 file-level dispositions still await independent parity acceptance. |
| Native CI preparation and review fixes | [Runner](../services/octopus-rs/scripts/ci/native.sh), [task](../services/octopus-rs/scripts/ci/tasks/native.sh), [delivery tests](../services/octopus-rs/scripts/tests/test_delivery.py) | Docker CLI/build prerequisites and Linux host networking added; cleanup/report-order tests pass. Docker CLI installation verified on Bookworm. Actual Linux CI runner connectivity remains unverified: Docker Desktop host-network smoke could not reach host loopback. Parent CI/Compose/image consumers still target Scala. |

Verification recorded for this checkpoint:

- `bash services/octopus-rs/scripts/ci/core.sh`: **62 native tests passed**
  (47 library, 10 DQ, two intake, one mock broker and two PostgreSQL contract
  tests), with Docker required; formatting, Clippy and release library build passed.
- `bash services/octopus-rs/scripts/ci/test.sh`: **49 tooling tests passed**,
  including the real compiler/LLVM fixture under Rust 1.100.0.
- Documentation, PostgreSQL schema contract, dependency boundaries and whitespace
  checks passed. The corrected Scala baseline remains 719 passed/one skipped;
  its 23-file formatting debt is unresolved.
- Review findings for SSL-disable validation and arbitrary-precision JSON were
  already correct: Scala permits disable outside development, and Serde's
  arbitrary-precision feature is enabled. Regression tests preserve those facts.

### Remaining work and next acceptance conditions

| Gate | Current status | Required work before completion |
| --- | --- | --- |
| G1 | **IN_PROGRESS** | Assemble the actual coordinator binary; finish runtime/resource packaging, final standalone context and Linux amd64 image build. Preserve the selected independent workspace and transfer native source into the existing Octopus submodule at G3, followed by validation from that final location. |
| G2 | **IN_PROGRESS** | Implement and integrate all five consumer lanes, thirteen typed load targets, authorization/load/result/outbox flows, supervision, leases, remaining processor/projection SQL, archive/retention, DQ runtime and HTTP/metrics/tracing. Resolve configuration/HOCON, Java regex/Unicode/time and optional TLS-store compatibility gaps. Map all seven coverage domains, meet protected floors with runtime tests, reconcile all source/test dispositions and pass differential PostgreSQL/Redpanda/MinIO failure/replay tests plus external DQ acceptance. |
| G3 | **IN_PROGRESS** | Both Jenkins entry points, image verification, both Compose configurations and the DQ launcher support native candidate validation. Activation still requires a buildable runtime, G2 parity, a committed native gitlink, and passing Linux CI, image and DQ runs. See the [candidate commands](../services/octopus-rs/README.md). |
| G4 | **IN_PROGRESS** | Production app-stack rendered and a disposable Git promotion/revert restored it byte-for-byte using a fixture digest. Native and Scala smoke configurations render. Real image startup, broker loss, SIGTERM, replay, Scala rollback on retained data and representative resource measurements remain unverified. See the deployment rehearsal in the [native README](../services/octopus-rs/README.md). |
| G5 | **NOT_STARTED** | After G3/G4 and rollback evidence, retire obsolete Octopus Scala/JAR/sbt paths, finish the 22 delivery dispositions and remap documentation. Preserve other services' Scala support. |

Next implementation order: complete load/result authorization and transactional
stores after the verified intake base; wire the five consumers and outbox with
real Redpanda failure/restart tests; then integrate processor, archive, DQ and
HTTP workloads. Close coverage and differential parity before artifact cutover.
Do not mark a whole baseline file migrated from the presence of a partial module
or aggregate passing test count.

### Prerequisite gates

G1 and G2 are **IN_PROGRESS** for library implementation and delivery tooling;
native executable, complete coverage and runtime parity evidence are still
absent. G3 candidate wiring is in progress. G4 and G5 remain open.

1. **G1 - Establish the native build contract.** Decide whether Octopus has an
   independent Cargo workspace or joins the parent workspace; document both
   standalone and umbrella checkout requirements. Define the binary name and
   path, supported target architecture/libc, pinned toolchain, committed lockfile,
   and actual release/test commands. Inventory native libraries and runtime
   resources, including schema-manifest verification, topic bootstrap files,
   proxy-authority data, and configuration. Dependency additions require their
   own explicit authorization. Acceptance: the intended checkout and root Docker
   build context can produce the native executable reproducibly with locked
   dependencies; runtime resources are present without a JVM or developer cache.
2. **G2 - Establish behavior and coverage parity.** Map the existing unit,
   PostgreSQL/broker integration and BDD assertions to Rust tests before retiring
   Scala verification. Preserve `OCTOPUS_REQUIRE_DOCKER=true` semantics: unavailable
   Docker must fail CI. Choose the native coverage format/tool and map the seven
   policy domains to real Rust source boundaries. Current line floors are 55%
   overall, config 97%, dispatch 31%, HTTP 8%, observability 64%, persistence 57%,
   PostgreSQL 29%, and processor 86%. Keep the Scala gate during overlap; do not
   interpret different language denominators as equivalent evidence or silently
   lower protected floors. Record any rebaseline justification and a fresh
   Docker-enabled report. Acceptance: mapped behavioral assertions pass, every
   policy domain has measurable coverage, and missing/empty/malformed reports,
   absent domains and below-floor results fail the new checker. Preserve the
   processor ownership/scenario checks from
   [FeatureContractSuite](../services/octopus/src/test/scala/com/sslproxy/coordinator/FeatureContractSuite.scala).
3. **G3 - Replace artifact consumers together.** Depends on G1 and G2. Update
   standalone and parent CI runners, report collection, native image validation,
   local launch commands and the DQ acceptance harness in one coordinated
   delivery change. Keep source-pin and both OCI revision-label checks; replace
   JVM bytecode inspection with native artifact and runtime assertions for the
   same obsolete validation behavior. Acceptance: both CI entry points collect
   the intended reports/artifact before cleanup, propagate failures, and the
   image plus DQ harness run the native executable with verified provenance.
4. **G4 - Verify deployment compatibility before promotion.** Depends on G3.
   Exercise port 8081, `/live`, `/ready`, health/metrics aliases, enabled-lane
   readiness, UID/GID 1000, read-only root filesystem, mounted secrets/CA/topic
   files, and graceful termination against the current deployment contract.
   Verify restart/replay with unchanged groups, committed offsets and ingestion
   evidence. Remove JVM tuning through Git at native cutover, measure resource
   needs, and preserve the one-replica `Recreate` strategy and broker-drain gates.
   Retain the `java-coordinator` deployment/image identity unless a separate
   rename is justified. Acceptance: native image smoke and parity tests plus
   production Kustomize rendering pass; reviewed digest promotion and a tested
   Git-revert rollback preserve schemas, offsets and evidence. No direct cluster
   repair or production promotion is part of this inventory.
5. **G5 - Retire Scala build support and finalize documentation.** Depends on
   G3 and G4, including an available rollback artifact. Remove Scala tooling only
   when no active Octopus build, test, launch, editor or documentation path
   requires it. Keep any necessary differential Scala harness until parity
   evidence has been accepted. Acceptance: reference searches and both CI entry
   points show no accidental JAR/sbt dependency, all replacement source links
   resolve, and documentation distinguishes current Rust behavior from dated
   Scala evidence. Other services still using sbt remain supported.

### File-by-file dispositions

Paths in this table are relative to the Octopus submodule. Gate references above
are shared prerequisites; the final column gives the file-specific acceptance
condition.

| File | Lines | Disposition | Prerequisite and acceptance |
| --- | ---: | --- | --- |
| [.github/CODEOWNERS](../services/octopus/.github/CODEOWNERS) | 2 | **Retain unchanged.** The wildcard owner covers Rust files too. | No language prerequisite; preserve `* @zlovtnik` and existing review policy. No new owner list is needed. |
| [.github/workflows/main-branch-source-policy.yml](../services/octopus/.github/workflows/main-branch-source-policy.yml) | 20 | **Retain unchanged.** This enforces branch provenance, not a build tool. | Preserve `dev` as the accepted PR source for `main`/`master` and read-only contents permissions; Rust CI must not bypass this check. |
| [.gitignore](../services/octopus/.gitignore) | 72 | **Adapt incrementally.** Reuse `target/`; retain secret, local override and editor exclusions. | After G1/G2, ignore only actual new generated/report paths and keep the application lockfile trackable. Remove sbt/Metals/Bloop entries only at G5; verify representative paths with `git check-ignore`. |
| [.scalafix.conf](../services/octopus/.scalafix.conf) | 11 | **Retire at G5.** Import organization rules have no literal Rust translation. | G1/G2 must provide Rust formatting, compiler-warning and lint checks; all `scalafixAll` callers must be removed or retained solely for an explicit Scala harness before deletion. |
| [.scalafmt.conf](../services/octopus/.scalafmt.conf) | 14 | **Retire at G5.** Use the selected toolchain's Rust formatter. | CI must run the real Rust formatting check. Do not invent a custom formatter configuration solely to mirror Scala options; retain this file while Scala sources remain under verification. |
| [AGENTS.md](../services/octopus/AGENTS.md) | 49 | **Rewrite for implemented Rust structure and commands.** Preserve ingestion, consumer-union, processor-ownership and coverage rules. | G1/G2 establish real paths and tests; G5 removes stale commands. Update parent/root language descriptions and checks together. Keep subtree-only rules and fewer than 60 lines; verify every path and command. |
| [Dockerfile](../services/octopus/Dockerfile) | 66 | **Replace the JDK/sbt builder and JRE/JAR entrypoint with native build/runtime stages.** Retain root-context resource packaging, revision labels, non-root execution and health behavior. | G1 selects target/libc and runtime libraries; G3 replaces JAR validation; G4 proves deployment compatibility. Acceptance includes both commit arguments, executable permissions, CA/timezone resources as needed, topic bootstrap assets and no JVM-only environment. |
| [INGESTION-AUDIT.md](../services/octopus/INGESTION-AUDIT.md) | 275 | **Retain the capability inventory; remap implementation and evidence links as Rust lands.** Preserve five main consumers, optional downstream work, DQ, HTTP and fail-closed intake semantics. | G2/G5: link each retained capability to implemented Rust and its tests. Keep prior Scala test counts explicitly historical. If retaining the entire audit as superseded history, add the required historical status/warning and valid archival references before deleting linked sources. |
| [Jenkinsfile](../services/octopus/Jenkinsfile) | 33 | **Adapt stage/artifact contracts; retain checkout, concurrency, timeout and cleanup behavior.** Replace `artifacts/octopus.jar` with the agreed native artifact. | G3: standalone job runs the Rust task, fingerprints the native binary and archives the chosen coverage/behavior reports. Keep `artifacts/octopus-coverage/**` if useful to existing consumers; prove failure and cleanup behavior. |
| [README.md](../services/octopus/README.md) | 487 | **Rewrite implementation-specific build, configuration, diagnostics and resource guidance.** Preserve processor IDs, topic names, env/HTTP contracts and service ownership. | G2/G4/G5: replace JDK/sbt/JDBC/JVM descriptions with verified Rust behavior; rederive artifact names from CI. Replace source-scanning documentation assertions with Rust contract checks before retiring their Scala suite. All links and commands must resolve. |
| [build.sbt](../services/octopus/build.sbt) | 149 | **Replace with the G1 Cargo build contract, then retire at G5.** Carry forward required runtime/test capabilities rather than translating dependencies one-for-one. | G1/G2: locked release build, compiler/lint gates, tests, coverage and resource packaging work. G3 removes every assembly/JAR consumer. The independent native library manifest, lockfile and toolchain now exist; the executable, final source placement and runtime package remain pending. |
| [coverage-policy.json](../services/octopus/coverage-policy.json) | 12 | **Adapt policy schema/domain mapping to the selected native coverage report.** Preserve overall and domain enforcement. | G2: map every current domain explicitly; do not drop persistence/processor/PostgreSQL/dispatch/config safeguards or merge them invisibly into an overall number. Checker and policy migrate together with a measured, justified baseline. |
| [project/build.properties](../services/octopus/project/build.properties) | 1 | **Retire with sbt at G5.** The sbt version pin is not a Rust toolchain specification. | G1 provides the Rust pin; G3 eliminates Octopus sbt callers. A clean build must no longer read this file before removal. |
| [project/metals.sbt](../services/octopus/project/metals.sbt) | 8 | **Retire generated Metals/Bloop integration at G5.** Do not hand-port generated editor configuration. | Scala editor/build support must no longer be required. Verify that the new checkout's Rust metadata works and no editor bootstrap regenerates this tracked Scala file. |
| [project/plugins.sbt](../services/octopus/project/plugins.sbt) | 6 | **Retire at G5 after replacing plugin responsibilities.** Formatting, linting, packaging, coverage and behavior-test reporting remain required. | G1/G2/G3 replace Scalafmt, Scalafix/WartRemover, assembly, JaCoCo and JUnit/Cucumber execution. All reports and checks must run through native delivery before plugin removal. |
| [scripts/check_coverage.py](../services/octopus/scripts/check_coverage.py) | 90 | **Adapt the existing policy checker to the selected Rust report; keep Python if sufficient.** Avoid adding a second permanent policy engine. | G2: test overall/domain boundaries, omitted domains, malformed/missing/empty inputs, threshold equality and below-floor failure. G3 updates every invocation and report path; overlap must still enforce Scala coverage. |
| [scripts/ci/cleanup.sh](../services/octopus/scripts/ci/cleanup.sh) | 27 | **Retain unchanged.** Resource reclamation is independent of implementation language. | Preserve build-scoped deletion and the established shared-copy contract. Existing CI tests must continue to prove cancellation/failure cleanup does not remove another run's resources. |
| [scripts/ci/common.sh](../services/octopus/scripts/ci/common.sh) | 90 | **Retain unchanged.** Container naming, labels, traps and Docker context helpers are shared infrastructure. | Keep byte-identical with the parent and other synchronized copies; put Rust-specific commands in task scripts. Existing shared-script tests must pass. |
| [scripts/ci/tasks/install-sbt.sh](../services/octopus/scripts/ci/tasks/install-sbt.sh) | 12 | **Retire the Octopus copy at G5.** Prefer the G1 pinned Rust builder over a new installer script unless installation is actually needed. | G3 removes its Octopus caller. Do not delete the parent's sbt installer: schema-migrator still needs it. Verify no remaining Octopus task installs sbt. |
| [scripts/ci/tasks/test-1.sh](../services/octopus/scripts/ci/tasks/test-1.sh) | 6 | **Replace with the native check/test/coverage/release sequence.** Export the G1 artifact instead of `octopus-ci.jar`. | G1/G2/G3: formatting and lint errors fail; locked tests/build pass; Docker is mandatory; coverage is enforced; the native artifact and reports exist at the runner's agreed paths. |
| [scripts/ci/test.sh](../services/octopus/scripts/ci/test.sh) | 13 | **Replace the JDK image and Scala artifact paths; retain tar staging, Docker socket access and lifecycle helpers.** | G3: standalone checkout requirements are explicit; collect native reports and binary before the EXIT trap removes the container. Both successful and failed tasks preserve correct exit status and cleanup. |
| [setup-wireless-redpanda.sh](../services/octopus/setup-wireless-redpanda.sh) | 12 | **Retain the compatibility wrapper.** Topic provisioning is language-neutral and remains owned by the canonical parent bootstrap. | Preserve bootstrap-server fallback, manifest override and exit propagation. Document its full-workspace layout requirement; any image relocation must preserve `docker/redpanda/bootstrap.sh` and the manifest. Never duplicate topic definitions in Rust. |

### Coordinated changes outside these 22 files

These are verified cutover consumers. Their coordinated implementation is
authorized by the full migration request, but remains gated on G1/G2:

| Existing consumer | Required coordination |
| --- | --- |
| [Parent CI task](../scripts/ci/tasks/octopus-1.sh), [runner](../scripts/ci/octopus.sh), [Jenkinsfile](../Jenkinsfile), [job configuration](../docker/jenkins/casc/jenkins.yaml) | Migrate the umbrella and standalone routes together. Preserve delegation/change-selection gates and report copying before cleanup; update exact Scala command/path assertions in the CI tests. |
| [Image contract checker](../scripts/octopus_image_contract.py), [Makefile](../Makefile) | Preserve clean parent/submodule pin checks and both revision labels. Replace `/app/octopus.jar` extraction, JAR scanning and the Octopus sbt command in the root `test` recipe together with native build/image checks. |
| [DQ acceptance harness](../services/dq/tests/acceptance/run.py), [acceptance instructions](../services/dq/tests/acceptance.md), [DQ README](../services/dq/README.md) | Replace JAR freshness/hash checks, default artifact path and JVM launch with native equivalents, then rerun acceptance. DQ remains an external consumer of Octopus behavior. |
| [Base deployment](../cyber-stack/base/java-coordinator/deployment.yaml), [production resource patch](../cyber-stack/matrix/prod/patches/java-coordinator.yaml), [broker-drain patch](../cyber-stack/matrix/prod/patches/java-coordinator-broker-drain.yaml), [app-stack images](../cyber-stack/matrix/prod/app-stack/kustomization.yaml) | Preserve deployment identity, mounts, security context, probes and enabled processors; remove JVM tuning and change resources only with measurements. Publish/promote through existing reviewed digest workflow. |
| [Change classifier](../scripts/classify_changes.py), [digest promotion](../scripts/bump-image-digest.sh) | If G1 joins the parent Cargo workspace, changes to shared Rust inputs must also select Octopus validation/publication. Retain the source-integrity gate on coordinator digest promotion. |
| [Root instructions](../AGENTS.md), [services instructions](../services/AGENTS.md), [CI guide](../docs/jenkins-ci.md) | Update Scala descriptions, commands and report/artifact paths at G5. Keep parent rules in parent files and service-specific details in Octopus. |

### Local development delivery consumers

The [local runtime configuration](../docker-compose.yaml) overrides the image
entrypoint and explicitly launches `java -jar`. Update that launch at G3 while
preserving schema-checksum injection, secret files and outbox access. The
[image build configuration](../docker-compose.build.yaml) also consumes the
Octopus Dockerfile. Updating only the Dockerfile leaves the local launch path
broken.

### Verification handoff

Before the corresponding implementation is accepted, update and run these
existing checks against the replacement behavior:

- `python3 -m unittest discover -s scripts/tests -p 'test_jenkins*.py' -v`
  covers command/report expectations, production gates, shared CI copies and
  cleanup ordering. Change the Scala-specific expectations together with CI.
- `python3 -m unittest discover -s scripts/tests -p 'test_octopus*.py' -v`
  covers source identity, image validation and topic startup. Add native positive
  and negative cases instead of simply deleting the JAR assertions.
- `python3 -m unittest discover -s scripts/tests -p 'test_classify_changes.py' -v`
  verifies affected-service selection; add parent Rust-input cases if G1 requires
  them.
- Run the selected native formatter, linter, locked tests/release build and
  coverage checker in both CI entry points. The library commands above work
  today; full native delivery still rejects missing runtime inputs. Include image startup,
  readiness, shutdown and DQ acceptance evidence in G3/G4.
- Run `python3 scripts/check-postgres-schema-contract.py`,
  `make dependency-boundaries`, `python3 scripts/check-docs.py`, and
  `git diff --check` for the integrated migration. Update implementation-specific
  validators while retaining their schema and service-boundary guarantees.

For the initial documentation-only disposition pass, verification on 2026-11-16 passed:
`python3 scripts/check-docs.py`, `git diff --check`, and an explicit check of all
22 requested rows, source-link existence, ASCII and trailing whitespace. The
explicit check includes this untracked inventory, which `git diff --check`
does not inspect. Verification is limited to the mapping, repository references,
documentation policy and whitespace.
No native build, coverage, runtime parity or rollout result is claimed. Rust
workspace layout, dependency/tool choices and release measurements remain open
prerequisites.

The subsequent scaffold implementation selected an independent Cargo workspace
template and Rust 1.95.0 with compiler-bundled LLVM coverage tools. Verification
passed 32 scaffold tests, shell/Python syntax, TOML parsing, documentation links
and whitespace checks. The native entry point rejects missing runtime inputs;
no native binary/image or runtime parity result was claimed by that scaffold.

Native library work began on 2026-11-17 with the independent
[Cargo manifest](../services/octopus-rs/Cargo.toml) and
[lockfile](../services/octopus-rs/Cargo.lock). The
[core runner](../services/octopus-rs/scripts/ci/core.sh) checks formatting,
Clippy, locked tests and a release library build. It does not validate a native
executable or runtime image. At that initial library checkpoint the tooling suite
passed 45 tests; the current count is 49 as recorded above. The
[migration checker](../services/octopus-rs/scripts/check_migration.py)
reconciles all 262 baseline files, whose dispositions remain pending independent
parity evidence. Coverage-domain mappings, runtime behavior, release measurements
and coordinated artifact cutover remain open. See the
[native README](../services/octopus-rs/README.md) for activation requirements.

The native workspace toolchain and builder templates were updated to Rust
1.100.0 on 2026-11-18 at the user's request. Earlier scaffold results retain
their original toolchain context; current checks use the new pin.

## Resources and fixtures

| File | Lines | Proposed disposition |
| --- | ---: | --- |
| [src/main/resources/application.conf](../services/octopus/src/main/resources/application.conf) | 322 | Preserve contract or replace runtime binding |
| [src/main/resources/logback.xml](../services/octopus/src/main/resources/logback.xml) | 23 | Preserve contract or replace runtime binding |
| [src/main/resources/proxy-authority/public_suffix_list.dat](../services/octopus/src/main/resources/proxy-authority/public_suffix_list.dat) | 16567 | Preserve contract or replace runtime binding |
| [src/test/resources/contracts/proxy-authority-v1.json](../services/octopus/src/test/resources/contracts/proxy-authority-v1.json) | 1229 | Preserve contract or replace runtime binding |
| [src/test/resources/contracts/proxy-events-v1.json](../services/octopus/src/test/resources/contracts/proxy-events-v1.json) | 114 | Preserve contract or replace runtime binding |
| [src/test/resources/features/embedding.feature](../services/octopus/src/test/resources/features/embedding.feature) | 57 | Preserve contract or replace runtime binding |
| [src/test/resources/features/maintenance.feature](../services/octopus/src/test/resources/features/maintenance.feature) | 24 | Preserve contract or replace runtime binding |
| [src/test/resources/features/search-projection.feature](../services/octopus/src/test/resources/features/search-projection.feature) | 22 | Preserve contract or replace runtime binding |
| [src/test/resources/features/sync.feature](../services/octopus/src/test/resources/features/sync.feature) | 31 | Preserve contract or replace runtime binding |
| [src/test/resources/features/wireless.feature](../services/octopus/src/test/resources/features/wireless.feature) | 33 | Preserve contract or replace runtime binding |
| [src/test/resources/fixtures/wiretrap-event-completion-2026-10-16.json](../services/octopus/src/test/resources/fixtures/wiretrap-event-completion-2026-10-16.json) | 38 | Preserve contract or replace runtime binding |
| [src/test/resources/junit-platform.properties](../services/octopus/src/test/resources/junit-platform.properties) | 4 | Preserve contract or replace runtime binding |

## Production Scala: entry point

| File | Lines | Proposed disposition |
| --- | ---: | --- |
| [src/main/scala/com/sslproxy/coordinator/Main.scala](../services/octopus/src/main/scala/com/sslproxy/coordinator/Main.scala) | 32 | Port behavior; simplify structure |

## Production Scala: archive

| File | Lines | Proposed disposition |
| --- | ---: | --- |
| [src/main/scala/com/sslproxy/coordinator/archive/PayloadArchive.scala](../services/octopus/src/main/scala/com/sslproxy/coordinator/archive/PayloadArchive.scala) | 217 | Port behavior; simplify structure |

## Production Scala: config

| File | Lines | Proposed disposition |
| --- | ---: | --- |
| [src/main/scala/com/sslproxy/coordinator/config/AppConfig.scala](../services/octopus/src/main/scala/com/sslproxy/coordinator/config/AppConfig.scala) | 625 | Port behavior; simplify structure |
| [src/main/scala/com/sslproxy/coordinator/config/WirelessConfig.scala](../services/octopus/src/main/scala/com/sslproxy/coordinator/config/WirelessConfig.scala) | 27 | Port behavior; simplify structure |
| [src/main/scala/com/sslproxy/coordinator/config/WirelessProjectionConfig.scala](../services/octopus/src/main/scala/com/sslproxy/coordinator/config/WirelessProjectionConfig.scala) | 66 | Port behavior; simplify structure |

## Production Scala: cron

| File | Lines | Proposed disposition |
| --- | ---: | --- |
| [src/main/scala/com/sslproxy/coordinator/cron/CronScheduler.scala](../services/octopus/src/main/scala/com/sslproxy/coordinator/cron/CronScheduler.scala) | 540 | Port behavior; simplify structure |

## Production Scala: dispatch

| File | Lines | Proposed disposition |
| --- | ---: | --- |
| [src/main/scala/com/sslproxy/coordinator/dispatch/BackpressureService.scala](../services/octopus/src/main/scala/com/sslproxy/coordinator/dispatch/BackpressureService.scala) | 94 | Port behavior; simplify structure |
| [src/main/scala/com/sslproxy/coordinator/dispatch/BatchDispatchService.scala](../services/octopus/src/main/scala/com/sslproxy/coordinator/dispatch/BatchDispatchService.scala) | 139 | Port behavior; simplify structure |

## Production Scala: domain

| File | Lines | Proposed disposition |
| --- | ---: | --- |
| [src/main/scala/com/sslproxy/coordinator/domain/BrokerRecordMetadata.scala](../services/octopus/src/main/scala/com/sslproxy/coordinator/domain/BrokerRecordMetadata.scala) | 75 | Port behavior; simplify structure |
| [src/main/scala/com/sslproxy/coordinator/domain/DatabaseError.scala](../services/octopus/src/main/scala/com/sslproxy/coordinator/domain/DatabaseError.scala) | 10 | Port behavior; simplify structure |
| [src/main/scala/com/sslproxy/coordinator/domain/IngestionInvariantViolation.scala](../services/octopus/src/main/scala/com/sslproxy/coordinator/domain/IngestionInvariantViolation.scala) | 4 | Port behavior; simplify structure |
| [src/main/scala/com/sslproxy/coordinator/domain/RetryableDependencyException.scala](../services/octopus/src/main/scala/com/sslproxy/coordinator/domain/RetryableDependencyException.scala) | 10 | Port behavior; simplify structure |
| [src/main/scala/com/sslproxy/coordinator/domain/ScanRequestRecord.scala](../services/octopus/src/main/scala/com/sslproxy/coordinator/domain/ScanRequestRecord.scala) | 136 | Port behavior; simplify structure |
| [src/main/scala/com/sslproxy/coordinator/domain/SyncLoad.scala](../services/octopus/src/main/scala/com/sslproxy/coordinator/domain/SyncLoad.scala) | 48 | Port behavior; simplify structure |

## Production Scala: dq

| File | Lines | Proposed disposition |
| --- | ---: | --- |
| [src/main/scala/com/sslproxy/coordinator/dq/DqApply.scala](../services/octopus/src/main/scala/com/sslproxy/coordinator/dq/DqApply.scala) | 222 | Port behavior; simplify structure |
| [src/main/scala/com/sslproxy/coordinator/dq/DqArtifacts.scala](../services/octopus/src/main/scala/com/sslproxy/coordinator/dq/DqArtifacts.scala) | 256 | Port behavior; simplify structure |
| [src/main/scala/com/sslproxy/coordinator/dq/DqConfig.scala](../services/octopus/src/main/scala/com/sslproxy/coordinator/dq/DqConfig.scala) | 98 | Port behavior; simplify structure |
| [src/main/scala/com/sslproxy/coordinator/dq/DqMetrics.scala](../services/octopus/src/main/scala/com/sslproxy/coordinator/dq/DqMetrics.scala) | 15 | Port behavior; simplify structure |
| [src/main/scala/com/sslproxy/coordinator/dq/DqModels.scala](../services/octopus/src/main/scala/com/sslproxy/coordinator/dq/DqModels.scala) | 298 | Port behavior; simplify structure |
| [src/main/scala/com/sslproxy/coordinator/dq/DqRetention.scala](../services/octopus/src/main/scala/com/sslproxy/coordinator/dq/DqRetention.scala) | 154 | Port behavior; simplify structure |
| [src/main/scala/com/sslproxy/coordinator/dq/DqRuntime.scala](../services/octopus/src/main/scala/com/sslproxy/coordinator/dq/DqRuntime.scala) | 451 | Port behavior; simplify structure |
| [src/main/scala/com/sslproxy/coordinator/dq/DqSnapshot.scala](../services/octopus/src/main/scala/com/sslproxy/coordinator/dq/DqSnapshot.scala) | 72 | Port behavior; simplify structure |
| [src/main/scala/com/sslproxy/coordinator/dq/DqStore.scala](../services/octopus/src/main/scala/com/sslproxy/coordinator/dq/DqStore.scala) | 127 | Port behavior; simplify structure |

## Production Scala: http

| File | Lines | Proposed disposition |
| --- | ---: | --- |
| [src/main/scala/com/sslproxy/coordinator/http/DqRoutes.scala](../services/octopus/src/main/scala/com/sslproxy/coordinator/http/DqRoutes.scala) | 158 | Port behavior; simplify structure |
| [src/main/scala/com/sslproxy/coordinator/http/HealthRoutes.scala](../services/octopus/src/main/scala/com/sslproxy/coordinator/http/HealthRoutes.scala) | 80 | Port behavior; simplify structure |
| [src/main/scala/com/sslproxy/coordinator/http/LiveMetricsRoutes.scala](../services/octopus/src/main/scala/com/sslproxy/coordinator/http/LiveMetricsRoutes.scala) | 35 | Port behavior; simplify structure |
| [src/main/scala/com/sslproxy/coordinator/http/PublicStatsRoutes.scala](../services/octopus/src/main/scala/com/sslproxy/coordinator/http/PublicStatsRoutes.scala) | 112 | Port behavior; simplify structure |

## Production Scala: ingest

| File | Lines | Proposed disposition |
| --- | ---: | --- |
| [src/main/scala/com/sslproxy/coordinator/ingest/SyncEventHydrationService.scala](../services/octopus/src/main/scala/com/sslproxy/coordinator/ingest/SyncEventHydrationService.scala) | 234 | Port behavior; simplify structure |

## Production Scala: kafka

| File | Lines | Proposed disposition |
| --- | ---: | --- |
| [src/main/scala/com/sslproxy/coordinator/kafka/BoundedBatching.scala](../services/octopus/src/main/scala/com/sslproxy/coordinator/kafka/BoundedBatching.scala) | 47 | Port behavior; simplify structure |
| [src/main/scala/com/sslproxy/coordinator/kafka/DurableIngestion.scala](../services/octopus/src/main/scala/com/sslproxy/coordinator/kafka/DurableIngestion.scala) | 52 | Port behavior; simplify structure |
| [src/main/scala/com/sslproxy/coordinator/kafka/KafkaComponents.scala](../services/octopus/src/main/scala/com/sslproxy/coordinator/kafka/KafkaComponents.scala) | 182 | Port behavior; simplify structure |
| [src/main/scala/com/sslproxy/coordinator/kafka/KafkaDatabaseResult.scala](../services/octopus/src/main/scala/com/sslproxy/coordinator/kafka/KafkaDatabaseResult.scala) | 24 | Port behavior; simplify structure |
| [src/main/scala/com/sslproxy/coordinator/kafka/LockedTopicConsumer.scala](../services/octopus/src/main/scala/com/sslproxy/coordinator/kafka/LockedTopicConsumer.scala) | 348 | Port behavior; simplify structure |
| [src/main/scala/com/sslproxy/coordinator/kafka/PostgresLoadStream.scala](../services/octopus/src/main/scala/com/sslproxy/coordinator/kafka/PostgresLoadStream.scala) | 122 | Port behavior; simplify structure |
| [src/main/scala/com/sslproxy/coordinator/kafka/PostgresResultStream.scala](../services/octopus/src/main/scala/com/sslproxy/coordinator/kafka/PostgresResultStream.scala) | 76 | Port behavior; simplify structure |
| [src/main/scala/com/sslproxy/coordinator/kafka/ScanRequestStream.scala](../services/octopus/src/main/scala/com/sslproxy/coordinator/kafka/ScanRequestStream.scala) | 72 | Port behavior; simplify structure |
| [src/main/scala/com/sslproxy/coordinator/kafka/WirelessAuditStream.scala](../services/octopus/src/main/scala/com/sslproxy/coordinator/kafka/WirelessAuditStream.scala) | 72 | Port behavior; simplify structure |
| [src/main/scala/com/sslproxy/coordinator/kafka/WirelessHeartbeatStream.scala](../services/octopus/src/main/scala/com/sslproxy/coordinator/kafka/WirelessHeartbeatStream.scala) | 88 | Port behavior; simplify structure |

## Production Scala: observability

| File | Lines | Proposed disposition |
| --- | ---: | --- |
| [src/main/scala/com/sslproxy/coordinator/observability/CoordinatorMetrics.scala](../services/octopus/src/main/scala/com/sslproxy/coordinator/observability/CoordinatorMetrics.scala) | 503 | Port behavior; simplify structure |
| [src/main/scala/com/sslproxy/coordinator/observability/CoordinatorTracing.scala](../services/octopus/src/main/scala/com/sslproxy/coordinator/observability/CoordinatorTracing.scala) | 182 | Port behavior; simplify structure |
| [src/main/scala/com/sslproxy/coordinator/observability/OperationalStatsService.scala](../services/octopus/src/main/scala/com/sslproxy/coordinator/observability/OperationalStatsService.scala) | 157 | Port behavior; simplify structure |
| [src/main/scala/com/sslproxy/coordinator/observability/StructuredLogger.scala](../services/octopus/src/main/scala/com/sslproxy/coordinator/observability/StructuredLogger.scala) | 58 | Port behavior; simplify structure |

## Production Scala: persistence

| File | Lines | Proposed disposition |
| --- | ---: | --- |
| [src/main/scala/com/sslproxy/coordinator/persistence/BatchStatement.scala](../services/octopus/src/main/scala/com/sslproxy/coordinator/persistence/BatchStatement.scala) | 17 | Port behavior; simplify structure |
| [src/main/scala/com/sslproxy/coordinator/persistence/Stores.scala](../services/octopus/src/main/scala/com/sslproxy/coordinator/persistence/Stores.scala) | 183 | Port behavior; simplify structure |
| [src/main/scala/com/sslproxy/coordinator/persistence/package.scala](../services/octopus/src/main/scala/com/sslproxy/coordinator/persistence/package.scala) | 25 | Port behavior; simplify structure |

## Production Scala: postgres

| File | Lines | Proposed disposition |
| --- | ---: | --- |
| [src/main/scala/com/sslproxy/coordinator/postgres/ArchiveCandidate.scala](../services/octopus/src/main/scala/com/sslproxy/coordinator/postgres/ArchiveCandidate.scala) | 9 | Port behavior; simplify structure |
| [src/main/scala/com/sslproxy/coordinator/postgres/JsonFields.scala](../services/octopus/src/main/scala/com/sslproxy/coordinator/postgres/JsonFields.scala) | 153 | Port behavior; simplify structure |
| [src/main/scala/com/sslproxy/coordinator/postgres/OutboxRecord.scala](../services/octopus/src/main/scala/com/sslproxy/coordinator/postgres/OutboxRecord.scala) | 35 | Port behavior; simplify structure |
| [src/main/scala/com/sslproxy/coordinator/postgres/PostgresChecksum.scala](../services/octopus/src/main/scala/com/sslproxy/coordinator/postgres/PostgresChecksum.scala) | 14 | Port behavior; simplify structure |
| [src/main/scala/com/sslproxy/coordinator/postgres/PostgresClock.scala](../services/octopus/src/main/scala/com/sslproxy/coordinator/postgres/PostgresClock.scala) | 10 | Port behavior; simplify structure |
| [src/main/scala/com/sslproxy/coordinator/postgres/PostgresErrorClass.scala](../services/octopus/src/main/scala/com/sslproxy/coordinator/postgres/PostgresErrorClass.scala) | 63 | Port behavior; simplify structure |
| [src/main/scala/com/sslproxy/coordinator/postgres/PostgresIngestionStore.scala](../services/octopus/src/main/scala/com/sslproxy/coordinator/postgres/PostgresIngestionStore.scala) | 63 | Port behavior; simplify structure |
| [src/main/scala/com/sslproxy/coordinator/postgres/PostgresLoad.scala](../services/octopus/src/main/scala/com/sslproxy/coordinator/postgres/PostgresLoad.scala) | 27 | Port behavior; simplify structure |
| [src/main/scala/com/sslproxy/coordinator/postgres/PostgresLoadHandler.scala](../services/octopus/src/main/scala/com/sslproxy/coordinator/postgres/PostgresLoadHandler.scala) | 213 | Port behavior; simplify structure |
| [src/main/scala/com/sslproxy/coordinator/postgres/PostgresMaintenanceStore.scala](../services/octopus/src/main/scala/com/sslproxy/coordinator/postgres/PostgresMaintenanceStore.scala) | 110 | Port behavior; simplify structure |
| [src/main/scala/com/sslproxy/coordinator/postgres/PostgresOutboxStore.scala](../services/octopus/src/main/scala/com/sslproxy/coordinator/postgres/PostgresOutboxStore.scala) | 27 | Port behavior; simplify structure |
| [src/main/scala/com/sslproxy/coordinator/postgres/PostgresPayloadReadException.scala](../services/octopus/src/main/scala/com/sslproxy/coordinator/postgres/PostgresPayloadReadException.scala) | 5 | Port behavior; simplify structure |
| [src/main/scala/com/sslproxy/coordinator/postgres/PostgresPayloadResolver.scala](../services/octopus/src/main/scala/com/sslproxy/coordinator/postgres/PostgresPayloadResolver.scala) | 51 | Port behavior; simplify structure |
| [src/main/scala/com/sslproxy/coordinator/postgres/PostgresProcessorStateStore.scala](../services/octopus/src/main/scala/com/sslproxy/coordinator/postgres/PostgresProcessorStateStore.scala) | 98 | Port behavior; simplify structure |
| [src/main/scala/com/sslproxy/coordinator/postgres/PostgresProjectionStore.scala](../services/octopus/src/main/scala/com/sslproxy/coordinator/postgres/PostgresProjectionStore.scala) | 79 | Port behavior; simplify structure |
| [src/main/scala/com/sslproxy/coordinator/postgres/PostgresRepository.scala](../services/octopus/src/main/scala/com/sslproxy/coordinator/postgres/PostgresRepository.scala) | 1377 | Port behavior; simplify structure |
| [src/main/scala/com/sslproxy/coordinator/postgres/PostgresResult.scala](../services/octopus/src/main/scala/com/sslproxy/coordinator/postgres/PostgresResult.scala) | 97 | Port behavior; simplify structure |
| [src/main/scala/com/sslproxy/coordinator/postgres/PostgresResultStore.scala](../services/octopus/src/main/scala/com/sslproxy/coordinator/postgres/PostgresResultStore.scala) | 22 | Port behavior; simplify structure |
| [src/main/scala/com/sslproxy/coordinator/postgres/PostgresRows.scala](../services/octopus/src/main/scala/com/sslproxy/coordinator/postgres/PostgresRows.scala) | 316 | Port behavior; simplify structure |
| [src/main/scala/com/sslproxy/coordinator/postgres/PostgresSchemaPreflight.scala](../services/octopus/src/main/scala/com/sslproxy/coordinator/postgres/PostgresSchemaPreflight.scala) | 76 | Port behavior; simplify structure |
| [src/main/scala/com/sslproxy/coordinator/postgres/PostgresSink.scala](../services/octopus/src/main/scala/com/sslproxy/coordinator/postgres/PostgresSink.scala) | 46 | Port behavior; simplify structure |
| [src/main/scala/com/sslproxy/coordinator/postgres/PostgresSinkTarget.scala](../services/octopus/src/main/scala/com/sslproxy/coordinator/postgres/PostgresSinkTarget.scala) | 36 | Port behavior; simplify structure |
| [src/main/scala/com/sslproxy/coordinator/postgres/PostgresTls.scala](../services/octopus/src/main/scala/com/sslproxy/coordinator/postgres/PostgresTls.scala) | 24 | Port behavior; simplify structure |
| [src/main/scala/com/sslproxy/coordinator/postgres/PostgresTransactor.scala](../services/octopus/src/main/scala/com/sslproxy/coordinator/postgres/PostgresTransactor.scala) | 1216 | Port behavior; simplify structure |
| [src/main/scala/com/sslproxy/coordinator/postgres/PostgresTransformService.scala](../services/octopus/src/main/scala/com/sslproxy/coordinator/postgres/PostgresTransformService.scala) | 420 | Port behavior; simplify structure |
| [src/main/scala/com/sslproxy/coordinator/postgres/PostgresWirelessStore.scala](../services/octopus/src/main/scala/com/sslproxy/coordinator/postgres/PostgresWirelessStore.scala) | 35 | Port behavior; simplify structure |
| [src/main/scala/com/sslproxy/coordinator/postgres/SchemaReadiness.scala](../services/octopus/src/main/scala/com/sslproxy/coordinator/postgres/SchemaReadiness.scala) | 9 | Port behavior; simplify structure |
| [src/main/scala/com/sslproxy/coordinator/postgres/StreamingPayloadRows.scala](../services/octopus/src/main/scala/com/sslproxy/coordinator/postgres/StreamingPayloadRows.scala) | 102 | Port behavior; simplify structure |
| [src/main/scala/com/sslproxy/coordinator/postgres/SyncEventHydrationCandidate.scala](../services/octopus/src/main/scala/com/sslproxy/coordinator/postgres/SyncEventHydrationCandidate.scala) | 18 | Port behavior; simplify structure |
| [src/main/scala/com/sslproxy/coordinator/postgres/WirelessBacklogEntry.scala](../services/octopus/src/main/scala/com/sslproxy/coordinator/postgres/WirelessBacklogEntry.scala) | 14 | Port behavior; simplify structure |
| [src/main/scala/com/sslproxy/coordinator/postgres/sql/BatchSinkSql.scala](../services/octopus/src/main/scala/com/sslproxy/coordinator/postgres/sql/BatchSinkSql.scala) | 210 | Port behavior; simplify structure |
| [src/main/scala/com/sslproxy/coordinator/postgres/sql/DispatchAuthorizationSql.scala](../services/octopus/src/main/scala/com/sslproxy/coordinator/postgres/sql/DispatchAuthorizationSql.scala) | 67 | Port behavior; simplify structure |
| [src/main/scala/com/sslproxy/coordinator/postgres/sql/DqControlSql.scala](../services/octopus/src/main/scala/com/sslproxy/coordinator/postgres/sql/DqControlSql.scala) | 881 | Port behavior; simplify structure |
| [src/main/scala/com/sslproxy/coordinator/postgres/sql/DqMetricsSql.scala](../services/octopus/src/main/scala/com/sslproxy/coordinator/postgres/sql/DqMetricsSql.scala) | 45 | Port behavior; simplify structure |
| [src/main/scala/com/sslproxy/coordinator/postgres/sql/DqProjectionSql.scala](../services/octopus/src/main/scala/com/sslproxy/coordinator/postgres/sql/DqProjectionSql.scala) | 81 | Port behavior; simplify structure |
| [src/main/scala/com/sslproxy/coordinator/postgres/sql/DqRetentionSql.scala](../services/octopus/src/main/scala/com/sslproxy/coordinator/postgres/sql/DqRetentionSql.scala) | 119 | Port behavior; simplify structure |
| [src/main/scala/com/sslproxy/coordinator/postgres/sql/DqSnapshotSql.scala](../services/octopus/src/main/scala/com/sslproxy/coordinator/postgres/sql/DqSnapshotSql.scala) | 111 | Port behavior; simplify structure |
| [src/main/scala/com/sslproxy/coordinator/postgres/sql/IdentityGraphSql.scala](../services/octopus/src/main/scala/com/sslproxy/coordinator/postgres/sql/IdentityGraphSql.scala) | 948 | Port behavior; simplify structure |
| [src/main/scala/com/sslproxy/coordinator/postgres/sql/IngestionSql.scala](../services/octopus/src/main/scala/com/sslproxy/coordinator/postgres/sql/IngestionSql.scala) | 315 | Port behavior; simplify structure |
| [src/main/scala/com/sslproxy/coordinator/postgres/sql/IntelligenceSql.scala](../services/octopus/src/main/scala/com/sslproxy/coordinator/postgres/sql/IntelligenceSql.scala) | 564 | Port behavior; simplify structure |
| [src/main/scala/com/sslproxy/coordinator/postgres/sql/JobBatchSql.scala](../services/octopus/src/main/scala/com/sslproxy/coordinator/postgres/sql/JobBatchSql.scala) | 155 | Port behavior; simplify structure |
| [src/main/scala/com/sslproxy/coordinator/postgres/sql/MaintenanceSql.scala](../services/octopus/src/main/scala/com/sslproxy/coordinator/postgres/sql/MaintenanceSql.scala) | 483 | Port behavior; simplify structure |
| [src/main/scala/com/sslproxy/coordinator/postgres/sql/OutboxSql.scala](../services/octopus/src/main/scala/com/sslproxy/coordinator/postgres/sql/OutboxSql.scala) | 206 | Port behavior; simplify structure |
| [src/main/scala/com/sslproxy/coordinator/postgres/sql/ProcessorStateSql.scala](../services/octopus/src/main/scala/com/sslproxy/coordinator/postgres/sql/ProcessorStateSql.scala) | 77 | Port behavior; simplify structure |
| [src/main/scala/com/sslproxy/coordinator/postgres/sql/ProjectionSql.scala](../services/octopus/src/main/scala/com/sslproxy/coordinator/postgres/sql/ProjectionSql.scala) | 129 | Port behavior; simplify structure |
| [src/main/scala/com/sslproxy/coordinator/postgres/sql/ProxyBehaviorSql.scala](../services/octopus/src/main/scala/com/sslproxy/coordinator/postgres/sql/ProxyBehaviorSql.scala) | 608 | Port behavior; simplify structure |
| [src/main/scala/com/sslproxy/coordinator/postgres/sql/ProxyPreparationSql.scala](../services/octopus/src/main/scala/com/sslproxy/coordinator/postgres/sql/ProxyPreparationSql.scala) | 776 | Port behavior; simplify structure |
| [src/main/scala/com/sslproxy/coordinator/postgres/sql/ProxySignalSql.scala](../services/octopus/src/main/scala/com/sslproxy/coordinator/postgres/sql/ProxySignalSql.scala) | 99 | Port behavior; simplify structure |
| [src/main/scala/com/sslproxy/coordinator/postgres/sql/ResultSql.scala](../services/octopus/src/main/scala/com/sslproxy/coordinator/postgres/sql/ResultSql.scala) | 231 | Port behavior; simplify structure |
| [src/main/scala/com/sslproxy/coordinator/postgres/sql/SearchPreparationSql.scala](../services/octopus/src/main/scala/com/sslproxy/coordinator/postgres/sql/SearchPreparationSql.scala) | 514 | Port behavior; simplify structure |
| [src/main/scala/com/sslproxy/coordinator/postgres/sql/ThreatRiskSql.scala](../services/octopus/src/main/scala/com/sslproxy/coordinator/postgres/sql/ThreatRiskSql.scala) | 164 | Port behavior; simplify structure |
| [src/main/scala/com/sslproxy/coordinator/postgres/sql/WirelessProcessorSql.scala](../services/octopus/src/main/scala/com/sslproxy/coordinator/postgres/sql/WirelessProcessorSql.scala) | 240 | Port behavior; simplify structure |
| [src/main/scala/com/sslproxy/coordinator/postgres/sql/WirelessProjectionSql.scala](../services/octopus/src/main/scala/com/sslproxy/coordinator/postgres/sql/WirelessProjectionSql.scala) | 357 | Port behavior; simplify structure |
| [src/main/scala/com/sslproxy/coordinator/postgres/sql/WirelessSql.scala](../services/octopus/src/main/scala/com/sslproxy/coordinator/postgres/sql/WirelessSql.scala) | 146 | Port behavior; simplify structure |
| [src/main/scala/com/sslproxy/coordinator/postgres/sql/WirelessStreamSql.scala](../services/octopus/src/main/scala/com/sslproxy/coordinator/postgres/sql/WirelessStreamSql.scala) | 383 | Port behavior; simplify structure |

## Production Scala: processor

| File | Lines | Proposed disposition |
| --- | ---: | --- |
| [src/main/scala/com/sslproxy/coordinator/processor/EventRetentionProcessor.scala](../services/octopus/src/main/scala/com/sslproxy/coordinator/processor/EventRetentionProcessor.scala) | 50 | Port behavior; simplify structure |
| [src/main/scala/com/sslproxy/coordinator/processor/FencedRetentionRunner.scala](../services/octopus/src/main/scala/com/sslproxy/coordinator/processor/FencedRetentionRunner.scala) | 141 | Port behavior; simplify structure |
| [src/main/scala/com/sslproxy/coordinator/processor/FencedWorkRunner.scala](../services/octopus/src/main/scala/com/sslproxy/coordinator/processor/FencedWorkRunner.scala) | 94 | Port behavior; simplify structure |
| [src/main/scala/com/sslproxy/coordinator/processor/IntelligencePreparation.scala](../services/octopus/src/main/scala/com/sslproxy/coordinator/processor/IntelligencePreparation.scala) | 420 | Port behavior; simplify structure |
| [src/main/scala/com/sslproxy/coordinator/processor/PayloadArchiver.scala](../services/octopus/src/main/scala/com/sslproxy/coordinator/processor/PayloadArchiver.scala) | 30 | Port behavior; simplify structure |
| [src/main/scala/com/sslproxy/coordinator/processor/Processor.scala](../services/octopus/src/main/scala/com/sslproxy/coordinator/processor/Processor.scala) | 70 | Port behavior; simplify structure |
| [src/main/scala/com/sslproxy/coordinator/processor/ProcessorId.scala](../services/octopus/src/main/scala/com/sslproxy/coordinator/processor/ProcessorId.scala) | 460 | Port behavior; simplify structure |
| [src/main/scala/com/sslproxy/coordinator/processor/ProcessorSupervisor.scala](../services/octopus/src/main/scala/com/sslproxy/coordinator/processor/ProcessorSupervisor.scala) | 383 | Port behavior; simplify structure |
| [src/main/scala/com/sslproxy/coordinator/processor/ProjectionFunctions.scala](../services/octopus/src/main/scala/com/sslproxy/coordinator/processor/ProjectionFunctions.scala) | 117 | Port behavior; simplify structure |
| [src/main/scala/com/sslproxy/coordinator/processor/ProxyAsnEnrichment.scala](../services/octopus/src/main/scala/com/sslproxy/coordinator/processor/ProxyAsnEnrichment.scala) | 151 | Port behavior; simplify structure |
| [src/main/scala/com/sslproxy/coordinator/processor/ProxyAuthority.scala](../services/octopus/src/main/scala/com/sslproxy/coordinator/processor/ProxyAuthority.scala) | 134 | Port behavior; simplify structure |
| [src/main/scala/com/sslproxy/coordinator/processor/ProxyBehavior.scala](../services/octopus/src/main/scala/com/sslproxy/coordinator/processor/ProxyBehavior.scala) | 1026 | Port behavior; simplify structure |
| [src/main/scala/com/sslproxy/coordinator/processor/ProxyBehaviorCohorts.scala](../services/octopus/src/main/scala/com/sslproxy/coordinator/processor/ProxyBehaviorCohorts.scala) | 331 | Port behavior; simplify structure |
| [src/main/scala/com/sslproxy/coordinator/processor/ProxyBehaviorScopes.scala](../services/octopus/src/main/scala/com/sslproxy/coordinator/processor/ProxyBehaviorScopes.scala) | 217 | Port behavior; simplify structure |
| [src/main/scala/com/sslproxy/coordinator/processor/ProxyBehaviorStatistics.scala](../services/octopus/src/main/scala/com/sslproxy/coordinator/processor/ProxyBehaviorStatistics.scala) | 350 | Port behavior; simplify structure |
| [src/main/scala/com/sslproxy/coordinator/processor/ProxyClientHelloDrift.scala](../services/octopus/src/main/scala/com/sslproxy/coordinator/processor/ProxyClientHelloDrift.scala) | 133 | Port behavior; simplify structure |
| [src/main/scala/com/sslproxy/coordinator/processor/ProxyDestinationInfrastructure.scala](../services/octopus/src/main/scala/com/sslproxy/coordinator/processor/ProxyDestinationInfrastructure.scala) | 123 | Port behavior; simplify structure |
| [src/main/scala/com/sslproxy/coordinator/processor/ProxyDomainLexical.scala](../services/octopus/src/main/scala/com/sslproxy/coordinator/processor/ProxyDomainLexical.scala) | 282 | Port behavior; simplify structure |
| [src/main/scala/com/sslproxy/coordinator/processor/ProxyEvidence.scala](../services/octopus/src/main/scala/com/sslproxy/coordinator/processor/ProxyEvidence.scala) | 148 | Port behavior; simplify structure |
| [src/main/scala/com/sslproxy/coordinator/processor/ProxyIntelligencePolicy.scala](../services/octopus/src/main/scala/com/sslproxy/coordinator/processor/ProxyIntelligencePolicy.scala) | 23 | Port behavior; simplify structure |
| [src/main/scala/com/sslproxy/coordinator/processor/ProxyThreatFeed.scala](../services/octopus/src/main/scala/com/sslproxy/coordinator/processor/ProxyThreatFeed.scala) | 281 | Port behavior; simplify structure |
| [src/main/scala/com/sslproxy/coordinator/processor/SearchDocumentPreparation.scala](../services/octopus/src/main/scala/com/sslproxy/coordinator/processor/SearchDocumentPreparation.scala) | 175 | Port behavior; simplify structure |
| [src/main/scala/com/sslproxy/coordinator/processor/SearchRetentionProcessor.scala](../services/octopus/src/main/scala/com/sslproxy/coordinator/processor/SearchRetentionProcessor.scala) | 40 | Port behavior; simplify structure |
| [src/main/scala/com/sslproxy/coordinator/processor/WirelessObservation.scala](../services/octopus/src/main/scala/com/sslproxy/coordinator/processor/WirelessObservation.scala) | 109 | Port behavior; simplify structure |

## Production Scala: util

| File | Lines | Proposed disposition |
| --- | ---: | --- |
| [src/main/scala/com/sslproxy/coordinator/util/ErrorSanitizer.scala](../services/octopus/src/main/scala/com/sslproxy/coordinator/util/ErrorSanitizer.scala) | 34 | Port behavior; simplify structure |
| [src/main/scala/com/sslproxy/coordinator/util/PayloadJsonInspection.scala](../services/octopus/src/main/scala/com/sslproxy/coordinator/util/PayloadJsonInspection.scala) | 45 | Port behavior; simplify structure |
| [src/main/scala/com/sslproxy/coordinator/util/Sha256Utils.scala](../services/octopus/src/main/scala/com/sslproxy/coordinator/util/Sha256Utils.scala) | 15 | Port behavior; simplify structure |

## Production Scala: wiring

| File | Lines | Proposed disposition |
| --- | ---: | --- |
| [src/main/scala/com/sslproxy/coordinator/wiring/CoordinatorApplication.scala](../services/octopus/src/main/scala/com/sslproxy/coordinator/wiring/CoordinatorApplication.scala) | 156 | Port behavior; simplify structure |
| [src/main/scala/com/sslproxy/coordinator/wiring/DatabaseModule.scala](../services/octopus/src/main/scala/com/sslproxy/coordinator/wiring/DatabaseModule.scala) | 103 | Port behavior; simplify structure |
| [src/main/scala/com/sslproxy/coordinator/wiring/ObservabilityModule.scala](../services/octopus/src/main/scala/com/sslproxy/coordinator/wiring/ObservabilityModule.scala) | 16 | Port behavior; simplify structure |
| [src/main/scala/com/sslproxy/coordinator/wiring/RuntimeStreams.scala](../services/octopus/src/main/scala/com/sslproxy/coordinator/wiring/RuntimeStreams.scala) | 56 | Port behavior; simplify structure |
| [src/main/scala/com/sslproxy/coordinator/wiring/ServerModule.scala](../services/octopus/src/main/scala/com/sslproxy/coordinator/wiring/ServerModule.scala) | 54 | Port behavior; simplify structure |
| [src/main/scala/com/sslproxy/coordinator/wiring/ServicesModule.scala](../services/octopus/src/main/scala/com/sslproxy/coordinator/wiring/ServicesModule.scala) | 110 | Port behavior; simplify structure |
| [src/main/scala/com/sslproxy/coordinator/wiring/workloads/ConsumerWorkloads.scala](../services/octopus/src/main/scala/com/sslproxy/coordinator/wiring/workloads/ConsumerWorkloads.scala) | 78 | Port behavior; simplify structure |
| [src/main/scala/com/sslproxy/coordinator/wiring/workloads/RetentionWorkloads.scala](../services/octopus/src/main/scala/com/sslproxy/coordinator/wiring/workloads/RetentionWorkloads.scala) | 55 | Port behavior; simplify structure |
| [src/main/scala/com/sslproxy/coordinator/wiring/workloads/ScheduledWorkloads.scala](../services/octopus/src/main/scala/com/sslproxy/coordinator/wiring/workloads/ScheduledWorkloads.scala) | 154 | Port behavior; simplify structure |

## Scala verification: root contracts

| File | Lines | Proposed disposition |
| --- | ---: | --- |
| [src/test/scala/com/sslproxy/coordinator/DocumentationContractSuite.scala](../services/octopus/src/test/scala/com/sslproxy/coordinator/DocumentationContractSuite.scala) | 45 | Map assertions to Rust/contract coverage |
| [src/test/scala/com/sslproxy/coordinator/FeatureContractSuite.scala](../services/octopus/src/test/scala/com/sslproxy/coordinator/FeatureContractSuite.scala) | 70 | Map assertions to Rust/contract coverage |
| [src/test/scala/com/sslproxy/coordinator/MainSuite.scala](../services/octopus/src/test/scala/com/sslproxy/coordinator/MainSuite.scala) | 124 | Map assertions to Rust/contract coverage |
| [src/test/scala/com/sslproxy/coordinator/ProcessorWorkloadWiringSuite.scala](../services/octopus/src/test/scala/com/sslproxy/coordinator/ProcessorWorkloadWiringSuite.scala) | 36 | Map assertions to Rust/contract coverage |

## Scala verification: archive

| File | Lines | Proposed disposition |
| --- | ---: | --- |
| [src/test/scala/com/sslproxy/coordinator/archive/MinioPayloadArchiveSuite.scala](../services/octopus/src/test/scala/com/sslproxy/coordinator/archive/MinioPayloadArchiveSuite.scala) | 167 | Map assertions to Rust/contract coverage |

## Scala verification: bdd

| File | Lines | Proposed disposition |
| --- | ---: | --- |
| [src/test/scala/com/sslproxy/coordinator/bdd/ProcessorContractSteps.scala](../services/octopus/src/test/scala/com/sslproxy/coordinator/bdd/ProcessorContractSteps.scala) | 32 | Map assertions to Rust/contract coverage |
| [src/test/scala/com/sslproxy/coordinator/bdd/RunCucumberTest.scala](../services/octopus/src/test/scala/com/sslproxy/coordinator/bdd/RunCucumberTest.scala) | 13 | Map assertions to Rust/contract coverage |

## Scala verification: config

| File | Lines | Proposed disposition |
| --- | ---: | --- |
| [src/test/scala/com/sslproxy/coordinator/config/AppConfigSuite.scala](../services/octopus/src/test/scala/com/sslproxy/coordinator/config/AppConfigSuite.scala) | 462 | Map assertions to Rust/contract coverage |

## Scala verification: cron

| File | Lines | Proposed disposition |
| --- | ---: | --- |
| [src/test/scala/com/sslproxy/coordinator/cron/CronSchedulerSuite.scala](../services/octopus/src/test/scala/com/sslproxy/coordinator/cron/CronSchedulerSuite.scala) | 92 | Map assertions to Rust/contract coverage |

## Scala verification: dispatch

| File | Lines | Proposed disposition |
| --- | ---: | --- |
| [src/test/scala/com/sslproxy/coordinator/dispatch/BackpressureServiceSuite.scala](../services/octopus/src/test/scala/com/sslproxy/coordinator/dispatch/BackpressureServiceSuite.scala) | 82 | Map assertions to Rust/contract coverage |

## Scala verification: domain

| File | Lines | Proposed disposition |
| --- | ---: | --- |
| [src/test/scala/com/sslproxy/coordinator/domain/ScanRequestRecordSuite.scala](../services/octopus/src/test/scala/com/sslproxy/coordinator/domain/ScanRequestRecordSuite.scala) | 57 | Map assertions to Rust/contract coverage |
| [src/test/scala/com/sslproxy/coordinator/domain/SyncLoadSuite.scala](../services/octopus/src/test/scala/com/sslproxy/coordinator/domain/SyncLoadSuite.scala) | 98 | Map assertions to Rust/contract coverage |

## Scala verification: dq

| File | Lines | Proposed disposition |
| --- | ---: | --- |
| [src/test/scala/com/sslproxy/coordinator/dq/DqContractSuite.scala](../services/octopus/src/test/scala/com/sslproxy/coordinator/dq/DqContractSuite.scala) | 137 | Map assertions to Rust/contract coverage |
| [src/test/scala/com/sslproxy/coordinator/dq/DqRetentionSuite.scala](../services/octopus/src/test/scala/com/sslproxy/coordinator/dq/DqRetentionSuite.scala) | 328 | Map assertions to Rust/contract coverage |
| [src/test/scala/com/sslproxy/coordinator/dq/DqRuntimeSuite.scala](../services/octopus/src/test/scala/com/sslproxy/coordinator/dq/DqRuntimeSuite.scala) | 121 | Map assertions to Rust/contract coverage |
| [src/test/scala/com/sslproxy/coordinator/dq/DqStoreIntegrationSuite.scala](../services/octopus/src/test/scala/com/sslproxy/coordinator/dq/DqStoreIntegrationSuite.scala) | 668 | Map assertions to Rust/contract coverage |

## Scala verification: http

| File | Lines | Proposed disposition |
| --- | ---: | --- |
| [src/test/scala/com/sslproxy/coordinator/http/HealthRoutesSuite.scala](../services/octopus/src/test/scala/com/sslproxy/coordinator/http/HealthRoutesSuite.scala) | 135 | Map assertions to Rust/contract coverage |
| [src/test/scala/com/sslproxy/coordinator/http/LiveMetricsRoutesSuite.scala](../services/octopus/src/test/scala/com/sslproxy/coordinator/http/LiveMetricsRoutesSuite.scala) | 67 | Map assertions to Rust/contract coverage |
| [src/test/scala/com/sslproxy/coordinator/http/PublicStatsRoutesSuite.scala](../services/octopus/src/test/scala/com/sslproxy/coordinator/http/PublicStatsRoutesSuite.scala) | 133 | Map assertions to Rust/contract coverage |

## Scala verification: ingest

| File | Lines | Proposed disposition |
| --- | ---: | --- |
| [src/test/scala/com/sslproxy/coordinator/ingest/OctopusPersistenceIntegrationSuite.scala](../services/octopus/src/test/scala/com/sslproxy/coordinator/ingest/OctopusPersistenceIntegrationSuite.scala) | 6662 | Map assertions to Rust/contract coverage |
| [src/test/scala/com/sslproxy/coordinator/ingest/SyncEventHydrationServiceSuite.scala](../services/octopus/src/test/scala/com/sslproxy/coordinator/ingest/SyncEventHydrationServiceSuite.scala) | 191 | Map assertions to Rust/contract coverage |

## Scala verification: kafka

| File | Lines | Proposed disposition |
| --- | ---: | --- |
| [src/test/scala/com/sslproxy/coordinator/kafka/BoundedBatchingSuite.scala](../services/octopus/src/test/scala/com/sslproxy/coordinator/kafka/BoundedBatchingSuite.scala) | 30 | Map assertions to Rust/contract coverage |
| [src/test/scala/com/sslproxy/coordinator/kafka/DurableIngestionSuite.scala](../services/octopus/src/test/scala/com/sslproxy/coordinator/kafka/DurableIngestionSuite.scala) | 90 | Map assertions to Rust/contract coverage |
| [src/test/scala/com/sslproxy/coordinator/kafka/LockedTopicConsumerSuite.scala](../services/octopus/src/test/scala/com/sslproxy/coordinator/kafka/LockedTopicConsumerSuite.scala) | 127 | Map assertions to Rust/contract coverage |
| [src/test/scala/com/sslproxy/coordinator/kafka/PostgresLoadStreamSuite.scala](../services/octopus/src/test/scala/com/sslproxy/coordinator/kafka/PostgresLoadStreamSuite.scala) | 135 | Map assertions to Rust/contract coverage |
| [src/test/scala/com/sslproxy/coordinator/kafka/PostgresResultStreamSuite.scala](../services/octopus/src/test/scala/com/sslproxy/coordinator/kafka/PostgresResultStreamSuite.scala) | 60 | Map assertions to Rust/contract coverage |
| [src/test/scala/com/sslproxy/coordinator/kafka/ScanRequestStreamSuite.scala](../services/octopus/src/test/scala/com/sslproxy/coordinator/kafka/ScanRequestStreamSuite.scala) | 41 | Map assertions to Rust/contract coverage |
| [src/test/scala/com/sslproxy/coordinator/kafka/WirelessAuditStreamSuite.scala](../services/octopus/src/test/scala/com/sslproxy/coordinator/kafka/WirelessAuditStreamSuite.scala) | 31 | Map assertions to Rust/contract coverage |
| [src/test/scala/com/sslproxy/coordinator/kafka/WirelessHeartbeatStreamSuite.scala](../services/octopus/src/test/scala/com/sslproxy/coordinator/kafka/WirelessHeartbeatStreamSuite.scala) | 40 | Map assertions to Rust/contract coverage |

## Scala verification: observability

| File | Lines | Proposed disposition |
| --- | ---: | --- |
| [src/test/scala/com/sslproxy/coordinator/observability/CoordinatorMetricsSuite.scala](../services/octopus/src/test/scala/com/sslproxy/coordinator/observability/CoordinatorMetricsSuite.scala) | 245 | Map assertions to Rust/contract coverage |
| [src/test/scala/com/sslproxy/coordinator/observability/CoordinatorTracingSuite.scala](../services/octopus/src/test/scala/com/sslproxy/coordinator/observability/CoordinatorTracingSuite.scala) | 117 | Map assertions to Rust/contract coverage |
| [src/test/scala/com/sslproxy/coordinator/observability/ObservabilityContractSuite.scala](../services/octopus/src/test/scala/com/sslproxy/coordinator/observability/ObservabilityContractSuite.scala) | 94 | Map assertions to Rust/contract coverage |
| [src/test/scala/com/sslproxy/coordinator/observability/OperationalStatsServiceSuite.scala](../services/octopus/src/test/scala/com/sslproxy/coordinator/observability/OperationalStatsServiceSuite.scala) | 94 | Map assertions to Rust/contract coverage |
| [src/test/scala/com/sslproxy/coordinator/observability/StructuredLoggerSqlSuite.scala](../services/octopus/src/test/scala/com/sslproxy/coordinator/observability/StructuredLoggerSqlSuite.scala) | 30 | Map assertions to Rust/contract coverage |
| [src/test/scala/com/sslproxy/coordinator/observability/StructuredLoggerSuite.scala](../services/octopus/src/test/scala/com/sslproxy/coordinator/observability/StructuredLoggerSuite.scala) | 60 | Map assertions to Rust/contract coverage |

## Scala verification: persistence

| File | Lines | Proposed disposition |
| --- | ---: | --- |
| [src/test/scala/com/sslproxy/coordinator/persistence/BatchStatementSuite.scala](../services/octopus/src/test/scala/com/sslproxy/coordinator/persistence/BatchStatementSuite.scala) | 13 | Map assertions to Rust/contract coverage |
| [src/test/scala/com/sslproxy/coordinator/persistence/DbResultTSuite.scala](../services/octopus/src/test/scala/com/sslproxy/coordinator/persistence/DbResultTSuite.scala) | 24 | Map assertions to Rust/contract coverage |

## Scala verification: postgres

| File | Lines | Proposed disposition |
| --- | ---: | --- |
| [src/test/scala/com/sslproxy/coordinator/postgres/LiveHydrationProbeSuite.scala](../services/octopus/src/test/scala/com/sslproxy/coordinator/postgres/LiveHydrationProbeSuite.scala) | 197 | Map assertions to Rust/contract coverage |
| [src/test/scala/com/sslproxy/coordinator/postgres/PostgresChecksumSuite.scala](../services/octopus/src/test/scala/com/sslproxy/coordinator/postgres/PostgresChecksumSuite.scala) | 26 | Map assertions to Rust/contract coverage |
| [src/test/scala/com/sslproxy/coordinator/postgres/PostgresErrorClassSuite.scala](../services/octopus/src/test/scala/com/sslproxy/coordinator/postgres/PostgresErrorClassSuite.scala) | 76 | Map assertions to Rust/contract coverage |
| [src/test/scala/com/sslproxy/coordinator/postgres/PostgresLoadHandlerSuite.scala](../services/octopus/src/test/scala/com/sslproxy/coordinator/postgres/PostgresLoadHandlerSuite.scala) | 311 | Map assertions to Rust/contract coverage |
| [src/test/scala/com/sslproxy/coordinator/postgres/PostgresPayloadResolverSuite.scala](../services/octopus/src/test/scala/com/sslproxy/coordinator/postgres/PostgresPayloadResolverSuite.scala) | 66 | Map assertions to Rust/contract coverage |
| [src/test/scala/com/sslproxy/coordinator/postgres/PostgresRepositoryRetrySuite.scala](../services/octopus/src/test/scala/com/sslproxy/coordinator/postgres/PostgresRepositoryRetrySuite.scala) | 71 | Map assertions to Rust/contract coverage |
| [src/test/scala/com/sslproxy/coordinator/postgres/PostgresRepositorySimilaritySuite.scala](../services/octopus/src/test/scala/com/sslproxy/coordinator/postgres/PostgresRepositorySimilaritySuite.scala) | 12 | Map assertions to Rust/contract coverage |
| [src/test/scala/com/sslproxy/coordinator/postgres/PostgresRepositoryStableIdSuite.scala](../services/octopus/src/test/scala/com/sslproxy/coordinator/postgres/PostgresRepositoryStableIdSuite.scala) | 19 | Map assertions to Rust/contract coverage |
| [src/test/scala/com/sslproxy/coordinator/postgres/PostgresResultSuite.scala](../services/octopus/src/test/scala/com/sslproxy/coordinator/postgres/PostgresResultSuite.scala) | 34 | Map assertions to Rust/contract coverage |
| [src/test/scala/com/sslproxy/coordinator/postgres/PostgresSinkRetrySuite.scala](../services/octopus/src/test/scala/com/sslproxy/coordinator/postgres/PostgresSinkRetrySuite.scala) | 126 | Map assertions to Rust/contract coverage |
| [src/test/scala/com/sslproxy/coordinator/postgres/PostgresSinkTargetSuite.scala](../services/octopus/src/test/scala/com/sslproxy/coordinator/postgres/PostgresSinkTargetSuite.scala) | 47 | Map assertions to Rust/contract coverage |
| [src/test/scala/com/sslproxy/coordinator/postgres/PostgresSinkTimeoutIntegrationSuite.scala](../services/octopus/src/test/scala/com/sslproxy/coordinator/postgres/PostgresSinkTimeoutIntegrationSuite.scala) | 166 | Map assertions to Rust/contract coverage |
| [src/test/scala/com/sslproxy/coordinator/postgres/PostgresTransactorSuite.scala](../services/octopus/src/test/scala/com/sslproxy/coordinator/postgres/PostgresTransactorSuite.scala) | 85 | Map assertions to Rust/contract coverage |
| [src/test/scala/com/sslproxy/coordinator/postgres/PostgresTransformServiceSuite.scala](../services/octopus/src/test/scala/com/sslproxy/coordinator/postgres/PostgresTransformServiceSuite.scala) | 161 | Map assertions to Rust/contract coverage |
| [src/test/scala/com/sslproxy/coordinator/postgres/StreamingPayloadRowsSuite.scala](../services/octopus/src/test/scala/com/sslproxy/coordinator/postgres/StreamingPayloadRowsSuite.scala) | 48 | Map assertions to Rust/contract coverage |
| [src/test/scala/com/sslproxy/coordinator/postgres/sql/BatchSinkSqlSuite.scala](../services/octopus/src/test/scala/com/sslproxy/coordinator/postgres/sql/BatchSinkSqlSuite.scala) | 113 | Map assertions to Rust/contract coverage |
| [src/test/scala/com/sslproxy/coordinator/postgres/sql/DownstreamCorrectnessIntegrationSuite.scala](../services/octopus/src/test/scala/com/sslproxy/coordinator/postgres/sql/DownstreamCorrectnessIntegrationSuite.scala) | 127 | Map assertions to Rust/contract coverage |
| [src/test/scala/com/sslproxy/coordinator/postgres/sql/IdentityGraphSqlSuite.scala](../services/octopus/src/test/scala/com/sslproxy/coordinator/postgres/sql/IdentityGraphSqlSuite.scala) | 70 | Map assertions to Rust/contract coverage |
| [src/test/scala/com/sslproxy/coordinator/postgres/sql/IngestionPeaksIntegrationSuite.scala](../services/octopus/src/test/scala/com/sslproxy/coordinator/postgres/sql/IngestionPeaksIntegrationSuite.scala) | 70 | Map assertions to Rust/contract coverage |
| [src/test/scala/com/sslproxy/coordinator/postgres/sql/IngestionSqlSuite.scala](../services/octopus/src/test/scala/com/sslproxy/coordinator/postgres/sql/IngestionSqlSuite.scala) | 16 | Map assertions to Rust/contract coverage |
| [src/test/scala/com/sslproxy/coordinator/postgres/sql/IntelligenceSqlSuite.scala](../services/octopus/src/test/scala/com/sslproxy/coordinator/postgres/sql/IntelligenceSqlSuite.scala) | 55 | Map assertions to Rust/contract coverage |
| [src/test/scala/com/sslproxy/coordinator/postgres/sql/JobBatchSqlSuite.scala](../services/octopus/src/test/scala/com/sslproxy/coordinator/postgres/sql/JobBatchSqlSuite.scala) | 33 | Map assertions to Rust/contract coverage |
| [src/test/scala/com/sslproxy/coordinator/postgres/sql/MaintenanceSqlSuite.scala](../services/octopus/src/test/scala/com/sslproxy/coordinator/postgres/sql/MaintenanceSqlSuite.scala) | 48 | Map assertions to Rust/contract coverage |
| [src/test/scala/com/sslproxy/coordinator/postgres/sql/ProcessorStateSqlSuite.scala](../services/octopus/src/test/scala/com/sslproxy/coordinator/postgres/sql/ProcessorStateSqlSuite.scala) | 32 | Map assertions to Rust/contract coverage |
| [src/test/scala/com/sslproxy/coordinator/postgres/sql/ProxyBehaviorSqlSuite.scala](../services/octopus/src/test/scala/com/sslproxy/coordinator/postgres/sql/ProxyBehaviorSqlSuite.scala) | 44 | Map assertions to Rust/contract coverage |
| [src/test/scala/com/sslproxy/coordinator/postgres/sql/ResultSqlSuite.scala](../services/octopus/src/test/scala/com/sslproxy/coordinator/postgres/sql/ResultSqlSuite.scala) | 26 | Map assertions to Rust/contract coverage |
| [src/test/scala/com/sslproxy/coordinator/postgres/sql/SearchPreparationSqlSuite.scala](../services/octopus/src/test/scala/com/sslproxy/coordinator/postgres/sql/SearchPreparationSqlSuite.scala) | 48 | Map assertions to Rust/contract coverage |
| [src/test/scala/com/sslproxy/coordinator/postgres/sql/SqlPlacementSuite.scala](../services/octopus/src/test/scala/com/sslproxy/coordinator/postgres/sql/SqlPlacementSuite.scala) | 41 | Map assertions to Rust/contract coverage |
| [src/test/scala/com/sslproxy/coordinator/postgres/sql/ThreatRiskSqlSuite.scala](../services/octopus/src/test/scala/com/sslproxy/coordinator/postgres/sql/ThreatRiskSqlSuite.scala) | 23 | Map assertions to Rust/contract coverage |
| [src/test/scala/com/sslproxy/coordinator/postgres/sql/WirelessSqlSuite.scala](../services/octopus/src/test/scala/com/sslproxy/coordinator/postgres/sql/WirelessSqlSuite.scala) | 78 | Map assertions to Rust/contract coverage |

## Scala verification: processor

| File | Lines | Proposed disposition |
| --- | ---: | --- |
| [src/test/scala/com/sslproxy/coordinator/processor/FencedRetentionRunnerSuite.scala](../services/octopus/src/test/scala/com/sslproxy/coordinator/processor/FencedRetentionRunnerSuite.scala) | 225 | Map assertions to Rust/contract coverage |
| [src/test/scala/com/sslproxy/coordinator/processor/IntelligencePreparationSuite.scala](../services/octopus/src/test/scala/com/sslproxy/coordinator/processor/IntelligencePreparationSuite.scala) | 201 | Map assertions to Rust/contract coverage |
| [src/test/scala/com/sslproxy/coordinator/processor/ProcessorCatalogSuite.scala](../services/octopus/src/test/scala/com/sslproxy/coordinator/processor/ProcessorCatalogSuite.scala) | 93 | Map assertions to Rust/contract coverage |
| [src/test/scala/com/sslproxy/coordinator/processor/ProcessorSupervisorSuite.scala](../services/octopus/src/test/scala/com/sslproxy/coordinator/processor/ProcessorSupervisorSuite.scala) | 412 | Map assertions to Rust/contract coverage |
| [src/test/scala/com/sslproxy/coordinator/processor/ProjectionFunctionsSuite.scala](../services/octopus/src/test/scala/com/sslproxy/coordinator/processor/ProjectionFunctionsSuite.scala) | 55 | Map assertions to Rust/contract coverage |
| [src/test/scala/com/sslproxy/coordinator/processor/ProxyAsnEnrichmentSuite.scala](../services/octopus/src/test/scala/com/sslproxy/coordinator/processor/ProxyAsnEnrichmentSuite.scala) | 139 | Map assertions to Rust/contract coverage |
| [src/test/scala/com/sslproxy/coordinator/processor/ProxyAuthoritySuite.scala](../services/octopus/src/test/scala/com/sslproxy/coordinator/processor/ProxyAuthoritySuite.scala) | 37 | Map assertions to Rust/contract coverage |
| [src/test/scala/com/sslproxy/coordinator/processor/ProxyBehaviorCohortsSuite.scala](../services/octopus/src/test/scala/com/sslproxy/coordinator/processor/ProxyBehaviorCohortsSuite.scala) | 375 | Map assertions to Rust/contract coverage |
| [src/test/scala/com/sslproxy/coordinator/processor/ProxyBehaviorScopeSuite.scala](../services/octopus/src/test/scala/com/sslproxy/coordinator/processor/ProxyBehaviorScopeSuite.scala) | 519 | Map assertions to Rust/contract coverage |
| [src/test/scala/com/sslproxy/coordinator/processor/ProxyBehaviorStatisticsSuite.scala](../services/octopus/src/test/scala/com/sslproxy/coordinator/processor/ProxyBehaviorStatisticsSuite.scala) | 161 | Map assertions to Rust/contract coverage |
| [src/test/scala/com/sslproxy/coordinator/processor/ProxyBehaviorSuite.scala](../services/octopus/src/test/scala/com/sslproxy/coordinator/processor/ProxyBehaviorSuite.scala) | 424 | Map assertions to Rust/contract coverage |
| [src/test/scala/com/sslproxy/coordinator/processor/ProxyClientHelloDriftSuite.scala](../services/octopus/src/test/scala/com/sslproxy/coordinator/processor/ProxyClientHelloDriftSuite.scala) | 114 | Map assertions to Rust/contract coverage |
| [src/test/scala/com/sslproxy/coordinator/processor/ProxyDestinationInfrastructureSuite.scala](../services/octopus/src/test/scala/com/sslproxy/coordinator/processor/ProxyDestinationInfrastructureSuite.scala) | 86 | Map assertions to Rust/contract coverage |
| [src/test/scala/com/sslproxy/coordinator/processor/ProxyDomainLexicalSuite.scala](../services/octopus/src/test/scala/com/sslproxy/coordinator/processor/ProxyDomainLexicalSuite.scala) | 243 | Map assertions to Rust/contract coverage |
| [src/test/scala/com/sslproxy/coordinator/processor/ProxyEvidenceSuite.scala](../services/octopus/src/test/scala/com/sslproxy/coordinator/processor/ProxyEvidenceSuite.scala) | 162 | Map assertions to Rust/contract coverage |
| [src/test/scala/com/sslproxy/coordinator/processor/ProxyFlowContractSuite.scala](../services/octopus/src/test/scala/com/sslproxy/coordinator/processor/ProxyFlowContractSuite.scala) | 170 | Map assertions to Rust/contract coverage |
| [src/test/scala/com/sslproxy/coordinator/processor/ProxyFollowOnIntegrationSuite.scala](../services/octopus/src/test/scala/com/sslproxy/coordinator/processor/ProxyFollowOnIntegrationSuite.scala) | 105 | Map assertions to Rust/contract coverage |
| [src/test/scala/com/sslproxy/coordinator/processor/ProxyIntelligenceEvidenceSuite.scala](../services/octopus/src/test/scala/com/sslproxy/coordinator/processor/ProxyIntelligenceEvidenceSuite.scala) | 34 | Map assertions to Rust/contract coverage |
| [src/test/scala/com/sslproxy/coordinator/processor/ProxyThreatFeedSuite.scala](../services/octopus/src/test/scala/com/sslproxy/coordinator/processor/ProxyThreatFeedSuite.scala) | 193 | Map assertions to Rust/contract coverage |
| [src/test/scala/com/sslproxy/coordinator/processor/RetryPolicySuite.scala](../services/octopus/src/test/scala/com/sslproxy/coordinator/processor/RetryPolicySuite.scala) | 20 | Map assertions to Rust/contract coverage |
| [src/test/scala/com/sslproxy/coordinator/processor/SearchDocumentPreparationSuite.scala](../services/octopus/src/test/scala/com/sslproxy/coordinator/processor/SearchDocumentPreparationSuite.scala) | 144 | Map assertions to Rust/contract coverage |
| [src/test/scala/com/sslproxy/coordinator/processor/WirelessObservationSuite.scala](../services/octopus/src/test/scala/com/sslproxy/coordinator/processor/WirelessObservationSuite.scala) | 65 | Map assertions to Rust/contract coverage |

## Scala verification: util

| File | Lines | Proposed disposition |
| --- | ---: | --- |
| [src/test/scala/com/sslproxy/coordinator/util/ErrorSanitizerSuite.scala](../services/octopus/src/test/scala/com/sslproxy/coordinator/util/ErrorSanitizerSuite.scala) | 41 | Map assertions to Rust/contract coverage |
| [src/test/scala/com/sslproxy/coordinator/util/PayloadJsonInspectionBenchmark.scala](../services/octopus/src/test/scala/com/sslproxy/coordinator/util/PayloadJsonInspectionBenchmark.scala) | 76 | Map assertions to Rust/contract coverage |
| [src/test/scala/com/sslproxy/coordinator/util/PayloadJsonInspectionSuite.scala](../services/octopus/src/test/scala/com/sslproxy/coordinator/util/PayloadJsonInspectionSuite.scala) | 122 | Map assertions to Rust/contract coverage |

## Inventory reconciliation gate

Before later design or implementation, compare this ledger with a fresh
`git -C services/octopus ls-files` result and both recorded revisions. Every
added or removed production file must be assigned to a workmap unit. Every
existing test must be ported, replaced by equivalent assertions, or retired
with a recorded reason. A passing aggregate count alone is insufficient.

