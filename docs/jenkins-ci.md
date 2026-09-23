# Jenkins Image CI

Jenkins provides the private build-and-publish loop for the repository's eight
Kubernetes image contracts. The checked-in controller configuration creates one
`ssl-proxy-images` pipeline from the root `Jenkinsfile`; the root Makefile
remains the authoritative image inventory and build contract.

## Local development CI server

Copy `.env.example` to the ignored `.env` and replace every placeholder used by
the CI stack. Create the administrator password with restrictive permissions,
validate the Compose model without printing it, and start the services:

```bash
umask 077
openssl rand -base64 32 > secrets/jenkins-admin-password
docker compose -f docker-compose.ci.yaml config --quiet
docker compose -f docker-compose.ci.yaml up -d --build
```

Open the `JENKINS_URL` value from `.env` and sign in with
`JENKINS_ADMIN_ID` plus the generated password. Configuration as Code disables
self-signup, anonymous read access and the setup wizard. Persistent named
volumes hold Jenkins state, registry content, Docker layer data and the
Docker-in-Docker client certificates.

The Jenkins BuildKit container uses host networking inside the isolated
Docker-in-Docker service. This keeps the Compose registry name resolvable from
BuildKit without exposing the host Docker socket or hard-coding the registry
container's address.

The privileged Docker-in-Docker entrypoint also ensures
`fs.inotify.max_user_instances` is at least `1024` before starting the daemon.
Build containers share this host-kernel limit, and sbt creates a native file
watcher while loading a project even for one-shot batch commands. Override the
floor with `JENKINS_DOCKER_INOTIFY_MAX_USER_INSTANCES` only when the CI host has
a reviewed higher requirement; the entrypoint never lowers an existing value.
After changing this setting or deploying the entrypoint for the first time,
recreate only the build engine and wait for its health check:

```bash
docker compose -f docker-compose.ci.yaml up -d --no-deps --force-recreate jenkins-docker
docker compose -f docker-compose.ci.yaml ps jenkins-docker
```

At the start of every registry and Buildx preflight, Jenkins reads the same
host-kernel value through its own `/proc` mount. An invalid value or a value
below `1024` stops the pipeline before any Docker context or BuildKit work and
prints the build-engine recreation command above. Verify the active entrypoint
and shared limit after recreation:

```bash
docker inspect "$(docker compose -f docker-compose.ci.yaml ps -q jenkins-docker)" \
  --format '{{json .Config.Entrypoint}}'
cat /proc/sys/fs/inotify/max_user_instances
docker compose -f docker-compose.ci.yaml exec -T jenkins-docker \
  cat /proc/sys/fs/inotify/max_user_instances
docker compose -f docker-compose.ci.yaml exec -T jenkins \
  cat /proc/sys/fs/inotify/max_user_instances
```

Recreating the build engine also regenerates its server-side TLS material. The
next pipeline run refreshes the CI-owned Docker context from the client
certificates in the shared volume before contacting the daemon, so the
persistent Jenkins home cannot retain a stale DinD CA.

The controller does not mount the host Docker socket. It connects over mutual
TLS to a dedicated privileged Docker-in-Docker service, which is still a
root-equivalent trust boundary. Bind Jenkins and the registry only to a trusted
private address and protect both with the host firewall.

To stop the CI services without deleting state:

```bash
docker compose -f docker-compose.ci.yaml down
```

Do not add `--volumes` unless permanent deletion of Jenkins and registry data
is explicitly intended and backed up.

## Pipeline behavior

The managed pipeline polls `main` every five minutes and supports manual builds.
When a new run is scheduled, Jenkins aborts any active run before starting it.
This prevents an obsolete checkout from publishing after newer `main` work has
started. The pipeline does not expose or require a GitHub webhook or write
credential. Before checkout, Jenkins deletes the CI-owned workspace so reports
or other untracked files from an interrupted build cannot fail the source
integrity gate. Docker and BuildKit caches live outside that workspace. Every
run has a 180-minute hard timeout.

Containerized validation extracts the streamed checkout without preserving the
Jenkins host UID. The root-run validation process therefore owns its temporary
`/workspace` checkout, including submodules, and Git's dubious-ownership check
remains enabled without a global `safe.directory` exception.

Each run:

1. checks out the superproject, compares the last successful Jenkins commit
   to `HEAD` with `scripts/classify_changes.py`, and archives
   `artifacts/changed-paths.json`; a first build or an unavailable base selects
   all checks and images;
2. checks out pinned submodules and requires the Octopus checkout to match its
   pin with both worktrees clean. Delivery documentation validation still
   inspects every pinned submodule, so this checkout remains necessary;
3. prepares Docker access and always runs delivery checks, then runs platform
   sync, Atheros Search, Schema Migrator, Octopus, and Sensor validation only
   for their changed owner paths or bumped submodule pins;
4. creates and bootstraps its shared Buildx builder after bounded registry
   checks when an image is selected;
5. publishes only the selected Kubernetes image contracts with at most three
   concurrent workers, using a 12-character commit tag plus the mutable
   `latest` channel. Redpanda maintenance publishes only when its source path
   changes; and
6. archives the release manifest and prints a final report containing only the
   `make bump-digest-<service> ENV=prod DIGEST=<digest>` commands required by
   newly published digests.

`services/octopus` is a Git submodule in this checkout. Its gitlink bump
selects `java-coordinator`; ordinary `services/octopus/**` paths are not
recorded by a superproject commit. Root `Cargo.toml`, `Cargo.lock`, the shared
`crates/` tree, and the root `Dockerfile` select both Rust images because both
targets share the Docker build. `sql/postgres/` selects the PostgreSQL schema
image. A manifest-only `cyber-stack/` change selects no first-party image.

Validation and publication are fail-closed. Jenkins never pushes a Git branch,
opens a pull request, updates a Kustomization or contacts the Kubernetes API.
The Scala validation requires Docker-backed Octopus tests, generates JaCoCo and
Cucumber reports, and archives them under `artifacts/octopus-coverage/` before
publication. Build results and report artifacts remain available in Jenkins; no
outbound failure webhook is configured.

## Submodule CI handoff

The controller configuration also defines Multibranch jobs for `octopus`,
`integration-console`, `schema-migrator`, and `wg-key-rotator`. Each external
repository has its own root `Jenkinsfile`. Octopus validates and archives its
JAR and coverage reports. Integration Console and Schema Migrator publish
their images under full source commit tags in the same registry; the key
rotator publishes its own image but remains outside the eight production image
contracts.

The umbrella pipeline currently keeps `SUBMODULE_CI_READY=false`. After the
four upstream Jenkinsfiles are committed to their own repositories, the
Octopus job has validated its exact pinned revision, the image jobs have
published their exact pinned revisions, and the change classifier has been
observed in production, set
that flag to `true` in a reviewed root Jenkinsfile change. The umbrella job
then skips Octopus, Atheros Search, and Schema Migrator tests. For a bumped
Integration Console or Schema Migrator pin, it
copies the existing full-SHA image tag to the umbrella commit tag and `latest`
with Buildx imagetools, records the resulting digest, and prints the manual
digest update command. Missing upstream images fail the umbrella job before
any promotion. The umbrella continues to build `java-coordinator` from the
pinned Octopus source because that image embeds and verifies the superproject
revision as well as the Octopus revision.

## Local development plugin lock workflow

[`plugins.txt`](../docker/jenkins/plugins.txt) contains only the eight
human-maintained direct plugin requirements. The sorted
[`plugins.lock.txt`](../docker/jenkins/plugins.lock.txt) records the complete
effective direct and transitive set resolved by the digest-pinned Jenkins base
image. The controller image installs only the lock with `--latest=false`, so a
rebuild cannot silently select newer dependencies.

After reviewing a direct requirement update, regenerate and audit the lock:

```bash
make jenkins-plugin-lock
make jenkins-plugin-audit
docker compose -f docker-compose.ci.yaml build jenkins
```

Lock generation resolves `plugins.txt` with `--latest=true` to select current
dependencies and atomically replaces the committed file. The read-only audit
checks that the lock matches the direct requirements, then resolves
`plugins.lock.txt` with `--latest=false`, just like the controller image build.
It rejects missing dependencies or changed resolved pins and checks every locked
version against the official Jenkins update-center warning patterns. A newer
upstream release alone does not fail an unchanged build. Resolver failures,
metadata fetch or format failures, invalid pins and any matching direct or
transitive security warning still fail the audit.
There is no warning allowlist. When the audit finds drift or a warning, update
the responsible direct requirement where a newer compatible version exists,
regenerate the lock, rebuild the controller and rerun the audit before merging.

The target set covers the proxy, Octopus coordinator, Atheros Sensor, Atheros
Search, Search UI, both Schema Migrator images and the PostgreSQL runtime
schema. The key rotator remains Compose-only and is not published by Jenkins.

The Octopus branch also assembles and inspects the JAR. Publication performs
the same artifact check inside the image build and embeds the exact parent and
Octopus revisions as OCI labels, so stale cutover classes or the superseded
replication/TLS validation cannot be pushed as `java-coordinator`.

## GitOps handoff

Jenkins publishes immutable image digests but does not mutate Kubernetes or
Git. The final console section and archived
`artifacts/bump-digest-commands.txt` list only the commands required to accept
new digests. Run the desired commands in a clean checkout, inspect the rendered
production diff, commit it to `main`, and push when ready. Argo CD then
reconciles the three production Applications. Images whose commands are not run
remain published but unused by production.
