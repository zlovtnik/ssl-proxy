# Jenkins Image CI

Jenkins provides the private build-and-publish loop for the repository's nine
first-party image targets. The checked-in controller configuration creates one
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
credential. Every run has a 180-minute hard timeout. Each run:

1. checks out the superproject and its pinned submodules, then requires the
   Octopus checkout to match that pin with both worktrees clean;
2. creates and bootstraps its shared Buildx builder after bounded Docker and
   registry checks;
3. runs the repository delivery, Go, Scala and Rust validation matrix before
   publication;
4. publishes the eight Kubernetes image contracts with at most three concurrent
   workers, using a 12-character commit tag plus the mutable `latest` channel;
   and
5. archives the release manifest and prints a final report containing only the
   `make bump-digest-<service> ENV=prod DIGEST=<digest>` commands required by
   newly published digests.

Validation and publication are fail-closed. Jenkins never pushes a Git branch,
opens a pull request, updates a Kustomization or contacts the Kubernetes API.
Build results and both report artifacts remain available in Jenkins; no
outbound failure webhook is configured.

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

Lock generation atomically replaces the committed file. The read-only audit
resolves `plugins.txt` again, rejects added, removed or changed lock entries,
and checks every locked version against the official Jenkins update-center
warning patterns. Resolver failures, metadata fetch or format failures, invalid
pins and any matching direct or transitive security warning fail the audit.
There is no warning allowlist. When the audit finds drift or a warning, update
the responsible direct requirement where a newer compatible version exists,
regenerate the lock, rebuild the controller and rerun the audit before merging.

The target set covers the proxy, Octopus coordinator, Atheros Sensor, Atheros
Search, key rotator, Search UI, both Schema Migrator images and the PostgreSQL runtime
schema. The key rotator remains Compose-only because it controls the staged
local rotation harness via the Docker API.

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
