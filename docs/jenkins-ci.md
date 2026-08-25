# Jenkins Image CI

Jenkins provides the private build-and-publish loop for the repository's nine
first-party image targets. The checked-in controller configuration creates one
`ssl-proxy-images` pipeline from the root `Jenkinsfile`; the root Makefile
remains the authoritative image inventory and build contract.

## Local development CI server

Copy `.env.example` to the ignored `.env` and replace every placeholder used by
the CI stack. The platform secret workflow must first write the production gate
kubeconfig to a root-owned file outside this repository. Add its absolute host
path to `.env`; the variable contains a path, never the kubeconfig itself:

```dotenv
JENKINS_PROD_READONLY_KUBECONFIG_FILE=/etc/ssl-proxy/jenkins/prod-readonly-kubeconfig
```

The variable is required: Compose refuses to render the CI stack when it is
unset. Create the administrator password with restrictive permissions, validate
the Compose model without printing it, and start the services:

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

### Local development credential reload

After the platform workflow atomically replaces the configured kubeconfig host
file, recreate only the controller in the local Compose CI harness so Docker
remounts the file and JCasC reloads it:

```bash
docker compose -f docker-compose.ci.yaml config --quiet
docker compose -f docker-compose.ci.yaml up -d --no-deps --force-recreate jenkins
docker compose -f docker-compose.ci.yaml ps jenkins
```

These commands manage only the local CI harness. They do not edit, restart or
otherwise mutate any production Kubernetes resource.

## Pipeline behavior

The managed pipeline polls `main` every five minutes and supports manual builds.
When a new run is scheduled, Jenkins aborts any active run before starting it.
This prevents an obsolete checkout from waiting on an exact-revision production
gate after Argo CD has advanced to newer `main`. The pipeline does not expose or
require a GitHub webhook. Each run:

1. checks out the superproject and its pinned submodules, then requires the
   Octopus checkout to match that pin with both worktrees clean;
2. creates and bootstraps its shared Buildx builder after bounded Docker and
   registry checks;
3. runs `make docs-check` and `make gitops-check` in parallel with image
   publishing;
4. publishes every Makefile service independently with a 30-minute limit and
   one retry, using a 12-character commit tag plus the mutable `latest`
   channel; and
5. when validation and every publication branch succeeded, waits up to 30
   minutes for all three production Argo CD Applications to report the full
   triggering checkout SHA with `Synced` sync and `Healthy` health.

Validation remains visible and fails the overall build, but does not cancel
unaffected image publication. Likewise, a failed image branch does not cancel
other branches. The production gate is skipped after either class of failure.
A missing Application, stale revision, `OutOfSync`, `Progressing`, `Degraded`
or timeout fails the otherwise-successful run with sanitized Argo operation and
condition messages. Build results remain available in Jenkins; no outbound
failure webhook is configured.

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
Git. Record an accepted published digest with
`make bump-digest-<service> ENV=prod DIGEST=sha256:<digest>` and review that
production desired-state change normally. It is reconciled only by the three
production Argo CD Applications.

The final gate certifies reconciliation of the reviewed `main` revision that
triggered Jenkins. It does not copy newly published digests into production or
make any Git, Argo CD or Kubernetes mutation. Newly published images remain
unpromoted until their digests are accepted through the normal production
review.

## Production gate credential

The platform secret workflow provisions the kubeconfig from Vault as the host
file named by `JENKINS_PROD_READONLY_KUBECONFIG_FILE`. It must authenticate only
the `argocd/ssl-proxy-production-gate` ServiceAccount declared under
`cyber-stack/argocd`. The checked-in Role is name-scoped to `get` the three
production Applications; it grants no Secret read, workload read or mutation
verb. Keep the source file outside the checkout, restrict host access to the
platform operator and Docker daemon, and never print, copy into `.env`, archive
or attach the file to a build.

Compose mounts that file only into the controller as the
`ssl-proxy-prod-readonly-kubeconfig` secret at
`/run/secrets/ssl-proxy-prod-readonly-kubeconfig`. At startup, Configuration as
Code reads it into a Jenkins secret-file credential with the same ID. The
pipeline binds the credential only around `make production-gate` and passes the
full checkout SHA explicitly. Neither the Compose model nor the checked-in
JCasC file contains credential bytes.

For rotation, have the platform workflow write and validate a candidate file,
then atomically replace the configured host path while preserving its owner and
restrictive mode. Then use the local development credential reload procedure
above to remount the file and reload JCasC.

Confirm the next production gate succeeds before revoking the old credential.
Record only the rotation time, credential version and verification result; do
not include kubeconfig content or command output that contains it.

The gate performs a read-only authorization preflight before polling. It
requires each named Application read and rejects a credential that can read
Secrets or perform representative Argo, workload, Secret or RBAC mutations.
`make gitops-check` separately enforces the exact ServiceAccount, Role and
RoleBinding rules, preventing repository RBAC drift from broadening that
identity.
