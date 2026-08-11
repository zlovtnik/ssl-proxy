# Jenkins Image CI

Jenkins provides the private build-and-publish loop for the repository's nine
first-party image targets. The checked-in controller configuration creates one
`ssl-proxy-images` pipeline from the root `Jenkinsfile`; the root Makefile
remains the authoritative image inventory and build contract.

## Local development CI server

Copy `.env.example` to the ignored `.env`, replace every placeholder used by
the CI stack, and create the administrator password with restrictive
permissions:

```bash
umask 077
openssl rand -base64 32 > secrets/jenkins-admin-password
docker compose -f docker-compose.ci.yaml config
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

The managed pipeline polls `main` every five minutes, supports manual builds,
and disables concurrent runs. It does not expose or require a GitHub webhook.
Each run:

1. checks out the superproject and its pinned submodules;
2. creates and bootstraps its shared Buildx builder after bounded Docker and
   registry checks;
3. runs `make docs-check` and `make gitops-check` in parallel with image
   publishing; and
4. publishes every Makefile service independently with a 30-minute limit and
   one retry, using a 12-character commit tag plus the mutable `latest`
   channel.

Validation remains visible and fails the overall build, but does not cancel
unaffected image publication. Likewise, a failed image branch does not cancel
other branches. Build results remain available in Jenkins; no outbound failure
webhook is configured.

The target set covers the proxy, Octopus coordinator, Atheros Sensor, Atheros
Search, key rotator, Search UI, both Schema Migrator images and the TiDB runtime
schema. The key rotator remains Compose-only because it controls the staged
local rotation harness via the Docker API.

## GitOps handoff

Jenkins publishes immutable image digests but does not mutate Kubernetes or
Git. Record a published digest in the dev slice with
`make bump-digest-<service> ENV=dev DIGEST=sha256:<digest>`, validate it on the
local Kubernetes context, and review that change normally. Production remains
a separate reviewed copy of accepted dev digests and is reconciled only by the
three production Argo CD Applications.
