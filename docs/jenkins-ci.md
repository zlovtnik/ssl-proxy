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

The managed pipeline polls `main` every five minutes and disables concurrent
runs. Each run:

1. checks out the superproject and its pinned submodules;
2. runs `make docs-check` and `make gitops-check`;
3. verifies Docker Buildx and registry reachability;
4. builds every target in `Makefile` before publishing anything; and
5. publishes a 12-character commit tag plus the mutable `latest` channel.

The target set covers the proxy, Octopus coordinator, Atheros Sensor, Atheros
Search, key rotator, Search UI, both Schema Migrator images and the TiDB runtime
schema. Image Updater observes the Kubernetes-deployed subset. The key rotator
remains Compose-only because it controls the staged local rotation harness via
the Docker API.

## GitOps handoff

The Argo CD control-plane Kustomization installs the pinned Image Updater chart
through a dedicated least-privilege AppProject. The controller watches only
the `argocd` namespace, reads the private HTTP registry at
`192.168.1.221:5000`, and reconciles the `ssl-proxy-dev` ImageUpdater custom
resource.

The platform must materialize `argocd/ssl-proxy-image-updater-git` outside this
repository. For GitHub pull-request write-back, provide either a scoped token
or GitHub App fields accepted by Image Updater; never commit those values.
Image Updater proposes only dev Kustomize digest changes. Production remains a
separate reviewed copy of accepted dev digests.
