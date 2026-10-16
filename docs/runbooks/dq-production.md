# DQ production promotion

> **Status: Blocked on platform inputs.** Last production inspection: October 16, 2026.

The [Search integration](../../apps/integration-console/atheros-search/README.md)
is implemented. Production image bumps alone do not activate DQ. The
[production app-stack](../../cyber-stack/matrix/prod/app-stack/kustomization.yaml)
does not yet include the [DQ base](../../cyber-stack/base/delip-queve), and the
Search, manager, and Octopus DQ gates remain disabled.

## Observed blockers

| Gate | Observed state |
| --- | --- |
| Vault | Initialized, sealed, Raft storage; secret reads return HTTP 503. |
| Platform synchronization | `vault-k8s-sync.timer` active; service exits with status 1 while Vault is sealed. |
| DQ credentials | No `ssl-proxy-dq-*` Secrets in `prod-ssl-proxy`; no DQ entries in the repository's platform input contract. Vault paths could not be inspected while sealed. |
| DQ images | Neither `delip-queve-manager` nor `delip-queve-worker` appears in the production registry catalog. Both Linux AMD64 Docker targets build locally. |
| DQ configuration | Worker manifest is `{}`; worker and manager ConfigMaps lack the approved production settings. Octopus installation, namespace, policy, scope modes, and approved digests are empty. |
| Application rollout | ApplicationSet step 2 is Progressing; app-stack waits for data-plane health. Jaeger is repeatedly OOM-killed at its 2 GiB limit. |

The [Jaeger recovery patch](../../cyber-stack/matrix/prod/patches/jaeger-recovery.yaml)
raises its request to 2 GiB and limit to 4 GiB, with a 3 GiB Go soft limit. This
is prepared desired state, not evidence of successful live recovery. The node
reported 32 percent memory requests and 55 percent memory use during inspection;
aggregate limits were already 98 percent, so observe total working set after
reconciliation. Preserve both Jaeger PVCs.

## Release images

The [umbrella Jenkins pipeline](../../Jenkinsfile) validates DQ Go/race tests,
both binary builds, UI tests, and standalone, embedded, and remote UI builds
before publication. A DQ gitlink bump or a full build publishes both candidates.
The release manifest records their actual pushed digests in `candidateImages`,
with `activationRequired=true`; publication does not promote them.

The root [Makefile](../../Makefile) also provides `build-delip-queve-manager`,
`build-delip-queve-worker`, `publish-delip-queve-manager`, and
`publish-delip-queve-worker`. Candidate publication requires the same registry,
builder, and platform inputs as the other image targets. A local image ID is
not a registry manifest digest.

## Platform inputs

Restore Vault availability through the platform's existing unseal procedure,
then inspect existing paths before adding inputs. Extend the
[platform input contract](../../cyber-stack/platform-input-contract.yaml) and
its generated RBAC, bootstrap shells, and contract checksum together when
onboarding DQ. Provision values in Vault; let platform-sync materialize them.
Do not add empty required DQ inputs to the active contract before their Vault
values exist, because validation blocks the complete synchronization pass.

The following names and keys are already consumed by the DQ base or its callers:

| Secret | Required keys |
| --- | --- |
| `ssl-proxy-dq-atheros-auth` | `service-token` |
| `ssl-proxy-dq-control-auth` | `control-token` |
| `ssl-proxy-dq-manager-auth` | `DQ_CONTROL_TOKEN`, `DQ_WORKER_TOKEN`, `DQ_IDENTITIES_JSON`, `DQ_BROKER_SASL_PASSWORD` |
| `ssl-proxy-dq-worker-auth` | `service-token`, `minio-access-key`, `minio-secret-key`, `redpanda-password` |
| `ssl-proxy-dq-manager-tls` | `ca.crt`, `tls.crt`, `tls.key` |
| `ssl-proxy-dq-worker-tls` | `ca.crt`, `tls.crt`, `tls.key` |
| `ssl-proxy-dq-broker-tls` | `ca.crt` |

The Search token must match a scoped manager identity, the manager control token
must match Octopus, and its worker token must match the worker Secret. Keep
processor-owner registration separate from Search's operational identity.

## Reviewed production configuration

Prepare all of these in one consistent production promotion after the platform
inputs and published digests are available:

1. Add the DQ base only to `app-stack`, pin both real image digests, set
   `imagePullPolicy: IfNotPresent`, and add the two services to the deployed
   image contract and digest bump helper. Keep base defaults disabled.
2. Replace the placeholder manifest with the approved `atheros.dedup` version
   `0.1.0` manifest. Verify its canonical checksum, implementation digest,
   parameter schema checksum, object bindings, worker service, and optional
   immutable remote digest. Match `DQ_WORKER_IMPLEMENTATION_DIGEST` and
   manager `DQ_WORKERS_JSON` to that manifest and image.
3. Configure manager `DQ_CONTROL_URL`, `DQ_INSTALLATION_ID`, `DQ_NAMESPACE`,
   `DQ_BROKERS`, `DQ_BROKER_SASL_USERNAME`, and approved worker addresses.
   The current Octopus control endpoint uses HTTP: either provide approved
   HTTPS or explicitly approve `DQ_CONTROL_ALLOW_PLAINTEXT` on the trusted
   internal network. Never use `DQ_INSECURE_DEVELOPMENT` in production.
4. Configure worker `MINIO_ENDPOINT`, broker addresses and scoped SASL username.
   Verify broker TLS, worker mutual TLS, scoped topic ACLs, and MinIO TLS,
   bucket versioning, encryption, and per-attempt object-prefix permissions.
   The existing in-cluster plaintext broker and MinIO endpoints are not evidence
   that these DQ transport requirements are satisfied.
5. Configure [Octopus DQ settings](../../cyber-stack/base/java-coordinator/dq-config.yaml):
   installation, namespace, scope modes, policy version, approved implementation
   digests, and artifact bucket. Start representative scopes in `shadow` and
   record comparisons before changing them to `enabled`. Verify that the schema
   executor has applied the canonical manifest before enabling Octopus.
6. Configure Search's manager URL, matching scope and service token. Make the
   token reference required when enabling `ATHSEARCH_DQ_ENABLED`. Configure
   the approved HTTPS processor-remote origin when using processor extensions;
   an empty remote origin retains the generic shell views. Provision remote
   routing and artifact browser access separately with their approved origins.
7. Enable manager beta, Octopus, and Search gates only after the preceding
   checks pass. Preserve Atheros merge-decision ownership and Octopus's
   reconciliation path.

## Acceptance and rollback

Run `make gitops-check` and `python3 scripts/check-docs.py`, the
[DQ acceptance procedure](../../services/dq/tests/acceptance.md), and the
[integration verification checks](../../apps/integration-console/atheros-search/README.md).
Capture representative shadow comparisons, access isolation, recovery and
rollback evidence before enabling projection writes. Synthetic local tests do
not establish production throughput.

After the reviewed Git promotion, verify all three production Applications are
Synced and Healthy at the accepted revision using `make production-gate`.
Verify signed-in `/dq` navigation, viewer read access, operator admission,
projection application, cancellation/replay, artifact authorization, and session
expiration against the published images. A successful local build does not
satisfy this live acceptance gate.

Roll back by reverting the Git promotion. Disable admission and dispatch, fence
active attempts, and restore the previous candidate preparation path as described
in the [DQ deployment contract](../../services/dq/README.md#deployment-and-beta-gates).
Preserve recorded human decisions and retained review evidence.
