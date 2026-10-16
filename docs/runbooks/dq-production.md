# DQ production promotion

> **Status: Platform recovered; DQ activation pending.** Last production inspection: October 16, 2026, 09:35 EDT.

The [Search integration](../../apps/integration-console/atheros-search/README.md)
is implemented. The [production app-stack](../../cyber-stack/matrix/prod/app-stack/kustomization.yaml)
stages the [DQ base](../../cyber-stack/base/delip-queve) with published image
digests and a checksummed processor manifest. Both DQ Deployments have zero
replicas in the [preparation patch](../../cyber-stack/matrix/prod/patches/dq-preparation.yaml).
Search, manager, and Octopus gates remain disabled until the host contract,
production transport, scoped permissions, and acceptance checks pass.

## Observed blockers

| Gate | Observed state |
| --- | --- |
| Vault | Unsealed through existing host recovery material; TLS reads and operator authentication succeed. Twelve DQ inputs were created without overwriting existing values. |
| Platform synchronization | The timer completed a successful 24-input sync at 09:34:58 EDT. The reviewed 31-input contract still requires the host installer. |
| DQ credentials | Seven runtime inputs are declared in Git with bootstrap shells, RBAC, checksum, and Argo data ownership rules. They are present in Vault; Kubernetes materialization awaits installation. Five additional transport/provisioning inputs are staged in Vault for the subsequent transport change. |
| DQ images | Both Linux AMD64 images are published; registry HEAD requests returned HTTP 200 and the digests recorded below. |
| DQ configuration | The production processor manifest pins the worker image and canonical parameter schema. Manager/worker transport configuration and Octopus scope/policy activation remain pending. |
| Application rollout | Bootstrap, data-plane, and app-stack were Synced and Healthy at `1dbe23a738f309f27987ac0d287ee18fc3e5a84d`, before the 31-input onboarding change. Jaeger is available at 1/1 replicas. This is platform recovery evidence, not DQ acceptance. |

The [Jaeger recovery patch](../../cyber-stack/matrix/prod/patches/jaeger-recovery.yaml)
raises its request to 2 GiB and limit to 4 GiB, with a 3 GiB Go soft limit. This
has reconciled and Jaeger is available. Continue observing its working set and
the node's aggregate memory use. Preserve both Jaeger PVCs.

## Release images

The [umbrella Jenkins pipeline](../../Jenkinsfile) validates DQ Go/race tests,
both binary builds, UI tests, and standalone, embedded, and remote UI builds
before publication. A DQ gitlink bump or a full build publishes both candidates.
The release manifest records their actual pushed digests in `candidateImages`,
with `activationRequired=true`; publication does not promote them.

Published from parent revision `1dbe23a738f309f27987ac0d287ee18fc3e5a84d`
and DQ revision `04aedeeb587de234bcbede6748f2e52e0141f1dc`, using tag
`1dbe23a7-dq-04aedee`:

| Repository on `192.168.1.242:5000` | Registry manifest digest |
| --- | --- |
| `delip-queve-manager` | `sha256:a5289409f325b7a7a50f0d582263544f8b09210bf8b1269b51e732b547729e3a` |
| `delip-queve-worker` | `sha256:f5ba34c90eec2d4d0ca250b50fba4c40a7da995d87488dfa9956a576c5a9cc31` |

DQ Go vet, race tests, and both binary builds passed. All 15 UI tests and the
standalone, embedded, and remote builds passed with Node. The Bun-only container
failed the three frame tests because it used Bun's Node fallback; the CI task
now installs Node before running Vitest. Local UI build outputs were regenerated.

The root [Makefile](../../Makefile) also provides `build-delip-queve-manager`,
`build-delip-queve-worker`, `publish-delip-queve-manager`, and
`publish-delip-queve-worker`. Candidate publication requires the same registry,
builder, and platform inputs as the other image targets. A local image ID is
not a registry manifest digest.

## Platform inputs

Inspect existing Vault paths before adding inputs. Extend the
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

### Host contract installation

After the onboarding change is merged and Argo has created all seven DQ Secret
shells and reconciled the writer Role, install from a clean temporary worktree
at that exact merged SHA. Leave the dirty host checkout and its submodules
untouched:

```bash
cd /home/wiretrap/git/ssl-proxy
git fetch origin main
reviewed_sha=<merged-onboarding-commit-sha>
release_root="$(mktemp -d /tmp/dq-platform-inputs.XXXXXX)"
git worktree add --detach "$release_root/worktree" "$reviewed_sha"
sudo bash "$release_root/worktree/scripts/install-dq-platform-inputs.sh"
```

The [DQ installer](../../scripts/install-dq-platform-inputs.sh) verifies the
reviewed contract checksum and target availability, stops the timer, preserves
the existing root-owned Vault token and CA, and installs the synchronizer and
contract together. It requires a successful 31-input synchronization and a new
`platform-ready` timestamp before restarting the timer. On failure, leave the
timer stopped and diagnose the service journal. It does not activate DQ.

## Reviewed production configuration

Prepare all of these in one consistent production promotion after the platform
inputs and published digests are available:

1. Confirm the DQ base appears only in `app-stack`, its real image digests are
   pinned, and the host synchronization has materialized every runtime input.
   Keep both Deployments at zero replicas until transport and permission checks
   pass. Keep base feature gates disabled.
2. Verify the staged `atheros.dedup` version `0.1.0`
   [manifest](../../cyber-stack/matrix/prod/config/dq/atheros-dedup-v0.1.0.json):
   its canonical checksum, implementation digest,
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
