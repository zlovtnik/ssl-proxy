# Actionable workmap: `stackctl`

The safest path is to implement this as several small PRs, with the existing umbrella deployment remaining available until the split-release output and test deployment are proven equivalent.

## Target end state

```text
make up-ready
    │
    ├── build/mirror images
    ├── generate TLS material
    ├── synchronize Secrets
    ├── prepare nodes
    ├── stackctl preflight
    └── stackctl deploy
            ├── Wave 1: infrastructure
            ├── Wave 2: TiDB schema executor
            ├── Wave 3: schema migrator
            ├── Wave 4: applications
            └── Wave 5: proxy
```

`stackctl` owns:

```text
dependency resolution
Helm release application
readiness gates
migration Job execution
failure diagnostics
descendant blocking
```

It does not own image builds, Secrets, TLS generation, or node provisioning.

---

# Phase 0 — Resolve deployment-mode questions

Do this before writing the orchestrator.

## 0.1 Confirm Redpanda and MinIO deployment modes

The current chart analysis says both Redpanda and MinIO default to `external: true`, and no umbrella-level subchart overrides were found. In that configuration, their standalone charts may produce no StatefulSet to wait for. 

Render both using the exact production values:

```bash
helm template ssl-proxy-redpanda \
  ./helm/ssl-proxy/charts/redpanda \
  -f ./helm/ssl-proxy/values.yaml \
  -f ./helm/ssl-proxy/values-k8s.yaml

helm template ssl-proxy-minio \
  ./helm/ssl-proxy/charts/minio \
  -f ./helm/ssl-proxy/values.yaml \
  -f ./helm/ssl-proxy/values-k8s.yaml
```

Determine which model applies:

### In-cluster

```yaml
redpanda:
  external: false

minio:
  external: false
```

They remain Helm components with Kubernetes resource gates.

### External

They should not be treated as normal Helm workloads:

```yaml
redpanda:
  type: external-check
  checks:
    - type: tcp
      host_from: global.shared.redpanda.bootstrapServers

minio:
  type: external-check
  checks:
    - type: http
      url_from: global.shared.minio.endpoint
```

**Exit condition:** each dependency is classified as either `helm` or `external-check`.

---

## 0.2 Establish the actual component names

Use these canonical stack IDs:

```text
tidb
redpanda
minio
redis
telemetry
tidb-schema-executor
schema-migrator
java-coordinator
atheros-search
atheros-sensor
proxy
```

Map `redis` to its actual chart:

```yaml
redis:
  chart: ./helm/ssl-proxy/charts/redis-runtime
```

The stack ID does not need to equal the Helm chart directory.

---

## 0.3 Capture the current umbrella baseline

Create:

```text
stackctl/baseline/
```

Render the existing deployment:

```bash
mkdir -p stackctl/baseline

helm template ssl-proxy ./helm/ssl-proxy \
  -f ./helm/ssl-proxy/values.yaml \
  -f ./helm/ssl-proxy/values-k8s.yaml \
  > stackctl/baseline/umbrella.yaml
```

Also capture the current cluster:

```bash
kubectl --context "$UP_READY_KUBE_CONTEXT" \
  get deploy,statefulset,daemonset,job,service,pvc,configmap \
  -n default \
  -o yaml \
  > stackctl/baseline/live-resources.yaml
```

Record:

* Resource names.
* Service names.
* Service selectors.
* PVC names.
* Workload labels.
* Secret and ConfigMap references.
* Current Helm ownership annotations.

**Exit condition:** the repository contains a reproducible baseline against which split releases can be compared.

---

# Phase 1 — Create the stack contract

## Files

```text
stackctl/
├── stackctl.py
├── stack.yaml
├── README.md
├── requirements.txt
└── tests/
    ├── test_graph.py
    ├── test_config.py
    └── test_values.py
```

## 1.1 Define supported component types

Start with four types:

```text
helm
helm-job
manifest
external-check
```

Responsibilities:

| Type             | Purpose                                            |
| ---------------- | -------------------------------------------------- |
| `helm`           | Deploy long-running workloads                      |
| `helm-job`       | Deploy a Job that must execute for this deployment |
| `manifest`       | Apply raw Kubernetes manifests                     |
| `external-check` | Verify an externally managed dependency            |

## 1.2 Define the CLI

```bash
python3 stackctl/stackctl.py plan
python3 stackctl/stackctl.py validate
python3 stackctl/stackctl.py dry-run
python3 stackctl/stackctl.py deploy
python3 stackctl/stackctl.py status
```

Common options:

```text
--file
--kube-context
--kubeconfig
--namespace
--set
--set-string
--set-literal
--component
--from-wave
--verbose
```

Suggested semantics:

```bash
stackctl deploy --component atheros-search
```

Deploys the selected component and any unsatisfied dependencies.

```bash
stackctl deploy --from-wave 4
```

Starts at Wave 4 after verifying Waves 1–3 are currently healthy.

---

## 1.3 Define the configuration model

Example:

```yaml
version: 1

defaults:
  namespace: default
  timeout: 10m
  values:
    - ./helm/ssl-proxy/values.yaml
    - ./helm/ssl-proxy/values-k8s.yaml

components:
  tidb:
    type: helm
    release: ssl-proxy-tidb
    chart: ./helm/ssl-proxy/charts/tidb
    values_key: tidb
    include_global: true
    set:
      external: false
    gates:
      - resource: statefulset/ssl-proxy-tidb

  tidb-schema-executor:
    type: helm-job
    release: ssl-proxy-tidb-schema
    chart: ./helm/ssl-proxy/charts/tidb-schema-executor
    values_key: tidbSchemaExecutor
    include_global: true
    depends_on:
      - tidb
    job:
      rerun: replace
    gates:
      - resource: job/ssl-proxy-tidb-schema
        condition: complete
```

**Exit condition:** `stackctl plan` can parse the file and print the graph without accessing Kubernetes.

---

# Phase 2 — Implement graph planning

## Required behavior

Implement:

* Unknown-dependency detection.
* Dependency-cycle detection.
* Topological sorting.
* Parallel components within a wave.
* Descendant blocking.
* Optional component targeting.

Expected plan:

```text
Wave 1
  minio
  redpanda
  redis
  telemetry
  tidb

Wave 2
  tidb-schema-executor

Wave 3
  schema-migrator

Wave 4
  atheros-search
  atheros-sensor
  java-coordinator

Wave 5
  proxy
```

## Correct application dependencies

```yaml
java-coordinator:
  depends_on:
    - tidb
    - redpanda
    - minio
    - schema-migrator

atheros-search:
  depends_on:
    - tidb
    - redpanda
    - schema-migrator

atheros-sensor:
  depends_on:
    - redpanda

proxy:
  depends_on:
    - redpanda
    - java-coordinator
    - atheros-search
```

`schema-migrator` must be explicitly included where current schema readiness is required. Depending only on TiDB is insufficient.

## Tests

```python
def test_detects_unknown_dependency(): ...

def test_detects_cycle(): ...

def test_calculates_expected_five_waves(): ...

def test_parallel_components_share_wave(): ...

def test_target_component_includes_dependencies(): ...
```

**Exit condition:**

```bash
pytest stackctl/tests/test_graph.py
python3 stackctl/stackctl.py plan --file stackctl/stack.yaml
```

Both pass and produce the expected five waves.

---

# Phase 3 — Implement effective values generation

This is the most important compatibility layer.

All 11 subcharts have their own `values.yaml`, but several require umbrella-provided `global.shared.*` values. Only TiDB and schema-migrator have significant parent-key values beyond simple enablement. 

## 3.1 Merge rules

For each component:

1. Load the subchart’s own defaults through Helm normally.
2. Load each umbrella values file in declared order.
3. Extract the component’s `values_key`.
4. Copy the umbrella `global` block.
5. Deep-merge runtime overrides.
6. Write a temporary effective-values file.
7. Pass that file to Helm.

Conceptually:

```python
effective_values = deep_merge(
    umbrella_values.get(values_key, {}),
    {"global": umbrella_values.get("global", {})},
    runtime_overrides,
)
```

Later files must override earlier files.

## 3.2 Explicit value-key mappings

```yaml
tidb:
  values_key: tidb

redis:
  values_key: redisRuntime

tidb-schema-executor:
  values_key: tidbSchemaExecutor

schema-migrator:
  values_key: schemaMigrator

java-coordinator:
  values_key: javaCoordinator

atheros-search:
  values_key: atherosSearch

atheros-sensor:
  values_key: atherosSensor

proxy:
  values_key: proxy

telemetry:
  values_key: telemetry

redpanda:
  values_key: redpanda

minio:
  values_key: minio
```

Confirm every key against `Chart.yaml` dependency aliases.

## 3.3 Critical component rules

### TiDB

TiDB requires the parent-scoped `external`, `minimumVersion`, and `egress.*` settings. Without them, it defaults to external mode. 

### Schema migrator

It requires:

```text
schemaMigrator.enabled
schemaMigrator.publicHostname
schemaMigrator.traefik.acme.email
global.shared.tidb.*
global.shared.keycloak.*
```

Its validation template enforces required hostname and ACME values when enabled. 

### Java coordinator

It needs the umbrella’s TiDB and MinIO shared configuration. Its own chart does not supply complete TiDB shared defaults. 

### TiDB schema executor

It requires `global.shared.tidb.tls.caSecret` from the umbrella. 

### Migration mode

Preserve:

```yaml
global:
  migration:
    mode: ...
```

The Java coordinator consumes this setting to control processor and consumer behavior. 

## Tests

Create fixtures containing:

```yaml
global:
  shared:
    tidb:
      host: example

tidb:
  external: false
  minimumVersion: "8.5.0"
```

Verify the generated TiDB effective file becomes:

```yaml
external: false
minimumVersion: "8.5.0"

global:
  shared:
    tidb:
      host: example
```

**Exit condition:** every component can be rendered standalone using the generated effective-values file.

---

# Phase 4 — Implement offline validation

`validate` must not modify the cluster.

For every Helm component:

```bash
helm dependency build <chart>
helm lint <chart> -f <effective-values>
helm template <release> <chart> -f <effective-values>
```

Parse the rendered YAML and check:

* At least one resource was rendered, unless explicitly allowed.
* Every configured gate exists.
* Resource names are unique across components.
* No two releases declare the same PVC.
* No two releases declare the same Service.
* Service selectors still match workload labels.
* Required Secrets are referenced consistently.
* Namespace matches the configured namespace.
* No unresolved template output exists.

## Validation output

```text
[PASS] tidb
  rendered: 8 resources
  gate: statefulset/ssl-proxy-tidb

[PASS] java-coordinator
  rendered: 4 resources
  gate: deployment/ssl-proxy-coordinator

[FAIL] redpanda
  configured gate statefulset/ssl-proxy-redpanda not rendered
  probable cause: external=true
```

Do not finalize gate names manually. Derive and verify them from rendered manifests.

**Exit condition:**

```bash
make stackctl-validate
```

passes for all 11 components.

---

# Phase 5 — Implement cluster preflight

Preflight verifies prerequisites but does not create them.

## Checks

```yaml
preflight:
  cluster:
    minimum_ready_nodes: 1

  storage_classes:
    - local-path

  secrets:
    - default/tidb-tls
    - default/tidb-owner
    - default/minio-credentials
    - default/redpanda-credentials

  service_accounts:
    - default/ssl-proxy

  # atheros-sensor is a DaemonSet scheduled on every eligible node.
  node_requirements: {}
```

Add checks for:

* Kubernetes API connectivity.
* Selected context.
* Nodes in `Ready` state.
* Required StorageClasses.
* Required Secrets.
* Required host devices for the sensor.
* Required CRDs.
* Available disk space where practical.
* Existing conflicting umbrella release.

## Safety check

Before split deployment:

```text
If umbrella release ssl-proxy owns a resource that a split release
will attempt to own, fail unless migration mode is explicitly enabled.
```

**Exit condition:** missing prerequisites fail in seconds, before Wave 1 begins.

---

# Phase 6 — Implement deployment execution

## Per-component lifecycle

```text
prepare effective values
        ↓
run Helm upgrade/install
        ↓
wait for configured gates
        ↓
run application-level checks
        ↓
mark component successful
        ↓
unlock descendants
```

## Context handling

For kubectl:

```bash
kubectl --context "$CONTEXT"
```

For Helm:

```bash
helm --kube-context "$CONTEXT"
```

For kubeconfig:

```bash
kubectl --kubeconfig "$KUBECONFIG"
helm --kubeconfig "$KUBECONFIG"
```

Centralize these in helper functions.

## Helm invocation

For long-running components:

```bash
helm upgrade --install "$RELEASE" "$CHART" \
  --namespace "$NAMESPACE" \
  --create-namespace \
  --wait \
  --wait-for-jobs \
  --timeout "$TIMEOUT" \
  -f "$EFFECTIVE_VALUES"
```

Add rollback selectively:

```yaml
java-coordinator:
  rollback_on_failure: true

atheros-search:
  rollback_on_failure: true

tidb:
  rollback_on_failure: false

schema-migrator:
  rollback_on_failure: false
```

## Wave behavior

Use concurrent execution only inside one wave:

```python
results = await asyncio.gather(
    *(deploy(component) for component in wave),
    return_exceptions=True,
)
```

If one sibling fails:

```text
- finish collecting sibling results
- mark the wave failed
- do not start the next wave
- retain successful sibling upgrades
- do not delete stateful data
```

**Exit condition:** failure in Wave 4 prevents Wave 5 from starting.

---

# Phase 7 — Make migration Jobs deployment-specific

Never allow an old completed Job to satisfy a new deployment.

## Preferred initial implementation

Use:

```yaml
job:
  rerun: replace
```

Execution:

```text
1. Inspect existing Job.
2. Record its UID and completion state.
3. Delete the existing completed Job.
4. Run Helm upgrade/install.
5. Wait for a Job with a new UID.
6. Wait for Complete.
7. Fail on Failed condition or timeout.
8. Preserve logs on failure.
```

Apply this to:

```text
tidb-schema-executor
```

Determine whether `schema-migrator` is a long-running Deployment or finite migration workload. Its chart contains backend, state store, UI, Keycloak, and Traefik settings, so it appears broader than a simple migration Job. Treat it according to its rendered resource types, not its name.

## Required migration test

```text
Deploy once
  -> Job completes

Deploy again
  -> old Job cannot satisfy the gate
  -> new Job runs
  -> new UID is observed
```

**Exit condition:** two consecutive deploys produce two real schema-executor executions.

---

# Phase 8 — Add diagnostics

When a component fails, automatically capture:

```bash
kubectl get pods -n default -o wide
kubectl get events -n default --sort-by=.metadata.creationTimestamp
kubectl describe <failed-resource>
kubectl logs <pods-for-component> --all-containers --tail=200
kubectl get pvc -n default
helm status <release>
helm get manifest <release>
helm get values <release> --all
```

Write results under:

```text
stackctl-artifacts/
└── 20260724T214500/
    ├── plan.txt
    ├── effective-values/
    ├── rendered/
    ├── events.txt
    └── failures/
```

Never print Secret values. Redact keys matching:

```text
password
secret
token
apiKey
privateKey
credentials
```

**Exit condition:** a failed test deployment leaves enough information to diagnose it without manually rerunning commands.

---

# Phase 9 — Build the real `stack.yaml`

Recommended initial graph:

```yaml
version: 1

defaults:
  namespace: default
  timeout: 10m
  values:
    - ./helm/ssl-proxy/values.yaml
    - ./helm/ssl-proxy/values-k8s.yaml

components:
  tidb:
    type: helm
    release: ssl-proxy-tidb
    chart: ./helm/ssl-proxy/charts/tidb
    values_key: tidb
    include_global: true
    timeout: 15m
    gates:
      - resource: statefulset/ssl-proxy-tidb

  redpanda:
    type: helm
    release: ssl-proxy-redpanda
    chart: ./helm/ssl-proxy/charts/redpanda
    values_key: redpanda
    include_global: true
    timeout: 15m
    gates:
      - discover:
          kind: StatefulSet

  minio:
    type: helm
    release: ssl-proxy-minio
    chart: ./helm/ssl-proxy/charts/minio
    values_key: minio
    include_global: true
    timeout: 15m
    gates:
      - discover:
          kind: StatefulSet

  redis:
    type: helm
    release: ssl-proxy-redis
    chart: ./helm/ssl-proxy/charts/redis-runtime
    values_key: redisRuntime
    include_global: true
    gates:
      - discover:
          kind: Deployment

  telemetry:
    type: helm
    release: ssl-proxy-telemetry
    chart: ./helm/ssl-proxy/charts/telemetry
    values_key: telemetry
    include_global: true
    timeout: 15m
    gates:
      - discover:
          kind: Deployment

  tidb-schema-executor:
    type: helm-job
    release: ssl-proxy-tidb-schema
    chart: ./helm/ssl-proxy/charts/tidb-schema-executor
    values_key: tidbSchemaExecutor
    include_global: true
    depends_on:
      - tidb
    timeout: 10m
    job:
      rerun: replace
    gates:
      - discover:
          kind: Job
        condition: complete

  schema-migrator:
    type: helm
    release: ssl-proxy-schema-migrator
    chart: ./helm/ssl-proxy/charts/schema-migrator
    values_key: schemaMigrator
    include_global: true
    depends_on:
      - tidb
      - tidb-schema-executor
    timeout: 15m
    gates:
      - discover:
          kind: Deployment

  java-coordinator:
    type: helm
    release: ssl-proxy-coordinator
    chart: ./helm/ssl-proxy/charts/java-coordinator
    values_key: javaCoordinator
    include_global: true
    depends_on:
      - tidb
      - redpanda
      - minio
      - schema-migrator
    gates:
      - discover:
          kind: Deployment

  atheros-search:
    type: helm
    release: ssl-proxy-atheros-search
    chart: ./helm/ssl-proxy/charts/atheros-search
    values_key: atherosSearch
    include_global: true
    depends_on:
      - tidb
      - redpanda
      - schema-migrator
    gates:
      - discover:
          kind: Deployment

  atheros-sensor:
    type: helm
    release: ssl-proxy-atheros-sensor
    chart: ./helm/ssl-proxy/charts/atheros-sensor
    values_key: atherosSensor
    include_global: true
    depends_on:
      - redpanda
    gates:
      - discover:
          kind: DaemonSet

  proxy:
    type: helm
    release: ssl-proxy-proxy
    chart: ./helm/ssl-proxy/charts/proxy
    values_key: proxy
    include_global: true
    depends_on:
      - redpanda
      - java-coordinator
      - atheros-search
    gates:
      - discover:
          kind: Deployment
```

Use discovered gates during development. Once rendered names are proven stable, replace discovery with explicit names.

---

# Phase 10 — Compare split releases with the umbrella

Render all split components:

```bash
python3 stackctl/stackctl.py render \
  --file stackctl/stack.yaml \
  --output stackctl/baseline/split.yaml
```

Normalize and compare:

```bash
python3 stackctl/tools/compare_manifests.py \
  stackctl/baseline/umbrella.yaml \
  stackctl/baseline/split.yaml
```

Ignore expected metadata differences:

```text
meta.helm.sh/release-name
meta.helm.sh/release-namespace
app.kubernetes.io/instance
```

Fail on unexpected differences in:

```text
resource existence
resource names
Service selectors
container images
ports
environment variables
Secret references
PVC names
volume mounts
security contexts
host networking
node selectors
```

## Special ownership risk

Resources currently owned by the umbrella Helm release cannot always be directly adopted by a split release.

Create an explicit migration report:

```text
Resource                         Current owner    New owner
StatefulSet/ssl-proxy-tidb       ssl-proxy        ssl-proxy-tidb
Service/ssl-proxy-tidb           ssl-proxy        ssl-proxy-tidb
PVC/data-ssl-proxy-tidb-0        unmanaged/PVC    unchanged
```

Do not uninstall the umbrella release until ownership migration is understood.

**Exit condition:** the comparison contains only reviewed, intentional differences.

---

# Phase 11 — Add Makefile integration

```makefile
STACKCTL := python3 stackctl/stackctl.py
STACK_FILE := stackctl/stack.yaml

STACKCTL_CONTEXT := $(if $(UP_READY_KUBE_CONTEXT),\
	--kube-context $(UP_READY_KUBE_CONTEXT),)

STACKCTL_KUBECONFIG := $(if $(KUBECONFIG),\
	--kubeconfig $(KUBECONFIG),)

.PHONY: stackctl-plan
stackctl-plan:
	$(STACKCTL) plan \
		--file $(STACK_FILE)

.PHONY: stackctl-validate
stackctl-validate:
	$(STACKCTL) validate \
		--file $(STACK_FILE)

.PHONY: stackctl-dry-run
stackctl-dry-run:
	$(STACKCTL) dry-run \
		--file $(STACK_FILE) \
		$(STACKCTL_CONTEXT) \
		$(STACKCTL_KUBECONFIG)

.PHONY: stackctl-deploy
stackctl-deploy:
	$(STACKCTL) deploy \
		--file $(STACK_FILE) \
		$(STACKCTL_CONTEXT) \
		$(STACKCTL_KUBECONFIG)

.PHONY: stackctl-status
stackctl-status:
	$(STACKCTL) status \
		--file $(STACK_FILE) \
		$(STACKCTL_CONTEXT) \
		$(STACKCTL_KUBECONFIG)
```

Initially, leave `up-ready` unchanged.

Add an opt-in path:

```makefile
up-ready-stackctl: registry-build-all registry-mirror-all ops-preflight
	$(MAKE) stackctl-deploy
```

Only replace the existing `up-ready` Helm command after test-cluster acceptance.

---

# Phase 12 — Test ladder

Run tests in this order.

## Test 1: Offline graph

```bash
make stackctl-plan
```

Expected: five waves in the correct order.

## Test 2: Offline rendering

```bash
make stackctl-validate
```

Expected: all chart paths, values, and gates validate.

## Test 3: Cluster dry-run

```bash
make stackctl-dry-run
```

Expected: API validation succeeds and no resources persist.

## Test 4: Fresh test-cluster deployment

```bash
make up-ready-stackctl
```

Verify:

```bash
python3 stackctl/stackctl.py status \
  --file stackctl/stack.yaml \
  --kube-context "$UP_READY_KUBE_CONTEXT"
```

## Test 5: Idempotent redeploy

Run it again without changes.

Expected:

* No destructive resource recreation.
* Stateful PVCs remain unchanged.
* Normal Helm components report healthy.
* The schema executor follows its explicit rerun policy.
* No duplicate Jobs remain unexpectedly.

## Test 6: Application-image upgrade

Change only one application image.

Expected:

* Foundation remains untouched.
* Relevant application release upgrades.
* Descendants deploy only when needed or explicitly requested.

## Test 7: Failure injection

Break the `atheros-search` image tag.

Expected:

```text
Wave 4 fails
proxy does not deploy
java-coordinator may remain successfully upgraded
atheros-sensor may remain successfully upgraded
diagnostics are written
```

## Test 8: Middleware failure

Make TiDB readiness fail.

Expected:

```text
Wave 1 fails
Waves 2–5 do not begin
```

## Test 9: Node restart

Restart the k3s node.

Expected:

* Kubernetes restores workloads without `stackctl`.
* Applications tolerate temporarily unavailable dependencies.
* Readiness remains false until dependencies return.
* No permanent application crash due to startup order.

## Test 10: Migration replay protection

Leave an old completed schema Job in place and deploy again.

Expected: the old Job cannot satisfy the new gate.

---

# Phase 13 — Cutover

## First production-style run

Do not remove the umbrella release immediately.

Use this sequence:

```text
1. Freeze chart changes.
2. Back up persistent data.
3. Capture current Helm release and manifests.
4. Stop public traffic if resource adoption requires it.
5. Transfer or recreate Helm ownership safely.
6. Deploy foundation with stackctl.
7. Verify data and Services.
8. Deploy migrations.
9. Deploy applications.
10. Deploy proxy.
11. Run smoke tests.
12. Restore public traffic.
```

## Smoke tests

At minimum:

```text
TiDB connection and version
Redpanda produce/consume
MinIO put/get/delete
Redis set/get
schema version
coordinator readiness
search readiness and query
sensor DaemonSet desired/ready count
proxy health and WireGuard handshake
Prometheus target health
Grafana access
```

## Rollback plan

Retain:

```text
previous umbrella values
previous umbrella chart version
database backup
previous image tags
rendered production manifests
Helm release history
```

Rollback should generally restore applications, not reverse already-applied database DDL unless a tested down-migration exists.

---

# Recommended PR sequence

| PR | Scope                                            | Merge condition                               |
| -- | ------------------------------------------------ | --------------------------------------------- |
| 1  | Baseline manifests and deployment-mode decisions | Redpanda/MinIO mode documented                |
| 2  | Config model, parser, graph and `plan`           | Unit tests pass                               |
| 3  | Effective-values extraction                      | All charts render standalone                  |
| 4  | `validate` and manifest/gate inspection          | No missing or duplicate resources             |
| 5  | Preflight and context handling                   | Test cluster prerequisites detected correctly |
| 6  | Deployment waves and diagnostics                 | Failure blocks descendants                    |
| 7  | Migration Job lifecycle                          | Repeat deployment executes a new Job          |
| 8  | Real `stack.yaml`, README and Makefile           | Full dry-run passes                           |
| 9  | Test-cluster deployment                          | Entire test ladder passes                     |
| 10 | `up-ready` integration and cutover               | Umbrella/split equivalence approved           |

# Immediate first actions

Start with these commands:

```bash
git checkout -b feature/stackctl-foundation

mkdir -p stackctl/{tests,baseline,tools}

helm template ssl-proxy ./helm/ssl-proxy \
  -f ./helm/ssl-proxy/values.yaml \
  -f ./helm/ssl-proxy/values-k8s.yaml \
  > stackctl/baseline/umbrella.yaml

helm template ssl-proxy-redpanda \
  ./helm/ssl-proxy/charts/redpanda \
  -f ./helm/ssl-proxy/values.yaml \
  -f ./helm/ssl-proxy/values-k8s.yaml \
  > stackctl/baseline/redpanda-standalone.yaml

helm template ssl-proxy-minio \
  ./helm/ssl-proxy/charts/minio \
  -f ./helm/ssl-proxy/values.yaml \
  -f ./helm/ssl-proxy/values-k8s.yaml \
  > stackctl/baseline/minio-standalone.yaml
```

Then answer these two questions from the rendered output:

```text
Does Redpanda render an in-cluster workload?
Does MinIO render an in-cluster workload?
```

Those answers determine whether Wave 1 uses Helm deployment gates or external dependency checks.
