from __future__ import annotations

import importlib.util
import sys
import tempfile
import unittest
from pathlib import Path


MODULE_PATH = Path(__file__).resolve().parents[1] / "check-gitops.py"
SPEC = importlib.util.spec_from_file_location("check_gitops", MODULE_PATH)
assert SPEC and SPEC.loader
check_gitops = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = check_gitops
SPEC.loader.exec_module(check_gitops)


def documents(text: str) -> list[dict[str, object]]:
    errors: list[str] = []
    loaded = check_gitops._load_documents(text, "test", errors)
    assert loaded is not None, errors
    return loaded


def workload(name: str, kind: str = "Deployment", containers: str = "[]") -> str:
    return f"""apiVersion: apps/v1
kind: {kind}
metadata:
  labels:
    app: test
  name: {name}
spec:
  template:
    spec:
      containers: {containers}
"""


class YamlLoadingTest(unittest.TestCase):
    def test_malformed_yaml_is_a_check_failure(self) -> None:
        errors: list[str] = []
        self.assertIsNone(check_gitops._load_documents("kind: [broken", "fixture.yaml", errors))
        self.assertEqual(1, len(errors))
        self.assertIn("fixture.yaml: invalid YAML", errors[0])

    def test_missing_file_is_reported_without_reading(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            errors: list[str] = []
            result = check_gitops._read_required(
                Path(directory), Path("cyber-stack/argocd/application-set.yaml"), errors, "ApplicationSet manifest"
            )
        self.assertIsNone(result)
        self.assertIn("required ApplicationSet manifest is missing", errors[0])


class SourceKustomizationTest(unittest.TestCase):
    def test_image_pins_ignore_order_and_scalar_wrapping(self) -> None:
        source = documents(
            """kind: Kustomization
images:
  - digest: sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
    name: app
    newName: registry/app
"""
        )
        self.assertEqual((1, 1), check_gitops._image_pin_counts(source))

    def test_image_pin_count_rejects_missing_digest(self) -> None:
        source = documents("kind: Kustomization\nimages:\n  - name: app\n    newName: registry/app\n")
        self.assertEqual((1, 0), check_gitops._image_pin_counts(source))


class RenderedWorkloadPolicyTest(unittest.TestCase):
    def test_otel_endpoint_rejects_any_structured_string(self) -> None:
        rendered = documents("kind: ConfigMap\ndata:\n  endpoint: http://ssl-proxy-otel-collector:4317\n")
        self.assertEqual(1, len(check_gitops._check_otel_endpoint(rendered, "test")))

    def test_redpanda_memory_is_independent_of_field_order(self) -> None:
        rendered = documents(
            workload(
                "ssl-proxy-redpanda",
                "StatefulSet",
                "[{resources: {limits: {memory: 2048Mi}}, args: ['--memory', 2G]}]",
            )
        )
        errors = check_gitops._check_redpanda_memory(rendered, "test")
        self.assertEqual(1, len(errors))
        self.assertIn("512 MiB headroom", errors[0])

    def test_proxy_probe_and_wireguard_policies(self) -> None:
        bad_probe = documents(
            workload(
                "ssl-proxy-proxy",
                containers="[{ports: [{protocol: UDP, containerPort: 443}], livenessProbe: {httpGet: {path: /health}}}]",
            )
        )
        self.assertEqual(1, len(check_gitops._check_proxy_probes(bad_probe, "test")))
        self.assertEqual(1, len(check_gitops._check_proxy_wireguard_route(bad_probe, "test")))
        good = documents(
            workload(
                "ssl-proxy-proxy",
                containers="[{ports: [{hostPort: 443, protocol: UDP, containerPort: 443}], livenessProbe: {exec: {command: [curl]}}, readinessProbe: {exec: {command: [curl]}}}]",
            )
        )
        self.assertEqual([], check_gitops._check_proxy_probes(good, "test"))
        self.assertEqual([], check_gitops._check_proxy_wireguard_route(good, "test"))

    def test_jaeger_probes_use_admin_health_with_startup_budget(self) -> None:
        bad = documents(
            workload(
                "ssl-proxy-telemetry-jaeger",
                containers="[{name: jaeger, ports: [{name: ui, containerPort: 16686}], livenessProbe: {httpGet: {path: /, port: ui}}}]",
            )
        )
        self.assertGreaterEqual(len(check_gitops._check_jaeger_probes(bad, "test")), 4)
        good = documents(
            workload(
                "ssl-proxy-telemetry-jaeger",
                containers="[{name: jaeger, ports: [{name: admin, containerPort: 14269}], startupProbe: {httpGet: {path: /, port: admin}, failureThreshold: 60, periodSeconds: 10}, livenessProbe: {httpGet: {path: /, port: admin}}, readinessProbe: {httpGet: {path: /, port: admin}}}]",
            )
        )
        self.assertEqual([], check_gitops._check_jaeger_probes(good, "test"))

    def test_prod_jaeger_has_badger_recovery_capacity(self) -> None:
        bad = documents(
            workload(
                "ssl-proxy-telemetry-jaeger",
                containers="[{name: jaeger, resources: {limits: {cpu: 500m}}, "
                "startupProbe: {failureThreshold: 60, periodSeconds: 10}}]",
            )
        )
        self.assertEqual(
            2, len(check_gitops._check_prod_jaeger_recovery(bad, "prod"))
        )
        good = documents(
            workload(
                "ssl-proxy-telemetry-jaeger",
                containers="[{name: jaeger, resources: {limits: {cpu: '2'}}, "
                "startupProbe: {failureThreshold: 180, periodSeconds: 10}}]",
            )
        )
        self.assertEqual(
            [], check_gitops._check_prod_jaeger_recovery(good, "prod")
        )

    def test_atheros_search_auth_and_proxy_policy(self) -> None:
        auth = documents(workload("ssl-proxy-atheros-search", containers="[{env: [{name: ATHSEARCH_API_TOKEN_SHA256}]}]"))
        self.assertEqual(1, len(check_gitops._check_atheros_search_auth(auth, "test")))
        nginx = documents(
            """kind: ConfigMap
metadata:
  name: ssl-proxy-atheros-search-ui-nginx-config
data:
  nginx.conf: |-
    proxy_pass $search_backend;
    proxy_pass $readyz_backend/readyz;
"""
        )
        self.assertEqual(4, len(check_gitops._check_atheros_search_ui_proxy(nginx, "test")))
        static = documents(
            """kind: ConfigMap
metadata: {name: ssl-proxy-atheros-search-ui-nginx-config}
data:
  nginx.conf: |-
    proxy_pass http://ssl-proxy-atheros-search:8080;
    proxy_pass http://ssl-proxy-atheros-search:8080/readyz;
"""
        )
        self.assertEqual([], check_gitops._check_atheros_search_ui_proxy(static, "test"))

    def test_keycloak_credential_is_a_structured_secret_reference(self) -> None:
        valid = documents(
            workload(
                "ssl-proxy-schema-migrator-keycloak",
                containers="[{env: [{name: KC_DB_PASSWORD, valueFrom: {secretKeyRef: {key: password, name: tidb-keycloak}}}]}]",
            )
        )
        self.assertEqual([], check_gitops._check_keycloak_database_credential(valid, "test"))
        invalid = documents(workload("ssl-proxy-schema-migrator-keycloak", containers="[{env: [{name: KC_DB_PASSWORD}]}]"))
        self.assertEqual(1, len(check_gitops._check_keycloak_database_credential(invalid, "test")))

    def test_replication_uses_configmap_and_env_values(self) -> None:
        rendered = documents(
            """apiVersion: apps/v1
kind: StatefulSet
metadata: {name: ssl-proxy-redpanda}
spec:
  replicas: 1
  template:
    spec:
      containers: []
---
kind: ConfigMap
data:
  topics.manifest: |-
    sync.scan.request|24|3|1000|-1
---
kind: Deployment
metadata: {name: producer}
spec:
  template:
    spec:
      containers:
        - env:
            - {name: SYNC_REDPANDA_TOPIC_REPLICATION_FACTOR, value: "2"}
"""
        )
        self.assertEqual(1, len(check_gitops._check_redpanda_topic_replication(rendered, "test")))

    def test_identity_hostname_and_traefik_policies(self) -> None:
        rendered = {
            "cyber-stack/matrix/dev/bootstrap": documents("kind: ConfigMap\ndata: {IDENTITY_HOSTNAME: identity.example.internal}\n"),
            "cyber-stack/matrix/prod/bootstrap": documents("data: {IDENTITY_HOSTNAME: identity.example.internal}\nkind: ConfigMap\n"),
        }
        self.assertEqual(3, len(check_gitops._check_environment_identity_hostnames(rendered)))
        redirect = documents("kind: ConfigMap\ndata: {args: entrypoints.web.http.redirections.entrypoint.port=:443}\n")
        self.assertEqual(1, len(check_gitops._check_traefik_redirect(redirect, "test")))

    def test_tidb_waves_are_selected_by_job_name(self) -> None:
        rendered = documents(
            """kind: Job
metadata: {name: ssl-proxy-tidb-init, annotations: {argocd.argoproj.io/sync-wave: "1"}}
---
metadata:
  annotations: {argocd.argoproj.io/sync-wave: "1"}
  name: ssl-proxy-tidb-schema-executor
kind: Job
---
kind: Job
metadata: {name: ssl-proxy-tidb-init-grants, annotations: {argocd.argoproj.io/sync-wave: "2"}}
"""
        )
        self.assertTrue(any("init wave" in error for error in check_gitops._check_tidb_waves(rendered, "test")))


class SchemaExecutorContractTest(unittest.TestCase):
    marker = "schema-migrator-001-" + "a" * 64

    def test_contract_marker_and_digest_are_structural(self) -> None:
        rendered = documents(
            f"""kind: Job
metadata: {{name: ssl-proxy-tidb-schema-executor}}
spec:
  template:
    metadata:
      annotations: {{ssl-proxy.io/content-hash: {self.marker}}}
    spec:
      containers:
        - image: registry/tidb-runtime-schema@sha256:{'b' * 64}
"""
        )
        self.assertEqual([], check_gitops._check_schema_executor_contract(rendered, "test", self.marker))
        rendered[0]["spec"]["template"]["metadata"]["annotations"]["ssl-proxy.io/content-hash"] = "stale"
        rendered[0]["spec"]["template"]["spec"]["containers"][0]["image"] = "registry/tidb-runtime-schema:latest"
        self.assertEqual(2, len(check_gitops._check_schema_executor_contract(rendered, "test", self.marker)))


class ApplicationSetTest(unittest.TestCase):
    def application_set(self) -> dict[str, object]:
        elements = []
        for name, expected in check_gitops.WORKLOAD_APPLICATIONS.items():
            elements.append({"name": name, **expected})
        return documents(
            """apiVersion: argoproj.io/v1alpha1
kind: ApplicationSet
metadata: {name: ssl-proxy-workloads}
spec:
  generators:
    - list:
        elements: PLACEHOLDER
  template:
    metadata:
      name: '{{name}}'
      labels:
        app.kubernetes.io/component: '{{component}}'
        environment: '{{environment}}'
    spec:
      project: ssl-proxy
      source:
        repoURL: https://github.com/zlovtnik/ssl-proxy.git
        targetRevision: main
        path: '{{path}}'
        kustomize: {}
      destination: {server: https://kubernetes.default.svc, namespace: '{{namespace}}'}
      syncPolicy:
        automated: {prune: true, selfHeal: true, allowEmpty: false}
        syncOptions: [PrunePropagationPolicy=foreground, ApplyOutOfSyncOnly=true, ServerSideApply=true]
      ignoreDifferences:
        - {group: apps, kind: StatefulSet, jsonPointers: [/spec/volumeClaimTemplates]}
""".replace("PLACEHOLDER", repr(elements).replace("'", '"'))
        )[0]

    def test_accepts_all_production_entries(self) -> None:
        errors: list[str] = []
        check_gitops._check_application_set([self.application_set()], errors)
        self.assertEqual([], errors)

    def test_rejects_missing_duplicate_misrouted_and_dev_entries(self) -> None:
        application_set = self.application_set()
        elements = application_set["spec"]["generators"][0]["list"]["elements"]
        elements.pop()
        elements.append(dict(elements[0]))
        elements[1]["path"] = "cyber-stack/matrix/prod/app-stack"
        elements.append(
            {
                "name": "ssl-proxy-app-stack",
                "path": "cyber-stack/matrix/dev/app-stack",
                "namespace": "dev-ssl-proxy",
                "component": "app-stack",
                "environment": "dev",
            }
        )
        errors: list[str] = []
        check_gitops._check_application_set([application_set], errors)
        self.assertTrue(any("ssl-proxy-prod-app-stack exactly once" in error for error in errors))
        self.assertTrue(any("ssl-proxy-prod-bootstrap exactly once" in error for error in errors))
        self.assertTrue(any("path: cyber-stack/matrix/prod/data-plane" in error for error in errors))
        self.assertTrue(any("unexpected Applications: ssl-proxy-app-stack" in error for error in errors))


class ProductionProjectTest(unittest.TestCase):
    def test_accepts_only_the_production_destination(self) -> None:
        project = documents(
            """apiVersion: argoproj.io/v1alpha1
kind: AppProject
metadata: {name: ssl-proxy}
spec:
  destinations:
    - {namespace: prod-ssl-proxy, server: https://kubernetes.default.svc}
"""
        )
        errors: list[str] = []
        check_gitops._check_prod_project(project, errors)
        self.assertEqual([], errors)

    def test_rejects_dev_destination_and_controller(self) -> None:
        project = documents(
            """apiVersion: argoproj.io/v1alpha1
kind: AppProject
metadata: {name: ssl-proxy}
spec:
  destinations:
    - {namespace: dev-ssl-proxy, server: https://kubernetes.default.svc}
---
apiVersion: argoproj.io/v1alpha1
kind: Application
metadata: {name: ssl-proxy-image-updater}
"""
        )
        errors: list[str] = []
        check_gitops._check_prod_project(project, errors)
        self.assertTrue(any("production-only" in error for error in errors))
        self.assertTrue(any("dev controllers" in error for error in errors))


class NamespaceDeletionProtectionTest(unittest.TestCase):
    def test_requires_prune_protection_and_delete_confirmation(self) -> None:
        protected = documents(
            """kind: Namespace
metadata:
  annotations: {argocd.argoproj.io/sync-options: "Delete=confirm,Prune=false"}
"""
        )[0]
        self.assertEqual(
            [], check_gitops._check_namespace_deletion_protection(protected, "namespace.yaml")
        )

        unprotected = documents(
            """kind: Namespace
metadata:
  annotations: {argocd.argoproj.io/sync-options: "Prune=false"}
"""
        )[0]
        errors = check_gitops._check_namespace_deletion_protection(unprotected, "namespace.yaml")
        self.assertEqual(["namespace.yaml: namespace deletion must require confirmation"], errors)


if __name__ == "__main__":
    unittest.main()
