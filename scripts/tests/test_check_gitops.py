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


class RequiredFileReadTest(unittest.TestCase):
    def test_missing_file_is_reported_without_reading(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            errors: list[str] = []
            result = check_gitops._read_required(
                Path(directory),
                Path("cyber-stack/argocd/application-app-stack.yaml"),
                errors,
                "Application manifest",
            )

        self.assertIsNone(result)
        self.assertEqual(1, len(errors))
        self.assertIn("required Application manifest is missing", errors[0])


class ImagePinCountTest(unittest.TestCase):
    def test_counts_only_entries_in_images_block(self) -> None:
        text = (
            "images:\n"
            "  - name: app\n"
            "    newName: registry/app\n"
            "    digest: sha256:abc\n"
            "vars:\n"
            "  - name: IDENTITY_HOSTNAME\n"
        )

        self.assertEqual((1, 1), check_gitops._image_pin_counts(text))


class OtelEndpointCheckTest(unittest.TestCase):
    def test_rejects_broken_service_reference(self) -> None:
        rendered = 'value: "http://ssl-proxy-otel-collector:4317"'
        errors = check_gitops._check_otel_endpoint(rendered, "test")
        self.assertEqual(1, len(errors))
        self.assertIn("ssl-proxy-otel-collector", errors[0])

    def test_accepts_correct_service_reference(self) -> None:
        rendered = 'value: "http://ssl-proxy-telemetry-otel-collector:4317"'
        self.assertEqual([], check_gitops._check_otel_endpoint(rendered, "test"))

    def test_accepts_empty_rendered(self) -> None:
        self.assertEqual([], check_gitops._check_otel_endpoint("", "test"))


class RedpandaMemoryCheckTest(unittest.TestCase):
    def test_rejects_insufficient_headroom(self) -> None:
        rendered = (
            "kind: StatefulSet\n"
            "  ssl-proxy-redpanda\n"
            "args:\n"
            "  - --memory\n"
            "  - 2G\n"
            "resources:\n"
            "  limits:\n"
            "    memory: 2048Mi"
        )
        errors = check_gitops._check_redpanda_memory(rendered, "test")
        self.assertEqual(1, len(errors))
        self.assertIn("512 MiB headroom", errors[0])

    def test_accepts_sufficient_headroom(self) -> None:
        rendered = (
            "kind: StatefulSet\n"
            "  ssl-proxy-redpanda\n"
            "args:\n"
            "  - --memory\n"
            "  - 2G\n"
            "resources:\n"
            "  limits:\n"
            "    memory: 2560Mi"
        )
        self.assertEqual([], check_gitops._check_redpanda_memory(rendered, "test"))

    def test_skips_non_redpanda_rendered(self) -> None:
        rendered = "kind: Deployment\n  ssl-proxy-proxy\n"
        self.assertEqual([], check_gitops._check_redpanda_memory(rendered, "test"))

    def test_parse_bytes_gigabytes(self) -> None:
        self.assertEqual(2 * 1024**3, check_gitops._parse_bytes("2", "G"))

    def test_parse_bytes_mebibytes(self) -> None:
        self.assertEqual(2560 * 1024**2, check_gitops._parse_bytes("2560", "Mi"))


class ProxyProbeCheckTest(unittest.TestCase):
    def test_rejects_httpget_liveness(self) -> None:
        rendered = (
            "---\n"
            "kind: Deployment\n"
            "metadata:\n"
            "  name: ssl-proxy-proxy\n"
            "spec:\n"
            "  template:\n"
            "    spec:\n"
            "      containers:\n"
            "      - livenessProbe:\n"
            "          httpGet:\n"
            "            path: /health\n"
            "            port: admin\n"
        )
        errors = check_gitops._check_proxy_probes(rendered, "test")
        self.assertTrue(any("livenessProbe" in e for e in errors))

    def test_rejects_httpget_readiness(self) -> None:
        rendered = (
            "---\n"
            "kind: Deployment\n"
            "metadata:\n"
            "  name: ssl-proxy-proxy\n"
            "spec:\n"
            "  template:\n"
            "    spec:\n"
            "      containers:\n"
            "      - readinessProbe:\n"
            "          httpGet:\n"
            "            path: /ready\n"
            "            port: admin\n"
        )
        errors = check_gitops._check_proxy_probes(rendered, "test")
        self.assertTrue(any("readinessProbe" in e for e in errors))

    def test_accepts_exec_probes(self) -> None:
        rendered = (
            "---\n"
            "kind: Deployment\n"
            "metadata:\n"
            "  name: ssl-proxy-proxy\n"
            "spec:\n"
            "  template:\n"
            "    spec:\n"
            "      containers:\n"
            "      - livenessProbe:\n"
            "          exec:\n"
            '            command: ["curl", "-fsS", "http://127.0.0.1:3002/health"]\n'
            "        readinessProbe:\n"
            "          exec:\n"
            '            command: ["curl", "-fsS", "http://127.0.0.1:3002/ready"]\n'
        )
        self.assertEqual([], check_gitops._check_proxy_probes(rendered, "test"))

    def test_skips_non_proxy_rendered(self) -> None:
        rendered = "ssl-proxy-java-coordinator\nlivenessProbe:\n  httpGet:\n"
        self.assertEqual([], check_gitops._check_proxy_probes(rendered, "test"))


class GitOpsRegressionCheckTest(unittest.TestCase):
    def test_proxy_wireguard_requires_host_route(self) -> None:
        rendered = (
            "name: ssl-proxy-proxy\nports:\n  - containerPort: 443\n    protocol: UDP\n"
        )
        self.assertEqual(
            1, len(check_gitops._check_proxy_wireguard_route(rendered, "test"))
        )

    def test_proxy_wireguard_accepts_host_port(self) -> None:
        rendered = (
            "name: ssl-proxy-proxy\n"
            "ports:\n"
            "  - containerPort: 443\n"
            "    hostPort: 443\n"
            "    protocol: UDP\n"
        )
        self.assertEqual(
            [], check_gitops._check_proxy_wireguard_route(rendered, "test")
        )

    def test_atheros_search_rejects_unusable_bearer_auth(self) -> None:
        rendered = (
            "name: ssl-proxy-atheros-search\n"
            "env:\n"
            "  - name: ATHSEARCH_API_TOKEN_SHA256\n"
        )
        self.assertEqual(
            1, len(check_gitops._check_atheros_search_auth(rendered, "test"))
        )

    def test_atheros_search_ui_rejects_dynamic_proxy_upstreams(self) -> None:
        rendered = (
            "name: ssl-proxy-atheros-search-ui-nginx\n"
            "proxy_pass $search_backend;\n"
            "proxy_pass $readyz_backend/readyz;\n"
        )
        errors = check_gitops._check_atheros_search_ui_proxy(rendered, "test")
        self.assertEqual(4, len(errors))
        self.assertTrue(any("dynamic upstream" in error for error in errors))
        self.assertTrue(any("missing static upstream" in error for error in errors))

    def test_atheros_search_ui_accepts_static_proxy_upstreams(self) -> None:
        rendered = (
            "name: ssl-proxy-atheros-search-ui-nginx\n"
            "proxy_pass http://ssl-proxy-atheros-search:8080;\n"
            "proxy_pass http://ssl-proxy-atheros-search:8080/readyz;\n"
        )
        self.assertEqual(
            [], check_gitops._check_atheros_search_ui_proxy(rendered, "test")
        )

    def test_keycloak_requires_provisioned_database_secret(self) -> None:
        rendered = (
            "name: ssl-proxy-schema-migrator-keycloak\n"
            "- name: KC_DB_PASSWORD\n"
            "  valueFrom:\n"
            "    secretKeyRef:\n"
            "      key: password\n"
            "      name: tidb-keycloak\n"
        )
        self.assertEqual(
            [], check_gitops._check_keycloak_database_credential(rendered, "test")
        )

    def test_topic_replication_cannot_exceed_brokers(self) -> None:
        rendered = (
            "kind: StatefulSet\n"
            "metadata:\n"
            "  name: ssl-proxy-redpanda\n"
            "spec:\n"
            "  replicas: 1\n"
            "topics.manifest: |\n"
            "  sync.scan.request|24|3|1000|-1\n"
        )
        self.assertEqual(
            1,
            len(check_gitops._check_redpanda_topic_replication(rendered, "test")),
        )

    def test_identity_hostnames_are_environment_specific(self) -> None:
        rendered = {
            "cyber-stack/matrix/dev/bootstrap": (
                "data:\n  IDENTITY_HOSTNAME: identity.dev.ssl-proxy.internal\n"
            ),
            "cyber-stack/matrix/prod/bootstrap": (
                "data:\n  IDENTITY_HOSTNAME: identity.prod.ssl-proxy.internal\n"
            ),
        }
        self.assertEqual(
            [], check_gitops._check_environment_identity_hostnames(rendered)
        )

    def test_identity_hostnames_reject_example_and_shared_values(self) -> None:
        rendered = {
            "cyber-stack/matrix/dev/bootstrap": (
                "data:\n  IDENTITY_HOSTNAME: identity.example.internal\n"
            ),
            "cyber-stack/matrix/prod/bootstrap": (
                "data:\n  IDENTITY_HOSTNAME: identity.example.internal\n"
            ),
        }
        self.assertEqual(
            3, len(check_gitops._check_environment_identity_hostnames(rendered))
        )


class TraefikRedirectCheckTest(unittest.TestCase):
    def test_rejects_unsupported_port_field(self) -> None:
        rendered = "entrypoints.web.http.redirections.entrypoint.port=:443"
        errors = check_gitops._check_traefik_redirect(rendered, "test")
        self.assertEqual(1, len(errors))
        self.assertIn("entrypoint.port", errors[0])

    def test_accepts_valid_redirect(self) -> None:
        rendered = (
            "entrypoints.web.http.redirections.entrypoint.to=websecure\n"
            "entrypoints.web.http.redirections.entrypoint.scheme=https"
        )
        self.assertEqual([], check_gitops._check_traefik_redirect(rendered, "test"))


class TiDBWaveCheckTest(unittest.TestCase):
    def test_rejects_init_wave_not_less_than_schema(self) -> None:
        rendered = (
            "name: ssl-proxy-tidb-init\n  annotations:\n"
            '    argocd.argoproj.io/sync-wave: "1"\n'
            "name: ssl-proxy-tidb-schema-executor\n  annotations:\n"
            '    argocd.argoproj.io/sync-wave: "1"\n'
            "name: ssl-proxy-tidb-init-grants\n  annotations:\n"
            '    argocd.argoproj.io/sync-wave: "2"'
        )
        errors = check_gitops._check_tidb_waves(rendered, "test")
        self.assertTrue(any("init wave" in e for e in errors))

    def test_rejects_schema_wave_not_less_than_grants(self) -> None:
        rendered = (
            "name: ssl-proxy-tidb-init\n  annotations:\n"
            '    argocd.argoproj.io/sync-wave: "0"\n'
            "name: ssl-proxy-tidb-schema-executor\n  annotations:\n"
            '    argocd.argoproj.io/sync-wave: "2"\n'
            "name: ssl-proxy-tidb-init-grants\n  annotations:\n"
            '    argocd.argoproj.io/sync-wave: "2"'
        )
        errors = check_gitops._check_tidb_waves(rendered, "test")
        self.assertTrue(any("schema executor wave" in e for e in errors))

    def test_accepts_correct_wave_ordering(self) -> None:
        rendered = (
            "name: ssl-proxy-tidb-init\n  annotations:\n"
            '    argocd.argoproj.io/sync-wave: "0"\n'
            "name: ssl-proxy-tidb-schema-executor\n  annotations:\n"
            '    argocd.argoproj.io/sync-wave: "1"\n'
            "name: ssl-proxy-tidb-init-grants\n  annotations:\n"
            '    argocd.argoproj.io/sync-wave: "2"'
        )
        self.assertEqual([], check_gitops._check_tidb_waves(rendered, "test"))

    def test_skips_rendered_without_tidb_jobs(self) -> None:
        rendered = "kind: Deployment\n  ssl-proxy-proxy\n"
        self.assertEqual([], check_gitops._check_tidb_waves(rendered, "test"))


if __name__ == "__main__":
    unittest.main()
