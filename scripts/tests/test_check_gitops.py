from __future__ import annotations

import importlib.util
import sys
import unittest
from pathlib import Path


MODULE_PATH = Path(__file__).resolve().parents[1] / "check-gitops.py"
SPEC = importlib.util.spec_from_file_location("check_gitops", MODULE_PATH)
assert SPEC and SPEC.loader
check_gitops = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = check_gitops
SPEC.loader.exec_module(check_gitops)


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
            "ssl-proxy-proxy\n"
            "livenessProbe:\n"
            "  httpGet:\n"
            "    path: /health\n"
            "    port: admin\n"
        )
        errors = check_gitops._check_proxy_probes(rendered, "test")
        self.assertTrue(any("livenessProbe" in e for e in errors))

    def test_rejects_httpget_readiness(self) -> None:
        rendered = (
            "ssl-proxy-proxy\n"
            "readinessProbe:\n"
            "  httpGet:\n"
            "    path: /ready\n"
            "    port: admin\n"
        )
        errors = check_gitops._check_proxy_probes(rendered, "test")
        self.assertTrue(any("readinessProbe" in e for e in errors))

    def test_accepts_exec_probes(self) -> None:
        rendered = (
            "ssl-proxy-proxy\n"
            "livenessProbe:\n"
            "  exec:\n"
            '    command: ["curl", "-fsS", "http://127.0.0.1:3002/health"]\n'
            "readinessProbe:\n"
            "  exec:\n"
            '    command: ["curl", "-fsS", "http://127.0.0.1:3002/ready"]\n'
        )
        self.assertEqual([], check_gitops._check_proxy_probes(rendered, "test"))

    def test_skips_non_proxy_rendered(self) -> None:
        rendered = "ssl-proxy-java-coordinator\nlivenessProbe:\n  httpGet:\n"
        self.assertEqual([], check_gitops._check_proxy_probes(rendered, "test"))


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
            'name: ssl-proxy-tidb-init\n  annotations:\n'
            '    argocd.argoproj.io/sync-wave: "1"\n'
            'name: ssl-proxy-tidb-schema-executor\n  annotations:\n'
            '    argocd.argoproj.io/sync-wave: "1"\n'
            'name: ssl-proxy-tidb-init-grants\n  annotations:\n'
            '    argocd.argoproj.io/sync-wave: "2"'
        )
        errors = check_gitops._check_tidb_waves(rendered, "test")
        self.assertTrue(any("init wave" in e for e in errors))

    def test_rejects_schema_wave_not_less_than_grants(self) -> None:
        rendered = (
            'name: ssl-proxy-tidb-init\n  annotations:\n'
            '    argocd.argoproj.io/sync-wave: "0"\n'
            'name: ssl-proxy-tidb-schema-executor\n  annotations:\n'
            '    argocd.argoproj.io/sync-wave: "2"\n'
            'name: ssl-proxy-tidb-init-grants\n  annotations:\n'
            '    argocd.argoproj.io/sync-wave: "2"'
        )
        errors = check_gitops._check_tidb_waves(rendered, "test")
        self.assertTrue(any("schema executor wave" in e for e in errors))

    def test_accepts_correct_wave_ordering(self) -> None:
        rendered = (
            'name: ssl-proxy-tidb-init\n  annotations:\n'
            '    argocd.argoproj.io/sync-wave: "0"\n'
            'name: ssl-proxy-tidb-schema-executor\n  annotations:\n'
            '    argocd.argoproj.io/sync-wave: "1"\n'
            'name: ssl-proxy-tidb-init-grants\n  annotations:\n'
            '    argocd.argoproj.io/sync-wave: "2"'
        )
        self.assertEqual([], check_gitops._check_tidb_waves(rendered, "test"))

    def test_skips_rendered_without_tidb_jobs(self) -> None:
        rendered = "kind: Deployment\n  ssl-proxy-proxy\n"
        self.assertEqual([], check_gitops._check_tidb_waves(rendered, "test"))


if __name__ == "__main__":
    unittest.main()
