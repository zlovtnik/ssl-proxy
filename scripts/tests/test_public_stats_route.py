"""Guardrail: public-gateway allowlisted paths must exist on real host overlays.

The prod/staging `cloudflare-edge` patches replace the public IngressRoute
wholesale. A path added only to `base/public-gateway/routes.yaml` silently
disappears from production. This test keeps base and overlay routes in sync and
requires Traefik ingress to the store-only stats-reader for `/public/stats`.
The IngressRoute targets the Service port; NetworkPolicy targets the pod port.
"""

from __future__ import annotations

import re
import unittest
from pathlib import Path

import yaml


REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
BASE_ROUTES = REPOSITORY_ROOT / "cyber-stack/base/public-gateway/routes.yaml"
PROD_EDGE = REPOSITORY_ROOT / "cyber-stack/matrix/prod/patches/cloudflare-edge.yaml"
STAGING_EDGE = REPOSITORY_ROOT / "cyber-stack/matrix/staging/patches/cloudflare-edge.yaml"
STATS_READER_DEPLOYMENT = (
    REPOSITORY_ROOT / "cyber-stack/base/stats-reader/deployment.yaml"
)
STATS_READER_NETPOL = (
    REPOSITORY_ROOT / "cyber-stack/base/stats-reader/networkpolicy.yaml"
)

# Match Path(`/x`) and PathPrefix(`/x`) literals in Traefik match expressions.
PATH_LITERAL = re.compile(r"Path(?:Prefix)?\(`([^`]+)`\)")
HOST_LITERAL = re.compile(r"Host\(`([^`]+)`\)")


def load_documents(path: Path) -> list[dict]:
    return [
        document
        for document in yaml.safe_load_all(path.read_text(encoding="utf-8"))
        if isinstance(document, dict)
    ]


def public_gateway_routes(path: Path) -> list[dict]:
    for document in load_documents(path):
        if (
            document.get("kind") == "IngressRoute"
            and document.get("metadata", {}).get("name") == "ssl-proxy-public-gateway"
        ):
            routes = document.get("spec", {}).get("routes")
            if isinstance(routes, list):
                return routes
    raise AssertionError(f"no ssl-proxy-public-gateway IngressRoute in {path}")


def match_paths(match: str) -> set[str]:
    return set(PATH_LITERAL.findall(match))


def match_hosts(match: str) -> set[str]:
    return set(HOST_LITERAL.findall(match))


class PublicStatsRouteTest(unittest.TestCase):
    def test_base_public_paths_appear_on_prod_and_staging_hosts(self) -> None:
        base_paths: set[str] = set()
        for route in public_gateway_routes(BASE_ROUTES):
            match = route.get("match", "")
            base_paths |= match_paths(match)
        self.assertIn("/public/stats", base_paths)

        failures: list[str] = []
        for label, path in (("prod", PROD_EDGE), ("staging", STAGING_EDGE)):
            overlay_paths: set[str] = set()
            overlay_hosts: set[str] = set()
            for route in public_gateway_routes(path):
                match = route.get("match", "")
                overlay_paths |= match_paths(match)
                overlay_hosts |= match_hosts(match)
            missing = sorted(base_paths - overlay_paths)
            if missing:
                failures.append(
                    f"{label} overlay {path.name} is missing base public paths: {missing}"
                )
            if not overlay_hosts:
                failures.append(f"{label} overlay {path.name} has no Host() match")
            for host in overlay_hosts:
                if host.endswith(".internal"):
                    failures.append(
                        f"{label} overlay {path.name} still matches placeholder host {host}"
                    )
        self.assertEqual([], failures)

    def test_public_stats_routes_to_stats_reader(self) -> None:
        reader_services = [
            document
            for document in load_documents(STATS_READER_DEPLOYMENT)
            if document.get("kind") == "Service"
            and document.get("metadata", {}).get("name") == "ssl-proxy-stats-reader"
        ]
        self.assertEqual(1, len(reader_services))
        http_ports = [
            port
            for port in reader_services[0].get("spec", {}).get("ports", [])
            if port.get("name") == "http"
        ]
        self.assertEqual(1, len(http_ports))
        service_port = http_ports[0].get("port")
        self.assertIsInstance(service_port, int)
        self.assertEqual(8080, http_ports[0].get("targetPort"))

        failures: list[str] = []
        for label, path in (("base", BASE_ROUTES), ("prod", PROD_EDGE), ("staging", STAGING_EDGE)):
            hits = [
                route
                for route in public_gateway_routes(path)
                if "/public/stats" in match_paths(route.get("match", ""))
            ]
            if len(hits) != 1:
                failures.append(
                    f"{label} {path.name}: expected exactly one /public/stats route, found {len(hits)}"
                )
                continue
            services = hits[0].get("services") or []
            names = {service.get("name") for service in services if isinstance(service, dict)}
            ports = {service.get("port") for service in services if isinstance(service, dict)}
            if names != {"ssl-proxy-stats-reader"}:
                failures.append(
                    f"{label} {path.name}: /public/stats must target ssl-proxy-stats-reader, got {names}"
                )
            if ports != {service_port}:
                failures.append(
                    f"{label} {path.name}: /public/stats must target Service port {service_port}, got {ports}"
                )
        self.assertEqual([], failures)

    def test_reader_networkpolicy_allows_traefik_on_8080(self) -> None:
        documents = load_documents(STATS_READER_NETPOL)
        policy = next(
            (d for d in documents if d.get("kind") == "NetworkPolicy"
             and d.get("metadata", {}).get("name") == "ssl-proxy-stats-reader"),
            None,
        )
        self.assertIsNotNone(policy, f"no NetworkPolicy in {STATS_READER_NETPOL}")
        ingress = policy.get("spec", {}).get("ingress") or []
        allowed = False
        for rule in ingress:
            ports = {
                port.get("port")
                for port in rule.get("ports") or []
                if isinstance(port, dict) and port.get("protocol") == "TCP"
            }
            if 8080 not in ports:
                continue
            for source in rule.get("from") or []:
                if not isinstance(source, dict):
                    continue
                pod = source.get("podSelector", {}).get("matchLabels", {})
                namespace = source.get("namespaceSelector", {}).get("matchLabels", {})
                if (
                    pod.get("app.kubernetes.io/name") == "traefik"
                    and namespace.get("kubernetes.io/metadata.name") == "kube-system"
                ):
                    allowed = True
        self.assertTrue(
            allowed,
            "stats-reader NetworkPolicy must allow Traefik (kube-system) to TCP 8080",
        )


if __name__ == "__main__":
    unittest.main()
