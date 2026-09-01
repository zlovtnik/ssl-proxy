#!/usr/bin/env python3
"""Tests for the namespace-scoped Reloader GitOps workload."""

from __future__ import annotations

import unittest
from pathlib import Path

import yaml


REPOSITORY_ROOT = Path(__file__).resolve().parents[2]


def load_documents(relative: str) -> list[dict]:
    return [
        document
        for document in yaml.safe_load_all(
            (REPOSITORY_ROOT / relative).read_text(encoding="utf-8")
        )
        if isinstance(document, dict)
    ]


class ReloaderTest(unittest.TestCase):
    def test_reloader_is_namespace_scoped_and_digest_pinned(self) -> None:
        role = load_documents("cyber-stack/base/reloader/role.yaml")[0]
        self.assertEqual("Role", role["kind"])
        workloads = next(
            rule for rule in role["rules"] if rule["apiGroups"] == ["apps"]
        )
        self.assertEqual(
            ["get", "list", "watch", "update", "patch"], workloads["verbs"]
        )
        deployment = load_documents("cyber-stack/base/reloader/deployment.yaml")[0]
        container = deployment["spec"]["template"]["spec"]["containers"][0]
        self.assertRegex(container["image"], r"@sha256:[0-9a-f]{64}$")
        environment = {entry["name"]: entry["value"] for entry in container["env"]}
        self.assertEqual("prod-ssl-proxy", environment["KUBERNETES_NAMESPACE"])
        self.assertIn("--reload-strategy=annotations", container["args"])
        self.assertTrue(deployment["spec"]["template"]["spec"]["automountServiceAccountToken"])
        for path in (REPOSITORY_ROOT / "cyber-stack/base/reloader").glob("*.yaml"):
            for document in load_documents(str(path.relative_to(REPOSITORY_ROOT))):
                self.assertNotIn(document.get("kind"), {"ClusterRole", "ClusterRoleBinding"})

    def test_only_production_bootstrap_installs_reloader(self) -> None:
        prod = load_documents("cyber-stack/matrix/prod/bootstrap/kustomization.yaml")[0]
        staging = load_documents("cyber-stack/matrix/staging/bootstrap/kustomization.yaml")[0]
        resources = {
            "../../../base/reloader/serviceaccount.yaml",
            "../../../base/reloader/role.yaml",
            "../../../base/reloader/rolebinding.yaml",
            "../../../base/reloader/deployment.yaml",
            "../../../base/reloader/networkpolicy.yaml",
        }
        self.assertTrue(resources.issubset(set(prod["resources"])))
        self.assertTrue(resources.isdisjoint(set(staging["resources"])))

    def test_rotating_consumers_opt_in(self) -> None:
        targets = {
            "cyber-stack/base/java-coordinator/deployment.yaml": "ssl-proxy-java-coordinator",
            "cyber-stack/base/atheros-search/deployment.yaml": "ssl-proxy-atheros-search",
            "cyber-stack/base/redis-runtime/deployment.yaml": "ssl-proxy-redis-runtime",
            "cyber-stack/base/proxy/deployment.yaml": "ssl-proxy-proxy",
            "cyber-stack/base/pgbouncer/workload.yaml": "postgres-pgbouncer",
        }
        for relative, name in targets.items():
            deployment = next(
                document
                for document in load_documents(relative)
                if document.get("kind") == "Deployment"
                and document.get("metadata", {}).get("name") == name
            )
            self.assertEqual(
                "true",
                deployment["metadata"]["annotations"]["reloader.stakater.com/auto"],
            )

    def test_argocd_ignores_only_reloader_owned_annotation(self) -> None:
        application_set = load_documents(
            "cyber-stack/argocd/applicationset-workloads.yaml"
        )[0]
        rules = application_set["spec"]["template"]["spec"]["ignoreDifferences"]
        deployment_rule = next(
            rule
            for rule in rules
            if rule.get("group") == "apps" and rule.get("kind") == "Deployment"
        )
        self.assertEqual(
            [
                "/spec/template/metadata/annotations/"
                "reloader.stakater.com~1last-reloaded-from"
            ],
            deployment_rule["jsonPointers"],
        )


if __name__ == "__main__":
    unittest.main()
