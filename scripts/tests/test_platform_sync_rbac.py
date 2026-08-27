#!/usr/bin/env python3
"""Tests for platform-sync Kubernetes RBAC resources."""

from __future__ import annotations

import unittest
from pathlib import Path

import yaml


REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
RBAC_DIR = REPOSITORY_ROOT / "cyber-stack" / "base" / "platform-sync"
BOOTSTRAP_KUST = REPOSITORY_ROOT / "cyber-stack" / "matrix" / "prod" / "bootstrap" / "kustomization.yaml"


def load_yaml(path: Path) -> list[dict]:
    return [
        doc
        for doc in yaml.safe_load_all(path.read_text(encoding="utf-8"))
        if isinstance(doc, dict)
    ]


class PlatformSyncRbacTest(unittest.TestCase):
    def test_serviceaccount_exists(self) -> None:
        """Verify ServiceAccount exists with correct properties."""
        docs = load_yaml(RBAC_DIR / "serviceaccount.yaml")
        self.assertEqual(1, len(docs))
        sa = docs[0]
        self.assertEqual("ServiceAccount", sa["kind"])
        self.assertEqual("ssl-proxy-platform-sync", sa["metadata"]["name"])
        self.assertEqual("prod-ssl-proxy", sa["metadata"]["namespace"])
        self.assertTrue(sa.get("automountServiceAccountToken", False))

    def test_role_exists(self) -> None:
        """Verify Role exists with least-privilege permissions."""
        docs = load_yaml(RBAC_DIR / "role.yaml")
        self.assertEqual(1, len(docs))
        role = docs[0]
        self.assertEqual("Role", role["kind"])
        self.assertEqual("ssl-proxy-platform-sync", role["metadata"]["name"])
        self.assertEqual("prod-ssl-proxy", role["metadata"]["namespace"])

        rules = role["rules"]
        self.assertEqual(2, len(rules))

        secrets_rule = next(r for r in rules if "secrets" in r["resources"])
        self.assertEqual(["get", "list", "watch", "create", "update", "patch"], secrets_rule["verbs"])
        self.assertNotIn("delete", secrets_rule["verbs"])

        configmaps_rule = next(r for r in rules if "configmaps" in r["resources"])
        self.assertEqual(["get", "list", "watch", "create", "update", "patch"], configmaps_rule["verbs"])
        self.assertNotIn("delete", configmaps_rule["verbs"])

    def test_rolebinding_exists(self) -> None:
        """Verify RoleBinding exists and references correct SA and Role."""
        docs = load_yaml(RBAC_DIR / "rolebinding.yaml")
        self.assertEqual(1, len(docs))
        rb = docs[0]
        self.assertEqual("RoleBinding", rb["kind"])
        self.assertEqual("ssl-proxy-platform-sync", rb["metadata"]["name"])
        self.assertEqual("prod-ssl-proxy", rb["metadata"]["namespace"])

        self.assertEqual("Role", rb["roleRef"]["kind"])
        self.assertEqual("ssl-proxy-platform-sync", rb["roleRef"]["name"])

        subjects = rb["subjects"]
        self.assertEqual(1, len(subjects))
        self.assertEqual("ServiceAccount", subjects[0]["kind"])
        self.assertEqual("ssl-proxy-platform-sync", subjects[0]["name"])
        self.assertEqual("prod-ssl-proxy", subjects[0]["namespace"])

    def test_kustomization_includes_rbac(self) -> None:
        """Verify bootstrap kustomization includes platform-sync RBAC."""
        docs = load_yaml(BOOTSTRAP_KUST)
        self.assertEqual(1, len(docs))
        kust = docs[0]
        resources = kust.get("resources", [])

        self.assertIn("../../../base/platform-sync/serviceaccount.yaml", resources)
        self.assertIn("../../../base/platform-sync/role.yaml", resources)
        self.assertIn("../../../base/platform-sync/rolebinding.yaml", resources)

    def test_no_cluster_roles(self) -> None:
        """Verify RBAC is namespace-scoped only (no ClusterRoles)."""
        for yaml_file in RBAC_DIR.glob("*.yaml"):
            docs = load_yaml(yaml_file)
            for doc in docs:
                self.assertNotIn(
                    doc.get("kind"),
                    ["ClusterRole", "ClusterRoleBinding"],
                    f"Found cluster-scoped resource in {yaml_file.name}",
                )


if __name__ == "__main__":
    unittest.main()
