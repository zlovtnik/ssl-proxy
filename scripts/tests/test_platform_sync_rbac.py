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
        self.assertFalse(sa.get("automountServiceAccountToken", True))

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
        self.assertEqual(["get", "update"], secrets_rule["verbs"])
        self.assertEqual(18, len(secrets_rule["resourceNames"]))

        configmaps_rule = next(r for r in rules if "configmaps" in r["resources"])
        self.assertEqual(["get", "update"], configmaps_rule["verbs"])
        self.assertEqual(
            ["platform-sync-lock", "ssl-proxy-prod-postgres-endpoint"],
            sorted(configmaps_rule["resourceNames"]),
        )

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
        self.assertIn("../../../base/platform-sync/targets.yaml", resources)

    def test_every_writable_target_is_preprovisioned(self) -> None:
        role = load_yaml(RBAC_DIR / "role.yaml")[0]
        target_docs = load_yaml(RBAC_DIR / "targets.yaml")
        targets = {
            (doc["kind"].lower() + "s", doc["metadata"]["name"])
            for doc in target_docs
        }
        allowed = {
            (resource, name)
            for rule in role["rules"]
            for resource in rule["resources"]
            for name in rule["resourceNames"]
        }
        self.assertEqual(allowed, targets)

    def test_oneshot_units_can_run_on_every_timer_activation(self) -> None:
        config_dir = REPOSITORY_ROOT / "config" / "platform-sync"
        for unit_name in ("credential-generator.service", "vault-k8s-sync.service"):
            unit = (config_dir / unit_name).read_text(encoding="utf-8")
            self.assertNotIn("RemainAfterExit", unit)
            self.assertIn("RuntimeDirectory=platform-sync", unit)
            self.assertIn("RuntimeDirectoryPreserve=yes", unit)

    def test_single_timer_refreshes_kubernetes_credentials(self) -> None:
        config_dir = REPOSITORY_ROOT / "config" / "platform-sync"
        timers = sorted(path.name for path in config_dir.glob("*.timer"))
        self.assertEqual(["vault-k8s-sync.timer"], timers)
        sync_unit = (config_dir / "vault-k8s-sync.service").read_text(encoding="utf-8")
        self.assertIn("Requires=credential-generator.service", sync_unit)
        self.assertIn("LoadCredential=vault-token:/etc/platform-sync/vault-token", sync_unit)
        self.assertIn("LoadCredential=vault-ca:/etc/platform-sync/vault-ca.crt", sync_unit)

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
