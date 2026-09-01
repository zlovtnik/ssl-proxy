#!/usr/bin/env python3
"""Tests for platform-sync Kubernetes RBAC resources."""

from __future__ import annotations

import subprocess
import sys
import unittest
from pathlib import Path

import yaml


REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
RBAC_DIR = REPOSITORY_ROOT / "cyber-stack" / "base" / "platform-sync"
BOOTSTRAP_KUST = REPOSITORY_ROOT / "cyber-stack" / "matrix" / "prod" / "bootstrap" / "kustomization.yaml"
INSTALLER = REPOSITORY_ROOT / "scripts" / "install-platform-sync.sh"
VAULT_BOOTSTRAP = REPOSITORY_ROOT / "scripts" / "bootstrap-vault-platform-sync.sh"
POSTGRES_ROTATION_BOOTSTRAP = REPOSITORY_ROOT / "scripts" / "bootstrap-postgres-rotation-token.sh"
POSTGRES_ROTATION_POLICY = REPOSITORY_ROOT / "vault" / "policies" / "postgres-rotation.hcl"
DEFAULT_CONFIG = REPOSITORY_ROOT / "config" / "platform-sync" / "platform-sync.conf.example"


def load_yaml(path: Path) -> list[dict]:
    return [
        doc
        for doc in yaml.safe_load_all(path.read_text(encoding="utf-8"))
        if isinstance(doc, dict)
    ]


class PlatformSyncRbacTest(unittest.TestCase):
    def test_generated_rbac_matches_platform_input_contract(self) -> None:
        subprocess.run(
            [sys.executable, "scripts/gen_platform_sync_rbac.py", "--check"],
            cwd=REPOSITORY_ROOT,
            check=True,
        )

    def test_host_scripts_have_valid_bash_syntax(self) -> None:
        for script in (INSTALLER, VAULT_BOOTSTRAP, POSTGRES_ROTATION_BOOTSTRAP):
            subprocess.run(["bash", "-n", str(script)], check=True)

    def test_installer_has_pinned_hardened_container_fallback(self) -> None:
        installer = INSTALLER.read_text(encoding="utf-8")
        self.assertIn("command -v go", installer)
        self.assertIn("command -v docker", installer)
        self.assertRegex(
            installer,
            r'GO_BUILDER_IMAGE="docker\.io/library/golang:1\.25-alpine@sha256:[0-9a-f]{64}"',
        )
        for flag in (
            "--read-only",
            "--cap-drop=ALL",
            "--security-opt=no-new-privileges",
            "-mod=readonly",
            "CGO_ENABLED=0",
        ):
            self.assertIn(flag, installer)

    def test_installer_default_configuration_is_packaged(self) -> None:
        installer = INSTALLER.read_text(encoding="utf-8")
        self.assertTrue(DEFAULT_CONFIG.is_file())
        self.assertIn("platform-sync.conf.example", installer)
        self.assertIn(
            'install -m 640 "$DEFAULT_CONFIG" "$CONFIG_DIR/platform-sync.conf"',
            installer,
        )

    def test_vault_bootstrap_preflights_admin_permissions(self) -> None:
        bootstrap = VAULT_BOOTSTRAP.read_text(encoding="utf-8")
        self.assertIn('require_admin_capability "sys/policies/acl/$POLICY_NAME"', bootstrap)
        self.assertIn('require_admin_capability "auth/token/create-orphan"', bootstrap)

    def test_postgres_rotation_policy_is_narrow_and_short_lived(self) -> None:
        policy = POSTGRES_ROTATION_POLICY.read_text(encoding="utf-8")
        expected_paths = {
            "postgres-atheros-search",
            "postgres-keycloak",
            "postgres-octopus",
            "postgres-schema-migrator",
            "postgres-schema-owner",
            "pgbouncer-runtime-users",
        }
        for name in expected_paths:
            self.assertIn(f'path "secret/data/ssl-proxy/prod/{name}"', policy)
        self.assertNotIn('path "secret/data/ssl-proxy/prod/*"', policy)
        self.assertNotIn("delete", policy)
        bootstrap = POSTGRES_ROTATION_BOOTSTRAP.read_text(encoding="utf-8")
        self.assertIn('-explicit-max-ttl="$TOKEN_MAX_TTL"', bootstrap)
        self.assertIn("-renewable=false", bootstrap)
        self.assertIn("Refusing to replace existing token file", bootstrap)

    def test_serviceaccount_exists(self) -> None:
        """Verify ServiceAccount exists with correct properties."""
        docs = load_yaml(RBAC_DIR / "serviceaccount.yaml")
        self.assertEqual(1, len(docs))
        sa = docs[0]
        self.assertEqual("ServiceAccount", sa["kind"])
        self.assertEqual("ssl-proxy-platform-sync", sa["metadata"]["name"])
        self.assertNotIn("namespace", sa["metadata"])
        self.assertFalse(sa.get("automountServiceAccountToken", True))

    def test_role_exists(self) -> None:
        """Verify Role exists with least-privilege permissions."""
        docs = load_yaml(RBAC_DIR / "role.yaml")
        self.assertEqual(1, len(docs))
        role = docs[0]
        self.assertEqual("Role", role["kind"])
        self.assertEqual("ssl-proxy-platform-sync", role["metadata"]["name"])
        self.assertNotIn("namespace", role["metadata"])

        rules = role["rules"]
        self.assertEqual(2, len(rules))

        secrets_rule = next(r for r in rules if "secrets" in r["resources"])
        self.assertEqual(["get", "update"], secrets_rule["verbs"])
        self.assertEqual(19, len(secrets_rule["resourceNames"]))

        configmaps_rule = next(r for r in rules if "configmaps" in r["resources"])
        self.assertEqual(["get", "update"], configmaps_rule["verbs"])
        self.assertEqual(
            [
                "platform-ready",
                "platform-sync-lock",
                "ssl-proxy-postgres-endpoint",
            ],
            sorted(configmaps_rule["resourceNames"]),
        )

    def test_rolebinding_exists(self) -> None:
        """Verify RoleBinding exists and references correct SA and Role."""
        docs = load_yaml(RBAC_DIR / "rolebinding.yaml")
        self.assertEqual(1, len(docs))
        rb = docs[0]
        self.assertEqual("RoleBinding", rb["kind"])
        self.assertEqual("ssl-proxy-platform-sync", rb["metadata"]["name"])
        self.assertNotIn("namespace", rb["metadata"])

        self.assertEqual("Role", rb["roleRef"]["kind"])
        self.assertEqual("ssl-proxy-platform-sync", rb["roleRef"]["name"])

        subjects = rb["subjects"]
        self.assertEqual(1, len(subjects))
        self.assertEqual("ServiceAccount", subjects[0]["kind"])
        self.assertEqual("ssl-proxy-platform-sync", subjects[0]["name"])
        self.assertNotIn("namespace", subjects[0])

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
