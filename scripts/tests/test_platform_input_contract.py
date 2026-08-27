from __future__ import annotations

import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

import yaml


REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPOSITORY_ROOT / "scripts"))

from platform_input_contract import (  # noqa: E402
    CONTRACT_RELATIVE_PATH,
    PLATFORM_BOOTSTRAP,
    PlatformInputContractError,
    compare_contract_to_rendered,
    find_committed_secret_values,
    load_platform_input_contract,
)


EXPECTED_INPUTS = {
    ("Secret", "cloudflared-tunnel-credentials"): {"credentials.json"},
    ("Secret", "minio-credentials"): {"access-key", "secret-key"},
    ("Secret", "observability-credentials"): {
        "grafana-admin-password",
        "loki-username",
        "loki-password",
        "loki-htpasswd",
        "alertmanager-webhook-url",
        "jenkins-prometheus-password",
        "minio-prometheus-bearer-token",
    },
    ("Secret", "proxy-admin-key"): {"api-key"},
    ("Secret", "proxy-runtime-secrets"): {"wg-obfuscation-key"},
    ("Secret", "redis-runtime"): {"password"},
    ("Secret", "schema-migrator-backend"): {
        "encrypt-key",
        "jwt-secret",
        "api-bearer-token",
    },
    ("Secret", "schema-migrator-bootstrap"): {"application-admin-password"},
    ("Secret", "schema-migrator-keycloak"): {"bootstrap-admin-password"},
    ("Secret", "ssl-proxy-identity-tls"): {"ca.crt", "tls.crt", "tls.key"},
    ("Secret", "postgres-atheros-search"): {"password"},
    ("Secret", "postgres-keycloak"): {"password"},
    ("Secret", "postgres-octopus"): {"password"},
    ("Secret", "postgres-schema-migrator"): {"password"},
    ("Secret", "postgres-schema-owner"): {"password"},
    ("Secret", "postgres-runtime-tls"): {"ca.crt"},
    ("Secret", "pgbouncer-runtime-users"): {"userlist.txt"},
    ("Secret", "wireguard-config"): {
        "server.conf",
        "Corefile",
        "privatekey-server",
        "publickey-server",
        "peer1.conf",
        "peer1-obfuscated.conf",
        "publickey-peer1",
        "presharedkey-peer1",
        "peer2.conf",
        "peer2-obfuscated.conf",
        "publickey-peer2",
        "presharedkey-peer2",
    },
    ("ConfigMap", "ssl-proxy-prod-postgres-endpoint"): {
        "POSTGRES_HOST",
        "POSTGRES_PORT",
        "POSTGRES_DATABASE",
        "POSTGRES_SSL_MODE",
        "POSTGRES_SSL_SERVER_NAME",
    },
}


def render_production() -> list[dict[str, object]]:
    result = subprocess.run(
        [
            "kustomize",
            "build",
            "--load-restrictor",
            "LoadRestrictionsNone",
            "cyber-stack/matrix/prod",
        ],
        cwd=REPOSITORY_ROOT,
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    return [document for document in yaml.safe_load_all(result.stdout) if isinstance(document, dict)]


class PlatformInputContractTest(unittest.TestCase):
    def test_bootstrap_contract_pins_postgres_pgvector_and_vault(self) -> None:
        contract = load_platform_input_contract(REPOSITORY_ROOT)

        self.assertEqual(PLATFORM_BOOTSTRAP, contract.document["spec"]["bootstrap"])
        self.assertEqual(16, PLATFORM_BOOTSTRAP["postgres"]["majorVersion"])
        self.assertEqual(
            ["pgcrypto", "vector", "pg_stat_statements"],
            PLATFORM_BOOTSTRAP["postgres"]["requiredExtensions"],
        )
        self.assertIn("@sha256:", PLATFORM_BOOTSTRAP["postgres"]["image"])
        self.assertIn("@sha256:", PLATFORM_BOOTSTRAP["secretControlPlane"]["image"])
        self.assertFalse(PLATFORM_BOOTSTRAP["secretControlPlane"]["developmentMode"])

    def test_contract_declares_every_required_object_key_and_vault_path(self) -> None:
        contract = load_platform_input_contract(REPOSITORY_ROOT)
        actual = {
            (entry.kind, entry.name): set(entry.keys) for entry in contract.inputs
        }

        self.assertEqual(EXPECTED_INPUTS, actual)
        self.assertEqual(18, sum(entry.kind == "Secret" for entry in contract.inputs))
        self.assertEqual(1, sum(entry.kind == "ConfigMap" for entry in contract.inputs))
        for entry in contract.inputs:
            self.assertEqual(
                f"secret/ssl-proxy/prod/{entry.name}", entry.vault_path
            )

    def test_tls_input_uses_kubernetes_tls_type(self) -> None:
        contract = load_platform_input_contract(REPOSITORY_ROOT)
        tls = contract.by_identity()[("Secret", "ssl-proxy-identity-tls")]

        self.assertEqual("kubernetes.io/tls", tls.secret_type)

    def test_production_render_exactly_matches_contract(self) -> None:
        contract = load_platform_input_contract(REPOSITORY_ROOT)

        self.assertEqual([], compare_contract_to_rendered(contract, render_production()))

    def test_rejects_undeclared_object_and_key_drift(self) -> None:
        contract = load_platform_input_contract(REPOSITORY_ROOT)
        rendered = render_production()
        deployment = next(
            document
            for document in rendered
            if document.get("kind") == "Deployment"
            and document.get("metadata", {}).get("name") == "ssl-proxy-proxy"
        )
        container = deployment["spec"]["template"]["spec"]["containers"][0]
        container["env"].extend(
            [
                {
                    "name": "UNDECLARED_KEY",
                    "valueFrom": {
                        "secretKeyRef": {
                            "name": "proxy-admin-key",
                            "key": "undeclared",
                        }
                    },
                },
                {
                    "name": "UNDECLARED_OBJECT",
                    "valueFrom": {
                        "secretKeyRef": {
                            "name": "surprise-secret",
                            "key": "token",
                        }
                    },
                },
            ]
        )

        errors = compare_contract_to_rendered(contract, rendered)

        self.assertTrue(any("Secret/surprise-secret" in error for error in errors))
        self.assertTrue(any("undeclared keys: undeclared" in error for error in errors))

    def test_rejects_tls_type_drift(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target = root / CONTRACT_RELATIVE_PATH
            target.parent.mkdir(parents=True)
            shutil.copyfile(REPOSITORY_ROOT / CONTRACT_RELATIVE_PATH, target)
            document = yaml.safe_load(target.read_text(encoding="utf-8"))
            tls = next(
                entry
                for entry in document["spec"]["inputs"]
                if entry["name"] == "ssl-proxy-identity-tls"
            )
            tls["type"] = "Opaque"
            target.write_text(yaml.safe_dump(document, sort_keys=False), encoding="utf-8")

            with self.assertRaisesRegex(
                PlatformInputContractError, "must use kubernetes.io/tls"
            ):
                load_platform_input_contract(root)

    def test_no_usable_secret_values_are_committed(self) -> None:
        self.assertEqual([], find_committed_secret_values(REPOSITORY_ROOT))

    def test_secret_data_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = root / "cyber-stack" / "bad-secret.yaml"
            path.parent.mkdir(parents=True)
            path.write_text(
                "apiVersion: v1\nkind: Secret\nmetadata: {name: bad}\n"
                "stringData: {password: usable}\n",
                encoding="utf-8",
            )

            errors = find_committed_secret_values(root)

        self.assertEqual(1, len(errors))
        self.assertIn("contains usable stringData values", errors[0])


if __name__ == "__main__":
    unittest.main()
