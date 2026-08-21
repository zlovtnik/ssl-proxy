from __future__ import annotations

import importlib.util
import sys
import unittest
from pathlib import Path


MODULE_PATH = Path(__file__).resolve().parents[1] / "check-gitops.py"
SPEC = importlib.util.spec_from_file_location("prod_manifest_check_gitops", MODULE_PATH)
assert SPEC and SPEC.loader
check_gitops = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = check_gitops
SPEC.loader.exec_module(check_gitops)


def documents(text: str) -> list[dict[str, object]]:
    errors: list[str] = []
    loaded = check_gitops._load_documents(text, "test", errors)
    assert loaded is not None, errors
    return loaded


def alloy() -> list[dict[str, object]]:
    return documents(
        """apiVersion: apps/v1
kind: DaemonSet
metadata: {name: ssl-proxy-telemetry-alloy}
spec:
  template:
    spec:
      volumes:
        - {name: positions, emptyDir: {}}
"""
    )


def keycloak() -> list[dict[str, object]]:
    return documents(
        """apiVersion: apps/v1
kind: Deployment
metadata: {name: ssl-proxy-schema-migrator-keycloak}
spec:
  template:
    spec:
      initContainers:
        - name: pem-to-pkcs12
        - name: prepare-keycloak-home
        - name: bootstrap-admin-service
          env:
            - name: KC_DB_URL_HOST
              valueFrom: {configMapKeyRef: {name: ssl-proxy-prod-tidb-endpoint, key: TIDB_HOST}}
            - name: KC_DB_URL_PORT
              valueFrom: {configMapKeyRef: {name: ssl-proxy-prod-tidb-endpoint, key: TIDB_PORT}}
      containers:
        - name: keycloak
          env:
            - name: KC_DB_URL_HOST
              valueFrom: {configMapKeyRef: {name: ssl-proxy-prod-tidb-endpoint, key: TIDB_HOST}}
            - name: KC_DB_URL_PORT
              valueFrom: {configMapKeyRef: {name: ssl-proxy-prod-tidb-endpoint, key: TIDB_PORT}}
"""
    )


def octopus() -> list[dict[str, object]]:
    processors = ",".join(sorted(check_gitops.OCTOPUS_RUNTIME_PROCESSORS))
    return documents(
        """apiVersion: apps/v1
kind: Deployment
metadata: {name: ssl-proxy-java-coordinator}
spec:
  replicas: 3
  template:
    spec:
      containers:
        - name: java-coordinator
          env:
            - {name: TIDB_ENABLED, value: "true"}
            - {name: TIDB_SCHEMA_MANIFEST_SHA256, value: canonical-checksum}
            - {name: SYNC_REDPANDA_TOPIC_REPLICATION_FACTOR, value: "1"}
            - {name: OCTOPUS_PROCESSORS_ENABLED, value: "true"}
            - {name: OCTOPUS_CONSUMERS_ENABLED, value: "true"}
            - {name: OCTOPUS_ARCHIVE_ENABLED, value: "true"}
            - {name: OCTOPUS_ENABLED_PROCESSORS, value: "__PROCESSORS__"}
            - {name: OCTOPUS_ENVIRONMENT, value: production}
""".replace("__PROCESSORS__", processors)
    )


class ProductionManifestContractTest(unittest.TestCase):
    def test_alloy_positions_requires_empty_dir_without_host_path(self) -> None:
        rendered = alloy()
        self.assertEqual(
            [], check_gitops._check_prod_alloy_positions(rendered, "prod")
        )

        positions = rendered[0]["spec"]["template"]["spec"]["volumes"][0]
        positions.pop("emptyDir")
        positions["hostPath"] = {"path": "/var/lib/alloy"}
        self.assertEqual(
            1, len(check_gitops._check_prod_alloy_positions(rendered, "prod"))
        )

    def test_keycloak_bootstrap_and_main_use_external_tidb(self) -> None:
        rendered = keycloak()
        self.assertEqual(
            [], check_gitops._check_prod_keycloak_external_tidb(rendered, "prod")
        )

        bootstrap = next(
            container
            for container in rendered[0]["spec"]["template"]["spec"][
                "initContainers"
            ]
            if container["name"] == "bootstrap-admin-service"
        )
        entry = bootstrap["env"][0]
        entry.pop("valueFrom")
        entry["value"] = "ssl-proxy-tidb"
        errors = check_gitops._check_prod_keycloak_external_tidb(rendered, "prod")
        self.assertTrue(any("bootstrap-admin-service" in error for error in errors))

    def test_keycloak_bootstrap_runs_after_home_preparation(self) -> None:
        rendered = keycloak()
        init_containers = rendered[0]["spec"]["template"]["spec"][
            "initContainers"
        ]
        init_containers.insert(0, init_containers.pop())

        errors = check_gitops._check_prod_keycloak_external_tidb(rendered, "prod")
        self.assertTrue(
            any("prepare keycloak-home" in error for error in errors)
        )

    def test_octopus_runtime_requires_all_lanes_and_rejects_retired_cutover_inputs(self) -> None:
        rendered = octopus()
        self.assertEqual(
            [], check_gitops._check_octopus_runtime(rendered, "prod")
        )

        environment = rendered[0]["spec"]["template"]["spec"]["containers"][0][
            "env"
        ]
        environment.append(
            {"name": "OCTOPUS_CUTOVER_ARTIFACT_PATH", "value": "/fake/cutover.json"}
        )
        next(
            entry
            for entry in environment
            if entry["name"] == "OCTOPUS_CONSUMERS_ENABLED"
        )["value"] = "false"
        next(
            entry
            for entry in environment
            if entry["name"] == "OCTOPUS_ENABLED_PROCESSORS"
        )["value"] = "sync-scan-ingestion"
        rendered[0]["spec"]["replicas"] = 4

        errors = check_gitops._check_octopus_runtime(rendered, "prod")
        self.assertTrue(any("exactly 3 replicas" in error for error in errors))
        self.assertTrue(any("OCTOPUS_CONSUMERS_ENABLED=true" in error for error in errors))
        self.assertTrue(any("complete processor catalog" in error for error in errors))
        self.assertTrue(any("retired cutover inputs" in error for error in errors))

    def test_octopus_schema_checksum_matches_canonical_manifest(self) -> None:
        rendered = octopus()
        self.assertEqual(
            [],
            check_gitops._check_octopus_schema_contract(
                rendered, "prod", "canonical-checksum"
            ),
        )

        environment = rendered[0]["spec"]["template"]["spec"]["containers"][0][
            "env"
        ]
        next(
            entry
            for entry in environment
            if entry["name"] == "TIDB_SCHEMA_MANIFEST_SHA256"
        )["value"] = "stale-checksum"
        errors = check_gitops._check_octopus_schema_contract(
            rendered, "prod", "canonical-checksum"
        )
        self.assertTrue(any("octopus_core/manifest.yaml" in error for error in errors))


if __name__ == "__main__":
    unittest.main()
