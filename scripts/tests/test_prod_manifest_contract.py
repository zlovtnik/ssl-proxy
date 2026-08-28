from __future__ import annotations

import importlib.util
import sys
import unittest
from pathlib import Path


MODULE_PATH = Path(__file__).resolve().parents[1] / "check-gitops.py"
ROOT = Path(__file__).resolve().parents[2]
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
            - {name: KC_DB, value: postgres}
            - name: KC_DB_URL_HOST
              valueFrom: {configMapKeyRef: {name: ssl-proxy-prod-postgres-endpoint, key: POSTGRES_HOST}}
            - name: KC_DB_URL_PORT
              valueFrom: {configMapKeyRef: {name: ssl-proxy-prod-postgres-endpoint, key: POSTGRES_PORT}}
            - {name: KC_DB_USERNAME, value: keycloak_runtime}
            - {name: KC_DB_URL_PROPERTIES, value: "?currentSchema=keycloak&sslmode=verify-full&sslrootcert=/var/run/postgres-tls/ca.crt"}
          volumeMounts:
            - {name: postgres-ca, mountPath: /var/run/postgres-tls, readOnly: true}
      containers:
        - name: keycloak
          env:
            - {name: KC_DB, value: postgres}
            - name: KC_DB_URL_HOST
              valueFrom: {configMapKeyRef: {name: ssl-proxy-prod-postgres-endpoint, key: POSTGRES_HOST}}
            - name: KC_DB_URL_PORT
              valueFrom: {configMapKeyRef: {name: ssl-proxy-prod-postgres-endpoint, key: POSTGRES_PORT}}
            - {name: KC_DB_USERNAME, value: keycloak_runtime}
            - {name: KC_DB_URL_PROPERTIES, value: "?currentSchema=keycloak&sslmode=verify-full&sslrootcert=/var/run/postgres-tls/ca.crt"}
          volumeMounts:
            - {name: postgres-ca, mountPath: /var/run/postgres-tls, readOnly: true}
      volumes:
        - name: postgres-ca
          secret: {secretName: postgres-runtime-tls}
"""
    )


def pgbouncer() -> list[dict[str, object]]:
    return documents(
        """apiVersion: apps/v1
kind: Deployment
metadata: {name: postgres-pgbouncer}
spec:
  template:
    spec:
      initContainers:
        - name: render-pgbouncer-config
          image: busybox@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
          args:
            - POSTGRES_SSL_MODE verify-full POSTGRES_SSL_SERVER_NAME POSTGRES_HOST unix_socket_dir = /var/run/pgbouncer ignore_startup_parameters = extra_float_digits,search_path client_tls_sslmode = require client_tls_cert_file = /etc/pgbouncer/listener/tls.crt client_tls_key_file = /etc/pgbouncer/listener/tls.key
          env:
            - {name: POSTGRES_HOST, valueFrom: {configMapKeyRef: {name: ssl-proxy-prod-postgres-endpoint, key: POSTGRES_HOST}}}
            - {name: POSTGRES_PORT, valueFrom: {configMapKeyRef: {name: ssl-proxy-prod-postgres-endpoint, key: POSTGRES_PORT}}}
            - {name: POSTGRES_DATABASE, valueFrom: {configMapKeyRef: {name: ssl-proxy-prod-postgres-endpoint, key: POSTGRES_DATABASE}}}
            - {name: POSTGRES_SSL_MODE, valueFrom: {configMapKeyRef: {name: ssl-proxy-prod-postgres-endpoint, key: POSTGRES_SSL_MODE}}}
            - {name: POSTGRES_SSL_SERVER_NAME, valueFrom: {configMapKeyRef: {name: ssl-proxy-prod-postgres-endpoint, key: POSTGRES_SSL_SERVER_NAME}}}
      containers:
        - name: pgbouncer
          securityContext: {runAsNonRoot: true, runAsUser: 70, runAsGroup: 70}
      volumes:
        - {name: generated-config, emptyDir: {}}
        - {name: users, secret: {secretName: pgbouncer-runtime-users}}
        - {name: upstream-tls, secret: {secretName: postgres-runtime-tls}}
        - {name: listener-tls, secret: {secretName: pgbouncer-listener-tls}}
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
            - {name: POSTGRES_ENABLED, value: "true"}
            - {name: POSTGRES_SCHEMA_MANIFEST_SHA256, value: canonical-checksum}
            - {name: SYNC_REDPANDA_TOPIC_REPLICATION_FACTOR, value: "1"}
            - {name: OCTOPUS_PROCESSORS_ENABLED, value: "true"}
            - {name: OCTOPUS_CONSUMERS_ENABLED, value: "true"}
            - {name: OCTOPUS_ARCHIVE_ENABLED, value: "true"}
            - {name: OCTOPUS_ENABLED_PROCESSORS, value: "__PROCESSORS__"}
            - {name: OCTOPUS_ENVIRONMENT, value: production}
""".replace("__PROCESSORS__", processors)
    )


class ProductionManifestContractTest(unittest.TestCase):
    def test_keycloak_bootstrap_probe_uses_tools_present_in_keycloak_image(self) -> None:
        rendered = documents(
            (ROOT / "cyber-stack/base/schema-migrator/bootstrap-job.yaml").read_text()
        )
        script = rendered[0]["spec"]["template"]["spec"]["containers"][0]["args"][0]
        self.assertIn("timeout 3 bash -c", script)
        self.assertIn("/dev/tcp/ssl-proxy-schema-migrator-keycloak/8080", script)
        self.assertNotIn("curl ", script)

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

    def test_keycloak_bootstrap_and_main_use_external_postgres(self) -> None:
        rendered = keycloak()
        self.assertEqual(
            [], check_gitops._check_prod_keycloak_external_postgres(rendered, "prod")
        )

        bootstrap = next(
            container
            for container in rendered[0]["spec"]["template"]["spec"][
                "initContainers"
            ]
            if container["name"] == "bootstrap-admin-service"
        )
        entry = bootstrap["env"][1]
        entry.pop("valueFrom")
        entry["value"] = "ssl-proxy-postgres"
        errors = check_gitops._check_prod_keycloak_external_postgres(rendered, "prod")
        self.assertTrue(any("bootstrap-admin-service" in error for error in errors))

        bootstrap["env"][0]["value"] = "postgresql"
        errors = check_gitops._check_prod_keycloak_external_postgres(rendered, "prod")
        self.assertTrue(any("KC_DB must use the postgres vendor" in error for error in errors))

    def test_pgbouncer_routes_to_the_external_postgres_contract(self) -> None:
        rendered = pgbouncer()
        self.assertEqual(
            [],
            check_gitops._check_prod_pgbouncer_external_postgres(rendered, "prod"),
        )

        renderer = rendered[0]["spec"]["template"]["spec"]["initContainers"][0]
        renderer["env"][0]["valueFrom"]["configMapKeyRef"]["name"] = "wrong-endpoint"
        errors = check_gitops._check_prod_pgbouncer_external_postgres(rendered, "prod")
        self.assertTrue(any("POSTGRES_HOST" in error for error in errors))

        pgbouncer_container = rendered[0]["spec"]["template"]["spec"]["containers"][0]
        pgbouncer_container["securityContext"].pop("runAsUser")
        errors = check_gitops._check_prod_pgbouncer_external_postgres(rendered, "prod")
        self.assertTrue(any("numeric postgres UID/GID 70" in error for error in errors))

    def test_keycloak_bootstrap_runs_after_home_preparation(self) -> None:
        rendered = keycloak()
        init_containers = rendered[0]["spec"]["template"]["spec"][
            "initContainers"
        ]
        init_containers.insert(0, init_containers.pop())

        errors = check_gitops._check_prod_keycloak_external_postgres(rendered, "prod")
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
            if entry["name"] == "POSTGRES_SCHEMA_MANIFEST_SHA256"
        )["value"] = "stale-checksum"
        errors = check_gitops._check_octopus_schema_contract(
            rendered, "prod", "canonical-checksum"
        )
        self.assertTrue(any("octopus_core/manifest.yaml" in error for error in errors))


if __name__ == "__main__":
    unittest.main()
