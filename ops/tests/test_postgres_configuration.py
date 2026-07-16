import unittest
from pathlib import Path

import yaml


REPO_ROOT = Path(__file__).resolve().parents[2]
POSTGRES_CHART = REPO_ROOT / "helm" / "ssl-proxy" / "charts" / "postgres"


class PostgresConfigurationTest(unittest.TestCase):
    def test_kubernetes_profile_fits_the_eight_gibibyte_limit(self):
        values = yaml.safe_load((POSTGRES_CHART / "values.yaml").read_text())

        self.assertEqual(values["resources"]["limits"]["memory"], "8Gi")
        self.assertEqual(values["resources"]["requests"]["memory"], "4Gi")
        self.assertEqual(
            values["tuning"],
            {
                "max_connections": 128,
                "shared_buffers": "2GB",
                "effective_cache_size": "6GB",
                "work_mem": "8MB",
                "maintenance_work_mem": "512MB",
                "autovacuum_work_mem": "256MB",
                "wal_buffers": "32MB",
                "max_parallel_workers_per_gather": 2,
                "max_parallel_maintenance_workers": 2,
            },
        )
        self.assertNotEqual(values["tuning"]["shared_buffers"], "8GB")

    def test_statefulset_overrides_every_kubernetes_tuning_value(self):
        template = (POSTGRES_CHART / "templates" / "statefulset.yaml").read_text()
        values = yaml.safe_load((POSTGRES_CHART / "values.yaml").read_text())

        for key in values["tuning"]:
            with self.subTest(key=key):
                self.assertIn(f"{key}={{{{ .Values.tuning.{key} }}}}", template)


if __name__ == "__main__":
    unittest.main()
