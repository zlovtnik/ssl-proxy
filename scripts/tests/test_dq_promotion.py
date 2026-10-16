from __future__ import annotations

import hashlib
import json
from pathlib import Path
import subprocess
import unittest

import yaml


ROOT = Path(__file__).resolve().parents[2]


def digest(value: object) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


class DQPreparationTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        rendered = subprocess.run(
            ["kustomize", "build", "--load-restrictor", "LoadRestrictionsNone",
             "cyber-stack/matrix/prod/app-stack"],
            cwd=ROOT, check=True, capture_output=True, text=True,
        ).stdout
        cls.documents = list(yaml.safe_load_all(rendered))

    def object(self, kind: str, name: str) -> dict:
        return next(item for item in self.documents
                    if item["kind"] == kind and item["metadata"]["name"] == name)

    def test_preparation_cannot_start_dq_or_enable_admission(self) -> None:
        for name in ("ssl-proxy-dq-manager", "ssl-proxy-dq-atheros-dedup-v0-1-0"):
            deployment = self.object("Deployment", name)
            self.assertEqual(0, deployment["spec"]["replicas"])
            container = deployment["spec"]["template"]["spec"]["containers"][0]
            self.assertIn("@sha256:", container["image"])
            self.assertEqual("IfNotPresent", container["imagePullPolicy"])
            environment = {item["name"]: item.get("value") for item in container["env"]}
            self.assertNotEqual("true", environment.get("DQ_INSECURE_DEVELOPMENT"))
            self.assertNotEqual("true", environment.get("DQ_BETA_ENABLED"))
        octopus = self.object("ConfigMap", "ssl-proxy-dq-control-config")
        self.assertEqual("false", octopus["data"]["OCTOPUS_DQ_ENABLED"])
        search = self.object("Deployment", "ssl-proxy-atheros-search")
        environment = search["spec"]["template"]["spec"]["containers"][0]["env"]
        self.assertEqual("false", next(item["value"] for item in environment if item["name"] == "ATHSEARCH_DQ_ENABLED"))

    def test_manifest_and_worker_pin_are_one_immutable_contract(self) -> None:
        worker = self.object("Deployment", "ssl-proxy-dq-atheros-dedup-v0-1-0")
        pod = worker["spec"]["template"]["spec"]
        manifest_name = next(item["configMap"]["name"] for item in pod["volumes"] if item["name"] == "manifest")
        manifest = json.loads(self.object("ConfigMap", manifest_name)["data"]["manifest.json"])
        expected = manifest.pop("manifest_sha256")
        self.assertEqual(expected, digest(manifest))
        self.assertEqual(manifest["parameter_schema_sha256"], digest(manifest["parameter_schema"]))
        self.assertEqual(json.loads((ROOT / "services/dq/schemas/atheros.dedup.parameters.v1.json").read_text()), manifest["parameter_schema"])
        image_digest = pod["containers"][0]["image"].split("@", 1)[1]
        self.assertEqual(image_digest, manifest["implementation_digest"])
        self.assertEqual(image_digest, self.object("ConfigMap", "ssl-proxy-dq-worker-config")["data"]["DQ_WORKER_IMPLEMENTATION_DIGEST"])
        self.assertEqual(worker["metadata"]["name"], manifest["worker_service"])
        self.assertTrue(all(binding["allowed_prefix"].startswith("wiretrap/prod-ssl-proxy/")
                            for binding in manifest["inputs"] + manifest["outputs"]))


if __name__ == "__main__":
    unittest.main()
