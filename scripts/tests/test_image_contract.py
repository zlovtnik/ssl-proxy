from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

import sys


REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPOSITORY_ROOT / "scripts"))

from image_contract import (  # noqa: E402
    FIRST_PARTY_SERVICES,
    ImageContractError,
    extract_buildx_digest,
    load_buildx_digest,
    load_image_contracts,
)


PIN = "sha256:" + "a" * 64


def write_contract(root: Path, environment: str, *, registry: str) -> None:
    matrix = root / "cyber-stack" / "matrix" / environment
    app_services = FIRST_PARTY_SERVICES[:-1]
    data_services = FIRST_PARTY_SERVICES[-1:]
    for slice_name, services in (("app-stack", app_services), ("data-plane", data_services)):
        path = matrix / slice_name / "kustomization.yaml"
        path.parent.mkdir(parents=True, exist_ok=True)
        images = "".join(
            f"  - name: {service}\n"
            f"    newName: {registry}/{environment}/{service}\n"
            f"    digest: {PIN}\n"
            for service in services
        )
        path.write_text(
            "apiVersion: kustomize.config.k8s.io/v1beta1\n"
            "kind: Kustomization\n"
            f"images:\n{images}",
            encoding="utf-8",
        )
    aggregate_images = "".join(
        f"  - name: {service}\n"
        f"    newName: {registry}/{environment}/{service}\n"
        f"    digest: {PIN}\n"
        for service in FIRST_PARTY_SERVICES
    )
    (matrix / "kustomization.yaml").write_text(
        "apiVersion: kustomize.config.k8s.io/v1beta1\n"
        "kind: Kustomization\n"
        f"namespace: {environment}-ssl-proxy\n"
        f"images:\n{aggregate_images}",
        encoding="utf-8",
    )


class ImageContractTest(unittest.TestCase):
    def setUp(self) -> None:
        self.directory = tempfile.TemporaryDirectory()
        self.root = Path(self.directory.name)
        write_contract(self.root, "dev", registry="dev.registry.test/team")
        write_contract(self.root, "prod", registry="prod.registry.test/release")

    def tearDown(self) -> None:
        self.directory.cleanup()

    def test_environment_selects_repositories_and_owning_slices(self) -> None:
        dev = load_image_contracts(self.root, "dev")
        prod = load_image_contracts(self.root, "prod")

        self.assertEqual(8, len(dev))
        self.assertTrue(all(contract.repository.startswith("dev.registry.test/team/dev/") for contract in dev))
        self.assertTrue(all(contract.repository.startswith("prod.registry.test/release/prod/") for contract in prod))
        self.assertEqual("data-plane", dev[-1].slice_name)
        self.assertEqual("app-stack", dev[0].slice_name)

    def test_rejects_slice_aggregate_inconsistency(self) -> None:
        aggregate = self.root / "cyber-stack/matrix/prod/kustomization.yaml"
        aggregate.write_text(
            aggregate.read_text(encoding="utf-8").replace(PIN, "sha256:" + "b" * 64, 1),
            encoding="utf-8",
        )

        with self.assertRaisesRegex(ImageContractError, "differs between"):
            load_image_contracts(self.root, "prod")

    def test_rejects_missing_duplicate_tagged_and_invalid_digest_mappings(self) -> None:
        app = self.root / "cyber-stack/matrix/dev/app-stack/kustomization.yaml"
        original = app.read_text(encoding="utf-8")
        ssl_proxy_block = (
            "  - name: ssl-proxy\n"
            "    newName: dev.registry.test/team/dev/ssl-proxy\n"
            f"    digest: {PIN}\n"
        )
        mutations = (
            original.replace(ssl_proxy_block, "", 1),
            original + ssl_proxy_block,
            original.replace("    digest: " + PIN, "    newTag: latest\n    digest: " + PIN, 1),
            original.replace(
                "dev.registry.test/team/dev/ssl-proxy",
                "dev.registry.test/team/dev/ssl-proxy:latest",
                1,
            ),
            original.replace(PIN, "sha256:" + "A" * 64, 1),
        )
        for content in mutations:
            with self.subTest(content=content[-100:]):
                app.write_text(content, encoding="utf-8")
                with self.assertRaises(ImageContractError):
                    load_image_contracts(self.root, "dev")
                app.write_text(original, encoding="utf-8")

    def test_extracts_only_a_consistent_buildx_manifest_digest(self) -> None:
        metadata_path = self.root / "metadata.json"
        metadata_path.write_text(
            json.dumps(
                {
                    "containerimage.digest": PIN,
                    "containerimage.descriptor": {"digest": PIN},
                    "containerimage.config.digest": "sha256:" + "b" * 64,
                }
            ),
            encoding="utf-8",
        )

        self.assertEqual(PIN, load_buildx_digest(metadata_path))
        with self.assertRaisesRegex(ImageContractError, "inconsistent"):
            extract_buildx_digest(
                {
                    "containerimage.digest": PIN,
                    "containerimage.descriptor": {"digest": "sha256:" + "b" * 64},
                }
            )
        with self.assertRaises(ImageContractError):
            extract_buildx_digest({"containerimage.config.digest": PIN})


if __name__ == "__main__":
    unittest.main()
