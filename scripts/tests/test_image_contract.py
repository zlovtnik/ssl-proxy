from __future__ import annotations

import io
import json
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
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
    load_registry_authority,
    main,
    update_image_digest,
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

    def test_registry_authority_prints_shared_environment_authority(self) -> None:
        self.assertEqual(
            "prod.registry.test",
            load_registry_authority(self.root, "prod"),
        )

        output = io.StringIO()
        with redirect_stdout(output):
            exit_code = main(
                [
                    "registry-authority",
                    "--environment",
                    "prod",
                    "--repository-root",
                    str(self.root),
                ]
            )

        self.assertEqual(0, exit_code)
        self.assertEqual("prod.registry.test\n", output.getvalue())

    def test_registry_authority_rejects_conflicting_authorities_with_exit_two(self) -> None:
        app = self.root / "cyber-stack/matrix/prod/app-stack/kustomization.yaml"
        content = app.read_text(encoding="utf-8").replace(
            "prod.registry.test/release/prod/ssl-proxy",
            "other.registry.test/release/prod/ssl-proxy",
            1,
        )
        app.write_text(content, encoding="utf-8")

        errors = io.StringIO()
        with redirect_stderr(errors):
            exit_code = main(
                [
                    "registry-authority",
                    "--environment",
                    "prod",
                    "--repository-root",
                    str(self.root),
                ]
            )

        self.assertEqual(2, exit_code)
        self.assertIn("must use one registry authority", errors.getvalue())
        self.assertIn("other.registry.test", errors.getvalue())
        self.assertIn("prod.registry.test", errors.getvalue())

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

    def test_updates_only_digest_and_accepts_kustomize_bare_equals(self) -> None:
        path = self.root / "cyber-stack/matrix/prod/app-stack/kustomization.yaml"
        original = path.read_text(encoding="utf-8") + "delimiter: =\n"
        path.write_text(original, encoding="utf-8")
        replacement = "sha256:" + "c" * 64

        update_image_digest(path, "ssl-proxy", replacement)

        updated = path.read_text(encoding="utf-8")
        self.assertEqual(original.replace(PIN, replacement, 1), updated)
        self.assertTrue(updated.endswith("delimiter: =\n"))


if __name__ == "__main__":
    unittest.main()
