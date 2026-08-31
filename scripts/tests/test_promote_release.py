from __future__ import annotations

import json
import sys
import tempfile
import unittest
import urllib.error
from pathlib import Path
from unittest import mock

REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPOSITORY_ROOT / "scripts"))

from image_contract import FIRST_PARTY_SERVICES, ImageContractError  # noqa: E402
from promote_release import github_request, load_release_manifest  # noqa: E402
from scripts.tests.test_publish_images import PIN, write_contract  # noqa: E402


class PromoteReleaseTest(unittest.TestCase):
    def test_github_transport_failures_are_contextual_runtime_errors(self) -> None:
        with mock.patch(
            "promote_release.urllib.request.urlopen",
            side_effect=urllib.error.URLError("offline"),
        ):
            with self.assertRaisesRegex(RuntimeError, "request failed: offline"):
                github_request("token", "owner/repository", "GET", "/pulls")

        with mock.patch(
            "promote_release.urllib.request.urlopen",
            side_effect=TimeoutError(),
        ):
            with self.assertRaisesRegex(RuntimeError, "timed out"):
                github_request("token", "owner/repository", "GET", "/pulls")

    def test_manifest_requires_all_services_and_exact_repositories(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            write_contract(root)
            source = "c" * 40
            path = root / "release.json"
            path.write_text(
                json.dumps(
                    {
                        "schemaVersion": 1,
                        "environment": "prod",
                        "sourceRevision": source,
                        "images": [
                            {
                                "service": service,
                                "repository": f"registry.test:5000/releases/{service}",
                                "digest": PIN,
                                "sourceRevision": source,
                            }
                            for service in FIRST_PARTY_SERVICES
                        ],
                    }
                ),
                encoding="utf-8",
            )

            manifest = load_release_manifest(path, root)
            self.assertEqual(source, manifest.source_revision)
            self.assertEqual(set(FIRST_PARTY_SERVICES), {image.service for image in manifest.images})

            document = json.loads(path.read_text(encoding="utf-8"))
            document["images"][0]["repository"] = "registry.test:5000/wrong/image"
            path.write_text(json.dumps(document), encoding="utf-8")
            with self.assertRaisesRegex(ImageContractError, "repository drift"):
                load_release_manifest(path, root)


if __name__ == "__main__":
    unittest.main()
