from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path

REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPOSITORY_ROOT / "scripts"))

from image_contract import FIRST_PARTY_SERVICES, ImageContractError  # noqa: E402
from promote_release import load_release_manifest  # noqa: E402
from test_publish_images import PIN, write_contract  # noqa: E402


class PromoteReleaseTest(unittest.TestCase):
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
